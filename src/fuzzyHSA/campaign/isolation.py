# SPDX-License-Identifier: Apache-2.0
"""Cross-process isolation oracle (D6).

Tests one firmware property: can a packet issued by one process reach another process's GPU
memory? A VICTIM fills a BO with a known word and publishes its GPU VA; it runs no packets, so
the region is constant. ATTACKER processes, each in their own VM, aim a write at that VA across a
few real surfaces (memory-selector WRITE_DATA + an absolute-addressing DMA). A changed victim
word is an ``ISOLATION_BREAK`` — the one finding treated as a hard security hit.

A negative ("holds") is only trustworthy with two guards, so this oracle enforces both:
  - a POSITIVE CONTROL (``self_write_probe``) proves the attack path actually lands a detectable
    write on a reachable VA; without it, a contained result is indistinguishable from a dud;
  - an EXECUTED count proves at least one attacker really submitted a write; a sweep where every
    attacker failed setup did zero work and must report ``inconclusive``, not ``holds``.

Scope, honestly: aiming the victim's GPUVM VA from a separate VM mostly probes VA/page-table
separation (a baseline VMID guarantee) plus absolute-addressing leakage. It does NOT yet probe
shared/imported handles, doorbell/MMIO, or VMID spoofing — those are stronger surfaces left for
later. A clean negative means these specific, executed attacks were contained.
"""
from __future__ import annotations

import dataclasses

from .classify import dedup_sig
from .finding import Finding, FindingClass, RawSignals, Recipe
from .record import Recorder

# attack surfaces, each a real way a write could reach target_va:
#   ("write", 5) memory selector, ("write", 2) TC/L2 selector, ("dma_das", None) absolute DMA.
# (dst_sel=0 is a REGISTER write — not memory — and engine_sel is reserved on MEC, so neither is
#  included: they cannot reach a memory VA and would overstate coverage.)
_VARIANTS = (("write", 5), ("write", 2), ("dma_das", None))
_WORD = 0xC0DEC0DE       # victim fill word
_POISON = 0xBADC0FFE     # attacker write value (deliberately != the fill word)

_EXECUTED = {"faulted", "wrote", "hw_exception", "nosig"}   # the attacker reached submit+observe


def _outcome(s: RawSignals) -> str:
    if "MEMORY" in s.kfd_events:
        return "faulted"
    if s.signal_written:
        return "wrote"
    if s.kfd_events:
        return s.kfd_events[0].lower()
    return "nosig"


def probe_isolation(victim, attacker, *, word: int = _WORD, poison: int = _POISON,
                    variants=_VARIANTS):
    """In-process probe over two backend-like objects. Returns (corrupted_offset | None,
    path_ok, outcomes). ``path_ok`` is the positive control: the attacker's write path lands a
    detectable word on its OWN reachable VA. Used by CI (fakes) and in-process checks; the real
    cross-process run uses ``run_isolation_campaign``'s forked ``_run``."""
    path_ok = attacker.self_write_probe(poison)
    va = victim.arm_canary(word)
    outcomes = []
    for kind, arg in variants:
        s = attacker.attack_write(va, poison, arg) if kind == "write" \
            else attacker.attack_dma_absolute(va, poison)
        outcomes.append((kind, arg, _outcome(s)))
    return victim.verify_canary(word), path_ok, outcomes


@dataclasses.dataclass
class IsolationResult:
    status: str            # "holds" | "isolation_break" | "inconclusive_attack_path" | "inconclusive_no_execution"
    broke: bool
    offset: int | None
    path_ok: bool          # positive control: the attack path demonstrably lands a write
    executed: int          # attackers that reached submit+observe (not a setup failure)
    attempts: int
    finding: dict | None


def run_isolation_campaign(gpu_index: int, record_root, *, campaign_id: str = "iso",
                           word: int = _WORD, poison: int = _POISON, variants=_VARIANTS,
                           worker_timeout: float = 120.0, guard=None, _run=None) -> IsolationResult:
    """Run the victim/attacker sweep and decide a trustworthy status. ``holds`` is reported ONLY
    when the positive control passed AND at least one attacker executed AND nothing broke. ``_run``
    is the two-process seam (real HW default; mocked in CI)."""
    _run = _run or _run_hw
    off, path_ok, outcomes = _run(gpu_index, word, poison, variants, worker_timeout)
    executed = sum(1 for (_k, _a, o) in outcomes if o in _EXECUTED)
    broke = off is not None

    finding = None
    if broke:
        status = "isolation_break"
        rec = Recorder(record_root)
        cid = f"{campaign_id}-break"
        recipe = Recipe(seed=0, spec_version="pm4@1", fw_version="mi300", opcode="WRITE_DATA",
                        mutated_field="isolation", mutated_value=poison)
        sig = dedup_sig(FindingClass.ISOLATION_BREAK, "WRITE_DATA", "isolation", f"offset={off}")
        finding = Finding(
            id=cid, cls=FindingClass.ISOLATION_BREAK, dedup_sig=sig, recipe=recipe,
            decoded_stream=[],
            signals=RawSignals(dmesg=(f"cross-process write reached victim VA at +0x{off:x}",)),
            replay_blob=None).to_dict()
        rec.resolve(cid, FindingClass.ISOLATION_BREAK.value, sig, finding)
    elif not path_ok:
        status = "inconclusive_attack_path"     # the write path itself didn't land -> negative is vacuous
    elif executed >= 1:
        status = "holds"                         # >=1 real attack executed and was contained
    else:
        status = "inconclusive_no_execution"     # every attacker failed setup -> no real work done

    return IsolationResult(status=status, broke=broke, offset=off, path_ok=path_ok,
                           executed=executed, attempts=len(outcomes), finding=finding)


def _run_hw(gpu_index, word, poison, variants, worker_timeout):
    """Real run: a positive-control process proves the write path lands; a long-lived victim holds
    the canary; a fresh attacker process per variant aims a write at the victim's VA and reports
    its outcome; the victim verifies once at the end. The parent holds no GPU state (fork-clean)."""
    import multiprocessing as mp

    ctx = mp.get_context("fork")

    # positive control: does the attack path land a detectable write on a reachable (own) VA?
    pc_q = ctx.Queue()

    def control_proc():
        from ..hw.mi300 import Mi300Backend
        try:
            b = Mi300Backend(gpu_index)
            b.setup()
            pc_q.put(b.self_write_probe(poison))
            b.teardown()
        except Exception:
            pc_q.put(False)

    cp = ctx.Process(target=control_proc)
    cp.start()
    cp.join(worker_timeout)
    if cp.is_alive():
        cp.terminate()
        cp.join()
    try:
        path_ok = pc_q.get_nowait()
    except Exception:
        path_ok = False

    # victim: hold the canary across the whole attacker sweep
    va_q, result_q, verify_evt = ctx.Queue(), ctx.Queue(), ctx.Event()

    def victim_proc():
        from ..hw.mi300 import Mi300Backend
        b = Mi300Backend(gpu_index)
        b.setup()
        va_q.put(b.arm_canary(word))
        verify_evt.wait()
        result_q.put(b.verify_canary(word))
        b.teardown()

    vp = ctx.Process(target=victim_proc)
    vp.start()
    va = va_q.get(timeout=worker_timeout)

    outcomes = []
    for kind, arg in variants:
        oq = ctx.Queue()

        def attacker_proc(kind=kind, arg=arg, q=oq):
            from ..hw.mi300 import Mi300Backend
            try:
                b = Mi300Backend(gpu_index)
                b.setup()
            except Exception:
                q.put((kind, arg, "setup_failed"))
                return
            try:
                s = b.attack_write(va, poison, arg) if kind == "write" \
                    else b.attack_dma_absolute(va, poison)
                q.put((kind, arg, _outcome(s)))
            except Exception:
                q.put((kind, arg, "exec_error"))
            finally:
                b.teardown()

        ap = ctx.Process(target=attacker_proc)
        ap.start()
        ap.join(worker_timeout)
        if ap.is_alive():
            ap.terminate()
            ap.join()
        try:
            outcomes.append(oq.get_nowait())
        except Exception:
            outcomes.append((kind, arg, "no_report"))

    verify_evt.set()
    off = result_q.get(timeout=worker_timeout)
    vp.join(worker_timeout)
    if vp.is_alive():
        vp.terminate()
        vp.join()
    return off, path_ok, outcomes
