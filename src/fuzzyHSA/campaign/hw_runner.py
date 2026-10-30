# SPDX-License-Identifier: Apache-2.0
"""Process-isolated campaign runner for real hardware.

A no-retry VM fault permanently wedges a process's GPU context — it cannot be cleared
in-process (re-acquire_vm returns EBUSY even after closing the fds). So each fuzz case
that faults/hangs is run to the point of the fault in a WORKER SUBPROCESS, which records
the result and exits; the parent respawns a fresh worker to continue. Blast radius of any
single case is one process. The manifest (record-before-send + fsync) is the source of
truth across respawns: a case written ``pending`` but never ``resolved`` is the culprit of
a hard crash (the worker died before it could classify), exactly as the map specifies.
"""
from __future__ import annotations

import dataclasses
import multiprocessing as mp
from pathlib import Path

from ..fuzz.gen import MAPPED
from ..pm4.decode import decode
from .classify import classify, dedup_sig, signal_class_of
from .finding import Finding, FindingClass, Recipe, is_finding
from .record import Recorder

# classes that leave the VM/queue unusable -> the worker must exit and the parent respawn
_VM_KILLING = {FindingClass.VM_FAULT, FindingClass.GPU_HANG, FindingClass.GPU_RESET,
               FindingClass.FIRMWARE_WEDGE, FindingClass.OS_KERNEL_BUG}


@dataclasses.dataclass
class _Conf:
    gpu_index: int
    packet: str
    seed: int
    total: int
    start: int
    record_root: str
    campaign_id: str
    spec_version: str
    fw_version: str
    timeout_ms: float
    field_weights: dict | None
    modes: dict | None = None


def _case_id(conf: _Conf, i: int) -> str:
    return f"{conf.campaign_id}-{i:06d}"


def _worker(conf: _Conf) -> None:
    """Runs in a fresh subprocess. Processes cases [start, total) until a VM-killing class,
    recording each; then returns (the parent respawns from the next index)."""
    from ..fuzz.gen import Pm4Generator
    from ..hw.mi300 import Mi300Backend
    from ..pm4.spec import REGISTRY

    backend = Mi300Backend(conf.gpu_index)
    backend.setup()
    rec = Recorder(conf.record_root)
    packet = REGISTRY[conf.packet]
    gen = Pm4Generator(packet, seed=conf.seed, field_weights=conf.field_weights, modes=conf.modes)
    try:
        for i, case in enumerate(gen.cases(conf.total)):
            if i < conf.start:
                continue
            cid = _case_id(conf, i)
            recipe = Recipe(seed=conf.seed, spec_version=conf.spec_version, fw_version=conf.fw_version,
                            opcode=case.packet.name, mutated_field=case.mutated_field,
                            mutated_value=case.mutated_value,
                            baseline={k: v for k, v in case.values.items() if v is not MAPPED})
            dwords = backend.materialize(case)
            blob = rec.record_pending(cid, recipe, dwords)     # fsync BEFORE submit
            backend.submit(dwords)
            sig = backend.observe(conf.timeout_ms)
            # the worker is alive and executing, so the GPU is live for THIS case; a VM-killing
            # class means we exit right after recording it.
            sig = dataclasses.replace(sig, liveness_pass=True)
            cls = classify(sig)
            sg = dedup_sig(cls, case.packet.name, case.mutated_field, signal_class_of(sig))
            finding = None
            if is_finding(cls):
                finding = Finding(id=cid, cls=cls, dedup_sig=sg, recipe=recipe,
                                  decoded_stream=[d.__dict__ for d in decode(dwords)],
                                  signals=sig, replay_blob=blob).to_dict()
            rec.resolve(cid, cls.value, sg, finding)
            if cls in _VM_KILLING:
                return                                          # VM dead; parent respawns
            if cls is FindingClass.CLEAN_REJECTION:
                backend.recover()                               # queue may be unmapped; rebuild
    finally:
        backend.teardown()


@dataclasses.dataclass
class HwCampaignResult:
    iters: int
    by_class: dict
    buckets: dict
    wedged: bool
    hard_crashes: int


def _spawn_worker(conf: _Conf, worker_timeout: float) -> None:
    """Run one worker in a forked subprocess (fresh KFD context) and wait for it. fork, not
    spawn: the parent holds NO GPU device, so a forked child starts clean, and fork avoids
    re-importing the caller's __main__ (the spawn 'freeze_support' trap)."""
    ctx = mp.get_context("fork")
    p = ctx.Process(target=_worker, args=(conf,))
    p.start()
    p.join(worker_timeout)
    if p.is_alive():                                           # worker hung -> kill it
        p.terminate()
        p.join()


def run_campaign_isolated(gpu_index: int, packet: str, seed: int, n: int, record_root: str | Path, *,
                          campaign_id: str = "hw", spec_version: str = "pm4@1", fw_version: str = "mi300",
                          timeout_ms: float = 1500.0, field_weights: dict | None = None,
                          modes: dict | None = None,
                          worker_timeout: float = 120.0, guard=None, _spawn=_spawn_worker) -> HwCampaignResult:
    """Spawn worker subprocesses until all ``n`` cases resolve. Respawns after each VM-killing
    case. A case written pending but never resolved (hard crash) is marked os_kernel_bug and
    skipped; if two consecutive workers make zero progress the GPU is wedged and we stop.
    ``_spawn`` is the worker-runner seam (overridable in tests)."""
    rec = Recorder(record_root)
    done, hard_crashes, wedged = 0, 0, False
    stall = 0
    resolved: set[int] = set()        # resolved case indices, accumulated incrementally
    offset = 0                        # manifest byte cursor -> O(N) total scan, not O(N^2)
    while done < n:
        conf = _Conf(gpu_index, packet, seed, n, done, str(record_root), campaign_id,
                     spec_version, fw_version, timeout_ms, field_weights, modes)
        _spawn(conf, worker_timeout)

        new, offset = rec.tail_records(offset)                # only the lines this worker appended
        for r in new:
            rid = r.get("id", "")
            if r.get("status") == "resolved" and rid.startswith(campaign_id + "-"):
                try:
                    resolved.add(int(rid.rsplit("-", 1)[1]))
                except ValueError:
                    pass
        new_done = done
        while new_done in resolved:                            # advance over contiguous resolved
            new_done += 1
        if new_done > done:
            stall = 0
            done = new_done
            continue
        # no progress: the pending case at `done` crashed the worker before it classified. We
        # only reach here when `done` is unresolved (the while loop didn't advance), so there is
        # by construction no finding for it — mark it unconditionally; probing rec.finding() here
        # would re-scan the whole manifest (O(N^2) on the wedge/hang path) to answer a known None.
        cid = _case_id(conf, done)
        sig = dedup_sig(FindingClass.OS_KERNEL_BUG, packet, "?", "hard_crash")
        rec.resolve(cid, FindingClass.OS_KERNEL_BUG.value, sig,
                    {"id": cid, "cls": "os_kernel_bug", "note": "worker died before classify",
                     "dedup_sig": sig})
        hard_crashes += 1
        done += 1
        stall += 1
        if stall >= 2:                                          # GPU won't make progress -> wedged
            wedged = True
            if guard is not None:
                guard.mark_wedged(gpu_index, "os_kernel_bug", campaign_id)
            break

    return _aggregate(rec, campaign_id, n, wedged, hard_crashes)


def _aggregate(rec: Recorder, campaign_id: str, n: int, wedged: bool, hard_crashes: int) -> HwCampaignResult:
    by_class: dict = {}
    for r in rec.records():
        if r.get("status") == "resolved" and r.get("id", "").startswith(campaign_id + "-"):
            by_class[r["cls"]] = by_class.get(r["cls"], 0) + 1
    return HwCampaignResult(iters=sum(by_class.values()), by_class=by_class,
                            buckets=rec.buckets(), wedged=wedged, hard_crashes=hard_crashes)
