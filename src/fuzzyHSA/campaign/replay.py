# SPDX-License-Identifier: Apache-2.0
"""Repro + minimize (D8): make a finding actionable.

repro re-runs a recorded finding and reports whether it reproduces the same class — a firmware
team needs to know a bug is deterministic, not flaky. minimize delta-debugs a multi-field finding
down to the smallest set of mutations that still triggers it, so the hand-off is "this one field
value wedges the GPU," not a soup of three.

Both re-execute a reconstructed case in an isolated worker (it may crash the GPU), so the HW
re-exec is a seam (``_run1``) that CI mocks. Reconstruction is pure: a case is rebuilt from its
recipe's baseline + mutated label, so no run-specific VA is needed (addresses re-resolve to the
replay backend's own BOs).
"""
from __future__ import annotations

_MAPPED_TAG = "__MAPPED__"   # how an address field crosses the worker boundary (UNBOUND isn't picklable)
_INCONCLUSIVE = "__inconclusive__"   # a trial that couldn't run (setup failed / worker died) — NOT a class


def _guard_rerunnable(rec: dict | None, finding_id: str) -> dict | None:
    """Return an error dict if this record must not be re-run, else None. repro/minimize only make
    sense for a reproducible FINDING that does not wedge the whole GPU."""
    from .finding import WEDGE_CLASSES, is_finding_name
    if rec is None or "recipe" not in rec:
        return {"error": "no_such_finding", "id": finding_id}
    cls = rec.get("cls")
    if cls is None or not is_finding_name(cls):
        return {"error": "not_a_finding", "id": finding_id, "cls": cls}
    if cls in {c.value for c in WEDGE_CLASSES}:          # re-running wedges a shared GPU; result unreliable
        return {"error": "unsafe_to_rerun", "id": finding_id, "cls": cls,
                "note": "re-running a GPU-wedging class on a shared device is refused"}
    return None


def mutated_fields(recipe: dict, packet) -> list[str]:
    """The fuzzable fields this case perturbed. recipe.baseline excludes only UNmutated address
    fields (they were MAPPED); so a mutated address appears there with its wild value, and a
    mutated non-address field appears with a value differing from the true baseline."""
    from ..pm4.spec import baseline_values
    base = baseline_values(packet)
    rb = recipe.get("baseline", {})
    out = []
    for f in packet.fields:
        if f.role == "count":
            continue
        if f.role == "address":
            if f.name in rb:                          # present => mutated to a concrete wild VA
                out.append(f.name)
        elif f.name in rb and rb[f.name] != base.get(f.name):
            out.append(f.name)
    return out


def _case_values(packet, recipe: dict, keep: set[str] | None):
    """Rebuild a case's field values from its recipe. ``keep`` (minimize) restricts which mutated
    fields stay perturbed; the rest revert to baseline. A mutated+active ADDRESS keeps its recorded
    wild VA (erasing it would hide an address-driven fault); otherwise addresses re-resolve to a
    real BO (the MAPPED tag)."""
    from ..pm4.spec import baseline_values
    base = baseline_values(packet)
    rb = recipe.get("baseline", {})
    muts = set(mutated_fields(recipe, packet))
    values = {}
    for f in packet.fields:
        if f.role == "count":
            continue
        active = f.name in muts and (keep is None or f.name in keep)
        if f.role == "address":
            values[f.name] = rb[f.name] if (active and f.name in rb) else _MAPPED_TAG
        elif active:
            values[f.name] = rb.get(f.name, base.get(f.name, 0))
        else:
            values[f.name] = base.get(f.name, 0)
    return values


def _struct_of(label: str | None):
    """Parse a ``struct:<kind><signed-k>`` label back to the (kind, k) op, else ()."""
    if not label or not label.replace("seq:", "").startswith("struct:"):
        return ()
    body = label.split("struct:", 1)[1]
    kind = "count" if body.startswith("count") else "truncate"
    return (kind, int(body[len(kind):]))


def repro(gpu_index, recorder, finding_id, *, timeout_ms=1500.0, worker_timeout=90.0, _run1=None):
    """Re-run a recorded finding once and report whether it reproduces the same class."""
    _run1 = _run1 or _run1_hw
    from ..pm4.spec import REGISTRY
    rec = _find_case(recorder, finding_id)
    err = _guard_rerunnable(rec, finding_id)
    if err:
        return err
    recipe = rec["recipe"]
    packet = REGISTRY[recipe["opcode"]]
    label = recipe.get("mutated_field")
    cls, sig = _run1(gpu_index, recipe["opcode"], _case_values(packet, recipe, None),
                     label, _struct_of(label), timeout_ms, worker_timeout)
    return {"id": finding_id, "original_cls": rec.get("cls"), "replay_cls": cls,
            "reproduced": cls == rec.get("cls"), "replay_dedup_sig": sig}


def minimize(gpu_index, recorder, finding_id, *, timeout_ms=1500.0, worker_timeout=90.0, _run1=None):
    """Delta-debug a finding to the minimal set of mutated fields that still reproduce its class.
    Greedy one-field removal: drop a mutation, re-run; if it still yields the same class, the field
    was not load-bearing. Returns the minimal set (a subset of the original mutations)."""
    _run1 = _run1 or _run1_hw
    from ..pm4.spec import REGISTRY
    rec = _find_case(recorder, finding_id)
    err = _guard_rerunnable(rec, finding_id)
    if err:
        return err
    recipe = rec["recipe"]
    packet = REGISTRY[recipe["opcode"]]
    label = recipe.get("mutated_field")
    struct = _struct_of(label)
    target = rec.get("cls")
    muts = mutated_fields(recipe, packet)

    keep = set(muts)
    trials = inconclusive = 0
    for f in list(muts):                              # try to drop each field in turn
        candidate = keep - {f}
        if not candidate and not struct:              # don't reduce to a no-op baseline
            continue
        cls, _ = _run1(gpu_index, recipe["opcode"], _case_values(packet, recipe, candidate),
                       label, struct, timeout_ms, worker_timeout)
        trials += 1
        if cls == target:                             # reproduced WITHOUT f -> f not load-bearing
            keep = candidate
        elif cls == _INCONCLUSIVE:                    # couldn't test (setup fail/crash) -> keep f
            inconclusive += 1
        # else: a different real class -> f IS load-bearing -> keep f
    return {"id": finding_id, "cls": target, "original_fields": muts,
            "minimal_fields": sorted(keep), "structural": bool(struct),
            "trials": trials, "inconclusive_trials": inconclusive}


def _find_case(recorder, finding_id) -> dict | None:
    for r in recorder.case_records():
        if r.get("id") == finding_id and "recipe" in r:
            return r
    return None


def _run1_hw(gpu_index, packet_name, values, label, struct, timeout_ms, worker_timeout):
    """Re-execute ONE reconstructed case in a forked worker; return (cls_value, dedup_sig). A
    crash (no report) is reported as os_kernel_bug, matching the campaign runner's semantics."""
    import multiprocessing as mp

    ctx = mp.get_context("fork")
    q = ctx.Queue()

    def worker():
        import dataclasses

        from ..fuzz.gen import MAPPED, GenCase
        from ..hw.mi300 import Mi300Backend
        from ..pm4.spec import REGISTRY, baseline_values
        from .classify import classify, dedup_sig, signal_class_of
        packet = REGISTRY[packet_name]
        vals = {k: (MAPPED if v == _MAPPED_TAG else v) for k, v in values.items()}
        # a seq finding only triggers after a valid baseline packet of the same opcode; rebuild it
        prefix = ()
        if (label or "").startswith("seq:"):
            pre = baseline_values(packet)
            for pf in packet.fields:
                if pf.role == "address":
                    pre[pf.name] = MAPPED
            prefix = (GenCase(packet, pre, None, None),)
        case = GenCase(packet, vals, label, None, struct=struct, prefix=prefix)
        try:
            b = Mi300Backend(gpu_index)
            b.setup()
        except Exception:
            q.put((_INCONCLUSIVE, ""))            # couldn't even set up (e.g. GPU wedged by a prior trial)
            return
        try:
            b.submit(b.materialize(case))
            sig = dataclasses.replace(b.observe(timeout_ms), liveness_pass=True)
            cls = classify(sig)
            q.put((cls.value, dedup_sig(cls, packet_name, label, signal_class_of(sig))))
        except Exception:
            q.put((_INCONCLUSIVE, ""))
        finally:
            try:
                b.teardown()
            except Exception:
                pass

    p = ctx.Process(target=worker)
    p.start()
    p.join(worker_timeout)
    if p.is_alive():
        p.terminate()
        p.join()
    try:
        return q.get_nowait()
    except Exception:
        return (_INCONCLUSIVE, "")                # worker died without reporting -> can't conclude
