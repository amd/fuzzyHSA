# SPDX-License-Identifier: Apache-2.0
"""Process-isolation orchestration (hw_runner parent). No GPU: the worker-spawn seam is
mocked by a fake that writes manifest records, simulating workers that resolve cases and
exit on VM-killing classes or die mid-case."""
from fuzzyHSA.campaign.finding import Recipe
from fuzzyHSA.campaign.hw_runner import _VM_KILLING, run_campaign_isolated
from fuzzyHSA.campaign.record import Recorder

_KILLING = {c.value for c in _VM_KILLING}


def _fake_spawn(outcomes):
    """outcomes: {index: "ok"|"vm_fault"|"gpu_hang"|"crash"}. A worker resolves cases from
    conf.start; on a VM-killing class it exits (parent respawns); on "crash" it records
    pending and returns WITHOUT resolving (a hard crash the parent must handle)."""
    def spawn(conf, timeout):
        rec = Recorder(conf.record_root)
        for i in range(conf.start, conf.total):
            cid = f"{conf.campaign_id}-{i:06d}"
            rec.record_pending(cid, Recipe(conf.seed, "v", "f", conf.packet, None, None), [i])
            o = outcomes.get(i, "ok")
            if o == "crash":
                return
            finding = {"id": cid, "cls": o, "dedup_sig": f"s{i}"} if o in _KILLING else None
            rec.resolve(cid, o, f"s{i}", finding)
            if o in _KILLING:
                return
    return spawn


def _run(tmp_path, n, outcomes):
    return run_campaign_isolated(0, "COPY_DATA", 1, n, tmp_path,
                                 _spawn=_fake_spawn(outcomes), worker_timeout=1)


def test_all_ok_one_worker(tmp_path):
    res = _run(tmp_path, 5, {})
    assert res.iters == 5 and res.by_class == {"ok": 5}
    assert not res.wedged and res.hard_crashes == 0


def test_vm_faults_respawn_no_cascade(tmp_path):
    # cases 1 and 3 fault; each exits its worker, parent respawns and finishes all 5
    res = _run(tmp_path, 5, {1: "vm_fault", 3: "vm_fault"})
    assert res.iters == 5
    assert res.by_class == {"ok": 3, "vm_fault": 2}
    assert len(res.buckets) == 2 and not res.wedged


def test_hard_crash_is_marked_and_skipped(tmp_path):
    # case 2 crashes the worker before classifying; next worker makes progress past it
    res = _run(tmp_path, 5, {2: "crash"})
    assert res.iters == 5
    assert res.by_class.get("os_kernel_bug") == 1 and res.hard_crashes == 1
    assert not res.wedged


def test_two_stalls_wedge_and_stop(tmp_path):
    # every worker crashes on the same index with no progress -> wedged after 2 stalls
    res = _run(tmp_path, 5, {0: "crash", 1: "crash"})
    assert res.wedged and res.hard_crashes >= 1


def test_resume_indices_are_contiguous(tmp_path):
    # a worker that faults on the first case still advances the parent one at a time
    res = _run(tmp_path, 3, {0: "vm_fault", 1: "vm_fault", 2: "vm_fault"})
    assert res.iters == 3 and res.by_class == {"vm_fault": 3}
