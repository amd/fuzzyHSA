# SPDX-License-Identifier: Apache-2.0
"""First-slice integration on real gfx942 hardware.

Gated behind --integration and an accessible /dev/kfd. These exercise the real MI300X
submission path: queue setup, and a process-isolated fuzz campaign that runs a baseline
PM4 stream to completion, detects VM faults with faulting VAs, and recovers without cascade.
"""
import os
import tempfile

import pytest

pytestmark = pytest.mark.integration

_HAS_KFD = os.path.exists("/dev/kfd")
_GPU = int(os.environ.get("FUZZYHSA_GPU", "0"))


@pytest.mark.skipif(not _HAS_KFD, reason="no /dev/kfd")
def test_mi300_queue_setup():
    """KFD submission-dance setup: open -> acquire_vm -> runtime_enable -> events ->
    alloc BOs -> create COMPUTE_AQL queue -> mmap doorbell."""
    from fuzzyHSA.hw.mi300 import Mi300Backend
    b = Mi300Backend(_GPU)
    b.setup()
    try:
        assert b._queue_id is not None and b._doorbell is not None
    finally:
        b.teardown()


@pytest.mark.skipif(not _HAS_KFD, reason="no /dev/kfd")
def test_mi300_slice_isolated():
    """The full first slice, process-isolated: a baseline COPY_DATA + RELEASE_MEM stream
    completes (D1), mutated addresses produce vm_faults with captured faulting VAs (D2),
    and the campaign recovers across faults without wedging."""
    from fuzzyHSA.campaign.hw_runner import run_campaign_isolated
    from fuzzyHSA.campaign.record import Recorder
    with tempfile.TemporaryDirectory() as root:
        res = run_campaign_isolated(_GPU, "COPY_DATA", seed=3, n=10, record_root=root,
                                    timeout_ms=1200)
        assert res.iters == 10, res
        assert res.by_class.get("ok", 0) >= 1, f"baseline must complete: {res.by_class}"
        assert res.by_class.get("vm_fault", 0) >= 1, f"fuzzing must find vm_faults: {res.by_class}"
        assert not res.wedged
        rec = Recorder(root)
        vms = [r["finding"] for r in rec.records()
               if r.get("finding") and r["finding"]["cls"] == "vm_fault"]
        assert vms and all(f["signals"]["faulting_va"] for f in vms)
