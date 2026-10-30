# SPDX-License-Identifier: Apache-2.0
"""Oracle classifier (06) — the rejection-vs-finding split is the whole point."""
from fuzzyHSA.campaign.classify import classify, dedup_sig, signal_class_of
from fuzzyHSA.campaign.finding import FindingClass as FC
from fuzzyHSA.campaign.finding import RawSignals, is_finding


def test_valid_baseline_completes_ok():
    s = RawSignals(kfd_events=("SIGNAL",), signal_written=True, liveness_pass=True)
    assert classify(s) is FC.OK and not is_finding(FC.OK)


def test_hw_exception_live_is_clean_rejection_not_crash():
    # firmware refused a malformed packet; GPU still serves work -> NOT a finding
    s = RawSignals(kfd_events=("HW_EXCEPTION",), reset_delta=0, liveness_pass=True,
                   dmesg=("amdgpu: IB test failed, invalid packet",))
    assert classify(s) is FC.CLEAN_REJECTION
    assert not is_finding(FC.CLEAN_REJECTION)


def test_hw_exception_dead_is_firmware_wedge():
    s = RawSignals(kfd_events=("HW_EXCEPTION",), reset_delta=0, liveness_pass=False)
    assert classify(s) is FC.FIRMWARE_WEDGE and is_finding(FC.FIRMWARE_WEDGE)


def test_memory_event_is_vm_fault():
    s = RawSignals(kfd_events=("MEMORY",), faulting_va=0xDEAD0000, liveness_pass=True)
    assert classify(s) is FC.VM_FAULT and is_finding(FC.VM_FAULT)


def test_reset_delta_beats_everything_short_of_kernel():
    s = RawSignals(kfd_events=("HW_EXCEPTION",), reset_delta=1, liveness_pass=True)
    assert classify(s) is FC.GPU_RESET


def test_kasan_marker_is_kernel_bug():
    s = RawSignals(dmesg=("BUG: KASAN: slab-out-of-bounds in amdgpu_foo",), liveness_pass=False)
    assert classify(s) is FC.OS_KERNEL_BUG


def test_hang_is_timeout_with_stalled_rptr():
    s = RawSignals(signal_timeout=True, rptr_advanced=False, liveness_pass=True)
    assert classify(s) is FC.GPU_HANG


def test_silent_corruption_only_on_clean_completion():
    # the packet completed cleanly (signal written, no fault/hang) but overran into the guard
    s = RawSignals(kfd_events=("SIGNAL",), signal_written=True, liveness_pass=True,
                   canary_corrupted=True, canary_offset=0x40)
    assert classify(s) is FC.SILENT_CORRUPTION and is_finding(FC.SILENT_CORRUPTION)


def test_fault_that_also_scribbled_is_vm_fault_not_silent():
    # an OOB write that ALSO tripped a VM fault is a vm_fault: the queue context is dead (the
    # runner must respawn), and the canary read is untrustworthy without the L2 flush. The
    # canary flag is still preserved in the record, just not the headline class.
    s = RawSignals(kfd_events=("MEMORY",), faulting_va=0x1000, liveness_pass=True,
                   canary_corrupted=True)
    assert classify(s) is FC.VM_FAULT


def test_canary_on_a_hang_is_gpu_hang_not_silent():
    s = RawSignals(signal_timeout=True, rptr_advanced=False, liveness_pass=True, canary_corrupted=True)
    assert classify(s) is FC.GPU_HANG


def test_corruption_yields_to_kernel_bug_and_reset():
    from fuzzyHSA.campaign.finding import WEDGE_CLASSES
    assert classify(RawSignals(reset_delta=1, canary_corrupted=True)) is FC.GPU_RESET
    # and silent corruption is a finding but does NOT wedge the GPU (still usable)
    assert FC.SILENT_CORRUPTION not in WEDGE_CLASSES


def test_dedup_excludes_per_run_noise():
    # two VM faults differing only in faulting VA + timestamp collapse to one bucket
    a = RawSignals(kfd_events=("MEMORY",), dmesg=("[123.4] amdgpu: VM fault at 0xdead0000 pid 99",))
    b = RawSignals(kfd_events=("MEMORY",), dmesg=("[987.6] amdgpu: VM fault at 0xbeef1111 pid 42",))
    sig_a = dedup_sig(FC.VM_FAULT, "COPY_DATA", "dst_addr_lo", signal_class_of(a))
    sig_b = dedup_sig(FC.VM_FAULT, "COPY_DATA", "dst_addr_lo", signal_class_of(b))
    assert sig_a == sig_b


def test_dedup_separates_distinct_fields():
    s = signal_class_of(RawSignals(kfd_events=("MEMORY",)))
    assert dedup_sig(FC.VM_FAULT, "COPY_DATA", "dst_addr_lo", s) \
        != dedup_sig(FC.VM_FAULT, "COPY_DATA", "src_addr_lo", s)
