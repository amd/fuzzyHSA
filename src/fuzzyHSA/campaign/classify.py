# SPDX-License-Identifier: Apache-2.0
"""The detection oracle (ticket 06).

The one rule that kills the naive "any amdgpu: line = crash": a result is a FINDING
only with a signal *beyond clean rejection*. HW_EXCEPTION with the GPU still live and
no reset is a rejection, not a bug. The lone ambiguous signal (HW_EXCEPTION) is split
purely by the liveness re-probe + reset delta.
"""
from __future__ import annotations

import hashlib
import re

from .finding import FindingClass, RawSignals

# dmesg markers, classified (NOT substring-any). Ordered most-severe first.
_DMESG_MARKERS: tuple[tuple[re.Pattern, FindingClass], ...] = (
    (re.compile(r"KASAN|BUG:|Oops|kernel NULL pointer|general protection fault"), FindingClass.OS_KERNEL_BUG),
    (re.compile(r"ring .* timeout|GPU reset|amdgpu_device_gpu_recover|GPU recovery"), FindingClass.GPU_RESET),
    (re.compile(r"VM_L2_PROTECTION_FAULT|retry page fault|VM fault|page fault"), FindingClass.VM_FAULT),
)


def classify(s: RawSignals) -> FindingClass:
    """Map observed signals to a finding class. Severity order matters: kernel bug >
    reset/wedge > vm_fault > hang > rejection > ok."""
    # 1. kernel-level: liveness gone, or a KASAN/BUG marker -> worst class
    if s.liveness_pass is False and _dmesg_class(s) is FindingClass.OS_KERNEL_BUG:
        return FindingClass.OS_KERNEL_BUG
    if _dmesg_class(s) is FindingClass.OS_KERNEL_BUG:
        return FindingClass.OS_KERNEL_BUG

    # 2. reset: the driver recovered the queue (counter moved)
    if s.reset_delta > 0:
        return FindingClass.GPU_RESET

    # 2.5 silent corruption: the case COMPLETED cleanly (signal written, no fault/hang) yet a
    # guard region past the target BO was overwritten — it wrote memory it had no business
    # touching. We require clean completion for two reasons: (a) "silent" means no fault — a case
    # that also faulted is a vm_fault (and the runner must treat it as one, to respawn its now-dead
    # queue context); (b) on a fault/hang the GPU L2 is never flushed, so the canary read would be
    # unreliable there anyway. canary_corrupted is still recorded in RawSignals on every path.
    if s.canary_corrupted and s.signal_written and not s.signal_timeout \
            and "MEMORY" not in s.kfd_events and "HW_EXCEPTION" not in s.kfd_events:
        return FindingClass.SILENT_CORRUPTION

    # 3. HW_EXCEPTION split: live+no-reset = rejection; dead = firmware wedge
    if "HW_EXCEPTION" in s.kfd_events:
        if s.liveness_pass is False:
            return FindingClass.FIRMWARE_WEDGE
        return FindingClass.CLEAN_REJECTION  # firmware refused a bad packet, correctly

    # 4. VM fault: the MEMORY event carries the faulting VA
    if "MEMORY" in s.kfd_events or _dmesg_class(s) is FindingClass.VM_FAULT:
        return FindingClass.VM_FAULT

    # 5. hang: no completion and the ring stalled at the packet
    if s.signal_timeout and not s.rptr_advanced:
        return FindingClass.GPU_HANG

    # 6. completion arrived (or ring advanced and nothing faulted) -> ran clean
    if s.signal_written:
        return FindingClass.OK

    # ambiguous: no event, no signal, but ring advanced -> treat as OK (slow but alive)
    return FindingClass.OK


def _dmesg_class(s: RawSignals) -> FindingClass | None:
    for line in s.dmesg:
        for pat, cls in _DMESG_MARKERS:
            if pat.search(line):
                return cls
    return None


# per-run noise stripped before a dmesg line contributes to a signature
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_NUM = re.compile(r"\b\d+\b")
_TS = re.compile(r"^\[\s*\d+\.\d+\]\s*")


def _normalize_dmesg(line: str) -> str:
    line = _TS.sub("", line)
    line = _HEX.sub("0xADDR", line)
    return _NUM.sub("N", line).strip()


def dedup_sig(cls: FindingClass, opcode: str, mutated_field: str | None,
              signal_class: str = "") -> str:
    """Stable per-bucket signature. Deliberately coarse: excludes per-run noise
    (faulting VA, timestamps, pids, seed). Start field-level; refine a class's key
    only if a bucket is later proven to hide two distinct bugs."""
    key = f"{cls.value}|{opcode}|{mutated_field or '-'}|{signal_class}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def signal_class_of(s: RawSignals) -> str:
    """A coarse signal fingerprint for the dedup key — the normalized dmesg marker
    set, not raw lines."""
    marks = sorted({_normalize_dmesg(line) for line in s.dmesg})
    ev = ",".join(sorted(s.kfd_events))
    return f"{ev};{'|'.join(marks)}" if marks else ev
