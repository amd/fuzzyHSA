# SPDX-License-Identifier: Apache-2.0
"""Finding taxonomy + records (oracle ticket 06).

``RawSignals`` is what the HW boundary observes for one submitted case; ``classify``
turns it into a ``FindingClass``; a ``Finding`` is the agent-readable record.
"""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field


class FindingClass(str, enum.Enum):
    OK = "ok"                            # completed, no fault — not a finding
    CLEAN_REJECTION = "clean_rejection"  # firmware refused a bad packet — not a finding
    VM_FAULT = "vm_fault"
    GPU_HANG = "gpu_hang"
    GPU_RESET = "gpu_reset"
    FIRMWARE_WEDGE = "firmware_wedge"
    OS_KERNEL_BUG = "os_kernel_bug"
    SILENT_CORRUPTION = "silent_corruption"  # completed without fault but wrote out of bounds
    ISOLATION_BREAK = "isolation_break"


# classes that are NOT findings: expected, correct outcomes
_NON_FINDING = {FindingClass.OK, FindingClass.CLEAN_REJECTION}
NON_FINDING_NAMES = frozenset(c.value for c in _NON_FINDING)
# classes that mean the GPU is no longer usable -> drives the wedge marker (08)
WEDGE_CLASSES = {FindingClass.GPU_RESET, FindingClass.FIRMWARE_WEDGE, FindingClass.OS_KERNEL_BUG}


def is_finding(cls: FindingClass) -> bool:
    return cls not in _NON_FINDING


def is_finding_name(cls: str) -> bool:
    """String-level predicate for callers reading class names off the manifest."""
    return cls not in NON_FINDING_NAMES


@dataclass(frozen=True)
class RawSignals:
    """Observed signals for one submitted case (the HW boundary's output)."""
    kfd_events: tuple[str, ...] = ()     # subset of {"SIGNAL","MEMORY","HW_EXCEPTION"}
    faulting_va: int | None = None
    signal_written: bool = False         # RELEASE_MEM completion arrived
    signal_timeout: bool = False         # completion never arrived within budget
    rptr_advanced: bool = True           # ring read-pointer moved past the packet
    reset_delta: int = 0                 # GPU reset-counter increment across the case
    dmesg: tuple[str, ...] = ()          # raw dmesg lines captured during the case
    liveness_pass: bool | None = None    # post-case re-probe on a fresh queue (None = not run)
    canary_corrupted: bool = False       # a guard region past the target BO was overwritten (OOB)
    canary_offset: int | None = None     # byte offset of the first corrupted guard word


@dataclass(frozen=True)
class Recipe:
    """Everything needed to regenerate a case (the two-track replay, track 1)."""
    seed: int
    spec_version: str
    fw_version: str
    opcode: str
    mutated_field: str | None
    mutated_value: int | None
    baseline: dict = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    cls: FindingClass
    dedup_sig: str
    recipe: Recipe
    decoded_stream: list        # list of DecodedPacket-as-dict
    signals: RawSignals
    replay_blob: str | None = None   # path to materialized bytes (track 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cls"] = self.cls.value
        return d
