# SPDX-License-Identifier: Apache-2.0
"""Regression guard for the ioctl-definition parser regexes.

These broke silently once: the ctypesgen output format changed to
`AMDKFD_IOC_X = (AMDKFD_IOWR (nr, struct))` while the patterns still expected an
older `_IOWR(ord('K'), ...)` form, so the collection parsed to zero ioctls — and
no test caught it because the only ioctl coverage lived in GPU-gated integration
tests. This locks the format AND the read-only (_IOR) recovery.
"""
from fuzzyHSA.kfd.ioctl import _CTYPESGEN_PATTERN, _DIRECTION_MAP, _LEGACY_PATTERN

# A verbatim slice of real ctypesgen (>=1.1.1) output.
CTYPESGEN_SAMPLE = """
    AMDKFD_IOC_GET_VERSION = (AMDKFD_IOR (0x01, struct_kfd_ioctl_get_version_args))
    AMDKFD_IOC_CREATE_QUEUE = (AMDKFD_IOWR (0x02, struct_kfd_ioctl_create_queue_args))
    AMDKFD_IOC_ACQUIRE_VM = (AMDKFD_IOW (0x15, struct_kfd_ioctl_acquire_vm_args))
"""
LEGACY_SAMPLE = "AMDKFD_IOC_GET_VERSION = _IOR(ord('K'), 0x01, struct_kfd_ioctl_get_version_args)"


def _parse(pattern, text):
    return {m.group(1): (m.group(2), int(m.group(3), 16), m.group(4))
            for m in pattern.finditer(text)}


def test_ctypesgen_format_parses_all_directions():
    got = _parse(_CTYPESGEN_PATTERN, CTYPESGEN_SAMPLE)
    assert set(got) == {
        "AMDKFD_IOC_GET_VERSION", "AMDKFD_IOC_CREATE_QUEUE", "AMDKFD_IOC_ACQUIRE_VM"
    }
    # the read-only one is the regression: it must not be dropped
    assert got["AMDKFD_IOC_GET_VERSION"] == ("IOR", 0x01, "struct_kfd_ioctl_get_version_args")
    assert got["AMDKFD_IOC_CREATE_QUEUE"][0] == "IOWR"
    assert got["AMDKFD_IOC_ACQUIRE_VM"][0] == "IOW"


def test_legacy_format_still_parses():
    got = _parse(_LEGACY_PATTERN, LEGACY_SAMPLE)
    assert got["AMDKFD_IOC_GET_VERSION"] == ("IOR", 0x01, "struct_kfd_ioctl_get_version_args")


def test_direction_map_covers_every_captured_token():
    # every direction the patterns can capture must have a mapping
    for tok in ("IO", "IOR", "IOW", "IOWR"):
        assert tok in _DIRECTION_MAP
    assert _DIRECTION_MAP["IOR"] == 2 and _DIRECTION_MAP["IOWR"] == 3
