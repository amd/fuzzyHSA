# SPDX-License-Identifier: Apache-2.0
"""A simulated GPU backend for CI.

An honest adapter of ``GpuBackend``: ``submit`` keeps the dwords and ``observe`` judges
*those bytes* (decode -> reconstruct per-BO VAs / check enum domains), exactly as a real
oracle judges what the firmware received. So a ``materialize`` bug — wrong VA math, a
corrupt packet — now fails a test, instead of hiding behind a case back-channel.

Models just enough physics: a baseline completes (SIGNAL); an address resolving outside
the mapped BOs -> MEMORY event (VM fault); an enum/flag outside its authored domain ->
HW_EXCEPTION with the GPU still live (a clean firmware rejection, NOT a finding). It is
explicitly a simulation — real behaviour is whatever the firmware does.
"""
from __future__ import annotations

from ..campaign.finding import RawSignals
from ..fuzz.gen import GenCase
from ..pm4 import addr
from ..pm4.decode import decode
from ..pm4.spec import BY_OPCODE
from .stream import build_stream

# fake mapped BO virtual addresses (all < 4 GiB so the hi dword is 0)
_SRC_VA, _DST_VA, _SIGNAL_VA = 0x10000, 0x20000, 0x30000
_BO_VAS = {"src": _SRC_VA, "dst": _DST_VA}
# every BO the firmware would find mapped, across all packets in the stream
_MAPPED = {"src": _SRC_VA, "dst": _DST_VA, "address": _SIGNAL_VA}
_DST_BYTES = 0x1000   # modeled size of the dst target; a write past it overruns the guard


class FakeGpu:
    def __init__(self) -> None:
        self._submitted: list[int] = []

    def setup(self) -> None:
        pass

    def materialize(self, case: GenCase) -> list[int]:
        return build_stream(case, _BO_VAS, _SIGNAL_VA)

    def submit(self, dwords: list[int]) -> None:
        self._submitted = list(dwords)

    def observe(self, timeout_ms: float) -> RawSignals:
        """Judge the submitted dwords, as the real oracle judges what the firmware ran."""
        for dp in decode(self._submitted):
            pkt = BY_OPCODE.get(dp.opcode)
            if pkt is None:
                continue
            values = {name: info["value"] for name, info in dp.fields.items()}
            # unmapped address -> VM fault
            for bo, va in addr.reconstruct(pkt, values).items():
                if _MAPPED.get(bo) != va:
                    return RawSignals(kfd_events=("MEMORY",), faulting_va=va, liveness_pass=True,
                                      dmesg=(f"amdgpu: VM fault at 0x{va:x}",))
            # out-of-domain enum/flag -> firmware rejects, stays alive
            for f in pkt.fields:
                if f.role in ("enum", "flag") and f.domain and values.get(f.name) not in f.domain:
                    return RawSignals(kfd_events=("HW_EXCEPTION",), reset_delta=0, liveness_pass=True,
                                      dmesg=("amdgpu: ring test failed on invalid packet",))
            # an over-long DMA into the mapped dst overruns it -> guard page clobbered (OOB write)
            if dp.name == "DMA_DATA" and values.get("byte_count", 0) > _DST_BYTES \
                    and addr.reconstruct(pkt, values).get("dst") == _DST_VA:
                return RawSignals(kfd_events=("SIGNAL",), signal_written=True, liveness_pass=True,
                                  canary_corrupted=True, canary_offset=_DST_BYTES)
        return RawSignals(kfd_events=("SIGNAL",), signal_written=True, liveness_pass=True)

    def liveness_probe(self) -> bool:
        return True

    def teardown(self) -> None:
        pass
