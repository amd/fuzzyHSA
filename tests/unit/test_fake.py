# SPDX-License-Identifier: Apache-2.0
"""FakeGpu judges the SUBMITTED BYTES (candidate #1).

The old fake re-derived its verdict from the GenCase, so a materialize bug was invisible.
Now observe() decodes what submit() received — so a corrupt stream is catchable, and the
fake exercises the same seam shape as the real backend.
"""
from fuzzyHSA.fuzz.gen import Pm4Generator
from fuzzyHSA.hw.fake import _DST_VA, _SIGNAL_VA, _SRC_VA, FakeGpu
from fuzzyHSA.pm4.spec import COPY_DATA, RELEASE_MEM, baseline_values, build


def _baseline_stream():
    cd = baseline_values(COPY_DATA)
    cd.update(src_addr_lo=_SRC_VA, dst_addr_lo=_DST_VA)
    rm = baseline_values(RELEASE_MEM)
    rm.update(address_lo=_SIGNAL_VA, data_lo=1)
    return build(COPY_DATA, cd) + build(RELEASE_MEM, rm)


def test_observe_reads_submitted_bytes_not_a_case():
    g = FakeGpu()
    g.submit(_baseline_stream())
    assert g.observe(1.0).signal_written is True        # all addresses mapped -> ok


def test_corrupt_submitted_address_is_caught():
    # forge a stream with an unmapped dst — observe must see it from the bytes alone
    cd = baseline_values(COPY_DATA)
    cd.update(src_addr_lo=_SRC_VA, dst_addr_lo=0xDEAD0000)   # unmapped
    rm = baseline_values(RELEASE_MEM)
    rm.update(address_lo=_SIGNAL_VA, data_lo=1)
    g = FakeGpu()
    g.submit(build(COPY_DATA, cd) + build(RELEASE_MEM, rm))
    sig = g.observe(1.0)
    assert sig.kfd_events == ("MEMORY",) and sig.faulting_va == 0xDEAD0000


def test_overlong_dma_overruns_guard_into_silent_corruption():
    # a DMA_DATA whose byte_count exceeds the target (all addresses mapped) completes but
    # writes past dst -> guard clobbered -> the oracle classes it SILENT_CORRUPTION
    from fuzzyHSA.campaign.classify import classify
    from fuzzyHSA.campaign.finding import FindingClass as FC
    from fuzzyHSA.hw.fake import _DST_BYTES
    from fuzzyHSA.pm4.spec import DMA_DATA
    dd = baseline_values(DMA_DATA)
    dd.update(src_addr_lo=_SRC_VA, dst_addr_lo=_DST_VA, byte_count=_DST_BYTES * 4)
    rm = baseline_values(RELEASE_MEM)
    rm.update(address_lo=_SIGNAL_VA, data_lo=1)
    g = FakeGpu()
    g.submit(build(DMA_DATA, dd) + build(RELEASE_MEM, rm))
    sig = g.observe(1.0)
    assert sig.canary_corrupted and sig.signal_written
    assert classify(sig) is FC.SILENT_CORRUPTION


def test_materialize_then_submit_then_observe_end_to_end():
    # a real GenCase round-trips through materialize -> submit -> observe honestly
    g = FakeGpu()
    cases = list(Pm4Generator(COPY_DATA, seed=2).cases(40))
    verdicts = []
    for c in cases:
        g.submit(g.materialize(c))
        verdicts.append(g.observe(1.0))
    assert verdicts[0].signal_written                      # baseline completes
    assert any(v.kfd_events == ("MEMORY",) for v in verdicts)   # some vm_faults surface
