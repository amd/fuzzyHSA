# SPDX-License-Identifier: Apache-2.0
"""Coverage accounting (D8) — pure over merged case records + the spec registry."""
from fuzzyHSA.campaign.coverage import _fields_of, coverage
from fuzzyHSA.pm4.spec import COPY_DATA, REGISTRY


def _rec(opcode, label, cls):
    return {"recipe": {"opcode": opcode, "mutated_field": label}, "cls": cls}


def test_fields_of_parses_every_label_shape():
    assert _fields_of(None) == []
    assert _fields_of("dst_addr_lo") == ["dst_addr_lo"]
    assert _fields_of("multi(a,b)") == ["a", "b"]
    assert _fields_of("seq:src_sel") == ["src_sel"]
    assert _fields_of("struct:count+2") == []          # structural touches no single field


def test_coverage_counts_packets_fields_and_classes():
    recs = [
        _rec("COPY_DATA", None, "ok"),
        _rec("COPY_DATA", "dst_addr_lo", "vm_fault"),
        _rec("COPY_DATA", "multi(src_sel,dst_sel)", "gpu_hang"),
        _rec("COPY_DATA", "struct:truncate+1", "gpu_hang"),
    ]
    cov = coverage(recs, REGISTRY)
    assert cov["cases"] == 4
    assert cov["classes"] == {"ok": 1, "vm_fault": 1, "gpu_hang": 2}
    cd = cov["packets"]["COPY_DATA"]
    assert cd["cases"] == 4 and cd["structural_cases"] is True
    assert set(cd["fields_hit"]) == {"dst_addr_lo", "src_sel", "dst_sel"}
    assert "src_addr_hi" in cd["fields_untested"]       # never mutated -> flagged as a gap


def test_coverage_flags_untested_packets():
    cov = coverage([_rec("COPY_DATA", "src_sel", "ok")], REGISTRY)
    assert "COPY_DATA" not in cov["untested_packets"]
    assert "DMA_DATA" in cov["untested_packets"]        # never fuzzed in this campaign
    # every fuzzable COPY_DATA field except the one hit is a gap
    fuzzable = {f.name for f in COPY_DATA.fields if f.role != "count"}
    assert set(cov["packets"]["COPY_DATA"]["fields_untested"]) == fuzzable - {"src_sel"}
