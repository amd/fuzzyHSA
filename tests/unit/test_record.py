# SPDX-License-Identifier: Apache-2.0
"""Recorder: record-before-send, pending=culprit-on-restart, blob round-trip."""
from fuzzyHSA.campaign.finding import Recipe
from fuzzyHSA.campaign.record import Recorder


def _recipe(seed=1):
    return Recipe(seed=seed, spec_version="v1", fw_version="fw", opcode="COPY_DATA",
                  mutated_field="dst_addr_lo", mutated_value=0xDEAD0000, baseline={})


def test_pending_then_resolved(tmp_path):
    r = Recorder(tmp_path)
    r.record_pending("c0", _recipe(), [0xC0044002, 1, 2, 3, 4, 5])
    assert r.pending_ids() == ["c0"]          # before resolve, it's the culprit
    r.resolve("c0", "ok", "sig", None)
    assert r.pending_ids() == []              # latest line wins


def test_blob_round_trips(tmp_path):
    r = Recorder(tmp_path)
    dw = [0xC0044002, 0x00100101, 0x1000, 0, 0x2000, 0]
    r.record_pending("c1", _recipe(), dw)
    assert r.load_blob("c1") == dw


def test_read_side_buckets_and_summary(tmp_path):
    # Recorder owns both write and read of its schema (candidate #3)
    r = Recorder(tmp_path)
    r.record_pending("a", _recipe(1), [0xC0044002, 0, 0, 0, 0, 0])
    r.record_pending("b", _recipe(2), [0xC0044002, 0, 0, 0, 0, 0])
    r.record_pending("c", _recipe(3), [0xC0044002, 0, 0, 0, 0, 0])
    r.resolve("a", "ok", "sig_ok", None)                   # not a finding
    r.resolve("b", "vm_fault", "sig_vm", {"id": "b", "dedup_sig": "sig_vm"})
    r.resolve("c", "vm_fault", "sig_vm", None)             # same bucket, no exemplar
    buckets = r.buckets()
    assert list(buckets) == ["sig_vm"]                     # ok is excluded
    assert buckets["sig_vm"]["count"] == 2 and buckets["sig_vm"]["exemplar_id"] == "b"
    s = r.summary()
    assert s["by_class"] == {"ok": 1, "vm_fault": 2} and s["buckets"] == 1
    assert r.finding("b")["dedup_sig"] == "sig_vm" and r.finding("c") is None


def test_crash_between_record_and_resolve_leaves_pending(tmp_path):
    # simulate: two cases recorded pending, only one resolved (the other "crashed" mid-send)
    r = Recorder(tmp_path)
    r.record_pending("a", _recipe(1), [0xC0044002, 0, 0, 0, 0, 0])
    r.record_pending("b", _recipe(2), [0xC0044002, 0, 0, 0, 0, 0])
    r.resolve("a", "ok", "s", None)
    # a fresh Recorder over the same dir sees "b" as the unresolved culprit
    assert Recorder(tmp_path).pending_ids() == ["b"]


def test_tail_records_is_incremental(tmp_path):
    # the runner reads only NEW manifest lines per respawn (O(N) total, not O(N^2) re-scan)
    from fuzzyHSA.campaign.finding import Recipe
    rec = Recorder(tmp_path)
    r = Recipe(0, "v", "f", "COPY_DATA", None, None)
    rec.record_pending("c-000000", r, [1])
    rec.resolve("c-000000", "ok", "s0", None)
    first, off = rec.tail_records(0)
    assert [x["id"] for x in first] == ["c-000000", "c-000000"]  # pending + resolved lines
    # nothing new -> empty, offset unchanged
    none, off2 = rec.tail_records(off)
    assert none == [] and off2 == off
    # append more; tail from the cursor returns only the new lines
    rec.record_pending("c-000001", r, [2])
    rec.resolve("c-000001", "vm_fault", "s1", {"id": "c-000001"})
    new, off3 = rec.tail_records(off)
    assert [x["id"] for x in new] == ["c-000001", "c-000001"] and off3 > off


def test_tail_records_fail_soft_on_torn_line(tmp_path):
    # a terminate() mid-append could leave a partial last line; tail must not crash the campaign
    rec = Recorder(tmp_path)
    with open(rec.manifest, "wb") as f:
        f.write(b'{"id":"a","status":"resolved"}\n{"id":"b","stat')   # complete + torn
    recs, off = rec.tail_records(0)
    assert [r["id"] for r in recs] == ["a"]            # only the complete line consumed
    with open(rec.manifest, "ab") as f:
        f.write(b'us":"resolved"}\n')                  # the torn line later completes
    recs2, off2 = rec.tail_records(off)
    assert [r["id"] for r in recs2] == ["b"] and off2 > off
