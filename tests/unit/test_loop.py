# SPDX-License-Identifier: Apache-2.0
"""End-to-end campaign core against the fake GPU (no hardware).

Proves the slice's done-criteria at the simulation level: a valid baseline completes,
mutated unmapped addresses produce a vm_fault bucket, out-of-domain enums classify as
clean_rejection (NOT crash), and every case lands resolved in the manifest.
"""
from fuzzyHSA.campaign.loop import run_campaign
from fuzzyHSA.campaign.record import Recorder
from fuzzyHSA.fuzz.gen import Pm4Generator
from fuzzyHSA.hw.fake import FakeGpu
from fuzzyHSA.pm4.spec import COPY_DATA


def _run(tmp_path, n=200, seed=1):
    rec = Recorder(tmp_path)
    gen = Pm4Generator(COPY_DATA, seed=seed)
    res = run_campaign(gen, FakeGpu(), rec, spec_version="v1", fw_version="fw",
                       iterations=n, campaign_id="t")
    return rec, res


def test_baseline_completes_and_campaign_runs(tmp_path):
    rec, res = _run(tmp_path)
    assert res.iters == 200
    assert res.by_class.get("ok", 0) >= 1          # the baseline (and mapped cases) complete
    assert not res.wedged


def test_vm_fault_bucket_emerges(tmp_path):
    rec, res = _run(tmp_path)
    # at least one dedup bucket, all of class vm_fault (the only finding the fake emits)
    assert res.findings, "expected at least one finding bucket"
    assert all(b["cls"] == "vm_fault" for b in res.findings.values())


def test_rejections_are_not_crashes(tmp_path):
    rec, res = _run(tmp_path)
    # out-of-domain enum/flag mutations exist and are clean_rejection, never a finding class
    assert res.by_class.get("clean_rejection", 0) >= 1
    assert "crash" not in res.by_class


def test_every_case_resolved_in_manifest(tmp_path):
    rec, res = _run(tmp_path, n=50)
    assert rec.pending_ids() == []                 # nothing left dangling
    # a first-exemplar finding carries decoded named fields, not hex
    import json
    lines = [json.loads(x) for x in (tmp_path / "manifest.jsonl").read_text().splitlines()]
    findings = [r for r in lines if r.get("finding")]
    assert findings
    stream = findings[0]["finding"]["decoded_stream"]
    assert any(p["name"] == "COPY_DATA" and "dst_addr_lo" in p["fields"] for p in stream)


def test_replay_blob_round_trips(tmp_path):
    rec, res = _run(tmp_path, n=30)
    # an exemplar's recorded bytes decode back to a COPY_DATA + RELEASE_MEM stream
    exemplar = next(iter(res.findings.values()))["exemplar_id"]
    from fuzzyHSA.pm4.decode import decode
    dec = decode(rec.load_blob(exemplar))
    assert [p.name for p in dec] == ["COPY_DATA", "RELEASE_MEM"]
