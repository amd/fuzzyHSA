# SPDX-License-Identifier: Apache-2.0
"""Agent surface (07): JSON envelopes, no prose. Exercised with the fake backend."""
import json

from fuzzyHSA.cli import main


def _run(capsys, *argv):
    rc = main(list(argv))
    out = capsys.readouterr().out.strip()
    return rc, json.loads(out)


def test_spec_validate_ok(capsys):
    rc, env = _run(capsys, "spec-validate", "--json", "{}")
    assert rc == 0 and env["ok"] and env["data"]["ok"] and env["data"]["errors"] == []


def test_decode_returns_named_fields(capsys):
    # COPY_DATA header + control + src/dst addrs
    dwords = [0xC0044002, 0x00100101, 0x1000, 0, 0x2000, 0]
    rc, env = _run(capsys, "decode", "--json", json.dumps({"dwords": dwords}))
    assert env["ok"]
    stream = env["data"]["decoded_stream"]
    assert stream[0]["name"] == "COPY_DATA"
    assert stream[0]["fields"]["dst_addr_lo"]["value"] == 0x2000


def test_campaign_start_and_findings_list(capsys, tmp_path):
    root = str(tmp_path / "findings")  # outside any git tree
    args = {"record_root": root, "backend": "fake", "seed": 1,
            "budget": {"iterations": 150}}
    rc, env = _run(capsys, "campaign-start", "--json", json.dumps(args))
    assert env["ok"], env
    assert env["data"]["iters"] == 150
    assert env["data"]["by_class"].get("ok", 0) >= 1
    assert env["data"]["findings"]["buckets"] >= 1
    env_total = env["data"]["findings"]["total"]

    rc, env = _run(capsys, "findings-list", "--json", json.dumps({"record_root": root}))
    assert env["ok"]
    rows = env["data"]["findings"]
    assert rows and all(r["cls"] == "vm_fault" for r in rows)
    # bucket counts aggregate ALL cases, not just persisted exemplars
    assert sum(r["count"] for r in rows) == env_total

    # the exemplar id resolves to a full finding record via findings-get
    rc, g = _run(capsys, "findings-get",
                 "--json", json.dumps({"record_root": root, "id": rows[0]["exemplar_id"]}))
    assert g["ok"] and g["data"]["dedup_sig"] == rows[0]["dedup_sig"]


def test_campaign_start_refuses_record_root_in_git_tree(capsys):
    # the repo cwd IS a git tree; writing findings there must be denied (08 §6)
    rc, env = _run(capsys, "campaign-start", "--json",
                   json.dumps({"record_root": "./findings", "backend": "fake"}))
    assert rc == 1 and not env["ok"] and env["error"]["code"] == "denied"


def test_bad_json_is_structured_error(capsys):
    rc, env = _run(capsys, "decode", "--json", "{not json")
    assert rc == 1 and env["error"]["code"] == "bad_json"
