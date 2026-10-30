# SPDX-License-Identifier: Apache-2.0
"""Agent command surface (ticket 07).

Every command emits one JSON envelope ``{ok, cmd, data, error}`` to stdout; the exit
code mirrors ``ok``. No prose, ever — an agent branches on ``ok`` + ``error.code``.
Findings are returned as decoded named-field streams and one row per dedup bucket,
never hex, never logs.

Slice-1 subset: ``campaign start/status``, ``findings list/get``, ``decode``,
``spec validate``. ``repro`` / ``minimize`` and an async campaign daemon are deferred.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _envelope(cmd: str, data=None, error=None) -> int:
    print(json.dumps({"ok": error is None, "cmd": cmd, "data": data, "error": error}))
    return 0 if error is None else 1


def _err(code: str, msg: str) -> dict:
    return {"code": code, "msg": msg}


def _load_json_arg(raw: str | None) -> dict:
    if not raw or raw == "-":
        data = sys.stdin.read().strip()
        return json.loads(data) if data else {}
    return json.loads(raw)


# --- pure commands ----------------------------------------------------------

def cmd_decode(args) -> int:
    from .pm4.decode import decode
    p = _load_json_arg(args.json)
    dwords = p.get("dwords")
    if dwords is None and p.get("blob"):
        import struct
        data = Path(p["blob"]).read_bytes()
        dwords = list(struct.unpack(f"<{len(data)//4}I", data))
    if not dwords:
        return _envelope("decode", error=_err("bad_input", "need dwords[] or blob"))
    stream = [{"name": d.name, "opcode": d.opcode, "fields": d.fields,
               "malformed": d.malformed} for d in decode([int(x) for x in dwords])]
    return _envelope("decode", {"decoded_stream": stream})


def cmd_spec_validate(args) -> int:
    from .pm4.spec import REGISTRY
    errors = []
    for name, pkt in REGISTRY.items():
        seen: dict[int, list] = {}
        for f in pkt.fields:
            if f.role == "count":
                continue
            for bit in range(f.lo, f.hi + 1):
                key = (f.dw, bit)
                if key in seen:
                    errors.append({"packet": name, "field": f.name,
                                   "msg": f"bit {f.dw}:{bit} overlaps {seen[key]}"})
                seen[key] = f.name
    return _envelope("spec.validate", {"ok": not errors, "errors": errors})


# --- findings (read via the Recorder, which owns the manifest schema) --------

def _recorder(args, p) -> object:
    from .campaign.record import Recorder
    return Recorder(Path(p.get("record_root", args.record_root or ".")))


def cmd_findings_list(args) -> int:
    p = _load_json_arg(args.json)
    want = p.get("class")
    rows = [b for b in _recorder(args, p).buckets().values() if not want or b["cls"] == want]
    return _envelope("findings.list", {"findings": rows})


def cmd_findings_get(args) -> int:
    p = _load_json_arg(args.json)
    fid = p.get("id")
    f = _recorder(args, p).finding(fid)
    if f is None:
        return _envelope("findings.get", error=_err("no_such_id", f"no finding {fid}"))
    return _envelope("findings.get", f)


# --- campaign (HW, gated) ---------------------------------------------------

def cmd_campaign_start(args) -> int:
    p = _load_json_arg(args.json)
    from .campaign.guard import Denied, Guard
    from .campaign.loop import run_campaign
    from .campaign.record import Recorder
    from .fuzz.gen import Pm4Generator
    from .pm4.spec import REGISTRY

    gpu_index = int(p.get("gpu_index", 0))
    record_root = Path(p.get("record_root", "./findings"))
    budget = p.get("budget", {})
    allow_dangerous = bool(p.get("allow_dangerous", False))
    backend_name = p.get("backend", "fake")

    try:
        clamped = Guard().check_start(gpu_index, record_root, allow_dangerous, budget)
    except Denied as d:
        return _envelope("campaign.start", error=_err(d.code, str(d)))

    iterations = int(clamped.get("iterations", budget.get("iterations", 1000)))
    packet_name = p.get("packet", "COPY_DATA")
    seed = int(p.get("seed", 0))
    guard = Guard()
    campaign_id = p.get("campaign_id", "c")

    if backend_name == "mi300":
        # real HW: claim the GPU (fails closed), then run process-isolated so a VM-killing
        # case can't cascade. The worker subprocesses touch the device; we only orchestrate.
        from .campaign.hw_runner import run_campaign_isolated
        from .hw.rocm import rocm_showpids
        try:
            guard.claim_gpu(gpu_index, campaign_id, rocm_showpids)
        except Denied as d:
            return _envelope("campaign.start", error=_err(d.code, str(d)))
        try:
            hr = run_campaign_isolated(
                gpu_index, packet_name, seed, iterations, record_root,
                campaign_id=campaign_id, field_weights=p.get("field_weights"),
                modes=p.get("modes"), guard=guard)
        finally:
            guard.release_gpu(gpu_index)
        return _envelope("campaign.start", {
            "campaign_id": campaign_id, "status": "wedged" if hr.wedged else "done",
            "wedged": hr.wedged, "iters": hr.iters, "by_class": hr.by_class,
            "hard_crashes": hr.hard_crashes,
            "findings": {"total": sum(b["count"] for b in hr.buckets.values()),
                         "buckets": len(hr.buckets)},
            "record_root": str(record_root),
        })

    # fake backend: in-process (it never wedges)
    from .hw.fake import FakeGpu
    packet = REGISTRY[packet_name]
    gen = Pm4Generator(packet, seed=seed, field_weights=p.get("field_weights"), modes=p.get("modes"))
    rec = Recorder(record_root)
    res = run_campaign(gen, FakeGpu(), rec, spec_version="pm4@1", fw_version="unknown",
                       iterations=iterations, rate_per_s=clamped.get("rate_per_s", 0),
                       gpu_index=gpu_index, guard=guard, campaign_id=campaign_id)
    return _envelope("campaign.start", {
        "campaign_id": campaign_id, "status": res.stopped_reason, "wedged": res.wedged,
        "iters": res.iters, "by_class": res.by_class,
        "findings": {"total": sum(b["count"] for b in res.findings.values()),
                     "buckets": len(res.findings)},
        "record_root": str(record_root),
    })


def cmd_isolation_start(args) -> int:
    """Cross-process isolation probe (D6): a victim holds a canary; attacker processes try to
    reach it. Fires ISOLATION_BREAK iff the victim's memory was reached from another process."""
    p = _load_json_arg(args.json)
    from .campaign.guard import Denied, Guard
    from .campaign.isolation import run_isolation_campaign
    from .hw.rocm import rocm_showpids

    gpu_index = int(p.get("gpu_index", 0))
    record_root = Path(p.get("record_root", "./findings"))
    guard = Guard()
    campaign_id = p.get("campaign_id", "iso")
    try:
        guard.claim_gpu(gpu_index, campaign_id, rocm_showpids)
    except Denied as d:
        return _envelope("isolation.start", error=_err(d.code, str(d)))
    try:
        r = run_isolation_campaign(gpu_index, record_root, campaign_id=campaign_id, guard=guard)
    finally:
        guard.release_gpu(gpu_index)
    return _envelope("isolation.start", {
        "campaign_id": campaign_id, "status": r.status, "broke": r.broke, "offset": r.offset,
        "path_ok": r.path_ok, "executed": r.executed, "attempts": r.attempts,
        "finding": r.finding, "record_root": str(record_root),
    })


def cmd_campaign_status(args) -> int:
    p = _load_json_arg(args.json)
    s = _recorder(args, p).summary()
    return _envelope("campaign.status", {
        "iters": s["iters"], "by_class": s["by_class"],
        "findings": {"buckets": s["buckets"]},
    })


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fuzzyHSA", description="agent-driven PM4 fuzzer")
    ap.add_argument("--record-root", default=None, help="findings dir (for read commands)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in [
        ("decode", cmd_decode), ("spec-validate", cmd_spec_validate),
        ("campaign-start", cmd_campaign_start), ("campaign-status", cmd_campaign_status),
        ("isolation-start", cmd_isolation_start),
        ("findings-list", cmd_findings_list), ("findings-get", cmd_findings_get),
    ]:
        sp = sub.add_parser(name)
        sp.add_argument("--json", default=None, help="JSON args inline or '-' for stdin")
        sp.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except json.JSONDecodeError as e:
        return _envelope(args.cmd, error=_err("bad_json", str(e)))


if __name__ == "__main__":
    sys.exit(main())
