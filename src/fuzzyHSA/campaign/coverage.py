# SPDX-License-Identifier: Apache-2.0
"""Coverage accounting (D8): what has a campaign actually exercised?

A firmware team needs to see the gaps, not just the hits — which PM4 packets were fuzzed, which
fields were mutated, which outcome classes appeared, and (the useful part) what is still dark.
Pure over the manifest's per-case records + the spec registry, so it is CI-testable and needs no
hardware.
"""
from __future__ import annotations


def _fields_of(label: str | None) -> list[str]:
    """Field names a case's mutated_field label touched. Labels: None (baseline), a bare field
    name, ``multi(a,b)``, ``seq:<label>``, or ``struct:<op>`` (structural — touches no one field)."""
    if not label:
        return []
    if label.startswith("multi("):
        return [f for f in label[len("multi("):-1].split(",") if f]
    if label.startswith("seq:"):
        return _fields_of(label[len("seq:"):])
    if label.startswith("struct:"):
        return []
    return [label]


def _fuzzable_fields(packet) -> list[str]:
    return [f.name for f in packet.fields if f.role != "count"]


def coverage(case_records: list[dict], registry: dict) -> dict:
    """Aggregate per-packet and overall coverage from merged case records (see
    ``Recorder.case_records``) against the spec ``registry``."""
    packets: dict[str, dict] = {}
    classes: dict[str, int] = {}
    used_struct = False

    for r in case_records:
        recipe = r.get("recipe") or {}
        op = recipe.get("opcode")
        if op not in registry:           # skip records from an older/unknown spec so cases==classes
            continue
        p = packets.setdefault(op, {"cases": 0, "fields_hit": set(), "classes": {}, "structural": False})
        p["cases"] += 1
        cls = r.get("cls")
        if cls is not None:
            p["classes"][cls] = p["classes"].get(cls, 0) + 1
            classes[cls] = classes.get(cls, 0) + 1
        label = recipe.get("mutated_field")
        p["fields_hit"].update(_fields_of(label))
        if label and label.replace("seq:", "").startswith("struct:"):
            p["structural"] = used_struct = True

    # per-packet view + untested fields, measured against the registry
    out_packets: dict[str, dict] = {}
    for name, pkt in registry.items():
        total = _fuzzable_fields(pkt)
        got = packets.get(name)
        hit = sorted(got["fields_hit"]) if got else []
        out_packets[name] = {
            "cases": got["cases"] if got else 0,
            "classes": got["classes"] if got else {},
            "structural_cases": bool(got and got["structural"]),
            "fields_hit": hit,
            "fields_untested": [f for f in total if f not in set(hit)],
        }

    return {
        "cases": sum(p["cases"] for p in out_packets.values()),
        "classes": classes,
        "packets": out_packets,
        "untested_packets": [n for n, p in out_packets.items() if p["cases"] == 0],
        "used_structural": used_struct,
    }
