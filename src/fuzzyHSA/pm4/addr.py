# SPDX-License-Identifier: Apache-2.0
"""Address-field convention for PM4 packets.

An address in a PM4 packet is a 64-bit GPU VA split across two fields named
``<bo>_addr_lo`` / ``<bo>_addr_hi`` — where ``<bo>`` names a logical buffer object
(``src``, ``dst``, ...). This module is the single owner of that convention: the
generator marks address fields ``UNBOUND``; ``resolve`` fills them from a per-BO VA map
driven by the spec's ``role=="address"`` fields (so adding an address field to a packet
cannot silently go unresolved); ``reconstruct`` reads the per-BO VAs back out of a
materialized packet. resolve and reconstruct are inverses.
"""
from __future__ import annotations

from .spec import Packet


class _Unbound:
    """Sentinel for an address field the generator left for the backend to resolve.
    Distinct (not None) so a missing resolution fails loudly in ``build`` rather than
    being mistaken for the literal value 0."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNBOUND"


UNBOUND = _Unbound()


def parse_addr_field(name: str) -> tuple[str, str] | None:
    """``"src_addr_lo"`` -> ``("src", "lo")``; non-address names -> ``None``."""
    for half in ("lo", "hi"):
        suffix = f"_addr_{half}"
        if name.endswith(suffix):
            return name[: -len(suffix)], half
    return None


def resolve(packet: Packet, values: dict, bo_vas: dict[str, int]) -> dict:
    """Fill every ``UNBOUND`` address field from ``bo_vas`` (one 64-bit VA per BO).
    Raises if a BO referenced by an address field has no VA — never resolves silently."""
    out = dict(values)
    for f in packet.fields:
        if f.role != "address" or out.get(f.name) is not UNBOUND:
            continue
        parsed = parse_addr_field(f.name)
        if parsed is None:
            raise ValueError(f"address field {f.name!r} does not match <bo>_addr_<lo|hi>")
        bo, half = parsed
        if bo not in bo_vas:
            raise KeyError(f"no VA for BO {bo!r} (needed by {f.name})")
        va = bo_vas[bo]
        out[f.name] = (va & 0xFFFFFFFF) if half == "lo" else (va >> 32)
    return out


def reconstruct(packet: Packet, values: dict) -> dict[str, int]:
    """Read per-BO 64-bit VAs back out of a packet's resolved field values."""
    los: dict[str, int] = {}
    his: dict[str, int] = {}
    for f in packet.fields:
        if f.role != "address":
            continue
        parsed = parse_addr_field(f.name)
        if parsed is None:
            continue
        bo, half = parsed
        (los if half == "lo" else his)[bo] = values.get(f.name, 0)
    return {bo: (los.get(bo, 0) | (his.get(bo, 0) << 32)) for bo in set(los) | set(his)}
