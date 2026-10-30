# SPDX-License-Identifier: Apache-2.0
"""Decode a PM4 dword stream into named packets + fields (the spec in reverse).

Used to build the agent-readable finding record (06): the agent reads
``COPY_DATA.dst_addr_lo = 0xdead0000``, never raw hex.
"""
from __future__ import annotations

from dataclasses import dataclass

from .spec import BY_OPCODE, PACKET_TYPE3, Packet


@dataclass
class DecodedPacket:
    name: str                 # packet name, or "UNKNOWN(0x..)"
    opcode: int
    fields: dict              # {field_name: {"value": int, "role": str}}
    raw: list[int]            # the dwords this packet consumed (header + body)
    malformed: str | None = None   # non-None describes why (e.g. count mismatch)


def _decode_one(dwords: list[int], off: int) -> tuple[DecodedPacket, int]:
    h = dwords[off]
    ptype = (h >> 30) & 0x3
    opcode = (h >> 8) & 0xFF
    count = (h >> 16) & 0x3FFF
    body_n = count + 1  # PACKET3: header carries n = body_dwords - 1
    body = dwords[off + 1 : off + 1 + body_n]
    raw = dwords[off : off + 1 + body_n]

    if ptype != PACKET_TYPE3:
        return DecodedPacket(f"NON_TYPE3(type={ptype})", opcode, {}, raw,
                             malformed=f"packet type {ptype} != 3"), off + 1 + body_n

    pkt: Packet | None = BY_OPCODE.get(opcode)
    if pkt is None:
        return DecodedPacket(f"UNKNOWN(0x{opcode:02x})", opcode, {}, raw,
                             malformed="opcode not in registry"), off + 1 + body_n

    malformed = None
    if body_n != pkt.body_dwords:
        malformed = f"count={count} implies {body_n} body dwords, {pkt.name} expects {pkt.body_dwords}"

    fields: dict = {}
    for f in pkt.fields:
        if f.role == "count" or f.dw >= len(body):
            continue
        fields[f.name] = {"value": (body[f.dw] & f.mask) >> f.lo, "role": f.role}

    return DecodedPacket(pkt.name, opcode, fields, raw, malformed), off + 1 + body_n


def decode(dwords: list[int]) -> list[DecodedPacket]:
    """Walk a concatenated PM4 stream into decoded packets."""
    out: list[DecodedPacket] = []
    off = 0
    n = len(dwords)
    while off < n:
        pkt, off = _decode_one(dwords, off)
        out.append(pkt)
    return out
