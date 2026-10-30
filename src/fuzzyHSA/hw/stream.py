# SPDX-License-Identifier: Apache-2.0
"""Shared PM4 stream construction (the one ``materialize`` both backends use).

A backend differs only in where its BO VAs come from (fake constants vs real KFD
allocations); the resolve-build-append-probe algorithm is identical and lives here,
driven by the spec's address roles via ``pm4.addr``. This is the deepening of
candidate #2: one place knows how a GenCase becomes dwords.
"""
from __future__ import annotations

from ..fuzz.gen import GenCase
from ..pm4 import addr
from ..pm4.spec import RELEASE_MEM, baseline_values, build, with_count


def _packet_dwords(case: GenCase, bo_vas: dict[str, int]) -> list[int]:
    """Resolve + build one case's packet, then apply any below-field structural corruption
    (``case.struct``): a header count-lie or a physical truncation of the body."""
    dwords = build(case.packet, addr.resolve(case.packet, case.values, bo_vas))
    if case.struct:
        kind, k = case.struct
        if kind == "count":                              # header lies about body length
            honest_n = len(dwords) - 2                    # = body_dwords - 1
            dwords = with_count(dwords, max(0, honest_n + k))  # clamp: a negative n would wrap to 0x3FFF
        elif kind == "truncate":                          # body shorter than header claims
            dwords = dwords[:max(1, len(dwords) - k)]
    return dwords


def build_stream(case: GenCase, bo_vas: dict[str, int], signal_va: int) -> list[int]:
    """Resolve the case's address fields from ``bo_vas``, build the packet (plus any
    ``prefix`` state-setter packets before it and ``struct`` corruption on it), and append
    a single RELEASE_MEM completion probe that writes 1 to ``signal_va``."""
    stream: list[int] = []
    for pre in case.prefix:                               # sequence: valid state-setters first
        stream += _packet_dwords(pre, bo_vas)
    stream += _packet_dwords(case, bo_vas)

    probe = baseline_values(RELEASE_MEM)
    probe.update(address_lo=signal_va & 0xFFFFFFFF, address_hi=signal_va >> 32,
                 data_lo=1, data_hi=0)
    return stream + build(RELEASE_MEM, probe)
