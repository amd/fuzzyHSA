# SPDX-License-Identifier: Apache-2.0
"""PM4 spec + decode round-trip. Golden dwords hand-computed from the gfx9 layout."""
from fuzzyHSA.pm4.decode import decode
from fuzzyHSA.pm4.spec import (
    COPY_DATA,
    REGISTRY,
    RELEASE_MEM,
    baseline_values,
    build,
    header,
    mutate,
)

# RELEASE_MEM is the completion PROBE, not a primary fuzz target: build_stream appends it
# and binds its bare address_lo/hi straight to the signal VA, so it never flows through
# addr.resolve against src/dst. The <bo>_addr naming + src/dst-resolution invariants apply
# to the fuzzable case packets, excluding it.
_FUZZ_TARGETS = [p for n, p in REGISTRY.items() if n != "RELEASE_MEM"]


def test_golden_headers():
    assert header(COPY_DATA) == 0xC0044000, hex(header(COPY_DATA))
    assert header(RELEASE_MEM) == 0xC0064900, hex(header(RELEASE_MEM))


def test_build_golden_copy_data():
    base = dict(src_sel=1, dst_sel=1, count_sel=0, wr_confirm=1, engine_sel=0,
                src_addr_lo=0x1000, src_addr_hi=0, dst_addr_lo=0x2000, dst_addr_hi=0)
    assert build(COPY_DATA, base) == [0xC0044000, 0x00100101, 0x1000, 0, 0x2000, 0]


def test_mutate_is_single_field_local():
    base = baseline_values(COPY_DATA)
    base.update(src_addr_lo=0x1000, dst_addr_lo=0x2000)
    dw = build(COPY_DATA, base)
    m = mutate(COPY_DATA, base, "dst_addr_lo", 0xDEAD0000)
    # dst_addr_lo is body dword 3 -> list index 4 (header is index 0); only it changes
    assert m[4] == 0xDEAD0000
    assert m[:4] == dw[:4] and m[5:] == dw[5:]


def test_count_is_unauthorable():
    # shrinking the body re-synthesizes the header's n; count is never a free field
    assert (header(COPY_DATA) >> 16 & 0x3FFF) == COPY_DATA.body_dwords - 1


def test_decode_round_trips_names_not_hex():
    base = baseline_values(COPY_DATA)
    base.update(dst_addr_lo=0xDEAD0000)
    dec = decode(build(COPY_DATA, base))
    assert len(dec) == 1 and dec[0].name == "COPY_DATA"
    assert dec[0].fields["dst_addr_lo"] == {"value": 0xDEAD0000, "role": "address"}
    assert dec[0].malformed is None


def test_decode_flags_count_mismatch():
    # hand-forge a COPY_DATA header claiming the wrong body length
    from fuzzyHSA.pm4.spec import PACKET_TYPE3
    bad_header = (PACKET_TYPE3 << 30) | (0x40 << 8) | (2 << 16) | (1 << 1)
    dec = decode([bad_header, 0, 0, 0])
    assert dec[0].malformed is not None and "expects 5" in dec[0].malformed


def test_address_role_is_the_vm_fault_surface():
    addr = [f.name for f in COPY_DATA.fields if f.role == "address"]
    assert addr == ["src_addr_lo", "src_addr_hi", "dst_addr_lo", "dst_addr_hi"]


# --- registry-wide invariants: every packet (incl. D3 breadth) must hold these ---

def test_no_packet_has_overlapping_fields():
    from fuzzyHSA.pm4.spec import REGISTRY
    for name, p in REGISTRY.items():
        seen: dict[tuple[int, int], str] = {}
        for f in p.fields:
            if f.role == "count":
                continue
            for bit in range(f.lo, f.hi + 1):
                key = (f.dw, bit)
                assert key not in seen, f"{name}: {f.name} overlaps {seen.get(key)} at dw{f.dw} bit{bit}"
                seen[key] = f.name


def test_every_baseline_round_trips_to_itself():
    from fuzzyHSA.pm4.spec import REGISTRY
    for name, p in REGISTRY.items():
        dw = build(p, baseline_values(p))
        assert len(dw) == p.body_dwords + 1, name
        dec = decode(dw)
        assert dec[0].name == name and dec[0].malformed is None, name


def test_every_address_field_follows_bo_naming():
    # addr.resolve can only bind fields named <bo>_addr_lo/hi; a stray address role elsewhere
    # would raise at materialize time on HW. Catch it in CI instead.
    from fuzzyHSA.pm4.addr import parse_addr_field
    for p in _FUZZ_TARGETS:
        for f in p.fields:
            if f.role == "address":
                assert parse_addr_field(f.name) is not None, f"{p.name}.{f.name} not <bo>_addr_lo/hi"


def test_generator_covers_every_packet_without_error():
    from fuzzyHSA.fuzz.gen import Pm4Generator
    from fuzzyHSA.pm4 import addr
    bo_vas = {"src": 0x1000, "dst": 0x2000}  # every D3 address field binds to src/dst
    for p in _FUZZ_TARGETS:
        cases = list(Pm4Generator(p, seed=2).cases(12))
        assert cases[0].mutated_field is None  # baseline first
        for c in cases:
            build(p, addr.resolve(p, c.values, bo_vas))  # resolves MAPPED addrs, then builds
