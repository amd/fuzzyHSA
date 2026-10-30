# SPDX-License-Identifier: Apache-2.0
"""PM4 generator: baseline-first, single-field locality, determinism."""
from fuzzyHSA.fuzz.gen import MAPPED, Pm4Generator
from fuzzyHSA.pm4.spec import COPY_DATA, baseline_values


def test_first_case_is_unmutated_baseline():
    g = Pm4Generator(COPY_DATA, seed=1)
    first = next(g.cases(5))
    assert first.mutated_field is None and first.mutated_value is None
    # every address field is the resolve-later sentinel
    for f in COPY_DATA.fields:
        if f.role == "address":
            assert first.values[f.name] is MAPPED


def test_mutation_touches_exactly_one_field():
    g = Pm4Generator(COPY_DATA, seed=7)
    base = {**baseline_values(COPY_DATA)}
    for c in list(g.cases(30))[1:]:
        diffs = [f.name for f in COPY_DATA.fields
                 if f.role not in ("count", "address")
                 and c.values.get(f.name) != base.get(f.name)]
        # at most one non-address field differs, and it's the recorded mutated field
        assert len(diffs) <= 1
        assert c.mutated_field is not None
        assert c.values[c.mutated_field] == c.mutated_value


def test_address_fields_are_weighted_target():
    g = Pm4Generator(COPY_DATA, seed=3)
    muts = [c.mutated_field for c in list(g.cases(200))[1:]]
    addr = {"src_addr_lo", "src_addr_hi", "dst_addr_lo", "dst_addr_hi"}
    # with 5x weight on 4 address fields vs 1x on 5 others, addresses dominate
    assert sum(m in addr for m in muts) > len(muts) * 0.6


def test_deterministic_for_seed():
    a = [(c.mutated_field, c.mutated_value) for c in Pm4Generator(COPY_DATA, seed=42).cases(20)]
    b = [(c.mutated_field, c.mutated_value) for c in Pm4Generator(COPY_DATA, seed=42).cases(20)]
    assert a == b


# --- D4: opt-in richer strategies (default stays pure single-field) --------------

_ALL_MODES = {"single": 1.0, "multi": 1.0, "struct": 1.0, "seq": 1.0}


def test_default_is_single_field_only():
    # no modes arg -> every non-baseline case is a plain single-field mutation (no struct/prefix)
    for c in list(Pm4Generator(COPY_DATA, seed=5).cases(30))[1:]:
        assert c.struct == () and c.prefix == ()
        assert "," not in (c.mutated_field or "")  # not a multi/seq label


def test_multi_mode_targets_several_fields():
    g = Pm4Generator(COPY_DATA, seed=4, modes={"multi": 1.0})
    for c in list(g.cases(20))[1:]:
        # the label records which fields were targeted; multi targets 2-3 of them. (Whether
        # each produces a visibly different value depends on _bad_value — a full-width flag
        # can't leave its domain — so we assert the intent via the label, not observed diffs.)
        assert c.mutated_field.startswith("multi(")
        names = c.mutated_field[len("multi("):-1].split(",")
        assert 2 <= len(names) <= 3


def test_struct_mode_emits_corruption_descriptor():
    g = Pm4Generator(COPY_DATA, seed=6, modes={"struct": 1.0})
    for c in list(g.cases(20))[1:]:
        assert c.struct and c.struct[0] in ("count", "truncate")
        assert c.mutated_field.startswith("struct:")


def test_unknown_mode_rejected_at_construction():
    import pytest
    with pytest.raises(ValueError, match="unknown generator modes"):
        Pm4Generator(COPY_DATA, seed=1, modes={"bogus": 1.0})


def test_seq_mode_prepends_a_valid_prefix():
    g = Pm4Generator(COPY_DATA, seed=8, modes={"seq": 1.0})
    for c in list(g.cases(10))[1:]:
        assert len(c.prefix) == 1 and c.prefix[0].mutated_field is None  # valid state-setter
        assert c.mutated_field.startswith("seq:")


def test_struct_count_lie_rewrites_header_only():
    from fuzzyHSA.hw.stream import _packet_dwords
    case = next(Pm4Generator(COPY_DATA, seed=0).cases(1))
    honest = _packet_dwords(case, {"src": 0x1000, "dst": 0x2000})
    case.struct = ("count", 2)
    lied = _packet_dwords(case, {"src": 0x1000, "dst": 0x2000})
    assert (lied[0] >> 16 & 0x3FFF) == (honest[0] >> 16 & 0x3FFF) + 2  # count bumped
    assert lied[1:] == honest[1:]                                       # body untouched


def test_struct_truncate_drops_trailing_dwords():
    from fuzzyHSA.hw.stream import _packet_dwords
    case = next(Pm4Generator(COPY_DATA, seed=0).cases(1))
    full = _packet_dwords(case, {"src": 0x1000, "dst": 0x2000})
    case.struct = ("truncate", 2)
    cut = _packet_dwords(case, {"src": 0x1000, "dst": 0x2000})
    assert len(cut) == len(full) - 2 and cut == full[:-2]


def test_full_stream_applies_sequence_and_probe():
    from fuzzyHSA.hw.stream import build_stream
    g = Pm4Generator(COPY_DATA, seed=8, modes={"seq": 1.0})
    case = list(g.cases(2))[1]
    stream = build_stream(case, {"src": 0x1000, "dst": 0x2000}, 0x30000)
    # prefix COPY_DATA (6) + main COPY_DATA (6) + RELEASE_MEM probe (8) = 20 dwords
    assert len(stream) == (COPY_DATA.body_dwords + 1) * 2 + 8
