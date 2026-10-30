# SPDX-License-Identifier: Apache-2.0
"""Address-field convention (candidate #2): one owner, resolve/reconstruct inverses."""
import pytest

from fuzzyHSA.pm4 import addr
from fuzzyHSA.pm4.spec import COPY_DATA, Field, Packet


def test_resolve_reconstruct_are_inverses():
    vals = {f.name: addr.UNBOUND for f in COPY_DATA.fields if f.role == "address"}
    vals.update({f.name: f.domain[0] if f.domain else 0
                 for f in COPY_DATA.fields if f.role != "address"})
    resolved = addr.resolve(COPY_DATA, vals, {"src": 0x1234_5000, "dst": 0x20000})
    assert addr.reconstruct(COPY_DATA, resolved) == {"src": 0x1234_5000, "dst": 0x20000}


def test_resolve_raises_on_unknown_bo_no_silent_drift():
    # the old hardcoded-pairs bug silently skipped unknown address fields; now it raises
    vals = {f.name: addr.UNBOUND if f.role == "address" else 0 for f in COPY_DATA.fields}
    with pytest.raises(KeyError):
        addr.resolve(COPY_DATA, vals, {"src": 0x1000})   # missing "dst"


def test_new_address_field_is_resolved_from_spec_not_hardcoded():
    # a hypothetical packet with a 'tmp' BO resolves with zero backend changes
    pkt = Packet("X", 0x40, 2, True, (
        Field("tmp_addr_lo", 0, 0, 31, "address"),
        Field("tmp_addr_hi", 1, 0, 31, "address"),
    ))
    out = addr.resolve(pkt, {"tmp_addr_lo": addr.UNBOUND, "tmp_addr_hi": addr.UNBOUND},
                       {"tmp": 0xABCD_0000})
    assert out["tmp_addr_lo"] == 0xABCD0000 and out["tmp_addr_hi"] == 0


def test_unbound_is_distinct_from_zero():
    assert addr.UNBOUND is not None and addr.UNBOUND != 0
