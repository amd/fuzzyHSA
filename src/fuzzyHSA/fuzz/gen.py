# SPDX-License-Identifier: Apache-2.0
"""PM4 case generator (pure, seeded, CI-testable).

Default strategy: a valid baseline then weighted single-field mutations — every case is
a valid packet except one field ('structured-but-plausible'). Address fields default to
the sentinel ``MAPPED`` (resolved to a real BO at submit time by the HW boundary).

Opt-in richer strategies via ``modes`` (D4) reach bugs single-field can't:
  single  : one field wrong (the default)
  multi   : 2-3 fields wrong at once (e.g. ACQUIRE_MEM needs size>0 AND a bad base)
  struct  : the built dwords are corrupted below the field layer — the header lies about
            its count, or the body is truncated — to hit the CP's command-stream parser
  seq     : a valid baseline of the same packet precedes a single-field-fuzzed packet, a
            repeated/stateful-submission probe (does prior valid state change the mutation)
``modes`` is a {name: weight} dict over these names; omit it (or pass None) for pure single-field.
"""
from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass

from ..pm4.addr import UNBOUND
from ..pm4.spec import Packet, baseline_values

# sentinel: this address field resolves to a real mapped BO at submit time. Owned by
# pm4.addr (a domain concept); re-exported here under the generator's name.
MAPPED = UNBOUND

# wild VAs a mutated address field is driven to — each likely a distinct fault shape
WILD_VAS = (0x0, 0xDEAD0000, 0xFFFFFFFF, 0x1, 0xDEADBEEF)

# the mutation strategies ``modes`` may select (validated at construction)
_MODE_NAMES = ("single", "multi", "struct", "seq")


@dataclass
class GenCase:
    packet: Packet
    values: dict                 # field -> int, or MAPPED for addresses to resolve
    mutated_field: str | None    # None for the baseline; a label for multi/struct/seq
    mutated_value: int | None
    struct: tuple = ()           # () or ("count", delta) / ("truncate", k): below-field corruption
    prefix: tuple = ()           # GenCase(s) emitted before this packet (sequences)


class Pm4Generator:
    """Weighted mutator over one spec packet. Single-field by default; ``modes`` opts into
    multi-field, structural, and sequence strategies."""

    def __init__(self, packet: Packet, seed: int = 0,
                 field_weights: dict[str, float] | None = None,
                 modes: dict[str, float] | None = None):
        self.packet = packet
        self.seed = seed
        self._rng = random.Random(seed)
        # default: weight address fields heavily (the VM-fault surface is the target)
        self._weights = field_weights or {
            f.name: (5.0 if f.role == "address" else 1.0)
            for f in packet.fields if f.role != "count"
        }
        self._fields = [f for f in packet.fields
                        if f.role != "count" and self._weights.get(f.name, 0) > 0]
        if modes:   # fail fast in the parent, not with a worker crash deep in a campaign
            bad = set(modes) - set(_MODE_NAMES)
            if bad:
                raise ValueError(f"unknown generator modes {sorted(bad)}; valid: {_MODE_NAMES}")
        self._modes = modes or {"single": 1.0}      # default: pure single-field

    def _baseline(self) -> dict:
        v = baseline_values(self.packet)
        for f in self.packet.fields:
            if f.role == "address":
                v[f.name] = MAPPED
        return v

    def _pick_field(self):
        ws = [self._weights[f.name] for f in self._fields]
        return self._rng.choices(self._fields, weights=ws, k=1)[0]

    def _bad_value(self, f) -> int:
        if f.role == "address":
            return self._rng.choice(WILD_VAS)
        if f.role in ("enum", "flag"):
            # a value outside the authored domain (one step past the max sample)
            hi = max(f.domain) if f.domain else 0
            cap = (1 << f.width) - 1
            return min(hi + 1, cap) if hi < cap else cap
        return self._rng.getrandbits(f.width)

    # --- one case per strategy ---------------------------------------------------

    def _single(self) -> GenCase:
        f = self._pick_field()
        vals = self._baseline()
        bad = self._bad_value(f)
        vals[f.name] = bad
        return GenCase(self.packet, vals, f.name, bad)

    def _multi(self) -> GenCase:
        if len(self._fields) < 2:          # nothing to combine -> fall back to single-field
            return self._single()
        k = self._rng.randint(2, min(3, len(self._fields)))
        picks = self._rng.sample(self._fields, k)
        vals = self._baseline()
        for f in picks:
            vals[f.name] = self._bad_value(f)
        names = ",".join(sorted(f.name for f in picks))
        return GenCase(self.packet, vals, f"multi({names})", None)

    def _struct(self) -> GenCase:
        kind, k = self._rng.choice(
            [("count", d) for d in (-2, -1, 1, 2)] + [("truncate", t) for t in (1, 2)])
        return GenCase(self.packet, self._baseline(), f"struct:{kind}{k:+d}", None,
                       struct=(kind, k))

    def _seq(self) -> GenCase:
        # a valid baseline of the SAME packet precedes a single-field-fuzzed one: a repeated /
        # stateful-submission probe (does prior valid state change how the mutation behaves).
        pre = GenCase(self.packet, self._baseline(), None, None)
        main = self._single()
        return GenCase(self.packet, main.values, f"seq:{main.mutated_field}",
                       main.mutated_value, prefix=(pre,))

    def cases(self, n: int) -> Iterator[GenCase]:
        if n <= 0:
            return
        yield GenCase(self.packet, self._baseline(), None, None)  # baseline first
        makers = {"single": self._single, "multi": self._multi,
                  "struct": self._struct, "seq": self._seq}
        names = [m for m in self._modes if m in makers]
        weights = [self._modes[m] for m in names]
        for _ in range(n - 1):
            mode = self._rng.choices(names, weights=weights, k=1)[0]
            yield makers[mode]()
