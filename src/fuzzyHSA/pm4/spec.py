# SPDX-License-Identifier: Apache-2.0
"""PM4 packet specification as data.

A PM4 packet is described as a dict of fields; a small engine turns that data into
dwords, mutates one field, and round-trips. Semantics live in each field's ``role``
(address = VM-fault surface, enum carries its domain, count is synthesized), not in
code. An agent extends the surface by appending one ``Packet`` to ``REGISTRY``.

Bit layouts are mined from the public gfx9/soc15 PM4 spec (Linux ``soc15d.h``, MIT) and
tinygrad ``amd_gpu.py`` — reference-only. Opcode numbers and bit positions are hardware
facts; per-field roles + representative domains are authored here. Source of truth is
hybrid: opcode values come from the KFD/PM4 surface table; layout + roles live in this file.

Enum value domains are representative, not exhaustive — the exact legal set per field
is a calibration knob to confirm against firmware (a value the firmware silently drops
is itself a finding).
"""
from __future__ import annotations

from dataclasses import dataclass

PACKET_TYPE3 = 3

# role vocabulary the generator + oracle branch on
#   address : 32-bit half of a GPU VA -> resolved to a mapped BO; the VM-fault surface
#   enum    : small coded selector; fuzz = in-domain, or one step out of domain
#   flag    : single bit
#   handle  : opaque id from a prior op (stateful dependency)
#   count   : SYNTHESIZED from body length, never authored
#   data    : free payload dword
ROLES = frozenset({"address", "enum", "flag", "handle", "count", "data", "reserved"})


@dataclass(frozen=True)
class Field:
    name: str
    dw: int          # body dword index (0-based; header is separate)
    lo: int          # low bit, inclusive
    hi: int          # high bit, inclusive
    role: str
    domain: tuple = ()      # representative in-domain values (enum/flag); () = any
    note: str = ""

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"{self.name}: bad role {self.role!r}")
        if not 0 <= self.lo <= self.hi <= 31:
            raise ValueError(f"{self.name}: bad bit range {self.lo}:{self.hi}")

    @property
    def width(self) -> int:
        return self.hi - self.lo + 1

    @property
    def mask(self) -> int:
        return ((1 << self.width) - 1) << self.lo


@dataclass(frozen=True)
class Packet:
    name: str
    opcode: int          # PACKET3 opcode (from the surface table)
    body_dwords: int     # fixed-size packets; variable ones carry a count field
    compute: bool        # reachable on an unprivileged MEC compute queue
    fields: tuple[Field, ...] = ()

    def field(self, name: str) -> Field:
        for f in self.fields:
            if f.name == name:
                return f
        raise KeyError(name)


def header(p: Packet) -> int:
    """PACKET3 header. ``n = body_dwords - 1`` is synthesized, so the cheapest
    malformation (count != len(body)-1) is expressible only on purpose.

    Note: no PACKET3_COMPUTE bit (bit 1). These packets are fetched via an
    INDIRECT_BUFFER on an AQL compute queue, where ROCr/tinygrad emit plain PACKET3
    (bit 1 = 0); setting it leaves the packet consumed-but-not-executed on gfx942.
    The ``compute`` flag is retained as metadata (surface reachability), not a header bit.
    """
    n = p.body_dwords - 1
    return (PACKET_TYPE3 << 30) | ((p.opcode & 0xFF) << 8) | ((n & 0x3FFF) << 16)


def with_count(dwords: list[int], n: int) -> list[int]:
    """Rewrite the PACKET3 header's count field (bits [29:16]) to ``n``, leaving the body
    untouched. The honest count is synthesized by ``header``; this is how a structural
    mutation makes the header lie about body length (``n != body_dwords-1``)."""
    hdr = (dwords[0] & ~(0x3FFF << 16)) | ((n & 0x3FFF) << 16)
    return [hdr] + dwords[1:]


def build(p: Packet, values: dict) -> list[int]:
    """Assemble a valid baseline from a ``{field_name: value}`` dict."""
    body = [0] * p.body_dwords
    for f in p.fields:
        if f.role == "count":
            continue
        body[f.dw] |= (values[f.name] << f.lo) & f.mask
    return [header(p)] + body


def mutate(p: Packet, values: dict, target: str, bad: int) -> list[int]:
    """One-field-mutated: baseline with exactly ``target`` set to ``bad``."""
    v = dict(values)
    v[target] = bad
    return build(p, v)


def baseline_values(p: Packet) -> dict:
    """A representative in-domain value per field; address/data default to 0 for the
    generator to fill with real mapped VAs. Enums take their first domain sample."""
    out: dict = {}
    for f in p.fields:
        if f.role == "count":
            continue
        out[f.name] = f.domain[0] if f.domain else 0
    return out


# --- the surface: COPY_DATA (address-taker) + RELEASE_MEM (completion probe) ---

COPY_DATA = Packet(
    name="COPY_DATA", opcode=0x40, body_dwords=5, compute=True, fields=(
        Field("src_sel",     0,  0,  3, "enum", (1, 0, 2, 5), "0=reg 1=mem 2=tc/l2 5=imm"),
        Field("dst_sel",     0,  8, 11, "enum", (2, 0, 1, 5),
              "2=tc/l2 (baseline; writes to coherent GTT work via L2), 1=mem_sync hangs, 0=reg"),
        Field("count_sel",   0, 16, 16, "flag", (0, 1)),
        Field("wr_confirm",  0, 20, 20, "flag", (1, 0)),
        Field("engine_sel",  0, 30, 30, "enum", (0, 1)),
        Field("src_addr_lo", 1,  0, 31, "address", note="or reg offset if src_sel=0"),
        Field("src_addr_hi", 2,  0, 31, "address"),
        Field("dst_addr_lo", 3,  0, 31, "address", note="or reg offset if dst_sel=0"),
        Field("dst_addr_hi", 4,  0, 31, "address"),
    ))

# gfx9 RELEASE_MEM: event control (dw0, incl. GCR cache wb/inv) and the data/int/dst
# selectors (dw1) are SEPARATE ordinals. Collapsing them (or omitting the cache flush)
# leaves the GPU's write in L2, invisible to the CPU — the completion probe never lands.
RELEASE_MEM = Packet(
    name="RELEASE_MEM", opcode=0x49, body_dwords=7, compute=True, fields=(
        Field("event_type",  0,  0,  5, "enum", (0x14,), "0x14=CACHE_FLUSH_AND_INV_TS"),
        Field("event_index", 0,  8, 11, "enum", (5,), "5=end_of_pipe"),
        Field("cache",       0, 12, 22, "data", (0x88,),
              "gfx9 EOP_TC_WB(1<<15)|TC_NC(1<<19) action-enable, >>12 into this field"),
        Field("dst_sel",     1, 16, 17, "enum", (0, 1), "0=memory 1=tc/l2"),
        Field("int_sel",     1, 24, 26, "enum", (2, 0, 1, 3), "2=write-confirm"),
        Field("data_sel",    1, 29, 31, "enum", (1, 0, 2, 3), "1=32b 2=64b 3=gpu_clock"),
        Field("address_lo",  2,  0, 31, "address", note="signal VA; the oracle probe"),
        Field("address_hi",  3,  0, 31, "address"),
        Field("data_lo",     4,  0, 31, "data"),
        Field("data_hi",     5,  0, 31, "data"),
        Field("int_ctxid",   6,  0, 31, "data"),
    ))

# --- D3 breadth: more of the unprivileged-compute PM4 surface ------------------
# Each address field uses the <bo>_addr_lo/hi convention so addr.resolve binds it to a
# mapped BO (src/dst already allocated by the backend). Enum domains + baselines are a
# calibration knob: a baseline that won't complete its RELEASE_MEM probe on HW is a wrong
# layout, not a finding — revert it. Everything non-baseline is the fuzz surface.

# WRITE_DATA: the CP's direct memory-write path. Baseline writes one dword to the mapped
# dst via L2 (proven coherent on gfx942); fuzz drives dst_sel/engine + the payload/addr.
WRITE_DATA = Packet(
    name="WRITE_DATA", opcode=0x37, body_dwords=4, compute=True, fields=(
        Field("dst_sel",      0,  8, 11, "enum", (2, 5, 0, 1),
              "2=tc/l2 (baseline), 5=memory, 0=reg, 1=mem_sync"),
        Field("wr_one_addr",  0, 16, 16, "flag", (0, 1), "1=write all data to one addr"),
        Field("wr_confirm",   0, 20, 20, "flag", (1, 0)),
        Field("cache_policy", 0, 25, 26, "enum", (0, 1, 2)),
        Field("engine_sel",   0, 30, 31, "enum", (0, 1, 2),
              "ME/PFP/CE on gfx rings; reserved on the MEC/compute variant (fuzzed as reserved)"),
        Field("dst_addr_lo",  1,  0, 31, "address"),
        Field("dst_addr_hi",  2,  0, 31, "address"),
        Field("data0",        3,  0, 31, "data"),
    ))

# DMA_DATA: the CP DMA engine (src+dst). Baseline is a 0-byte sync copy (completes cleanly);
# fuzz drives byte_count (huge copies), the sel/addr-space flags, and both VAs.
DMA_DATA = Packet(
    name="DMA_DATA", opcode=0x50, body_dwords=6, compute=True, fields=(
        Field("engine",      0,  0,  0, "flag", (0, 1)),
        Field("src_cache",   0, 13, 14, "enum", (0, 1, 2)),
        Field("dst_sel",     0, 20, 21, "enum", (0, 1, 3), "0=dst addr via L2"),
        Field("dst_cache",   0, 25, 26, "enum", (0, 1, 2)),
        Field("src_sel",     0, 29, 30, "enum", (0, 1, 2, 3), "0=src addr via L2 2=imm data"),
        Field("cp_sync",     0, 31, 31, "flag", (1, 0)),
        Field("src_addr_lo", 1,  0, 31, "address"),
        Field("src_addr_hi", 2,  0, 31, "address"),
        Field("dst_addr_lo", 3,  0, 31, "address"),
        Field("dst_addr_hi", 4,  0, 31, "address"),
        Field("byte_count",  5,  0, 25, "data", note="bytes to copy (26-bit); 0=baseline no-op"),
        Field("cmd_sas",     5, 26, 26, "flag", (0, 1)),
        Field("cmd_das",     5, 27, 27, "flag", (0, 1)),
        Field("cmd_saic",    5, 28, 28, "flag", (0, 1)),
        Field("cmd_daic",    5, 29, 29, "flag", (0, 1)),
        Field("cmd_raw_wait", 5, 30, 30, "flag", (0, 1)),
    ))

# ATOMIC_MEM: atomic ALU on a memory address. The atomic opcode [5:0] is itself a fuzz
# surface (undefined TC ops -> firmware behaviour). Baseline target = mapped dst.
ATOMIC_MEM = Packet(
    name="ATOMIC_MEM", opcode=0x1E, body_dwords=8, compute=True, fields=(
        Field("atomic",       0,  0,  6, "enum", (0x7, 0x0, 0x3F),
              "TC_OP atomic opcode, 7-bit on gfx9_plus/gfx942 (calibrate; 0x7~add_rtn_32)"),
        Field("command",      0,  8, 11, "enum", (0, 1), "0=single_pass 1=loop_until_cmp"),
        Field("cache_policy", 0, 25, 26, "enum", (0, 1, 2)),
        Field("dst_addr_lo",  1,  0, 31, "address", note="atomic target"),
        Field("dst_addr_hi",  2,  0, 31, "address"),
        Field("src_data_lo",  3,  0, 31, "data"),
        Field("src_data_hi",  4,  0, 31, "data"),
        Field("cmp_data_lo",  5,  0, 31, "data"),
        Field("cmp_data_hi",  6,  0, 31, "data"),
        Field("loop_interval", 7, 0, 12, "data"),
    ))

# WAIT_REG_MEM: the CP poll/wait state machine (a prime hang surface). Baseline function=0
# (ALWAYS_PASS) completes immediately; fuzz drives function/operation + the poll addr/ref/mask.
WAIT_REG_MEM = Packet(
    name="WAIT_REG_MEM", opcode=0x3C, body_dwords=6, compute=True, fields=(
        Field("function",     0,  0,  2, "enum", (0, 3, 4, 6), "0=always 3=eq 4=ne 6=gt"),
        Field("mem_space",    0,  4,  5, "enum", (1, 0), "1=memory 0=register"),
        Field("operation",    0,  6,  7, "enum", (0, 1, 3)),
        Field("engine_sel",   0,  8,  8, "enum", (0, 1)),
        Field("cache_policy", 0, 25, 26, "enum", (0, 1, 2)),
        Field("src_addr_lo",  1,  0, 31, "address", note="poll address"),
        Field("src_addr_hi",  2,  0, 31, "address"),
        Field("reference",    3,  0, 31, "data"),
        Field("mask",         4,  0, 31, "data"),
        Field("poll_interval", 5, 0, 15, "data"),
    ))

# ACQUIRE_MEM: cache/coherence acquire over an address range. Baseline is an all-zero no-op
# acquire; fuzz drives the cache-action bits (weird flush combos) and the range base/size.
ACQUIRE_MEM = Packet(
    name="ACQUIRE_MEM", opcode=0x58, body_dwords=6, compute=True, fields=(
        Field("coher_cntl",   0,  0, 30, "data", note="gfx9 cache-action bits"),
        Field("engine_sel",   0, 31, 31, "enum", (0, 1)),
        Field("coher_size",   1,  0, 31, "data"),
        Field("coher_size_hi", 2, 0,  7, "data"),
        Field("coher_base_lo", 3, 0, 31, "data", note="range base (not VA-mapped)"),
        Field("coher_base_hi", 4, 0, 23, "data"),
        Field("poll_interval", 5, 0, 15, "data"),
    ))

# SET_SH_REG: writes a shader/compute SH register. Fuzzing reg_offset probes whether an
# unprivileged compute queue can reach a privileged register. Baseline = COMPUTE_USER_DATA_0
# (harmless), calibrate on HW; fuzz = arbitrary 16-bit offsets.
SET_SH_REG = Packet(
    name="SET_SH_REG", opcode=0x76, body_dwords=2, compute=True, fields=(
        Field("reg_offset", 0,  0, 15, "data", (0x240,), "offset from SH base 0x2c00; calibrate"),
        Field("data0",      1,  0, 31, "data"),
    ))

_PACKETS = (COPY_DATA, RELEASE_MEM, WRITE_DATA, DMA_DATA, ATOMIC_MEM,
            WAIT_REG_MEM, ACQUIRE_MEM, SET_SH_REG)
REGISTRY: dict[str, Packet] = {p.name: p for p in _PACKETS}
BY_OPCODE: dict[int, Packet] = {p.opcode: p for p in REGISTRY.values()}
