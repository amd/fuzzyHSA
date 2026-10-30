# Glossary

Domain vocabulary for fuzzyHSA. Names the seams the code is built around, so changes
land in the right module.

- **PM4 packet** — a command the GPU's command processor executes, described as data in
  `pm4/spec.py` (a `Packet` of `Field`s with bit ranges and roles).
- **Role** — the semantic kind of a field (`address`, `enum`, `flag`, `count`, `data`,
  `handle`). Roles, not names, drive the generator and oracle: an `address` field *is* the
  VM-fault surface; a `count` field is synthesized, never authored.
- **BO (buffer object)** — a GPU allocation with a 64-bit virtual address. A packet refers
  to BOs through address fields.
- **Address-field convention** — an address is split across two fields named
  `<bo>_addr_lo` / `<bo>_addr_hi`, where `<bo>` names a BO (`src`, `dst`, `address`).
  `pm4/addr.py` is the single owner: `resolve` fills addresses from a per-BO VA map,
  `reconstruct` reads them back. The two are inverses.
- **UNBOUND** — the sentinel (`pm4/addr.py`) a generated case puts in an address field it
  leaves for a backend to resolve. Distinct from `0`, so a missed resolution fails loudly.
  Re-exported as `MAPPED` from `fuzz/gen.py`.
- **PM4 stream** — the dword sequence actually submitted: the mutated packet plus a
  RELEASE_MEM completion probe. Built once in `hw/stream.py` (`build_stream`), shared by
  every backend.
- **Case** — one generated test (`GenCase`): a packet, its field values (with UNBOUND
  addresses), and which single field was mutated.
- **Finding** — a result worth reporting: a signal *beyond clean rejection* (vm_fault,
  hang, reset, firmware wedge, kernel bug, isolation break). A firmware rejection of a bad
  packet is **not** a finding. See `campaign/classify.py`.
- **Dedup bucket** — findings collapsed by `sha1(class|opcode|mutated_field|signal_class)`,
  excluding per-run noise. An agent sees one row per bucket.
- **Backend** — an adapter satisfying the `GpuBackend` protocol (`hw/base.py`): `fake`
  (simulated, judges submitted bytes) or `mi300` (real KFD queue). The loop depends only
  on this seam.
- **Grant** — the human-written `~/.config/fuzzyhsa/grant.json` that authorizes dangerous
  campaigns on specific GPUs. The agent's command surface cannot write it; the harness
  (`campaign/guard.py`) refuses without it.
