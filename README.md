# fuzzyHSA

An agent-driven PM4 firmware fuzzer for AMD GPUs (MI300X / gfx942).

fuzzyHSA submits structured, deliberately-malformed **PM4 command packets** to the GPU and
classifies what the firmware does with them — clean rejection, VM fault, hang, an
out-of-bounds write, or a cross-process isolation break. The primary user is an *agent*:
every command speaks JSON in and JSON out, findings come back as decoded named fields
(never hex), and the harness enforces its own safety — not the prompt.

Each case runs in an isolated worker process, so a case that wedges its GPU context can't
cascade into the next: the worker exits and the campaign respawns and continues.

**What it exercises**

- **Packets** — seven PACKET3 opcodes on an unprivileged compute queue: `COPY_DATA`,
  `WRITE_DATA`, `DMA_DATA`, `ATOMIC_MEM`, `WAIT_REG_MEM`, `ACQUIRE_MEM`, `SET_SH_REG`. The
  spec is data (`pm4/spec.py`); adding a packet is adding a table entry.
- **Mutation** — `single` (one field wrong), `multi` (several at once), `struct` (the
  header lies about its length, or the body is truncated — hitting the command-stream
  parser), and `seq` (a valid packet sets state before a fuzzed one).
- **Oracles** — a KFD-event + dmesg oracle classifies each case; a canary guard page
  detects **silent out-of-bounds writes** (a packet that completes but scribbles past its
  target); a two-process probe tests **cross-process isolation** (can one process's packet
  reach another's GPU memory). The isolation probe covers VA-level separation and
  absolute addressing; stronger surfaces (shared handles, MMIO) are future work.

**What it reports** — findings are bucketed by a coarse dedup signature and classed as one
of: `ok`, `clean_rejection`, `vm_fault`, `gpu_hang`, `gpu_reset`, `firmware_wedge`,
`os_kernel_bug`, `silent_corruption`, `isolation_break`. Only the last seven are findings.

## Quick Start

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/amd/fuzzyHSA.git
cd fuzzyHSA

# Install dependencies and generate KFD bindings
uv sync
uv run python generate_bindings.py

# Try the pipeline with the simulated backend (no GPU needed)
uv run fuzzyHSA campaign-start --json \
  '{"record_root":"/tmp/fuzz","backend":"fake","budget":{"iterations":500}}'
uv run fuzzyHSA findings-list --json '{"record_root":"/tmp/fuzz"}'
```

## Requirements

- Linux with an AMD GPU (KFD driver) — for real campaigns
- Python 3.10+
- Linux kernel headers (for binding generation)

## Agent command surface

Every command prints one envelope `{ok, cmd, data, error}`; the exit code mirrors `ok`.

```bash
# run a campaign (backend: "fake" = simulated, "mi300" = real hardware)
# packet selects the opcode; modes mixes the mutation strategies
fuzzyHSA campaign-start --json '{"record_root":"/tmp/f","backend":"mi300","gpu_index":0,
                                 "packet":"DMA_DATA","allow_dangerous":true,
                                 "modes":{"single":1,"multi":1,"struct":1,"seq":1},
                                 "budget":{"iterations":100000}}'

fuzzyHSA campaign-status   --json '{"record_root":"/tmp/f"}'
fuzzyHSA findings-list     --json '{"record_root":"/tmp/f"}'  # one row per dedup bucket
fuzzyHSA findings-get      --json '{"record_root":"/tmp/f","id":"c-000017"}'
fuzzyHSA campaign-coverage --json '{"record_root":"/tmp/f"}'  # packets/fields/classes hit + gaps
fuzzyHSA campaign-repro    --json '{"record_root":"/tmp/f","id":"c-000017"}'  # does it reproduce?
fuzzyHSA campaign-minimize --json '{"record_root":"/tmp/f","id":"c-000017"}'  # shrink to its trigger
fuzzyHSA isolation-start   --json '{"record_root":"/tmp/f","gpu_index":0}'    # cross-process probe
fuzzyHSA decode            --json '{"dwords":[3221505538, ...]}'  # bytes -> named stream
fuzzyHSA spec-validate     --json '{}'
```

`campaign-repro` / `campaign-minimize` rebuild a recorded finding from its recipe and
re-run it in an isolated worker; they refuse GPU-wedging classes (re-running those wedges a
shared device). `isolation-start` reports `holds` / `isolation_break` / `inconclusive` —
and only trusts a negative after a positive control proves the attack path actually fired.

Real campaigns require a grant file at `~/.config/fuzzyhsa/grant.json` (host, allowed GPU
indices, budget ceilings) — the harness refuses `allow_dangerous` without it, refuses a
record root inside a git tree, and refuses a GPU another process holds. Every case is
recorded (recipe + exact bytes) and fsync'd **before** the doorbell rings, so a wedge loses
nothing and findings replay deterministically.

## Development

```bash
uv sync
uv run pytest                 # unit suite is GPU-free; integration tests are gated
uv run ruff check src/
uv run python generate_bindings.py   # regenerate bindings after a kernel update
```

## Project structure

```
src/fuzzyHSA/
├── kfd/          # KFD substrate: device discovery, ioctl exec, GTT/ring allocation
├── pm4/          # PM4 domain: packet spec (format as data), decode, address resolution
├── fuzz/         # spec-driven case generation (single/multi/struct/seq strategies)
├── campaign/     # pure core: finding taxonomy, oracle (classify), recorder, guard, loop,
│                 #   process-isolated runner (hw_runner), isolation probe, coverage, repro/minimize
├── hw/           # hardware boundary: backend Protocol + fake (CI) + mi300 (gated) + shared stream
└── cli.py        # the agent JSON command surface
```

Everything outside `hw/` is GPU-free and covered by the unit suite; the hardware-touching
logic sits behind a backend Protocol with a simulated `fake` adapter, so the whole pipeline
— generation, oracle, recording, coverage, the isolation/replay orchestration — is tested
in CI without a device. `hw/mi300.py` is the only part that drives real silicon.

## Acknowledgments

This project thanks [tinycorp](https://tinygrad.org/) for their efforts pushing boundaries. Check out [tinygrad](https://github.com/tinygrad/tinygrad)!

## License

Apache 2.0 License. See [LICENSE](LICENSE).
