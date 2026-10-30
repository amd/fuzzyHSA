# fuzzyHSA

An agent-driven PM4 firmware fuzzer for AMD GPUs.

fuzzyHSA submits structured **PM4 command packets** to a KFD compute queue and classifies
what the firmware does with them. The primary user is an *agent*: every command speaks
JSON in and JSON out, findings come back as decoded named fields (never hex), and the
harness enforces its own safety — not the prompt.

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
fuzzyHSA campaign-start --json '{"record_root":"/tmp/f","backend":"mi300","gpu_index":0,
                                 "allow_dangerous":true,"budget":{"iterations":100000}}'

fuzzyHSA campaign-status --json '{"record_root":"/tmp/f"}'
fuzzyHSA findings-list   --json '{"record_root":"/tmp/f"}'   # one row per dedup bucket
fuzzyHSA findings-get    --json '{"record_root":"/tmp/f","id":"c-000017"}'
fuzzyHSA decode          --json '{"dwords":[3221505538, ...]}'   # bytes -> named stream
fuzzyHSA spec-validate   --json '{}'
```

Real campaigns require a grant file at `~/.config/fuzzyhsa/grant.json` (host, allowed GPU
indices, budget ceilings) — the harness refuses `allow_dangerous` without it, refuses a
record root inside a git tree, and refuses a GPU another process holds.

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
├── pm4/          # PM4 domain: packet spec (format as data) + decode
├── fuzz/         # structured, spec-driven case generation
├── campaign/     # pure core: finding taxonomy, oracle, recorder, guard, loop
├── hw/           # hardware boundary: backend Protocol + fake (CI) + mi300 (gated)
└── cli.py        # the agent JSON command surface
```

The `campaign/` core and `pm4/` domain are GPU-free and covered by the unit suite; `hw/`
is the only part that touches the device.

## Acknowledgments

This project thanks [tinycorp](https://tinygrad.org/) for their efforts pushing boundaries. Check out [tinygrad](https://github.com/tinygrad/tinygrad)!

## License

Apache 2.0 License. See [LICENSE](LICENSE).
