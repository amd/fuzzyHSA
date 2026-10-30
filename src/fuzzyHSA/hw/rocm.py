# SPDX-License-Identifier: Apache-2.0
"""rocm-smi occupancy probe for the shared-box claim (guard.claim_gpu).

Returns the foreign processes on a GPU index, or raises — and the Guard treats a raise
or None as *occupied* (fails closed), so a missing/unreadable rocm-smi never reads as
"free". ponytail: the exact rocm-smi --showpids layout and the pid->index mapping are
hardware-specific; confirm the parse on real gfx942 hardware.
"""
from __future__ import annotations

import os
import subprocess


def rocm_showpids(gpu_index: int) -> list[dict] | None:
    """Processes holding the GPU, excluding our own pid. None/raise => occupied."""
    out = subprocess.run(["rocm-smi", "--showpids"], capture_output=True, text=True, timeout=15)
    if out.returncode != 0:
        raise RuntimeError(f"rocm-smi --showpids failed: {out.stderr.strip()}")

    mine = os.getpid()
    pids: list[dict] = []
    for line in out.stdout.splitlines():
        parts = line.split()
        # lines that start with a bare PID integer are process rows
        if parts and parts[0].isdigit():
            pid = int(parts[0])
            if pid != mine:
                pids.append({"pid": pid, "raw": line.strip()})
    return pids
