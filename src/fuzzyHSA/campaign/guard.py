# SPDX-License-Identifier: Apache-2.0
"""Safety / permission model (ticket 08).

Every guardrail here is code, not prompt text: an agent that wants to wedge a shared
box must be unable to, and refusal is an exception with a stable ``code``. The human
gate is a grant FILE the agent's command surface cannot write; the device allowlist,
fails-closed GPU claim, budget clamp, wedge marker, and git-tree record refusal all
live here. No hostname or device identity is baked into this code — it all comes from
the user-written grant, which lives outside the repo.
"""
from __future__ import annotations

import json
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG = Path.home() / ".config" / "fuzzyhsa"
DEFAULT_DATA = Path.home() / ".local" / "share" / "fuzzyhsa"


class Denied(Exception):
    """A guardrail refused the operation. ``code`` is stable for agents to branch on."""
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


@dataclass(frozen=True)
class Grant:
    host: str
    gpus: tuple[int, ...]
    dangerous: tuple[str, ...] = ()
    max_iters: int = 100_000
    max_seconds: int = 3600
    max_rate_per_s: int = 200
    expires: float = 0.0            # unix epoch; 0 = never


def load_grant(config_dir: Path = DEFAULT_CONFIG) -> Grant | None:
    p = config_dir / "grant.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text())
    return Grant(
        host=d["host"], gpus=tuple(d["gpus"]), dangerous=tuple(d.get("dangerous", ())),
        max_iters=int(d.get("max_iters", 100_000)),
        max_seconds=int(d.get("max_seconds", 3600)),
        max_rate_per_s=int(d.get("max_rate_per_s", 200)),
        expires=float(d.get("expires", 0.0)),
    )


def _inside_git_tree(path: Path) -> bool:
    for parent in [path, *path.parents]:
        if (parent / ".git").exists():
            return True
    return False


class Guard:
    def __init__(self, config_dir: Path = DEFAULT_CONFIG, data_dir: Path = DEFAULT_DATA):
        self.config_dir = Path(config_dir)
        self.data_dir = Path(data_dir)
        (self.data_dir / "locks").mkdir(parents=True, exist_ok=True)

    # --- start gate -------------------------------------------------------
    def check_start(self, gpu_index: int, record_root: Path, allow_dangerous: bool,
                    requested_budget: dict) -> dict:
        """Raise Denied, or return the budget clamped to the grant's ceilings."""
        if _inside_git_tree(Path(record_root).resolve()):
            raise Denied("denied", f"record root {record_root} is inside a git tree; "
                                   "findings must never land in a repo")
        if self.is_wedged(gpu_index):
            raise Denied("wedged", f"GPU {gpu_index} is marked wedged; a human must clear it")

        grant = load_grant(self.config_dir)
        if grant is None:
            if allow_dangerous:
                raise Denied("denied", "allow_dangerous requires a grant file; none present")
            # no grant + no dangerous ops: only non-destructive campaigns, no device claim
            return dict(requested_budget)

        if grant.expires and time.time() > grant.expires:
            raise Denied("denied", "grant expired")
        if socket.gethostname() != grant.host:
            raise Denied("denied", f"host {socket.gethostname()} not the granted host")
        if gpu_index not in grant.gpus:
            raise Denied("denied", f"GPU {gpu_index} not in grant {list(grant.gpus)}")
        return self.clamp_budget(requested_budget, grant)

    @staticmethod
    def clamp_budget(requested: dict, grant: Grant) -> dict:
        return {
            "iterations": min(int(requested.get("iterations", grant.max_iters)), grant.max_iters),
            "seconds": min(int(requested.get("seconds", grant.max_seconds)), grant.max_seconds),
            "rate_per_s": min(int(requested.get("rate_per_s", grant.max_rate_per_s)), grant.max_rate_per_s),
        }

    # --- shared-box claim (fails closed) ----------------------------------
    def claim_gpu(self, gpu_index: int, campaign_id: str,
                  showpids: Callable[[int], list | None]) -> Path:
        """Claim a GPU via showpids + lockfile. FAILS CLOSED: an unreadable showpids
        (None / exception) is treated as occupied, never as free."""
        try:
            pids = showpids(gpu_index)
        except Exception as e:  # unreadable -> occupied
            raise Denied("busy", f"cannot read GPU {gpu_index} occupancy: {e}")
        if pids is None:
            raise Denied("busy", f"GPU {gpu_index} occupancy unknown (fails closed)")
        if pids:
            raise Denied("busy", f"GPU {gpu_index} held by {pids}")

        lock = self.data_dir / "locks" / f"gpu{gpu_index}.lock"
        if lock.exists():
            try:
                held = json.loads(lock.read_text())
                os.kill(held["pid"], 0)           # raises if dead -> stale, reclaim
                raise Denied("busy", f"GPU {gpu_index} locked by campaign {held.get('campaign_id')}")
            except (ProcessLookupError, ValueError, KeyError):
                pass  # stale lock, reclaim
        lock.write_text(json.dumps({"pid": os.getpid(), "campaign_id": campaign_id}))
        return lock

    def release_gpu(self, gpu_index: int) -> None:
        (self.data_dir / "locks" / f"gpu{gpu_index}.lock").unlink(missing_ok=True)

    # --- wedge marker (terminal, persistent, human-cleared) ---------------
    def _wedge_path(self, gpu_index: int) -> Path:
        return self.data_dir / f"wedged.gpu{gpu_index}"

    def is_wedged(self, gpu_index: int) -> bool:
        return self._wedge_path(gpu_index).exists()

    def mark_wedged(self, gpu_index: int, cls: str, campaign_id: str) -> None:
        self._wedge_path(gpu_index).write_text(
            json.dumps({"cls": cls, "campaign_id": campaign_id, "when": time.time()}))
