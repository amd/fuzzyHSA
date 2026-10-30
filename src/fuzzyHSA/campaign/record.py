# SPDX-License-Identifier: Apache-2.0
"""Durable record (ticket 04).

Append-only JSONL manifest + one sidecar blob per case. The case is written
``pending`` and fsync'd BEFORE the doorbell rings; a wedge + reboot therefore loses
nothing, and on restart any still-``pending`` case is the culprit. Replay is two-track:
the recipe (seed+spec+fw) regenerates, the blob replays the exact bytes.

The manifest is append-only, so a status change is a new line; the latest line for an
id wins. That makes every write a single atomic append — no in-place mutation to tear.
"""
from __future__ import annotations

import dataclasses
import json
import os
import struct
import time
from pathlib import Path


class Recorder:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.cases = self.root / "cases"
        self.cases.mkdir(parents=True, exist_ok=True)
        self.manifest = self.root / "manifest.jsonl"

    def _append(self, obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        # append + flush + fsync so the line survives a crash immediately after
        fd = os.open(self.manifest, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def record_pending(self, case_id: str, recipe, dwords: list[int]) -> str:
        """Write the blob + a ``pending`` manifest line, fsync both, return blob path.
        MUST be called before the doorbell — this is the record-before-send contract."""
        blob = self.cases / f"{case_id}.bin"
        data = struct.pack(f"<{len(dwords)}I", *dwords)
        fd = os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._append({
            "id": case_id, "status": "pending", "ts": time.time(),
            "recipe": dataclasses.asdict(recipe), "blob": str(blob),
        })
        return str(blob)

    def resolve(self, case_id: str, cls: str, dedup_sig: str, finding: dict | None) -> None:
        """Mark a case done with its classification (append-only)."""
        self._append({
            "id": case_id, "status": "resolved", "ts": time.time(),
            "cls": cls, "dedup_sig": dedup_sig, "finding": finding,
        })

    def _latest(self) -> dict[str, dict]:
        latest: dict[str, dict] = {}
        if not self.manifest.exists():
            return latest
        for line in self.manifest.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            latest[rec["id"]] = rec
        return latest

    def pending_ids(self) -> list[str]:
        """Ids whose latest status is still ``pending`` — the culprit on restart."""
        return [i for i, r in self._latest().items() if r["status"] == "pending"]

    # --- read side: the schema has one owner, so reads live here too ---

    def records(self) -> list[dict]:
        """Latest manifest record per case (latest line wins)."""
        return list(self._latest().values())

    def tail_records(self, offset: int) -> tuple[list[dict], int]:
        """Parse only the manifest lines at/after byte ``offset``; return (new_records, new_offset).
        Lets a long campaign advance without re-parsing the whole manifest each respawn — O(N)
        total instead of O(N^2). The caller must read only when the manifest is quiescent (the
        writing worker has exited), so ``offset`` always lands on a line boundary."""
        if not self.manifest.exists():
            return [], offset
        with open(self.manifest, "rb") as f:
            f.seek(offset)
            data = f.read()
        out: list[dict] = []
        consumed = 0
        for raw in data.splitlines(keepends=True):     # keepends: advance offset by exact bytes
            if raw.strip():
                try:
                    out.append(json.loads(raw))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    break                               # torn tail line -> stop before it, re-read later
            consumed += len(raw)
        return out, offset + consumed

    def buckets(self) -> dict[str, dict]:
        """One row per dedup bucket: ``sig -> {dedup_sig, cls, count, exemplar_id}``.
        Counts ALL resolved finding cases; the exemplar holds the full record."""
        from .finding import is_finding_name
        out: dict[str, dict] = {}
        for r in self._latest().values():
            if r.get("status") != "resolved" or not is_finding_name(r.get("cls", "")):
                continue
            sig = r.get("dedup_sig")
            if sig is None:
                continue
            b = out.setdefault(sig, {"dedup_sig": sig, "cls": r["cls"],
                                     "count": 0, "exemplar_id": r["id"]})
            b["count"] += 1
            if r.get("finding"):
                b["exemplar_id"] = r["finding"]["id"]
        return out

    def finding(self, finding_id: str) -> dict | None:
        """The full finding record for an exemplar id, or None."""
        for r in self._latest().values():
            f = r.get("finding")
            if f and f["id"] == finding_id:
                return f
        return None

    def summary(self) -> dict:
        """``{by_class: {...}, buckets: N}`` over resolved cases."""
        by_class: dict[str, int] = {}
        for r in self._latest().values():
            if r.get("status") == "resolved":
                by_class[r["cls"]] = by_class.get(r["cls"], 0) + 1
        return {"by_class": by_class, "iters": sum(by_class.values()),
                "buckets": len(self.buckets())}

    def load_blob(self, case_id: str) -> list[int]:
        data = (self.cases / f"{case_id}.bin").read_bytes()
        return list(struct.unpack(f"<{len(data) // 4}I", data))
