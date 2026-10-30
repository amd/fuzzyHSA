# SPDX-License-Identifier: Apache-2.0
"""The hardware boundary (ticket 04's thin seam).

The campaign loop depends only on this Protocol, so the entire core is CI-testable
against ``FakeGpu`` and the real tinygrad-backed ``Mi300Backend`` slots in behind the
same contract. ``materialize`` (resolve address sentinels -> final dwords) is separate
from ``submit`` (ring the doorbell) so the recorder can persist the exact bytes BEFORE
the send — the record-before-send contract.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..campaign.finding import RawSignals
from ..fuzz.gen import GenCase


@runtime_checkable
class GpuBackend(Protocol):
    def setup(self) -> None:
        """Open device, create the compute queue, map ring/doorbell/signal BOs."""
        ...

    def materialize(self, case: GenCase) -> list[int]:
        """Resolve MAPPED address sentinels to real BO VAs and build the full PM4
        stream (the packet + the RELEASE_MEM completion probe). No doorbell yet."""
        ...

    def submit(self, dwords: list[int]) -> None:
        """Copy dwords into the ring, advance wptr, ring the doorbell. Call AFTER the
        recorder has persisted these exact dwords."""
        ...

    def observe(self, timeout_ms: float) -> RawSignals:
        """Wait for completion/fault; read KFD events, rptr, reset counter, dmesg, and
        the liveness re-probe. Populating ``RawSignals.liveness_pass`` is the backend's
        job inside ``observe`` — the loop never probes liveness across the seam, so it is
        not on this interface (a backend may keep a private helper)."""
        ...

    def teardown(self) -> None:
        ...
