# SPDX-License-Identifier: Apache-2.0
"""The campaign process (ticket 04): generate -> record -> submit -> observe ->
classify -> persist, with zero LLM inside. One process, one GPU, one queue.

The sequence per case is load-bearing: the recorder persists the exact dwords and
fsyncs BEFORE ``submit`` rings the doorbell, so a wedge loses nothing and a restart
finds the culprit as the lone ``pending`` case. A wedge-class result marks the GPU and
stops — the tool never drives into a dead GPU.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..fuzz.gen import MAPPED
from ..pm4.decode import decode
from .classify import classify, dedup_sig, signal_class_of
from .finding import WEDGE_CLASSES, Finding, RawSignals, Recipe, is_finding
from .record import Recorder


@dataclass
class CampaignResult:
    iters: int = 0
    by_class: dict = field(default_factory=dict)
    findings: dict = field(default_factory=dict)   # dedup_sig -> {cls, count, exemplar_id}
    wedged: bool = False
    stopped_reason: str = "done"


def run_campaign(gen, backend, recorder: Recorder, *, spec_version: str, fw_version: str,
                 iterations: int, rate_per_s: float = 0.0, timeout_ms: float = 1000.0,
                 gpu_index: int = 0, guard=None, campaign_id: str = "c",
                 should_stop=lambda: False) -> CampaignResult:
    res = CampaignResult()
    backend.setup()
    min_interval = 1.0 / rate_per_s if rate_per_s > 0 else 0.0
    try:
        for i, case in enumerate(gen.cases(iterations)):
            if should_stop():
                res.stopped_reason = "stopped"
                break
            t0 = time.monotonic()
            case_id = f"{campaign_id}-{i:06d}"
            recipe = Recipe(seed=getattr(gen, "seed", 0), spec_version=spec_version,
                            fw_version=fw_version, opcode=case.packet.name,
                            mutated_field=case.mutated_field, mutated_value=case.mutated_value,
                            baseline={k: v for k, v in case.values.items() if v is not MAPPED})

            dwords = backend.materialize(case)
            blob = recorder.record_pending(case_id, recipe, dwords)   # fsync BEFORE doorbell
            backend.submit(dwords)
            signals: RawSignals = backend.observe(timeout_ms)

            cls = classify(signals)
            sig = dedup_sig(cls, case.packet.name, case.mutated_field, signal_class_of(signals))
            res.iters += 1
            res.by_class[cls.value] = res.by_class.get(cls.value, 0) + 1

            finding_dict = None
            if is_finding(cls):
                bucket = res.findings.setdefault(
                    sig, {"cls": cls.value, "count": 0, "exemplar_id": case_id})
                bucket["count"] += 1
                if bucket["count"] == 1:
                    finding_dict = Finding(
                        id=case_id, cls=cls, dedup_sig=sig, recipe=recipe,
                        decoded_stream=[d.__dict__ for d in decode(dwords)],
                        signals=signals, replay_blob=blob,
                    ).to_dict()
            recorder.resolve(case_id, cls.value, sig, finding_dict)

            if cls in WEDGE_CLASSES:
                res.wedged = True
                res.stopped_reason = f"wedged:{cls.value}"
                if guard is not None:
                    guard.mark_wedged(gpu_index, cls.value, campaign_id)
                break

            if min_interval:
                time.sleep(max(0.0, min_interval - (time.monotonic() - t0)))
    finally:
        backend.teardown()
    return res
