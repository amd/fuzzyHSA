# SPDX-License-Identifier: Apache-2.0
"""Cross-process isolation oracle (D6). No GPU: fake victim/attacker backends model the OUTCOMES
(does the victim word change, did the write land) — not the HW mechanism — to exercise the
oracle's wiring: the positive-control gate, the executed count, break detection, and the
holds/break/inconclusive status logic."""
from fuzzyHSA.campaign.finding import RawSignals
from fuzzyHSA.campaign.isolation import probe_isolation, run_isolation_campaign


class _World:
    """Shared truth for a fake victim+attacker pair. ``broken`` = a write reaches the victim;
    ``path_ok`` = the attacker's own write path lands (the positive control)."""
    def __init__(self, *, broken: bool, path_ok: bool = True):
        self.broken, self.path_ok = broken, path_ok
        self.victim_word: int | None = None


class _Victim:
    def __init__(self, world: _World):
        self.world = world

    def arm_canary(self, word: int) -> int:
        self.world.victim_word = word
        return 0x7000

    def verify_canary(self, word: int) -> int | None:
        return None if self.world.victim_word == word else 0


class _Attacker:
    def __init__(self, world: _World):
        self.world = world

    def self_write_probe(self, poison: int) -> bool:
        return self.world.path_ok

    def _attempt(self, poison: int) -> RawSignals:
        if self.world.broken:                       # the write reaches the victim and completes
            self.world.victim_word = poison
            return RawSignals(kfd_events=("SIGNAL",), signal_written=True, liveness_pass=True)
        return RawSignals(kfd_events=("MEMORY",), faulting_va=0x7000, liveness_pass=True)  # contained

    def attack_write(self, va, poison, dst_sel):
        return self._attempt(poison)

    def attack_dma_absolute(self, va, poison):
        return self._attempt(poison)


def test_sound_isolation_holds_with_executed_attacks():
    w = _World(broken=False)
    off, path_ok, outcomes = probe_isolation(_Victim(w), _Attacker(w))
    assert off is None and path_ok and len(outcomes) == 3
    assert all(o[2] == "faulted" for o in outcomes)        # each attack executed and was contained


def test_broken_isolation_is_detected():
    w = _World(broken=True)
    off, path_ok, outcomes = probe_isolation(_Victim(w), _Attacker(w))
    assert off == 0 and all(o[2] == "wrote" for o in outcomes)


def test_campaign_holds_only_when_path_ok_and_executed(tmp_path):
    # positive control passed, 3 attacks executed+contained -> trustworthy "holds"
    res = run_isolation_campaign(0, tmp_path, campaign_id="h",
                                 _run=lambda *a: (None, True, [("write", 5, "faulted")] * 3))
    assert res.status == "holds" and not res.broke and res.executed == 3 and res.finding is None


def test_campaign_inconclusive_when_attack_path_broken(tmp_path):
    # nothing broke, but the positive control failed -> the negative is vacuous, not "holds"
    res = run_isolation_campaign(0, tmp_path, campaign_id="p",
                                 _run=lambda *a: (None, False, [("write", 5, "faulted")] * 3))
    assert res.status == "inconclusive_attack_path" and not res.broke


def test_campaign_inconclusive_when_nothing_executed(tmp_path):
    # path ok, but every attacker failed setup -> zero real work -> not "holds"
    res = run_isolation_campaign(0, tmp_path, campaign_id="n",
                                 _run=lambda *a: (None, True, [("write", 5, "setup_failed")] * 3))
    assert res.status == "inconclusive_no_execution" and res.executed == 0


def test_campaign_records_break_finding(tmp_path):
    from fuzzyHSA.campaign.record import Recorder
    res = run_isolation_campaign(0, tmp_path, campaign_id="b",
                                 _run=lambda *a: (0x40, True, [("write", 5, "wrote")]))
    assert res.status == "isolation_break" and res.offset == 0x40
    assert res.finding["cls"] == "isolation_break"
    assert any(b["cls"] == "isolation_break" for b in Recorder(tmp_path).buckets().values())
