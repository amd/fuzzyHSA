# SPDX-License-Identifier: Apache-2.0
"""Guard (08): the gate is code. Invariants, incl. the one from ticket 08."""
import json
import socket

import pytest

from fuzzyHSA.campaign.guard import Denied, Guard


def _dirs(tmp_path):
    return tmp_path / "config", tmp_path / "data"


def _write_grant(config, **over):
    config.mkdir(parents=True, exist_ok=True)
    g = dict(host=socket.gethostname(), gpus=[3], dangerous=["unmapped_addr"],
             max_iters=1000, max_seconds=60, max_rate_per_s=50)
    g.update(over)
    (config / "grant.json").write_text(json.dumps(g))


def test_allow_dangerous_without_grant_is_denied(tmp_path):
    """Ticket 08 invariant: allow_dangerous + no grant -> denied, before any HW touch."""
    config, data = _dirs(tmp_path)
    g = Guard(config, data)
    with pytest.raises(Denied) as e:
        g.check_start(3, tmp_path / "recs", allow_dangerous=True, requested_budget={})
    assert e.value.code == "denied"


def test_record_root_in_git_tree_denied(tmp_path):
    config, data = _dirs(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write_grant(config)
    with pytest.raises(Denied) as e:
        Guard(config, data).check_start(3, repo / "findings", False, {})
    assert e.value.code == "denied"


def test_wrong_gpu_index_denied(tmp_path):
    config, data = _dirs(tmp_path)
    _write_grant(config, gpus=[3])
    with pytest.raises(Denied) as e:
        Guard(config, data).check_start(7, tmp_path / "recs", True, {})
    assert e.value.code == "denied"


def test_budget_clamped_to_grant(tmp_path):
    config, data = _dirs(tmp_path)
    _write_grant(config, max_iters=1000)
    b = Guard(config, data).check_start(3, tmp_path / "recs", True,
                                        {"iterations": 10_000_000, "seconds": 10, "rate_per_s": 999})
    assert b["iterations"] == 1000 and b["rate_per_s"] == 50 and b["seconds"] == 10


def test_claim_fails_closed_on_unreadable_showpids(tmp_path):
    config, data = _dirs(tmp_path)
    g = Guard(config, data)
    with pytest.raises(Denied) as e:            # showpids raises -> occupied, never "free"
        g.claim_gpu(3, "camp", showpids=lambda i: (_ for _ in ()).throw(OSError("rocm-smi gone")))
    assert e.value.code == "busy"
    with pytest.raises(Denied):                 # None also fails closed
        g.claim_gpu(3, "camp", showpids=lambda i: None)


def test_claim_succeeds_when_free_then_blocks_wedged(tmp_path):
    config, data = _dirs(tmp_path)
    _write_grant(config)
    g = Guard(config, data)
    lock = g.claim_gpu(3, "camp", showpids=lambda i: [])
    assert lock.exists()
    g.mark_wedged(3, "gpu_reset", "camp")
    with pytest.raises(Denied) as e:
        g.check_start(3, tmp_path / "recs", True, {})
    assert e.value.code == "wedged"
