# SPDX-License-Identifier: Apache-2.0
"""Repro + minimize (D8). No GPU: the single-case HW re-exec (_run1) is mocked; the reconstruction
and delta-debug logic are what's under test."""
from fuzzyHSA.campaign.finding import Recipe
from fuzzyHSA.campaign.record import Recorder
from fuzzyHSA.campaign.replay import minimize, mutated_fields, repro
from fuzzyHSA.pm4.spec import COPY_DATA, baseline_values


def _nonaddr_baseline():
    # mimic a real recipe.baseline: non-address fuzzable fields only (unmutated addresses were
    # MAPPED and are filtered out when the recipe is recorded)
    return {f.name: baseline_values(COPY_DATA)[f.name]
            for f in COPY_DATA.fields if f.role not in ("count", "address")}


def _recorder_with_multi_finding(tmp_path):
    """A COPY_DATA finding whose recipe perturbed TWO fields (src_sel, count_sel) off baseline."""
    recorded = {**_nonaddr_baseline(), "src_sel": 0, "count_sel": 1}    # two mutations
    rec = Recorder(tmp_path)
    recipe = Recipe(seed=1, spec_version="pm4@1", fw_version="mi300", opcode="COPY_DATA",
                    mutated_field="multi(count_sel,src_sel)", mutated_value=None, baseline=recorded)
    rec.record_pending("c-000005", recipe, [1, 2, 3])
    rec.resolve("c-000005", "vm_fault", "sig5", {"id": "c-000005"})
    return rec


def test_mutated_fields_finds_the_perturbed_set(tmp_path):
    rec = _recorder_with_multi_finding(tmp_path)
    r = next(x for x in rec.case_records() if x["id"] == "c-000005")
    assert set(mutated_fields(r["recipe"], COPY_DATA)) == {"src_sel", "count_sel"}


def test_repro_reports_reproduced_when_class_matches(tmp_path):
    rec = _recorder_with_multi_finding(tmp_path)

    def same(*a):
        return ("vm_fault", "sig5")

    def flaky(*a):
        return ("ok", "s")

    assert repro(0, rec, "c-000005", _run1=same)["reproduced"] is True
    out = repro(0, rec, "c-000005", _run1=flaky)
    assert out["reproduced"] is False and out["original_cls"] == "vm_fault" and out["replay_cls"] == "ok"


def test_minimize_shrinks_to_the_load_bearing_field(tmp_path):
    rec = _recorder_with_multi_finding(tmp_path)

    # the fault is caused by count_sel alone; src_sel is noise. _run1 sees the reconstructed values.
    def run1(gpu, name, values, label, struct, t, wt):
        return ("vm_fault", "s") if values.get("count_sel") == 1 else ("ok", "s")

    out = minimize(0, rec, "c-000005", _run1=run1)
    assert out["minimal_fields"] == ["count_sel"]       # src_sel dropped as not load-bearing
    assert out["original_fields"] and out["trials"] >= 1


def _recorder_with_address_finding(tmp_path):
    """A finding whose fault came from a WILD address (src_addr_lo), plus a noise enum mutation."""
    recorded = {**_nonaddr_baseline(), "src_sel": 0, "src_addr_lo": 0xDEADBEEF}  # wild-VA mutation
    rec = Recorder(tmp_path)
    recipe = Recipe(seed=1, spec_version="pm4@1", fw_version="mi300", opcode="COPY_DATA",
                    mutated_field="multi(src_addr_lo,src_sel)", mutated_value=None, baseline=recorded)
    rec.record_pending("c-000009", recipe, [1])
    rec.resolve("c-000009", "vm_fault", "sig9", {"id": "c-000009"})
    return rec


def test_mutated_fields_includes_wild_address():
    recipe = {"baseline": {**baseline_values(COPY_DATA), "src_addr_lo": 0xDEADBEEF}}
    assert "src_addr_lo" in mutated_fields(recipe, COPY_DATA)   # address mutation is not erased


def test_minimize_keeps_the_wild_address_that_faults(tmp_path):
    rec = _recorder_with_address_finding(tmp_path)

    # the fault is the wild src_addr_lo; src_sel is noise. The reconstruction must PRESERVE the
    # wild VA for the active field (the bug the HW demo caught) — so _run1 sees it here.
    def run1(gpu, name, values, label, struct, t, wt):
        return ("vm_fault", "s") if values.get("src_addr_lo") == 0xDEADBEEF else ("ok", "s")

    out = minimize(0, rec, "c-000009", _run1=run1)
    assert out["minimal_fields"] == ["src_addr_lo"]      # src_sel dropped; wild address kept


def test_repro_unknown_id_is_an_error(tmp_path):
    assert repro(0, Recorder(tmp_path), "nope", _run1=lambda *a: ("ok", "s"))["error"] == "no_such_finding"


def _record(tmp_path, cid, cls, label, baseline):
    rec = Recorder(tmp_path)
    recipe = Recipe(1, "v", "f", "COPY_DATA", label, None, baseline)
    rec.record_pending(cid, recipe, [1])
    rec.resolve(cid, cls, "s", {"id": cid} if cls not in ("ok", "clean_rejection") else None)
    return rec


def test_repro_refuses_a_non_finding(tmp_path):
    rec = _record(tmp_path, "c-1", "ok", "src_sel", {**_nonaddr_baseline(), "src_sel": 0})
    assert repro(0, rec, "c-1", _run1=lambda *a: ("ok", "s"))["error"] == "not_a_finding"


def test_minimize_refuses_a_gpu_wedging_class(tmp_path):
    # re-running os_kernel_bug/gpu_reset/firmware_wedge would wedge a shared GPU -> refuse
    rec = _record(tmp_path, "c-2", "os_kernel_bug", "multi(src_sel,count_sel)",
                  {**_nonaddr_baseline(), "src_sel": 0, "count_sel": 1})
    assert minimize(0, rec, "c-2", _run1=lambda *a: ("os_kernel_bug", "s"))["error"] == "unsafe_to_rerun"


def test_minimize_keeps_fields_when_trials_are_inconclusive(tmp_path):
    from fuzzyHSA.campaign.replay import _INCONCLUSIVE
    rec = _recorder_with_multi_finding(tmp_path)   # vm_fault, muts = {src_sel, count_sel}
    out = minimize(0, rec, "c-000005", _run1=lambda *a: (_INCONCLUSIVE, ""))
    # no trial could conclude (e.g. GPU wedged) -> drop nothing, flag it, don't falsely collapse
    assert set(out["minimal_fields"]) == {"src_sel", "count_sel"} and out["inconclusive_trials"] >= 1
