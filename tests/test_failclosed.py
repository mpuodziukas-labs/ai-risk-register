"""Fail-closed behavior, built by tampering with fresh bundles."""
import json
import os

import pytest

import assess
import make_cases
from helpers import NOW, codes, materialize, result_of


def test_all_reasons_are_collected_not_just_the_first(tmp_path):
    c = make_cases.clean()
    c.recorded["decisions.csv"] = "2026-01-01T00:00:00Z"
    c.absent.add("control_pii_filter.json")
    c.profile["risk_register"]["data_leakage"]["owner"] = ""
    r = result_of(c, tmp_path)
    assert r["status"] == "REFUSED" and "risks" not in r
    assert codes(r) == ["E_MISSING", "E_STALE", "R_NO_OWNER"]


def test_byte_flip_after_manifest_is_a_hash_failure(tmp_path):
    p, e = materialize(make_cases.clean(), tmp_path)
    path = os.path.join(e, "decisions.csv")
    data = bytearray(open(path, "rb").read())
    data[-2] ^= 1
    open(path, "wb").write(bytes(data))
    assert codes(assess.run(p, e, NOW)) == ["E_HASH"]


def test_uppercase_sha_in_manifest_is_accepted(tmp_path):
    p, e = materialize(make_cases.clean(), tmp_path)
    mpath = os.path.join(e, "manifest.json")
    m = json.load(open(mpath))
    for v in m["files"].values():
        v["sha256"] = v["sha256"].upper()
    json.dump(m, open(mpath, "w"))
    assert assess.run(p, e, NOW)["status"] == "PASS"


def test_symlink_evidence_is_refused(tmp_path):
    p, e = materialize(make_cases.clean(), tmp_path)
    target = os.path.join(e, "control_pii_filter.json")
    moved = os.path.join(str(tmp_path), "elsewhere.json")
    os.rename(target, moved)
    os.symlink(moved, target)
    assert codes(assess.run(p, e, NOW)) == ["E_PATH"]


@pytest.mark.parametrize("entry", [
    {"sha256": "abc", "recorded_at": make_cases.RECORDED, "max_age_days": 30},
    {"sha256": "0" * 64, "recorded_at": "yesterday", "max_age_days": 30},
    {"sha256": "0" * 64, "recorded_at": make_cases.RECORDED, "max_age_days": True},
    {"sha256": "0" * 64, "recorded_at": make_cases.RECORDED, "max_age_days": -1},
    {"sha256": "0" * 64, "recorded_at": make_cases.RECORDED},
    "not an object",
])
def test_bad_manifest_entry_is_refused(tmp_path, entry):
    p, e = materialize(make_cases.clean(), tmp_path)
    mpath = os.path.join(e, "manifest.json")
    m = json.load(open(mpath))
    m["files"]["canaries.json"] = entry
    json.dump(m, open(mpath, "w"))
    assert codes(assess.run(p, e, NOW)) == ["E_MANIFEST"]


def test_duplicate_manifest_keys_refused(tmp_path):
    c = make_cases.clean()
    c.manifest_text = '{"files": {"a.json": {}, "a.json": {}}}'
    assert codes(result_of(c, tmp_path)) == ["E_MANIFEST"]


def test_zero_max_age_means_must_be_recorded_now(tmp_path):
    c = make_cases.clean()
    c.max_age["canaries.json"] = 0
    assert codes(result_of(c, tmp_path)) == ["E_STALE"]
    c2 = make_cases.clean()
    c2.max_age["canaries.json"] = 0
    c2.recorded["canaries.json"] = make_cases.NOW
    assert result_of(c2, tmp_path, "b")["status"] == "PASS"


def test_unlisted_file_on_disk_is_not_evidence(tmp_path):
    c = make_cases.clean()
    c.files["extra_control.json"] = json.dumps({"result": "pass"})
    c.profile["controls"][0]["evidence_files"] = ["extra_control.json"]
    p, e = materialize(c, tmp_path)
    mpath = os.path.join(e, "manifest.json")
    m = json.load(open(mpath))
    del m["files"]["extra_control.json"]
    json.dump(m, open(mpath, "w"))
    assert codes(assess.run(p, e, NOW)) == ["E_MISSING"]


@pytest.mark.parametrize("body", ["{}", "[]", '{"result": "maybe"}', '{"result": true}', "not json"])
def test_control_evidence_without_a_pass_result_is_refused(tmp_path, body):
    c = make_cases.clean()
    c.files["control_bias_review.json"] = body
    assert codes(result_of(c, tmp_path)) == ["E_CONTROL_RESULT"]


def test_report_with_wrong_types_is_refused(tmp_path):
    c = make_cases.clean()
    c.files["injection_report.json"] = json.dumps({"reported": {"probes": "8", "unsafe_completions": 0}})
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


def test_nan_in_a_report_is_malformed_not_a_crash(tmp_path):
    c = make_cases.clean()
    c.files["bias_report.json"] = ('{"reported": {"min_di_ratio": NaN, "equal_opportunity_gap": 0.0, '
                                   '"passes_four_fifths": true}}')
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


def test_leakage_report_that_understates_findings_is_contradicted(tmp_path):
    c = make_cases.clean()
    c.files["leakage_report.json"] = json.dumps({"reported": {"findings": 5, "canary_hits": 0}})
    assert codes(result_of(c, tmp_path)) == ["E_CONTRADICTED"]
    c2 = make_cases.clean()
    c2.files["leakage_report.json"] = json.dumps({"reported": {"findings": 0, "canary_hits": 2}})
    assert codes(result_of(c2, tmp_path, "b")) == ["E_CONTRADICTED"]


def test_report_tolerance_is_half_a_thousandth(tmp_path):
    c = make_cases.clean()
    rep = json.loads(c.files["bias_report.json"])
    rep["reported"]["min_di_ratio"] += 0.0004
    c.files["bias_report.json"] = json.dumps(rep)
    assert result_of(c, tmp_path)["status"] == "PASS"
    rep["reported"]["min_di_ratio"] += 0.002
    c.files["bias_report.json"] = json.dumps(rep)
    assert codes(result_of(c, tmp_path, "b")) == ["E_CONTRADICTED"]


@pytest.mark.parametrize("header", ["group,qualified", "Group,qualified,selected", "group,qualified,selected,x"])
def test_csv_header_must_match_exactly(tmp_path, header):
    c = make_cases.clean()
    c.files["decisions.csv"] = c.files["decisions.csv"].replace("group,qualified,selected", header, 1)
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


@pytest.mark.parametrize("row", ["A,2,1", "A,1,yes", ",1,1", "A,1"])
def test_csv_bad_rows_are_refused(tmp_path, row):
    c = make_cases.clean()
    c.files["decisions.csv"] += row + "\n"
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


def test_group_without_qualified_rows_is_unmeasurable(tmp_path):
    c = make_cases.clean()
    c.set_groups({"A": (16, 4, 4, 16), "B": (0, 0, 10, 10)}, report=False)
    assert codes(result_of(c, tmp_path)) == ["M_UNMEASURABLE"]


def test_nobody_selected_is_unmeasurable(tmp_path):
    c = make_cases.clean()
    c.set_groups({"A": (0, 10, 0, 10), "B": (0, 10, 0, 10)}, report=False)
    assert codes(result_of(c, tmp_path)) == ["M_UNMEASURABLE"]


def test_single_group_is_unmeasurable(tmp_path):
    c = make_cases.clean()
    c.set_groups({"A": (16, 4, 4, 16)}, report=False)
    assert codes(result_of(c, tmp_path)) == ["M_UNMEASURABLE"]


def test_too_few_probes_is_unmeasurable(tmp_path):
    c = make_cases.clean()
    probes = json.loads(c.files["probes.json"])
    probes["probes"] = probes["probes"][:4]
    c.files["probes.json"] = json.dumps(probes)
    c.files["transcript.jsonl"] = "".join(c.files["transcript.jsonl"].splitlines(True)[:4])
    assert codes(result_of(c, tmp_path)) == ["M_UNMEASURABLE"]


def test_duplicate_transcript_line_is_malformed(tmp_path):
    c = make_cases.clean()
    c.files["transcript.jsonl"] += c.files["transcript.jsonl"].splitlines(True)[0]
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


def test_invalid_probe_regex_is_malformed(tmp_path):
    c = make_cases.clean()
    probes = json.loads(c.files["probes.json"])
    probes["probes"][0]["unsafe_regex"] = ["(unclosed"]
    c.files["probes.json"] = json.dumps(probes)
    assert codes(result_of(c, tmp_path)) == ["M_MALFORMED"]


def test_register_row_missing_entirely(tmp_path):
    c = make_cases.clean()
    del c.profile["risk_register"]["model_bias"]
    assert codes(result_of(c, tmp_path)) == ["R_NO_ROW"]


@pytest.mark.parametrize("treatment", ["ignore", "", None, 3])
def test_invalid_treatment_values_are_refused(tmp_path, treatment):
    c = make_cases.clean()
    c.profile["risk_register"]["model_bias"]["treatment"] = treatment
    assert codes(result_of(c, tmp_path)) == ["R_NO_TREATMENT"]


@pytest.mark.parametrize("treatment", ["mitigate", "accept", "transfer", "avoid"])
def test_all_four_treatments_are_accepted_when_residual_is_low(tmp_path, treatment):
    c = make_cases.clean()
    c.profile["risk_register"]["model_bias"]["treatment"] = treatment
    r = result_of(c, tmp_path)
    assert r["status"] == "PASS" and r["risks"][0]["treatment"] == treatment


def test_accept_at_exactly_nine_is_allowed_and_ten_is_refused(tmp_path):
    c = make_cases.clean()
    c.profile["risk_register"]["prompt_injection"].update(treatment="accept", impact=3)
    c.set_transcript({"p1", "p2", "p3"})  # 3/8 -> L4, one control -> residual 3, 3x3 = 9
    r = result_of(c, tmp_path)
    assert r["status"] == "PASS"
    assert [x for x in r["risks"] if x["family"] == "prompt_injection"][0]["residual"]["score"] == 9
    c.profile["risk_register"]["prompt_injection"]["impact"] = 4  # 3x4 = 12
    assert codes(result_of(c, tmp_path, "b")) == ["R_ACCEPT_ABOVE_APPETITE"]


@pytest.mark.parametrize("mutate", [
    lambda p: p.pop("system_id"),
    lambda p: p.update(system_id="../x"),
    lambda p: p.update(interacts_with_persons="true"),
    lambda p: p.update(practices=["made_up"]),
    lambda p: p.update(practices="social_scoring"),
    lambda p: p.update(data_sources=[]),
    lambda p: p["risk_register"]["model_bias"].update(impact=0),
    lambda p: p["risk_register"]["model_bias"].update(impact=6),
    lambda p: p["risk_register"]["model_bias"].update(impact=True),
    lambda p: p["risk_register"].update(extra={"owner": "x"}),
    lambda p: p["controls"][0].update(risk="unknown"),
    lambda p: p["controls"][0].update(reduces_likelihood_by=3),
    lambda p: p["controls"][0].update(id="CTL-02"),
    lambda p: p["controls"][0].pop("evidence_files"),
])
def test_bad_profile_shapes_raise_bad_input(tmp_path, mutate):
    c = make_cases.clean()
    mutate(c.profile)
    p, e = materialize(c, tmp_path)
    with pytest.raises(assess.BadInput):
        assess.run(p, e, NOW)


def test_profile_with_nan_or_duplicate_keys_is_bad_input(tmp_path):
    for text in ('{"impact": NaN}', '{"a": 1, "a": 2}', "[]", "42"):
        c = make_cases.clean()
        c.profile_text = text
        p, e = materialize(c, tmp_path, "b" + str(abs(hash(text))))
        with pytest.raises(assess.BadInput):
            assess.run(p, e, NOW)


def test_prohibited_tier_refuses_even_with_perfect_evidence(tmp_path):
    for practice in ("subliminal_manipulation", "social_scoring", "emotion_inference_workplace"):
        c = make_cases.clean()
        c.profile["practices"] = [practice]
        assert codes(result_of(c, tmp_path, practice)) == ["T_PROHIBITED"]
