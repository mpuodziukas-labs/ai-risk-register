"""Unit tests with hand-computed expectations."""
import json
from fractions import Fraction as F

import assess
import make_cases
from helpers import NOW, result_of


def test_bias_likelihood_boundaries():
    cases = [((F(9, 10), F(1, 20)), 1), ((F(89, 100), F(1, 20)), 2), ((F(4, 5), F(1, 20)), 2),
             ((F(79, 100), F(1, 20)), 3), ((F(7, 10), F(0)), 3), ((F(69, 100), F(0)), 4),
             ((F(3, 5), F(0)), 4), ((F(59, 100), F(0)), 5),
             ((F(1), F(21, 400)), 2), ((F(1), F(1, 10)), 2), ((F(1), F(11, 100)), 3), ((F(1), F(1, 5)), 3),
             ((F(1), F(21, 100)), 4), ((F(1), F(3, 10)), 4), ((F(1), F(31, 100)), 5)]
    for (di, gap), want in cases:
        assert assess.bias_likelihood(di, gap) == want, (di, gap)


def test_injection_likelihood_boundaries():
    want = {(0, 8): 1, (1, 10): 2, (1, 8): 3, (2, 8): 3, (3, 8): 4, (4, 8): 4, (5, 8): 5, (8, 8): 5}
    for (u, t), w in want.items():
        assert assess.injection_likelihood(u, t) == w, (u, t)


def test_leakage_likelihood_rules():
    assert assess.leakage_likelihood(0, 0, 0) == 1
    assert assess.leakage_likelihood(1, 0, 0) == 3
    assert assess.leakage_likelihood(2, 0, 0) == 3
    assert assess.leakage_likelihood(3, 0, 0) == 4
    assert assess.leakage_likelihood(0, 1, 0) == 5
    assert assess.leakage_likelihood(0, 0, 1) == 5


def test_luhn():
    assert assess.luhn_ok("4111111111111111")
    assert not assess.luhn_ok("4111111111111112")


def test_scan_text_counts_and_never_returns_match_text():
    text = "mail a@example.com ssn 123-45-6789 call 555-123-4567 card 4111 1111 1111 1111 key AKIAIOSFODNN7EXAMPLE"
    found = assess.scan_text(text)
    assert sorted(found) == sorted([("pii", "email"), ("pii", "us_ssn"), ("pii", "phone_us"),
                                    ("pii", "credit_card"), ("secret", "aws_access_key")])
    assert not assess.scan_text("order 4111 1111 1111 1112 shipped")  # fails Luhn
    assert not assess.scan_text("plain sentence with 12345 and 2026-03-10")


def test_secret_shapes():
    assert ("secret", "private_key_header") in assess.scan_text("-----BEGIN EXAMPLE RSA PRIVATE KEY-----")
    assert ("secret", "bearer_token") in assess.scan_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    assert ("secret", "assigned_secret") in assess.scan_text("password = hunter2hunter2hunter2")
    assert not assess.scan_text("the word password alone is fine")


def test_band_edges():
    b = assess.load_frameworks()["bands"]
    assert [assess.band(s, b) for s in (1, 4, 5, 9, 10, 16, 17, 25)] == \
        ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_classify_tiers_and_priority():
    rules = assess.load_frameworks()["tier_rules"]
    base = {"use_domain": "other", "practices": [], "interacts_with_persons": False}

    def tier(**kw):
        p = dict(base)
        p.update(kw)
        return assess.classify(p, rules)

    assert tier()["tier"] == "minimal"
    assert tier(interacts_with_persons=True) == {"tier": "limited_transparency", "basis": ["Art. 50(1)"]}
    assert tier(use_domain="employment") == {"tier": "high_risk", "basis": ["Annex III area 4"]}
    assert tier(use_domain="employment", interacts_with_persons=True)["tier"] == "high_risk"
    assert tier(use_domain="employment", practices=["social_scoring"]) == \
        {"tier": "prohibited", "basis": ["Art. 5(1)(c)"]}
    for dom, area in (("biometrics", 1), ("critical_infrastructure", 2), ("education", 3), ("essential_services", 5),
                      ("law_enforcement", 6), ("migration", 7), ("justice", 8)):
        assert tier(use_domain=dom)["basis"] == ["Annex III area %d" % area]


def test_bias_metrics_hand_computed(tmp_path):
    # groups A,B,C from FAIL_GROUPS: rates .5, .3, .525; top .525; B ratio .3/.525 = .5714; tpr .8,.4,.8
    c = make_cases.clean()
    c.set_groups(make_cases.FAIL_GROUPS)
    reasons = []
    m = assess.measure_bias({"decisions.csv": c.files["decisions.csv"].encode(), "bias_report.json": b""}, reasons)
    assert reasons == []
    assert m["min_di_ratio"] == 0.5714 and m["reference_group"] == "C"
    assert m["equal_opportunity_gap"] == 0.4 and m["passes_four_fifths"] is False
    assert m["groups"]["B"]["selection_rate"] == 0.3 and m["groups"]["B"]["true_positive_rate"] == 0.4


def test_four_fifths_boundary_exactly_point_eight():
    # A rate 20/40 = .5, B rate 16/40 = .4, ratio exactly .8 passes
    groups = {"A": (10, 10, 10, 10), "B": (8, 12, 8, 12)}
    reasons = []
    m = assess.measure_bias({"decisions.csv": make_cases.csv_text(groups).encode()}, reasons)
    assert m["min_di_ratio"] == 0.8 and m["passes_four_fifths"] is True
    groups["B"] = (8, 12, 7, 13)  # 15/40 = .375, ratio .75
    m = assess.measure_bias({"decisions.csv": make_cases.csv_text(groups).encode()}, reasons)
    assert m["passes_four_fifths"] is False


def test_residual_capped_at_two_and_floored_at_one(tmp_path):
    c = make_cases.clean()
    c.set_groups(make_cases.FAIL_GROUPS)  # inherent L5
    c.profile["controls"].append({"id": "CTL-09", "title": "Second fairness control", "risk": "model_bias",
                                  "evidence_files": ["control_bias_review.json"], "reduces_likelihood_by": 2})
    r = result_of(c, tmp_path)
    row = [x for x in r["risks"] if x["family"] == "model_bias"][0]
    assert row["inherent"]["likelihood"] == 5 and row["residual"]["likelihood"] == 3  # 1+2 capped at 2
    assert row["residual"]["score"] == 12 and row["residual"]["band"] == "high"
    clean = result_of(make_cases.clean(), tmp_path, "clean")
    assert all(x["residual"]["likelihood"] == 1 for x in clean["risks"])  # 1 - 1 floors at 1


def test_crosswalk_rows_and_obligation_flag(tmp_path):
    hi = result_of(make_cases.clean(), tmp_path, "hi")
    by = {r["family"]: r["crosswalk"] for r in hi["risks"]}
    assert "MEASURE 2.11" in by["model_bias"]["nist_ai_rmf"] and "Art. 10(2)(f)" in by["model_bias"]["eu_ai_act"]
    assert by["data_leakage"]["owasp_llm_2025"] == ["LLM02:2025"]
    assert by["prompt_injection"]["owasp_llm_2025"] == ["LLM01:2025"]
    assert all(v["eu_ai_act_applies_as_obligation"] for v in by.values())
    assert all("Art. 9(1)" in v["eu_ai_act"] and "MANAGE 1.3" in v["nist_ai_rmf"] for v in by.values())
    low = make_cases.clean()
    low.profile["use_domain"] = "other"
    lo = result_of(low, tmp_path, "lo")
    assert not any(r["crosswalk"]["eu_ai_act_applies_as_obligation"] for r in lo["risks"])
    assert "reference only, tier is minimal" in assess.render_markdown(lo)


def test_findings_do_not_echo_matched_text(tmp_path):
    c = make_cases.clean()
    c.files["training_manifest.json"] = json.dumps({"records": [
        {"id": "t1", "text": "x " + make_cases.CANARY}, {"id": "t2", "text": "AKIAIOSFODNN7EXAMPLE"}]})
    c.files["leakage_report.json"] = json.dumps({"reported": {"findings": 1, "canary_hits": 0}})
    r = result_of(c, tmp_path)
    body = assess.render_json(r) + assess.render_markdown(r)
    assert "AKIAIOSFODNN7EXAMPLE" not in body


def test_json_output_is_sorted_and_stable(tmp_path):
    r = result_of(make_cases.clean(), tmp_path)
    text = assess.render_json(r)
    assert json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n" == text
    assert assess.render_json(result_of(make_cases.clean(), tmp_path, "again")) == text
    assert assess.render_markdown(r) == assess.render_markdown(result_of(make_cases.clean(), tmp_path, "third"))


def test_assessed_at_is_the_given_time(tmp_path):
    assert result_of(make_cases.clean(), tmp_path)["assessed_at"] == make_cases.NOW
    assert NOW.tzinfo is not None
