# ai-risk-register

Proves: an engine that scores bias, data leakage and prompt injection risk for a synthetic AI system from runnable evidence, classifies its EU AI Act tier, writes a register with owner, treatment, inherent and residual score, maps every risk to NIST AI RMF, EU AI Act, ISO/IEC 42001 and OWASP LLM ids, and refuses on missing, stale, contradicted or tampered evidence. Verify in 60s: `python3 evaluate.py`

## The problem

A risk register usually holds adjectives. "Bias: medium." Nobody can say which data produced that word, whether the control listed beside it was ever tested, or whether the test result still describes the system. That is evidence rot: a register row stays in the file after the facts behind it have changed or aged out. Collection by screenshot and spreadsheet edit makes it worse, because a screenshot cannot be recomputed and a cell can be changed without a trace. Control drift follows: the register says a control reduces likelihood, while the control's last recorded result is a failure or is months old.

Here every score comes from files. The engine reads a decision CSV, model outputs, a training manifest and a recorded injection transcript, recomputes the metrics itself, and compares them with what the evidence bundle reports. A control claimed with no evidence, an old recording, a changed file, or a report that disagrees with its raw data makes the run exit 1 with the reasons.

## What this proves, and what it does not

Proves, each by a named case in `cases/` that `evaluate.py` scores:

- A register row is computed from raw evidence, not typed. A bundle whose reported metric disagrees with the recomputed one is refused (`contradicted_bias_report`, `contradicted_injection_report`, `contradicted_control_result`).
- Missing, stale, future-dated and altered evidence is refused with a reason code (`missing_evidence_file`, `stale_evidence`, `future_recorded_at`, `hash_mismatch`). The age boundary is exact: `exactly_max_age` passes, `one_second_past_max_age` is refused.
- A row with no owner or no treatment is refused, and risk acceptance above a residual score of 9 is refused (`no_owner`, `no_treatment`, `accept_above_appetite`).
- The EU AI Act tier is derived by rule, and a prohibited practice stops the run (`prohibited_practice`).
- The checks can fail: `mutants.py` changes one spot in the engine at a time, 24 of 24 changes are caught by the tests.

Does not prove (Limitations):

- That the evidence is a true record. The sha256 manifest detects an edited file. It cannot stop someone who rewrites the file and the manifest together. The engine checks internal consistency, freshness and integrity, not provenance.
- That the checks generalize. The cases are synthetic and the expected results sit beside them, so `cases: N/N match` is a consistency check on the engine, not a measure of detection rate on real systems.
- That injection resistance is real. Injection scoring is a pattern match over a recorded transcript, not a live attack. Leakage scanning uses fixed patterns and misses what they do not describe.
- Anything about a production system. Nothing here was run against production data.
- Coverage. Three risk families only. Likelihood bands and the appetite limit are fixed choices in `assess.py`, not an organization's risk methodology.
- Compliance, certification or legal classification. The mappings are engineering evidence. See the Mapping section.

## The one command

Standard library Python 3.9 or later. No network. No install.

```
python3 evaluate.py
```

It runs every folder in `cases/` through the engine and compares the result with that folder's `expected.json`. Exit 0 means every case matched. Real output, last 3 lines (the table above them has one row per case):

```
| stale_evidence | REFUSE E_STALE | REFUSE E_STALE | yes |

cases: 32/32 match
```

Each PASS row reads `PASS <tier> bias=LxI>LxI leak=... inj=...`: inherent likelihood x impact, then residual. Each REFUSE row lists the reason codes. The whole proof is `bash run.sh`: table, then `91 passed` from pytest, then `mutants: 24/24 killed`. Exit 0 only if all three pass.

## What it checks

| risk | evidence | measure |
|---|---|---|
| R1 model_bias | decisions.csv (group, qualified, selected) | selection-rate impact ratio against the top group, four-fifths rule (ratio of 0.8 passes), equal-opportunity gap (max minus min true positive rate), exact fractions |
| R2 data_leakage | model_outputs.jsonl, training_manifest.json, canaries.json | PII (email, SSN, phone, Luhn-valid card), secrets (key shapes, tokens, assigned passwords), planted canary strings found in outputs. Matched text is never printed |
| R3 prompt_injection | probes.json, transcript.jsonl | count of recorded responses matching a probe's unsafe pattern |

Each risk has likelihood and impact from 1 to 5. Score is likelihood x impact. Bands: low 1 to 4, medium 5 to 9, high 10 to 16, critical 17 to 25. Residual likelihood is inherent likelihood minus the control reductions (capped at 2 in total, never below 1). Treatment is mitigate, accept, transfer or avoid. Accept is refused above a residual score of 9.

The engine refuses (exit 1) on: a control with no evidence file, evidence older than its `max_age_days`, a recorded time after the assessment time, a sha256 mismatch, a report that contradicts the recomputed value, a control whose evidence records a failed result, a register row with no owner or no treatment, a canary not planted in the training manifest, an unsafe file name or symbolic link, a prohibited practice. Malformed JSON, duplicate keys and NaN never pass.

EU AI Act tier: first matching rule wins in `frameworks.json`: prohibited (Art. 5(1) practices), high-risk (Annex III areas 1 to 8 by use domain), limited transparency (Art. 50(1)), minimal.

## Mapping

A mapping, not an attestation or audit opinion. GROUNDED means the engine computes or enforces the thing the id describes, a named case fails if it stops, and the id with a quoted line is in `SOURCES.md`. INFERRED means a reasonable reading that no case enforces. The EU quotes come from a secondary mirror because EUR-Lex returned no content, so check them against the Official Journal before relying on them. EU AI Act cells in the register are marked "reference only" when the tier is not high-risk.

| register behavior | NIST AI RMF 1.0 | EU AI Act | ISO/IEC 42001 | NIST SP 800-53 rev5 | label |
|---|---|---|---|---|---|
| Bias and fairness measured, result written to the register | MEASURE 2.11 | none | GAP | none | GROUNDED (`bias_four_fifths_fail`, `bias_equal_opportunity_gap`) |
| Metric selected for the most significant risk | MEASURE 1.1 | none | GAP | none | INFERRED |
| Bias examination of data | none | Art. 10(2)(f), 10(2)(g) | GAP | none | INFERRED: the engine measures decision outcomes from a CSV, not the training-data examination the article describes |
| Privacy risk examined (PII, secrets, canaries) | MEASURE 2.10 | none | GAP | none | GROUNDED (`leak_pii_in_outputs`, `leak_secret_in_manifest`, `leak_canary_in_outputs`) |
| Security and resilience evaluated (injection, leakage) | MEASURE 2.7 | Art. 15(1) | GAP | none | INFERRED: a pattern match over a recorded transcript is a narrow evaluation |
| Risks prioritized by likelihood x impact | MANAGE 1.2 | none | GAP | none | GROUNDED (score and band computed in `assess.py`) |
| Treatment required and recorded per risk | MANAGE 1.3 | none | GAP | none | GROUNDED (`no_treatment`) |
| Risk tolerance written down and enforced | MAP 1.5 | none | GAP | none | GROUNDED (`accept_above_appetite`, `accept_within_appetite`) |
| Named owner required per risk | GOVERN 2.1 | none | GAP | none | GROUNDED (`no_owner`) |
| Freshness window on evidence | MANAGE 4.1 | none | GAP | none | INFERRED: a staleness limit is not a post-deployment monitoring plan |
| Risk management system exists | none | Art. 9(1) | GAP | none | INFERRED: the register is one component, not the system the article requires |
| Tier by rule: prohibited, high-risk, limited, minimal | none | Art. 5(1), Annex III, Art. 50(1) | GAP | none | GROUNDED (`prohibited_practice`, `limited_tier_chatbot`, `minimal_tier`); the Art. 5(1) subjects come from a paraphrase, see `SOURCES.md` |
| Injection and sensitive-information risks labeled | none | none | GAP | none | GROUNDED for the OWASP LLM Top 10 2025 ids LLM01:2025 and LLM02:2025 emitted in the register |
| Risk assessment and risk response | none | none | clauses 6.1.2 and 6.1.3 (AI risk assessment, AI risk treatment) | RA-3, RA-7 | INFERRED, documentation only: the engine does not emit these ids and no case enforces them |
| Evidence integrity by sha256 | none | none | none | SI-7 | INFERRED, documentation only: the check covers evidence files, not software or firmware |

The ISO/IEC 42001 column in the register output reads "clause not verified from public text" because the standard is paywalled and was not fetched. GAP in the table means no clause id is emitted by the engine, on purpose.

## How an auditor reproduces this in 2 minutes

1. Run `python3 evaluate.py`. Confirm the last line is `cases: 32/32 match` and the exit code is 0.
2. Run the clean case: `python3 assess.py cases/clean_pass_high_risk/profile.json cases/clean_pass_high_risk/evidence --now 2026-03-10T00:00:00Z --out out`. It prints `PASS: wrote register to out` and exits 0. Open `out/register.md`: one row per risk with owner, treatment, inherent and residual score.
3. Run a planted failure: `python3 assess.py cases/hash_mismatch/profile.json cases/hash_mismatch/evidence --now 2026-03-10T00:00:00Z --out out`. Real output, exit 1:

```
REFUSED: 1 reason(s)
  E_HASH: transcript.jsonl does not match its recorded sha256
```

4. Tamper yourself: copy `cases/clean_pass_high_risk` to a scratch folder, change one character in `evidence/decisions.csv`, rerun step 2 against the copy. Real output for a one-character change, exit 1:

```
REFUSED: 1 reason(s)
  E_HASH: decisions.csv does not match its recorded sha256
```

5. Optional: `python3 mutants.py` ends with `mutants: 24/24 killed`, meaning each of 24 planted engine defects makes at least one test fail.

## Design decisions

- Recompute, then compare. The engine does not trust a reported metric. It recomputes from raw rows and refuses on disagreement, because a register that accepts reported numbers is a spreadsheet.
- Refuse, do not warn. Every refusal is exit 1 with a reason code, and malformed input is exit 2. A warning gets scrolled past; an exit code stops a pipeline.
- Exact arithmetic. Impact ratios use fractions, so the four-fifths boundary is not decided by floating-point rounding.
- Time is an argument. With `--now` passed in, a result is the same on every machine on every day, and the age boundary is pinned to the second. The clock is read only when `--now` is omitted, so every case in `cases/` pins it.
- Matched text is never printed. A leak finding reports counts (`pii 0, secret 0, canary hits 0`), so the register does not become a second copy of the secret.
- Expected results beside the cases. This keeps the evaluator simple and makes the consistency check cheap; the cost, stated above, is that it is not a generalization claim.
- Mutants as the test of the tests. A passing suite proves little until a deliberately broken engine fails it.
- No ISO clause ids emitted. The standard's text was not fetched, so the engine prints a "not verified" marker instead of an id it could not check.

## Honesty

The cases are synthetic and were written for this repo. No language model runs in the loop: the engine and the evaluator import only the Python standard library and open no network connection. The key-shaped string in the leak fixture is a documented example value planted as a test fixture, not a secret.

Sources for every framework id, with the page fetched and the line quoted, are in `SOURCES.md`.
