# ai-risk-register

[![CI](https://github.com/mpuodziukas-labs/ai-risk-register/actions/workflows/ci.yml/badge.svg)](https://github.com/mpuodziukas-labs/ai-risk-register/actions/workflows/ci.yml)

Proves: an engine that scores bias, data leakage and prompt injection risk for a synthetic AI system from runnable evidence, classifies its EU AI Act tier, writes a register with owner, treatment, inherent and residual score, maps every risk to NIST AI RMF, EU AI Act, ISO/IEC 42001 and OWASP LLM ids, and refuses on missing, stale, contradicted or tampered evidence. Verify in 60s: `python3 evaluate.py`

## The problem

A risk register usually holds adjectives. "Bias: medium." Nobody can say which data produced that word or whether the control listed beside it was ever tested.

Here every score comes from files. The engine reads a decision CSV, model outputs, a training manifest and a recorded injection transcript, recomputes the metrics itself, and compares them with what the evidence bundle reports. A control claimed with no evidence, an old recording, a changed file, or a report that disagrees with its raw data makes the run exit 1 with the reasons.

## Run it

Standard library Python 3.9 or later. No network. No install.

```
python3 evaluate.py
python3 assess.py cases/clean_pass_high_risk/profile.json cases/clean_pass_high_risk/evidence --now 2026-03-10T00:00:00Z --out out
```

`evaluate.py` runs every folder in `cases/` and compares the result with `expected.json`. Its last line is `cases: N/N match`. `assess.py` exit codes: 0 register written, 1 refused with reasons on stderr, 2 bad input. The whole proof (table, tests, mutants) is `bash run.sh`; its last line is `mutants: K/K killed`.

Output as `evaluate.py` prints it:

```
cases: 32/32 match
```

The full table has one row per case. Each PASS row reads `PASS <tier> bias=LxI>LxI leak=... inj=...`: inherent likelihood x impact, then residual. Each REFUSE row lists the reason codes.

## What it checks

| risk | evidence | measure |
|---|---|---|
| R1 model_bias | decisions.csv (group, qualified, selected) | selection-rate impact ratio against the top group, four-fifths rule (ratio of 0.8 passes), equal-opportunity gap (max minus min true positive rate), exact fractions |
| R2 data_leakage | model_outputs.jsonl, training_manifest.json, canaries.json | PII (email, SSN, phone, Luhn-valid card), secrets (key shapes, tokens, assigned passwords), planted canary strings found in outputs. Matched text is never printed |
| R3 prompt_injection | probes.json, transcript.jsonl | count of recorded responses matching a probe's unsafe pattern |

Each risk has likelihood and impact from 1 to 5. Score is likelihood x impact. Bands: low 1 to 4, medium 5 to 9, high 10 to 16, critical 17 to 25. Residual likelihood is inherent likelihood minus the control reductions (capped at 2 in total, never below 1). Treatment is mitigate, accept, transfer or avoid. Accept is refused above a residual score of 9.

The engine refuses (exit 1) on: a control with no evidence file, evidence older than its `max_age_days` (exact boundary is fresh), a recorded time after the assessment time, a sha256 mismatch, a report that contradicts the recomputed value, a control whose evidence records a failed result, a register row with no owner or no treatment, a canary not planted in the training manifest, an unsafe file name or symbolic link, a prohibited practice. Malformed JSON, duplicate keys and NaN never pass.

EU AI Act tier: first matching rule wins in `frameworks.json`: prohibited (Art. 5(1) practices), high-risk (Annex III areas 1 to 8 by use domain), limited transparency (Art. 50(1)), minimal.

## Mapping

Crosswalk columns per risk: NIST AI RMF 1.0 subcategories, EU AI Act articles, ISO/IEC 42001, OWASP LLM Top 10 2025. Ids and the line quoted for each are in `SOURCES.md`. EU AI Act rows are marked "reference only" when the tier is not high-risk. The EU quotes come from a secondary mirror because EUR-Lex returned no content. The ISO/IEC 42001 column reads "clause not verified from public text" because the standard is paywalled.

## Crosswalk

`crosswalk.tsv` maps register ids (R1 to R3, CTL-01 to CTL-03, named evidence files, profile fields) to ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria, Federal Reserve SR 11-7 and EU AI Act Article 9 and Annex IV. Columns: register id, framework, external id, paraphrased title, source URL, status. GROUNDED means the external id and its subject were read in a fetched source on 2026-11-05. INFERRED means the id was not confirmed from a fetched source. The status describes the external id, not how strong the fit is; titles say "partial" where the register covers only part of an item.

| framework | GROUNDED | INFERRED |
|---|---|---|
| SR 11-7 (attachment sections V.1, V.2, V.3, VI) | 14 | 0 |
| EU AI Act (Art. 9 and Annex IV) | 0 | 28 |
| SOC 2 TSC | 0 | 11 |
| ISO/IEC 27001:2022 Annex A | 0 | 9 |

SOC 2: the AICPA download page was fetched but the criteria text sits in a PDF behind a free account, so no CC id was confirmed. ISO/IEC 27001: control ids only, standard is paywalled. EU AI Act: EUR-Lex blocks automated fetches, so ids and subjects were read from a secondary mirror of Regulation (EU) 2024/1689 (see `SOURCES.md`) and stay INFERRED until checked against the EUR-Lex text. SR 11-7: the attachment PDF was fetched from federalreserve.gov.

Annex IV items the register does not cover (gaps): 1(b) to 1(h) (interaction with other systems, software versions, distribution forms, hardware, interface description, instructions for use), 2(a) development methods, 2(b) design specifications, 2(c) architecture and compute, 2(f) pre-determined changes, 6 lifecycle changes, 7 harmonised standards, 8 declaration of conformity, 9 post-market monitoring plan. Partial: 1(a), 2(d), 2(e), 2(h), 3 and 4. Article 9 paragraph 2(c) (post-market data) and the testing paragraphs 9(6) to 9(8) are not mapped.

This is a mapping, not a compliance or certification claim.

## Verify

```
bash scripts/verify.sh
bash scripts/verify.sh --selftest
```

The first runs `evaluate.py` and requires `cases: 32/32 match`, then runs `crosswalk_check.py`, which requires every register id to exist, every row to carry a source URL and a valid status, and no row to use the words compliant, certified or attested. Exit 0 or 1. The second plants bad rows in a temporary copy and prints `selftest 3/3` when the clean copy passes and both planted rows fail. `shellcheck` is run on the script when installed.

## Honesty

The cases are synthetic and were written for this repo. No language model runs in the loop: the engine and the evaluator import only the Python standard library and open no network connection. The expected results sit beside the cases the checks are scored against, so the match count is a consistency check and not a claim that the checks generalize. The key-shaped string in the leak fixture is a documented example value planted as a test fixture, not a secret. Nothing here was run against production data.

## Limitations

- Engineering evidence, not legal advice. No certification is claimed. The mappings are the author's reading, not an auditor's opinion.
- All data in `cases/` is synthetic.
- The checks prove the evidence is internally consistent, fresh and unaltered. They do not prove the evidence is a true record. The sha256 in the manifest cannot stop someone who rewrites the file and the manifest.
- Injection scoring is a regex over a recorded transcript, not a live attack. Leakage scanning uses fixed patterns and misses what they do not describe.
- Three risk families only. Likelihood bands and the appetite limit are fixed choices in `assess.py`.
- Time is passed with `--now`; results are deterministic for a given input.
