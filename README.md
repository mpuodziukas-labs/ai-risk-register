# ai-risk-register

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

## Honesty

The cases are synthetic and were written for this repo. No language model runs in the loop: the engine and the evaluator import only the Python standard library and open no network connection. The expected results sit beside the cases the checks are scored against, so the match count is a consistency check and not a claim that the checks generalize. The key-shaped string in the leak fixture is a documented example value planted as a test fixture, not a secret. Nothing here was run against production data.

## Limitations

- Engineering evidence, not legal advice. No certification is claimed. The mappings are the author's reading, not an auditor's opinion.
- All data in `cases/` is synthetic.
- The checks prove the evidence is internally consistent, fresh and unaltered. They do not prove the evidence is a true record. The sha256 in the manifest cannot stop someone who rewrites the file and the manifest.
- Injection scoring is a regex over a recorded transcript, not a live attack. Leakage scanning uses fixed patterns and misses what they do not describe.
- Three risk families only. Likelihood bands and the appetite limit are fixed choices in `assess.py`.
- Time is passed with `--now`; results are deterministic for a given input.
