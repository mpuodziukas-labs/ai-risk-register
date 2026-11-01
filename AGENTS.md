# Verifying this repository

Purpose: Show that a risk assessment engine scores bias, data leakage and prompt injection risk for a synthetic AI system from runnable evidence, classifies its EU AI Act tier, maps each risk to NIST AI RMF, EU AI Act, ISO/IEC 42001 and OWASP LLM Top 10 ids, and refuses on missing, stale, contradicted or tampered evidence.

Verify: `bash run.sh`

Pass condition: exit code 0 and this exact output line: `mutants: K/K killed` where K equals the number of mutants. The first block ends with `cases: N/N match`.

Scope: synthetic data, offline, standard library Python 3.9 or later, under 60 seconds.

Limitations: Engineering evidence, not legal advice. No certification is claimed. The framework mappings are the author's reading, not an auditor's opinion. The ISO/IEC 42001 column is not verified from public text.

Anything else = not verified.
