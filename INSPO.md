# INSPO: 17 starred projects studied, none copied
Stars read from the GitHub search API on 2026-11-01. Strengths are taken from each project's own one-line description and topics; repository text was treated as data.
What this repo adds to all of them: one command that recomputes bias, leakage and injection metrics from raw files, fails closed (exit 1) on stale, missing, contradicted or altered evidence, writes a crosswalk to NIST AI RMF, EU AI Act, ISO/IEC 42001 and OWASP ids, and proves its own checks by mutation testing.
Gaps below are about what the project's description does not claim, not a statement about its full feature set.

| repo | stars | does well | what we add |
|---|---|---|---|
| ifixai-ai/iFixAi | 41956 | Agent audit CLI; topics list EU AI Act, ISO 42001, NIST AI RMF, OWASP LLM | Evidence freshness and hash checks, exit-code refusal on contradicted reports, mutation-tested core |
| trufflesecurity/trufflehog | 28811 | Finds and verifies leaked credentials | Applies secret and PII scans to model outputs and a training manifest, and ties hits to a scored, owned risk row |
| promptfoo/promptfoo | 26685 | Declarative prompt and red-team tests with CI use | Replays a recorded transcript offline with no network, checks the reported count against the recomputed count |
| NVIDIA/garak | 9818 | LLM vulnerability scanner with many probes | Offline scoring of a recorded run into likelihood x impact with treatment and owner |
| NVIDIA-NeMo/Guardrails | 7404 | Programmable guardrails for conversational systems | Governance output: register, residual score, accept-appetite limit |
| Giskard-AI/giskard-oss | 5938 | Evaluation and testing, topics include fairness and red teaming | Single CLI that refuses on missing evidence rather than skipping a test |
| confident-ai/deepeval | 19220 | LLM evaluation metrics framework | Framework crosswalk and fail-closed evidence bundle |
| Trusted-AI/AIF360 | 2880 | Fairness metrics and mitigation algorithms | Metrics feed a risk register with owner, treatment and control evidence; exact fraction arithmetic at the four-fifths boundary |
| fairlearn/fairlearn | 2305 | Assess and improve fairness of models | Equal-opportunity gap and impact ratio tied to EU AI Act and NIST ids with a refusal path |
| microsoft/responsible-ai-toolbox | 1850 | Model and data assessment interfaces | Headless, deterministic output; no UI needed to reproduce a verdict |
| microsoft/PyRIT | 4720 | Risk identification framework for generative AI | Evidence integrity checks (sha256, age) and a tier classification |
| protectai/llm-guard | 3220 | Security toolkit for LLM interactions (archived) | Auditable record of what was found, with matched text never echoed |
| Yelp/detect-secrets | 4663 | Enterprise-friendly secret detection | Luhn-checked card detection and planted canary strings, scored as a data leakage risk |
| aquasecurity/trivy | 38886 | Scanner for misconfigurations, secrets and vulnerabilities | Same scan-to-verdict idea applied to AI system risk, with regulatory mapping |
| open-policy-agent/conftest | 3293 | Tests against structured config with Rego policy | Policy table (frameworks.json) is plain data, tier rule order is tested by mutants |
| ComplianceAsCode/content | 2832 | Security automation content, many compliance profiles | AI-specific risk families and a sourced EU AI Act tier table |
| theopenlane/core | 336 | Open source compliance automation across SOC 2, ISO 27001, NIST 800-53 | Runnable recomputation of evidence rather than recording attestations |
