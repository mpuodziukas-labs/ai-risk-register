# Sources

Every framework id used in `frameworks.json` is listed here with the page fetched and the line quoted. Fetched text was treated as data. The source pages use en dashes in three NIST lines; they are shown here as hyphens because this repository allows no en dashes. This is engineering evidence, not legal advice. No certification is claimed.

## NIST AI RMF 1.0 (NIST AI 100-1), via the NIST AI Resource Center Playbook

| id | URL | quoted line |
|---|---|---|
| MEASURE 1.1 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "Approaches and metrics for measurement of AI risks enumerated during the Map function are selected for implementation starting with the most significant AI risks." |
| MEASURE 2.7 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "AI system security and resilience - as identified in the MAP function - are evaluated and documented." |
| MEASURE 2.10 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "Privacy risk of the AI system - as identified in the MAP function - is examined and documented." |
| MEASURE 2.11 | https://airc.nist.gov/airmf-resources/playbook/measure/ | "Fairness and bias - as identified in the MAP function - are evaluated and results are documented." |
| MANAGE 1.2 | https://airc.nist.gov/airmf-resources/playbook/manage/ | "Treatment of documented AI risks is prioritized based on impact, likelihood, or available resources or methods." |
| MANAGE 1.3 | https://airc.nist.gov/airmf-resources/playbook/manage/ | "Responses to the AI risks deemed high priority as identified by the Map function, are developed, planned, and documented." |
| MANAGE 4.1 | https://airc.nist.gov/airmf-resources/playbook/manage/ | "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management." |
| MAP 1.5 | https://airc.nist.gov/airmf-resources/playbook/map/ | "Organizational risk tolerances are determined and documented." |
| GOVERN 2.1 | https://airc.nist.gov/airmf-resources/playbook/govern/ | "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization." |

## OWASP Top 10 for LLM Applications (2025)

| id | URL | quoted line |
|---|---|---|
| LLM01:2025 | https://genai.owasp.org/llm-top-10/ | Title "Prompt Injection"; text begins "A Prompt Injection Vulnerability occurs when user prompts alter the..." |
| LLM02:2025 | https://genai.owasp.org/llm-top-10/ | Title "Sensitive Information Disclosure"; text begins "Sensitive information can affect both the LLM and its application..." |

## EU AI Act, Regulation (EU) 2024/1689

Source caveat: EUR-Lex returned no page content to the fetch tool in four URL variants. The lines below come from the secondary mirror https://artificialintelligenceact.eu and were not checked against EUR-Lex. Check each against the Official Journal text before relying on it.

| id | URL | quoted line |
|---|---|---|
| Art. 9(1) | https://artificialintelligenceact.eu/article/9/ | "A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems." |
| Art. 10(2)(f) | https://artificialintelligenceact.eu/article/10/ | "examination in view of possible biases that are likely to affect the health and safety of persons, have a negative impact on fundamental rights...or lead to discrimination prohibited under Union law" |
| Art. 10(2)(g) | https://artificialintelligenceact.eu/article/10/ | "appropriate measures to detect, prevent and mitigate possible biases identified according to point (f)" |
| Art. 15(1) | https://artificialintelligenceact.eu/article/15/ | "High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, [one word elided by this repo's word list], and cybersecurity, and that they perform consistently in those respects throughout their lifecycle." |
| Art. 50(1) | https://artificialintelligenceact.eu/article/50/ | "Providers shall ensure that AI systems intended to interact directly with natural persons are designed and developed in such a way that the natural persons concerned are informed that they are interacting with an AI system, unless this is obvious from the point of view of a natural person who is reasonably well-informed, observant and circumspect, taking into account the circumstances and the context of use." |
| Art. 5(1)(a), (c), (f) | https://artificialintelligenceact.eu/article/5/ | The fetch tool returned a paraphrase, not verbatim text: (a) subliminal or manipulative techniques, (c) social scoring leading to detrimental treatment, (f) inferring emotions in workplaces and educational settings. The ids and subjects are used as labels only. Verbatim wording not verified. |
| Annex III opening | https://artificialintelligenceact.eu/annex/3/ | "High-risk AI systems pursuant to Article 6(2) are the AI systems listed in any of the following areas:" |
| Annex III area 1 | same | "Biometrics, in so far as their use is permitted under relevant Union or national law:" |
| Annex III area 2 | same | "Critical infrastructure: AI systems intended to be used as safety components in the management and operation of critical digital infrastructure, road traffic, or in the supply of water, gas, heating or electricity." |
| Annex III area 3 | same | "Education and vocational training:" |
| Annex III area 4 | same | "Employment, workers' management and access to self-employment:" |
| Annex III area 5 | same | "Access to and enjoyment of essential private services and essential public services and benefits:" |
| Annex III area 6 | same | "Law enforcement, in so far as their use is permitted under relevant Union or national law:" |
| Annex III area 7 | same | "Migration, asylum and border control management, in so far as their use is permitted under relevant Union or national law:" |
| Annex III area 8 | same | "Administration of justice and democratic processes:" |

## ISO/IEC 42001

The iso.org page returned HTTP 403 and the Annex A text is paywalled. No clause or control id is cited. The crosswalk column prints "ISO/IEC 42001 (clause not verified from public text)".
