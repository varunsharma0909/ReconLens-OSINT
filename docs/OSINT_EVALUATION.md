# ReconLens OSINT Correlation and Evaluation Protocol

## 1. Intelligence correlation rules

1. Normalise identifiers before matching (lowercase DNS names, canonical IP text, URL host parsing, lowercased email domain).
2. Merge nodes only on an exact canonical identifier and compatible entity type.
3. Preserve source name, source URL, collection timestamp, finding code and scan ID as evidence provenance.
4. A shared IP, CDN, DNS provider, certificate authority, registrar or username is a pivot only; it is not evidence of common ownership.
5. Separate direct observations from derived edges. Analysts must independently verify high-impact attribution claims.
6. Treat stale CT records, recycled IPs, shared hosting and reused usernames as known ambiguity classes.

The graph's confidence is a heuristic evidence-strength label, not a calibrated probability. Do not describe it as a probability or use it alone for attribution.

## 2. Exposure-score definition

| Risk category | Maximum weight |
|---|---:|
| Malware / malicious URL | 30 |
| IP abuse | 25 |
| Email exposure | 20 |
| Domain security | 15 |
| Threat intelligence | 10 |
| **Total** | **100** |

Only `confirmed` findings contribute. Severity factors: high=1.0, medium=0.65, low=0.30, info=0. Each distinct finding code contributes with diminishing coefficients (60%, 20%, 10%, then 5%) of its category budget multiplied by severity. Duplicate codes count once, and category contributions cannot exceed their maximum weight. `not_found`, `inconclusive`, and `error` contribute zero. Missing or unavailable data must never be interpreted as a clean result.

These weights are initial design assumptions. Validate them on a labelled dataset and report sensitivity analysis before claiming that the score predicts compromise.

## 3. Scenario matrix

| Scenario | Ground truth | Expected behaviour |
|---|---|---|
| S1 clean reserved/test asset | no known malicious indicator | no malicious finding; missing data remains unknown |
| S2 known phishing URL from a controlled test corpus | malicious | positive only when a source returns a confirmed match |
| S3 public IP with independently verified abuse reports | abusive | IP reputation finding with provider and observation date |
| S4 email in a provider's official test fixture | exposed | breach finding; email masked in stored result |
| S5 conflicting provider verdicts | unresolved | show both sources, mark conflict; do not silently choose one |
| S6 shared CDN / shared hosting IP | multiple unrelated tenants | graph pivot only; do not infer common ownership |
| S7 stale certificate-transparency hostname | historical only | show historical observation; do not claim current service is live |
| S8 unavailable / rate-limited source | unknown | source error/inconclusive; no score penalty or clean verdict |

Use fictional fixtures, official provider test fixtures, or assets for which you have written permission. Keep the ground-truth label and evidence source separate from ReconLens output.

## 4. Comparative evaluation

Compare ReconLens with relevant tools/services (for example VirusTotal for URL/domain/IP reputation, AbuseIPDB for IP abuse, URLhaus for malware URLs, and SpiderFoot for OSINT workflow coverage). These are not identical products; score only comparable features on the same labelled targets. Record tool/version, API plan, query time, source coverage, rate-limit responses and configuration.

Metrics:

- Accuracy = (TP + TN) / (TP + TN + FP + FN)
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- False-positive rate = FP / (FP + TN)
- Response time = per-scan wall-clock time; report median and maximum across repeated runs.

Do not count `inconclusive`, `error` or unavailable source responses as true negatives. Report them separately as coverage/availability. Evaluate false-positive rates using a sufficiently large, independently labelled benign set. A tiny sample is illustrative, not statistically conclusive.

Use `tests/benchmark_template.csv` and `python tests/evaluate_osint.py <csv>`. The evaluator reports measured results only; it does not generate sample metrics.

## 5. Privacy and responsible use

- Require authorisation for each live scan; only query assets/accounts you own or are permitted to assess.
- Keep secrets in environment variables and rotate exposed keys.
- Minimise retained personal data; mask email targets in stored summaries and logs.
- Set a short retention period appropriate to the assessment and delete records when no longer required.
- Do not include raw personal data in screenshots, public reports or benchmark CSVs.
- Keep source attribution and collection timestamps so findings can be challenged and corrected.
- Do not equate correlation with identity, ownership, intent or attribution.
