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

## 6. Reproducible labelled demo benchmark (not a live-provider comparison)

The eight `tests/benchmark_template.csv` scenarios are **fictional fixtures**, with labels specified by `collectors/demo_data.py`: weak/strong domain, reused/low-footprint username, exposed/clean email, and flagged/clean reputation. This is a reproducibility and regression check, **not an independently labelled real-world malware-detection benchmark**.

Run from the repository root on a machine with dependencies installed:

```bash
python tests/build_demo_benchmark.py
python tests/evaluate_osint.py tests/benchmark_demo_results.csv
python tests/measure_performance.py --runs 2
```

The benchmark runner makes eight actual Flask test-client requests with an isolated temporary SQLite file. It records the application's predicted class (`exposure_score > 0`) and wall-clock milliseconds for each request, writing a populated `tests/benchmark_demo_results.csv`. The evaluator then computes TP, FP, TN, FN, accuracy, precision, recall, false-positive rate and latency summaries. `measure_performance.py` requires a separately running `python app.py` server; demo timings are local HTTP timings, not live-API latency.

| Evidence | Status | Value / file |
|---|---|---|
| Fixture count | Defined (fictional) | 8 (4 positive, 4 negative) |
| Predicted labels | **Pending execution** | Generated by `build_demo_benchmark.py` |
| Measured accuracy / precision / recall / FPR | **Pending execution** | Evaluator output, not guessed |
| Local demo response times | **Pending execution** | `tests/benchmark_demo_results.csv` and `measure_performance.py` |
| Live-provider detection performance | **Not measured** | Requires independently labelled, ethically usable real samples and network/API access |
| Tool-versus-tool comparative results | **Not measured** | Must use the same known ground truth, target type, timing procedure and eligible API access |

**Interpretation:** Even a perfect score on eight fictional fixtures would only show that demo-mode scoring agrees with its own test fixtures. It must never be reported as a real-world threat-detection accuracy or as evidence that ReconLens outperforms VirusTotal, URLhaus, AbuseIPDB or SpiderFoot.

### Comparative coverage (capabilities, not measured accuracy)

| System | Comparable function | Qualification |
|---|---|---|
| ReconLens | Combines passive domain, username, email and reputation results, including correlated graphs | Composite dashboard, not a single intelligence database |
| VirusTotal | Domain, public IP, URL and file-hash reputation | One provider queried by ReconLens if configured |
| URLhaus | Known malware-distribution URL/host records | Source coverage is narrower than generic URL reputation |
| AbuseIPDB | Abuse-report reputation for public IP addresses | Reports and confidence scores are not malware confirmation |
| SpiderFoot | Broader modular OSINT collection and pivots | Feature scope differs; no comparative accuracy measured |

