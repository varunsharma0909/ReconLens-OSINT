# Testing and Evaluation Plan

Two layers of testing:

1. **Automated tests** (`python -m pytest -v`): offline tests use mocked
   network responses. The pass count **must be copied from an actual run**; old numbers of 82 and 132 were inconsistent and unverified.
2. **Manual test cases** (table below), executed in the browser or with `curl`.
   Pending cases are explicitly labelled **Not executed / Pending**, not falsely passed.
   Fill them only after observing the actual result. Mocked unit tests do not count as manual executions.

Only test with fictional demo targets, `example.com` (reserved for documentation),
XposedOrNot's official test addresses (`*@XposedOrNot-integration-tests.com`), or assets you own or are
authorised to assess.

## 1. Test environment (verification pending)

| Item | Value |
|---|---|
| Laptop / CPU / RAM | Not recorded |
| OS | Not recorded for a manual test session; deployment log shows Render Linux |
| Python version (`python --version`) | Render deployment log: 3.14.10; local test runtime not recorded |
| Browser | Not recorded |
| Network (home Wi-Fi / college / mobile hotspot) | Not recorded |
| Date of testing | 23 Nov 2026 (automated only; manual session pending) |
| Automated test result (`pytest` summary line) | 153 passed in 1.36s, Python 3.12 on GitHub Actions (23 Nov 2026), [run evidence](https://github.com/varunsharma0909/ReconLens-OSINT/actions/runs/45222088362); manual tests remain pending |

## 2. Manual test cases

| ID | Feature | Input / steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| **Functional - domain** |||||||
| F-01 | Domain demo | Demo mode, `demo-corp.test` | Score 46 Moderate; RDAP, DNS, CT sections; DMARC missing (medium), sensitive subdomains (medium), expiry soon (medium) | Not executed | Pending |
| F-02 | Domain demo, strong | Demo mode, `secure-shop.test` | Score 0 Low; SPF/DMARC/CAA OK; DNSSEC on | Not executed | Pending |
| F-03 | Domain live | Live, tick authorisation, `example.com` | Registrar and dates from RDAP; DNS records listed; CT section shows hostnames or a labelled crt.sh error | Not executed | Pending |
| F-04 | Domain live, own domain | Live, a domain you own | Findings match what you know about the domain's DNS/registration | Not executed | Pending |
| F-05 | Non-existent domain | Live, `this-domain-should-not-exist-12345.com` | RDAP "not found", DNS NXDOMAIN (not_found), no crash | Not executed | Pending |
| F-06 | URL input accepted | Live, `https://www.example.com/path?x=1` | Analysed as `www.example.com` | Not executed | Pending |
| **Functional - username** |||||||
| F-07 | Username demo | Demo, `demo_analyst` | 8 found, 2 inconclusive, 9 not found; reuse warning (medium) | Not executed | Pending |
| F-08 | Username demo, low footprint | Demo, `ghost_user_404` | 0 found, score 0 | Not executed | Pending |
| F-09 | Username live, own handle | Live, your own username | Known accounts appear under "Profile found"; blocked platforms under "Inconclusive", never "found" | Not executed | Pending |
| F-10 | Username live, random | Live, a random 20-character handle | Mostly "Not found"; none falsely "found" (record any false positives) | Not executed | Pending |
| **Functional - email** |||||||
| F-11 | Email demo | Demo, `alice@demo-corp.test` | 3 breaches (high, medium, low); stored as `a***@demo-corp.test` | Not executed | Pending |
| F-12 | Email live, XposedOrNot test key | Live, `account-exists@XposedOrNot-integration-tests.com` | Source shows "(official test key)"; at least one breach listed | Not executed | Pending |
| F-13 | Email live, test "no data" | Live, `opt-out@XposedOrNot-integration-tests.com` (XposedOrNot-defined test account; see the XposedOrNot API docs for the current list) | "Not found in any known breach" (not_found). If XposedOrNot's test data differs, record what it returns | Not executed | Pending |
| F-14 | Email live, real address without key | Live, your own address | Public XposedOrNot is keyless; observe and record returned status or provider error | Not executed | Pending |
| **Functional - reputation** |||||||
| F-15 | Reputation demo | Demo, `phish-login.demo-corp.test` | Malicious 7/92 (high), suspicious (medium), verdict chart | Not executed | Pending |
| F-16 | Reputation live without key | Live, `example.com`, remove all applicable reputation keys | HTTP 400 `reputation_keys_missing` | Not executed | Pending |
| F-17 | Reputation live with key (optional) | Live, `example.com` with a configured compatible reputation key | Provider findings or labelled no-match/error; reputation is not proof of safety | Not executed | Pending |
| **Summary, recommendations, reports** |||||||
| F-18 | Score breakdown | Open "How the score was calculated" | Sum of listed points equals the score (cap 100) | Not executed | Pending |
| F-19 | Recommendations | After F-01 | Each recommendation shows "Because:" linked to a confirmed finding; baseline items listed | Not executed | Pending |
| F-20 | PDF export | Download PDF for F-01 | Opens; contains summary, score method, sources, findings with timestamps, recommendations, limitations, appendix tables | Not executed | Pending |
| F-21 | CSV export | Download CSV for F-01, open in Excel | Sections SCAN SUMMARY, SOURCES, FINDINGS, RECOMMENDATIONS, LIMITATIONS | Not executed | Pending |
| F-22 | History | Scan history page | All scans newest first; filter by module works | Not executed | Pending |
| F-23 | Delete scan | Delete a scan in history | Disappears; `/scan/<id>` returns 404 | Not executed | Pending |
| **Invalid input** |||||||
| V-01 | Empty input | Run with empty field | "Enter a value to analyse." | Not executed | Pending |
| V-02 | Bad domain | `exa mple..com` | 400 `invalid_input` | Not executed | Pending |
| V-03 | IP as domain | `8.8.8.8` on domain page | 400 "enter a domain name, not an IP" | Not executed | Pending |
| V-04 | Script injection | `<script>alert(1)</script>` | 400 `invalid_input`; nothing executes | Not executed | Pending |
| V-05 | Private IP | `192.168.1.1` on reputation page | 400 private address rejected | Not executed | Pending |
| V-06 | Non-http URL | `ftp://example.com/file` | 400 | Not executed | Pending |
| V-07 | Demo mode, real target | Demo, `example.com` | 400 `not_a_demo_target` with demo list | Not executed | Pending |
| V-08 | Non-JSON body | `curl -X POST .../api/scan/domain -d "target=x"` | 415 | Not executed | Pending |
| V-09 | Smart search API | `POST /api/scan/auto` with `alice@demo-corp.test`, demo | 201, `scan.scan_type` = `email` (automated: `test_auto_scan_runs_the_detected_module`) | Not executed | Pending |
| **Safeguards and application security** |||||||
| S-01 | Authorisation required (UI) | Live mode, untick box, Run | Error message; no request sent | Not executed | Pending |
| S-02 | Authorisation required (API) | curl live request without `"authorized": true` | 403 `authorization_required` | Not executed | Pending |
| S-03 | Live mode disabled | `ALLOW_LIVE_MODE=false`, restart, try live | Switch disabled; API 403 `live_disabled` | Not executed | Pending |
| S-04 | Authorised email domains | `AUTHORIZED_EMAIL_DOMAINS=mycollege.edu` + XposedOrNot key; check another domain | 403 `domain_not_authorised` | Not executed | Pending |
| S-05 | Security headers | Browser dev tools → Network → response headers | CSP, X-Frame-Options DENY, nosniff, Referrer-Policy present | Not executed | Pending |
| S-06 | Secrets not exposed | Search source, logs, PDF/CSV for your API key | Key not found anywhere except `.env` | Not executed | Pending |
| S-07 | Email masking | Check history, `logs/app.log`, CSV after F-11 | Only `a***@...` appears | Not executed | Pending |
| S-08 | CSV formula injection | Covered by automated test `test_csv_formula_injection_is_neutralised` | Cells starting with `=,+,-,@` prefixed with `'` | Not executed | Pending |
| S-09 | Unknown API path | GET `/api/xyz` | 404 JSON error, no stack trace | Not executed | Pending |
| S-10 | Localhost binding (local only) | With `python app.py` on a laptop, try another device | Not reachable in local mode; Render uses Gunicorn and is deliberately public | Not executed | Pending |
| S-11 | Email masked in console log | Smart-search an email address, look at the terminal running `app.py` | Request line shows `a***%40domain`, never the full address | Not executed | Pending |
| S-12 | TLS SSRF / DNS rebinding | Automated: `test_tls_refuses_every_non_public_address`, `test_tls_connects_to_the_checked_address` | Private, shared, multicast and IPv4-mapped addresses skipped; connection goes to the vetted IP | Not executed | Pending |
| **Errors, timeouts, rate limits** |||||||
| E-01 | No internet, live | Disconnect Wi-Fi, live domain scan | Scan returns with sources marked error and readable reasons; app does not crash | Not executed | Pending |
| E-02 | No internet, demo | Disconnect Wi-Fi, demo scan | Works normally | Not executed | Pending |
| E-03 | crt.sh slow/unavailable | Live scan of a large domain you are authorised to assess | crt.sh marked error/inconclusive after ≤ 25 s; other sources still shown; scan status `partial` | Not executed | Pending |
| E-04 | Rate limit | Run 11 scans within one minute | 11th returns "Too many requests" (429) | Not executed | Pending |
| E-05 | VirusTotal quota guard | With VT key, 5 reputation scans within a minute | 5th shows local quota message; VT never returns 429 | Not executed | Pending |
| **Database** |||||||
| D-01 | Persistence | Run a scan, restart app | Scan still in history | Not executed | Pending |
| D-02 | Cascade delete | Delete a scan, inspect `findings` table (DB Browser for SQLite) | No orphan findings | Not executed | Pending |
| D-03 | Retention | Set `RETENTION_DAYS=0`, restart | Old scans purged on start-up | Not executed | Pending |
| **Performance (measured, not estimated)** |||||||
| P-01 | Demo response time | `python tests/measure_performance.py` | Record min/median/max per module | Not executed | Pending |
| P-02 | Live domain response time | `python tests/measure_performance.py --live example.com --runs 3` | Record total and per-source times | Not executed | Pending |
| P-03 | Username live response time | Time 3 live checks of your own handle (browser shows duration) | Record | Not executed | Pending |
| **Responsive UI** |||||||
| U-01 | Mobile layout | Browser dev tools, 390 px wide | No horizontal scrolling; navigation scrolls; results readable | Not executed | Pending |
| U-02 | Dark mode | Switch OS to dark mode | Readable colours, charts visible | Not executed | Pending |

### Executing and recording evidence

Run `python -m pytest -q` in the repository root and preserve the actual final summary line. Start the local server with `python app.py`, then from a second terminal run `python tests/measure_performance.py --runs 2`; this measures demo HTTP response times. For a permitted public live target, run `python tests/measure_performance.py --runs 1 --live example.com`. Note that results depend on the machine, network, available keys, and rate limits. Do not treat local demo timings as live API latency.

To produce a reproducible **fictional-fixture** evaluation CSV, run `python tests/build_demo_benchmark.py`, followed by `python tests/evaluate_osint.py tests/benchmark_demo_results.csv`. These are not real-world detection accuracy figures.

## 3. Evaluation criteria

Compute these from **your own** test results. Do not estimate.

| Criterion | How to measure | Formula / target |
|---|---|---|
| Automated test pass rate | `pytest` summary | passed ÷ total |
| Manual test pass rate | Table above | passed ÷ executed |
| Lookup handling rate | Over all live scans run during testing, count sources that ended `ok` or with a **labelled** error/inconclusive result (never a crash or blank screen) | handled ÷ attempted (goal: 100 %) |
| Source availability | Per source: runs with status `ok` ÷ total runs | report per source (crt.sh is expected to be lowest) |
| Response time | P-01 to P-03 | median and max per scan type |
| Report completeness | For 3 PDF reports, tick: summary, score method, sources, every finding has source + timestamp, recommendations, limitations | items present ÷ 6 |
| Source attribution accuracy | For 10 random findings, open "view source" and confirm the link supports the finding | correct ÷ 10 |
| Username accuracy | For your own handle plus 2 friends' handles (with permission): compare results with the accounts they actually have | true positives, false positives, false negatives; inconclusive counted separately |
| Safeguard effectiveness | S-01 to S-12 | passed ÷ 12 (goal: all) |

## 4. Recording results

- Take screenshots of each passed functional test for the report appendix.
- Paste the output of `python -m pytest -v` and `tests/measure_performance.py`.
- For any failure, note the cause and fix (or why it is a known limitation, e.g. a platform
  blocking automated requests).
