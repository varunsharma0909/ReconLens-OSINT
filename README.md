# ReconLens - OSINT-Based Dashboard for Digital Footprint Analysis and Cybersecurity

A web application that performs **passive, authorised OSINT** on a domain, a username, an
email address or an IP/URL. It aggregates public sources, labels every result by
certainty, **maps how the collected intelligence connects in an interactive relationship
graph**, correlates separate scans through shared entities, computes a transparent weighted
exposure score with evidence attribution, and produces security recommendations and PDF/CSV reports.

Team (confirm against your official submission cover page): Aryan Sharma (2024A1R101), Varun Sharma (2024A1R107)

### What's new in version 2

- **Relationship graph** (Cytoscape.js) for every scan: domains, IPs, nameservers, mail
  servers, subdomains, certificate authorities, SaaS services, accounts, breaches and risk
  issues as linked nodes. Click a node for details, hide types via the legend, export PNG.
- **Investigation graph** page: merge stored scans using exact canonical identifiers. Shared
  identifiers are candidate pivots, not proof of common ownership; graph nodes expose
  heuristic confidence and verification caveats to reduce misleading attribution.
- **SSL/TLS certificate analysis**: issuer, validity, protocol; expiring, expired and
  untrusted certificates are flagged and scored.
- **Smart search**: type anything - the type (domain / email / IP-URL / username) is
  detected and the right module runs. Press `/` to focus it from any page. The same
  detection is available to API clients: `POST /api/detect` and `POST /api/scan/auto`.
- Redesigned interface in an enterprise-security style: white top navigation with an
  Investigate menu, red/black curved-light heroes, a frosted-glass sample strip, a figure
  carousel of charts, one-click sample investigations, tabbed results
  (Overview, Graph, Findings, Actions, Limitations), light/dark theme, mobile layout.

B.E. Computer Science · Minor Discipline Course (MDC) Cybersecurity project.

| Module | Sources | Key needed? |
|---|---|---|
| Domain intelligence | RDAP (IANA bootstrap) with WHOIS fallback, DNS, crt.sh, TLS certificate | No |
| Username footprint | 19 public platforms (`collectors/sites.json`) | No |
| Email exposure | XposedOrNot public API | No API key required |
| Domain / URL reputation | VirusTotal, URLhaus, ThreatFox (when applicable) | VirusTotal and abuse.ch keys for their respective sources |
| Public IP reputation | VirusTotal, ThreatFox, AbuseIPDB | Provider-specific keys |
| File-hash reputation (MD5/SHA-1/SHA-256) | VirusTotal, MalwareBazaar; ThreatFox for supported hashes | VirusTotal / abuse.ch keys |

**Demo mode** works fully offline with fictional `.test` targets, so the project can be
presented without the internet and without analysing anyone real.

---


## Scoring, correlation and evaluation

The exposure score is an explainable heuristic with category budgets totalling 100: malware/URL 30, IP abuse 25, email exposure 20, domain security 15 and threat intelligence 10. Only confirmed findings contribute; severity factors are high 1.0, medium 0.65, low 0.30 and info 0. Duplicate finding codes are counted once and each category is capped at its weight. The score is **not** a probability of compromise and should be recalibrated against a labelled corpus before making accuracy claims.

Graph edges represent observed or derived technical relationships. Shared canonical identifiers can be shared hosting, DNS infrastructure or third-party services; they do not prove shared ownership. The graph marks shared entities as candidate correlations and provides a confidence heuristic. Analysts must independently verify attribution.

For comparative evaluation, prepare a labelled CSV using `tests/benchmark_template.csv`, run the same authorised test corpus against ReconLens and each comparator, then calculate metrics with:

```bash
python tests/evaluate_osint.py tests/my_results.csv
```

The eight fictional fixture scenarios produced **TP=4, FP=0, TN=4, FN=0**, with accuracy/precision/recall **1.000** and local Flask test-client median/max **5.0/7.8 ms** in [GitHub Actions run #45222088362](https://github.com/varunsharma0909/ReconLens-OSINT/actions/runs/45222088362). **These are demo fixture consistency results, not real-world predictive accuracy.** A second [verification run](https://github.com/varunsharma0909/ReconLens-OSINT/actions/runs/45222389273) captured all eight measured rows in `tests/benchmark_demo_results.csv` and two local HTTP demo timings per scan type (domain median 15 ms; username/email/reputation 5 ms). For real benchmarks, record accuracy, precision, recall, false-positive rate, median and maximum response time. Compare tools only on overlapping supported target types and the same ground-truth set. Do not invent benchmark results; document API coverage, quotas, timestamps and unavailable responses. See `docs/OSINT_EVALUATION.md`.

### Privacy safeguards

- Keep API keys only in server environment variables; never place them in browser JavaScript or reports.
- Email targets are masked in persisted scan summaries and logs; only submit addresses you own or are authorised to assess.
- Use the configured `RETENTION_DAYS` and delete scans when no longer needed.
- Avoid collecting unnecessary personal data; export reports only to controlled storage.
- Live mode requires explicit authorisation per scan.

## 1. Requirements

- Windows 10/11 (also works on Linux/macOS)
- Python **3.10 or newer**. Check with `python --version`. During installation tick
  "Add python.exe to PATH".
- ~100 MB disk space, any laptop with 4 GB RAM.
- Internet only for installation and for live lookups.

## 2. Setup on Windows

Option A - double-click **`setup.bat`**, then **`run.bat`**.

Option B - manually in Command Prompt, inside the `ReconLens-OSINT` folder:

```bat
py -3 -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
copy .env.example .env
python app.py
```

Expected terminal output:

```
  OSINT Footprint Dashboard running at  http://127.0.0.1:5000
  Press CTRL+C to stop.
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000** in your browser.

> PowerShell users: if `venv\Scripts\activate` is blocked, run
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt.

## 3. Using the dashboard

1. Keep the header switch on **Demo**.
2. On the Overview, click the sample card `demo-corp.test` (or type it in the big search box).
3. Read the exposure gauge and certainty bar, then use the tabs: **Overview** (top risks,
   score breakdown), **Relationship graph**, **Findings**, **What to do next**, **Limitations**.
   Click **Download PDF report**.
4. Run the samples `alice@demo-corp.test` and `phish-login.demo-corp.test`, then open
   **Investigation graph**: all three scans meet at the shared node `demo-corp.test`.
5. Compare with `secure-shop.test` (well configured, score 0).
6. **Scan history** lists stored scans; filter, open or delete any of them, or export up to 200 newest scan summaries as a formula-safe CSV.

### Live lookups

Switch the header to **Live lookups**. An authorisation statement appears; you must tick
it (the server also enforces this). Only analyse assets you own or are authorised to assess.

| What to try live | Needs |
|---|---|
| Your own domain, or `example.com` (reserved for documentation, RFC 2606) | Nothing |
| Your own username | Nothing |
| Any email address you own or are authorised to assess | No API key required |
| Public domain / IP / URL / file hash reputation | Configure the relevant provider keys below; at least one supported provider must be configured |

### Reputation provider keys

Copy `.env.example` to `.env`, or configure the equivalent environment variables in Render:

| Environment variable | Used for |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 domain, IP, URL and file-hash lookups |
| `ABUSE_CH_AUTH_KEY` | abuse.ch URLhaus, ThreatFox and MalwareBazaar read-only queries |
| `ABUSEIPDB_API_KEY` | AbuseIPDB public-IP abuse reports |

Never commit actual keys. Missing keys skip the corresponding source; a *live reputation* scan must have at least one applicable configured provider. No key is needed for demo mode. Google Public DNS and Cloudflare DNS public DoH queries do not require API keys.

After editing `.env`, stop the server (CTRL+C) and start it again.

## 4. Running the tests

```bat
venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -v
```

or double-click `run_tests.bat`. The test suite uses mocked network responses, so it
needs no internet and never queries real targets. **Record the actual count printed by pytest**;
the number changes as tests are added. **Verified result:** `153 passed in 1.36s` on Python 3.12 in [GitHub Actions run #45222088362](https://github.com/varunsharma0909/ReconLens-OSINT/actions/runs/45222088362) (23 November 2026). This includes the newly added four-provider mocked tests. The old `132 passed` figure was incorrect.

## 5. Project structure

```
ReconLens-OSINT/
├── app.py                    Flask application factory, security headers, error handlers
├── config.py                 Settings loaded from .env (keys, timeouts, rate limit, retention)
├── extensions.py             Rate limiter (Flask-Limiter) shared by the routes
├── .env.example              Template for .env (copy it; never commit .env)
├── requirements.txt          Pinned runtime Python dependencies (Render)
├── requirements-dev.txt      Test dependencies (pytest)
├── setup.bat / run.bat / run_tests.bat   Windows helpers
├── database/
│   ├── schema.sql            Tables: scans, findings
│   └── db.py                 SQLite helpers (parameterised queries, retention purge)
├── collectors/               One file per OSINT source - all return the same Finding format
│   ├── base.py               Finding / CollectorResult / BaseCollector (timeouts, errors)
│   ├── rdap_collector.py     RDAP via IANA bootstrap + WHOIS port-43 fallback
│   ├── dns_collector.py      DNS records, SPF, DMARC, CAA, SaaS footprint
│   ├── crtsh_collector.py    Certificate transparency subdomains
│   ├── username_collector.py Username checks, confirmed / not found / inconclusive
│   ├── sites.json            Curated platform list for username checks
│   ├── xposedornot_collector.py     XposedOrNot email exposure records
│   ├── vt_collector.py       VirusTotal domain/IP/URL/hash reputation (+ quota guard)
│   ├── urlhaus_collector.py  abuse.ch URLhaus URL/host lookups
│   ├── threatfox_collector.py abuse.ch ThreatFox IOC/hash lookups
│   ├── malwarebazaar_collector.py abuse.ch MalwareBazaar file-hash lookups
│   ├── abuseipdb_collector.py AbuseIPDB public-IP lookups
│   ├── tls_collector.py      TLS certificate via one HTTPS handshake (SSRF-safe)
│   └── demo_data.py          Fictional fixtures for safe demo mode
├── services/
│   ├── validation.py         Allow-list input validation, email masking
│   ├── scan_service.py       Runs collectors in parallel, builds the scan result
│   ├── scoring.py            Transparent 0-100 exposure score
│   ├── recommendations.py    Finding code -> defensive action rules
│   ├── graph.py              Findings -> nodes/edges; merges scans into a case graph
│   └── report.py             PDF (ReportLab) and CSV export
├── routes/
│   ├── common.py             Shared scan handler: JSON check, validation, authorisation
│   ├── domain_routes.py      POST /api/scan/domain
│   ├── username_routes.py    POST /api/scan/username
│   ├── email_routes.py       POST /api/scan/email (+ email-specific policy)
│   ├── reputation_routes.py  POST /api/scan/reputation
│   ├── auto_routes.py        POST /api/detect, POST /api/scan/auto (smart search)
│   ├── scan_routes.py        history, detail, delete, stats, health, demo targets
│   ├── report_routes.py      PDF / CSV downloads
│   └── page_routes.py        HTML pages
├── templates/                Jinja2 pages (base layout, one page per module, history, about)
├── static/
│   ├── css/style.css         Responsive theme, light + dark
│   ├── js/                   common.js, search.js, graph.js, render.js, scan_form.js,
│   │                         dashboard.js, history.js, case_graph.js, scan_detail.js,
│   │                         vendor/chart.umd.min.js (Chart.js, MIT),
│   │                         vendor/cytoscape.min.js (Cytoscape.js, MIT)
│   └── fonts/                Red Hat Display, Public Sans, IBM Plex Mono (SIL OFL) - served locally
├── logs/                     app.log (rotating)
├── tests/                    pytest suite, mocked threat-source tests, benchmark tools
└── docs/                     Architecture diagrams, API reference, test plan
```

Small additions to the original plan: `extensions.py`, `routes/common.py`,
`routes/reputation_routes.py`, `routes/auto_routes.py`, `routes/scan_routes.py`,
`routes/page_routes.py`,
`services/validation.py`, `services/scan_service.py`, `collectors/vt_collector.py`,
`collectors/demo_data.py`, and the `about`, `reputation`, `scan_detail` and `error` templates.

## 6. How it works (short)

Browser → `POST /api/scan/<type>` (JSON) → validation, rate limit, authorisation check →
collectors run **in parallel**, each with its own timeout → findings in one common format →
score + recommendations + limitations → saved in SQLite → turned into a relationship graph
(services/graph.py) → rendered in the browser → exported as PDF/CSV. Stored scans can be
merged into one investigation graph via `GET /api/graph`. Full diagrams: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [current system architecture](docs/diagrams/09_current_system_architecture.svg) and [reputation-provider routing](docs/diagrams/08_reputation_provider_routing.svg). API reference:
[`docs/API.md`](docs/API.md). Test plan: [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md).

### Adding a new OSINT source

1. Create `collectors/my_collector.py` with a class extending `BaseCollector` and a
   `collect(target)` method returning `Finding` objects.
2. Add the class to `COLLECTORS` in `services/scan_service.py`.
3. Optionally add rules for its finding codes in `services/recommendations.py`.

No changes are needed in the database, UI or reports.

## 7. Security and ethical safeguards

- Passive only: no port scanning, exploitation, password attacks, logins or CAPTCHA bypass.
  The only direct contact is one standard HTTPS handshake to read the TLS certificate;
  hosts resolving to private/internal addresses are never contacted, and the connection
  goes to the exact address that was checked (no DNS-rebinding bypass).
- Live mode needs an explicit, server-enforced authorisation statement per scan; it is stored
  with the scan as an audit trail. `ALLOW_LIVE_MODE=false` makes a demo-only deployment.
- Demo mode uses only fictional data on the reserved `.test` TLD.
- Email addresses are sent only to XposedOrNot and are stored, logged and reported masked
  (`a***@domain`) - including the console access log, where page URLs could carry them. `AUTHORIZED_EMAIL_DOMAINS` can restrict live email checks to your organisation.
- API keys only in `.env` (git-ignored); never in code, logs or reports.
- Flask-Limiter rate limit on scan endpoints (`SCAN_RATE_LIMIT`) plus a general limit on
  pages and API reads (`DEFAULT_RATE_LIMIT`); per-source timeouts; VirusTotal quota guard.
- Allow-list validation; private/internal IPs rejected; URLs are never fetched by the app.
- CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`; all third-party data rendered as text.
- CSV formula-injection protection; PDF text escaped.
- Data minimisation: retention purge (`RETENTION_DAYS`, applied at start-up and on every
  save), delete button, raw WHOIS not stored. Registrar RDAP links are followed only over HTTPS.
- Server binds to `127.0.0.1` only.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python with "Add to PATH", or use `py -3` |
| `ModuleNotFoundError: No module named 'flask'` | Activate the venv first: `venv\Scripts\activate` |
| `Address already in use` / port 5000 busy | Close the other server, or change `port=5000` at the bottom of `app.py` |
| Live domain scan: crt.sh "busy or unavailable" | crt.sh is often overloaded - retry after a minute; other sources still work |
| Every DNS record type fails | Check internet/DNS; on college Wi-Fi a captive portal may block DNS |
| Username results all "inconclusive" | The network or platforms are blocking automated requests; that is reported honestly |
| Email live lookup fails | Check connectivity to XposedOrNot and retry later |
| `429 Too many requests` | Rate limit reached (default 10 scans/minute) - wait a minute |
| Charts missing | Make sure `static/js/vendor/chart.umd.min.js` exists |
| Want a fresh database | Stop the app and delete `database/osint.db` |

## 9. Demo-day checklist

- [ ] Run `run_tests.bat` the day before - all tests pass.
- [ ] Delete `database/osint.db` for an empty history, then run 3-4 demo scans so the
      overview charts have data.
- [ ] Keep the switch on **Demo data** unless the venue has reliable internet.
- [ ] For a live moment, use `example.com` (domain) and
      `alice@demo-corp.test` (email demo).
- [ ] Have one PDF report already downloaded as a backup.

## 10. Credits and licences

Chart.js (MIT), Cytoscape.js (MIT), Red Hat Display, Public Sans and IBM Plex Mono (SIL Open Font License), Flask, dnspython,
requests, Flask-Limiter, python-dotenv, ReportLab. Username detection approach adapted
from the open-source Sherlock project. Data from IANA/ICANN RDAP, crt.sh, XposedOrNot, VirusTotal, abuse.ch
(URLhaus, ThreatFox and MalwareBazaar) and AbuseIPDB is subject to each provider's terms of use.
