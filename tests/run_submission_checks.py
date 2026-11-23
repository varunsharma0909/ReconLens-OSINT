"""Submission evidence: safe local API checks, never live third-party lookups.

This is automated HTTP/API verification using Flask's test client. It is not a
manual browser, unplugged-network, API-key, or live-provider verification.

    python tests/run_submission_checks.py
"""
import csv
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import create_app  # noqa: E402


def main():
    observations = []
    with tempfile.TemporaryDirectory() as tempdir:
        app = create_app({
            "TESTING": True, "AUTH_TEST_BYPASS": True, "SECRET_KEY": "test-only-stable-secret", "DATABASE_PATH": str(Path(tempdir) / "checks.db"),
            "SCAN_RATE_LIMIT": "1000 per minute", "ALLOW_LIVE_MODE": True,
            "VIRUSTOTAL_API_KEY": "", "ABUSE_CH_AUTH_KEY": "",
            "ABUSEIPDB_API_KEY": "", "AUTHORIZED_EMAIL_DOMAINS": [],
        })
        client = app.test_client()
        def record(case_id, desc, okay):
            observations.append((case_id, desc, "Pass" if okay else "Fail"))
            print(f"{case_id:<5} {'PASS' if okay else 'FAIL'} {desc}")
        def demo(kind, target):
            return client.post(f"/api/scan/{kind}", json={"mode": "demo", "target": target})
        for case_id, kind, target, score in [
            ("F-01", "domain", "demo-corp.test", 10),
            ("F-02", "domain", "secure-shop.test", 0),
            ("F-07", "username", "demo_analyst", 7),
            ("F-08", "username", "ghost_user_404", 0),
            ("F-11", "email", "alice@demo-corp.test", 12),
            ("F-15", "reputation", "phish-login.demo-corp.test", 23),
        ]:
            response = demo(kind, target)
            observed = response.get_json().get("scan", {}) if response.status_code == 201 else {}
            got = observed.get("exposure_score")
            record(case_id, f"HTTP {response.status_code}, score {got}; expected {score}",
                   response.status_code == 201 and got == score)

        scan_response = demo("domain", "demo-corp.test")
        scan = scan_response.get_json()["scan"]
        sid = scan["id"]
        pdf = client.get(f"/api/scans/{sid}/report.pdf")
        record("F-20", f"PDF HTTP {pdf.status_code}, starts with PDF signature",
               pdf.status_code == 200 and pdf.data.startswith(b"%PDF"))
        csv_response = client.get(f"/api/scans/{sid}/report.csv")
        record("F-21", f"CSV HTTP {csv_response.status_code}, nonempty",
               csv_response.status_code == 200 and len(csv_response.data) > 100)

        history = client.get("/api/scans").get_json()["scans"]
        record("F-22", f"History includes demo scan id {sid}",
               any(row["id"] == sid for row in history))
        deletion = client.delete(f"/api/scans/{sid}")
        record("F-23", f"DELETE HTTP {deletion.status_code}",
               deletion.status_code == 200 and client.get(f"/api/scans/{sid}").status_code == 404)

        cases = [
            ("V-02", {"target": "exa mple..com", "mode": "demo"}, "domain", 400),
            ("V-03", {"target": "8.8.8.8", "mode": "live", "authorized": True}, "domain", 400),
            ("V-04", {"target": "<script>alert(1)</script>", "mode": "demo"}, "domain", 400),
            ("V-05", {"target": "192.168.1.1", "mode": "live", "authorized": True}, "reputation", 400),
            ("V-06", {"target": "ftp://example.com/file", "mode": "live", "authorized": True}, "reputation", 400),
            ("V-07", {"target": "example.com", "mode": "demo"}, "domain", 400),
        ]
        for case_id, payload, kind, expected in cases:
            response = client.post(f"/api/scan/{kind}", json=payload)
            record(case_id, f"HTTP {response.status_code}; expected {expected}",
                   response.status_code == expected)

        non_json = client.post("/api/scan/domain", data="target=x")
        record("V-08", f"Non-JSON HTTP {non_json.status_code}", non_json.status_code == 415)

        auto = client.post("/api/scan/auto",
                           json={"target": "alice@demo-corp.test", "mode": "demo"})
        detected = auto.get_json().get("scan", {}).get("scan_type")
        record("V-09", f"Smart search HTTP {auto.status_code} type={detected}",
               auto.status_code == 201 and detected == "email")
        forbidden = client.post("/api/scan/domain",
                                json={"target": "example.com", "mode": "live"})
        record("S-02", f"Unauthorised live HTTP {forbidden.status_code}",
               forbidden.status_code == 403 and forbidden.get_json()["error"]["code"] == "authorization_required")
        headers = client.get("/").headers
        record("S-05", "CSP / X-Frame-Options / nosniff response headers",
               "Content-Security-Policy" in headers and
               headers.get("X-Frame-Options") == "DENY" and
               headers.get("X-Content-Type-Options") == "nosniff")
        email_scan = demo("email", "alice@demo-corp.test").get_json()["scan"]
        record("S-07", f"Stored result email masked: {email_scan['target']}",
               email_scan["target"] == "a***@demo-corp.test")
        unknown = client.get("/api/xyz")
        record("S-09", f"Unknown API HTTP {unknown.status_code}",
               unknown.status_code == 404 and unknown.is_json)
        no_keys = client.post("/api/scan/reputation",
                              json={"target": "example.com", "mode": "live", "authorized": True})
        code = no_keys.get_json().get("error", {}).get("code")
        record("F-16", f"No configured reputation keys: HTTP {no_keys.status_code} {code}",
               no_keys.status_code == 400 and code == "reputation_keys_missing")

    out = ROOT / "tests" / "submission_checks_results.csv"
    with out.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["case_id", "actual_result", "pass_fail"])
        writer.writerows(observations)
    passed = sum(x[2] == "Pass" for x in observations)
    print(f"Verified {passed}/{len(observations)} safe automated API cases. Output: {out}")
    if passed != len(observations):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
