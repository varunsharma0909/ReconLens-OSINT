"""Reproducible *sensitivity*, not calibration, of exposure-category weights.

Run: python tests/score_sensitivity.py
Creates: tests/score_sensitivity_results.csv

Eight fictional demo fixtures are rescored under six alternative budgets; no
real OSINT APIs, private records or production scoring settings are changed.
"""
from __future__ import annotations

import csv
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from services.scoring import CATEGORY_WEIGHTS, compute_score  # noqa: E402

FIXTURES = [
    ("domain_weak", "domain", "demo-corp.test"),
    ("domain_strong", "domain", "secure-shop.test"),
    ("username_reused", "username", "demo_analyst"),
    ("username_low", "username", "ghost_user_404"),
    ("email_exposed", "email", "alice@demo-corp.test"),
    ("email_clean", "email", "bob@secure-shop.test"),
    ("reputation_flagged", "reputation", "phish-login.demo-corp.test"),
    ("reputation_clean", "reputation", "secure-shop.test"),
]

# Each scenario is a deliberate budget perturbation, not a learned optimum.
# Keys: malware_url, ip_abuse, email_exposure, domain_security, threat_intel
BUDGETS = {
    "baseline": (30, 25, 20, 15, 10),
    "malware_plus_20pct": (36, 23, 18, 14, 9),
    "malware_minus_20pct": (24, 27, 22, 16, 11),
    "ip_plus_20pct": (28, 30, 18, 15, 9),
    "email_plus_20pct": (28, 23, 24, 15, 10),
    "domain_plus_20pct": (28, 23, 19, 18, 12),
    "threat_plus_50pct": (28, 23, 19, 15, 15),
}
FIELDS = ["scenario", "fixture", "scan_type", "baseline_score",
          "alternative_score", "delta_points", "baseline_level",
          "alternative_level", *CATEGORY_WEIGHTS.keys()]


def evaluate():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app({"TESTING": True, "AUTH_TEST_BYPASS": True, "SECRET_KEY": "test-only-stable-secret",
                          "DATABASE_PATH": str(Path(directory) / "sensitivity.db"),
                          "SCAN_RATE_LIMIT": "1000 per minute",
                          "VIRUSTOTAL_API_KEY": "", "ABUSE_CH_AUTH_KEY": "",
                          "ABUSEIPDB_API_KEY": ""})
        client = app.test_client()
        rows = []
        for fixture, scan_type, target in FIXTURES:
            response = client.post(f"/api/scan/{scan_type}",
                                   json={"target": target, "mode": "demo"})
            if response.status_code != 201:
                raise RuntimeError(f"{fixture}: HTTP {response.status_code}")
            scan = response.get_json()["scan"]
            findings = scan["findings"]
            baseline = compute_score(findings)
            if baseline["score"] != scan["exposure_score"]:
                raise AssertionError(f"Baseline differs from real scan for {fixture}")
            for name, values in BUDGETS.items():
                weights = dict(zip(CATEGORY_WEIGHTS, values))
                result = compute_score(findings, weights=weights)
                rows.append({
                    "scenario": name, "fixture": fixture, "scan_type": scan_type,
                    "baseline_score": baseline["score"],
                    "alternative_score": result["score"],
                    "delta_points": result["score"] - baseline["score"],
                    "baseline_level": baseline["level"],
                    "alternative_level": result["level"],
                    **weights,
                })
        return rows


def main():
    rows = evaluate()
    output = ROOT / "tests" / "score_sensitivity_results.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {len(rows)} real computed rows in {output}")
    print(f"{'scenario':<23} {'max_abs_delta':>13} {'mean_abs_delta':>14} {'level_changes':>14}")
    for name in BUDGETS:
        subset = [row for row in rows if row["scenario"] == name]
        maximum = max(abs(row["delta_points"]) for row in subset)
        mean = sum(abs(row["delta_points"]) for row in subset) / len(subset)
        transitions = sum(row["baseline_level"] != row["alternative_level"] for row in subset)
        print(f"{name:<23} {maximum:>13} {mean:>14.2f} {transitions:>14}")


if __name__ == "__main__":
    main()
