"""Auditable 0-100 digital exposure score.

Risk domains and maximum contributions (sum = 100): malware/URL 30, IP abuse
25, email exposure 20, domain security 15, threat-intelligence match 10.
Each confirmed finding contributes a severity fraction of its domain budget.
Repeated findings in one domain are combined with diminishing returns and the
domain is capped at its published weight. Not-found, inconclusive and error
responses never increase risk. A missing source is NOT evidence of safety.

This is a transparent project heuristic, not a calibrated probability of
compromise. Recalibrate only against a labelled test corpus.
"""
from __future__ import annotations

CATEGORY_WEIGHTS = {
    "malware_url": 30,
    "ip_abuse": 25,
    "email_exposure": 20,
    "domain_security": 15,
    "threat_intel": 10,
}
SEVERITY_FACTORS = {"high": 1.0, "medium": 0.65, "low": 0.30, "info": 0.0}
LEVELS = [(75, "Critical"), (50, "High"), (20, "Moderate"), (0, "Low")]


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def category_for(f: dict) -> str:
    code = str(f.get("code", "")).upper()
    module = str(f.get("module", "")).lower()
    if code.startswith("VT_") and f.get("target_kind") == "ip":
        return "ip_abuse"
    if code.startswith(("VT_", "URLHAUS_", "MALWAREBAZAAR_")):
        return "malware_url"
    if code.startswith("ABUSEIPDB_") or f.get("target_kind") == "ip":
        return "ip_abuse"
    if code.startswith(("XON_",)) or module == "email":
        return "email_exposure"
    if code.startswith(("DNS_", "RDAP_", "TLS_", "CRTSH_")) or module == "domain":
        return "domain_security"
    if code.startswith(("THREATFOX_", "ABUSE_CH_")):
        return "threat_intel"
    # Generic reputation results are treated conservatively as threat intel.
    if module == "reputation":
        return "threat_intel"
    return "domain_security"


def compute_score(findings: list[dict]) -> dict:
    grouped: dict[str, list[dict]] = {k: [] for k in CATEGORY_WEIGHTS}
    counts = {s: 0 for s in ("confirmed", "not_found", "inconclusive", "error")}
    for finding in findings:
        status = finding.get("status", "error")
        counts[status] = counts.get(status, 0) + 1
        if status == "confirmed":
            grouped[category_for(finding)].append(finding)

    category_breakdown = {}
    breakdown = []
    total = 0.0
    for category, weight in CATEGORY_WEIGHTS.items():
        # Distinct confirmed findings have diminishing marginal contribution;
        # duplicates from the same code do not multiply the score linearly.
        unique = {}
        for f in grouped[category]:
            code = str(f.get("code", "UNKNOWN"))
            factor = SEVERITY_FACTORS.get(f.get("severity", "info"), 0.0)
            unique[code] = max(unique.get(code, 0.0), factor)
        factors = sorted(unique.items(), key=lambda item: item[1], reverse=True)
        # First signal contributes 60% of its severity-adjusted budget; each
        # additional distinct signal contributes 20%, then 10%, then 5%.
        diminishing = [0.60, 0.20, 0.10, 0.05]
        allocations = {code: round(weight * factor * diminishing[min(i, 3)], 2)
                       for i, (code, factor) in enumerate(factors)}
        raw = sum(allocations.values())
        if raw > weight and raw > 0:
            scale = weight / raw
            allocations = {code: round(value * scale, 2) for code, value in allocations.items()}
        points = round(min(weight, sum(allocations.values())), 2)
        category_breakdown[category] = {"weight": weight, "points": points,
                                        "confirmed_indicators": len(unique)}
        total += points
        first_by_code = {}
        for f in grouped[category]:
            code = str(f.get("code", "UNKNOWN"))
            if code not in first_by_code:
                first_by_code[code] = f
        for code, f in first_by_code.items():
            breakdown.append({"code": code, "title": f.get("title"),
                              "severity": f.get("severity"), "category": category,
                              "source": f.get("source"), "points": allocations.get(code, 0.0)})

    score = min(100, round(total))
    return {
        "score": score, "raw_total": round(total, 2), "level": level_for(score),
        "method": ("Weighted heuristic: category budgets are malware/URL 30, IP abuse 25, "
                   "email exposure 20, domain security 15, threat intelligence 10 (total 100). "
                   "Only confirmed findings count. Severity multipliers: high 1.0, medium 0.65, "
                   "low 0.30, info 0. Duplicate codes count once; distinct indicators use "
                   "diminishing contributions (60%, 20%, 10%, then 5% of category budget). "
                   "Each category is capped at its weight. This is a heuristic, not a probability."),
        "weights": CATEGORY_WEIGHTS, "severity_factors": SEVERITY_FACTORS,
        "category_breakdown": category_breakdown,
        "breakdown": breakdown, "status_counts": counts,
        "calibration_note": "Weights require validation against a labelled corpus; do not interpret as breach probability.",
    }
