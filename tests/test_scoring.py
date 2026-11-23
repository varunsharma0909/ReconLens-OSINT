from services.scoring import CATEGORY_WEIGHTS, category_for, compute_score, level_for


def f(code, module="domain", status="confirmed", severity="info", source="test"):
    return {"code": code, "module": module, "status": status, "severity": severity,
            "title": code, "source": source}


def test_category_weights_sum_to_100():
    assert sum(CATEGORY_WEIGHTS.values()) == 100


def test_only_confirmed_findings_contribute():
    result = compute_score([
        f("VT_MALICIOUS", "reputation", severity="high"),
        f("XON_BREACH", "email", severity="high"),
        f("DNS_DMARC_MISSING", severity="medium"),
        f("ABUSEIPDB_HIGH", "reputation", status="inconclusive", severity="high"),
        f("DNS_TIMEOUT", status="error", severity="high"),
        f("DNS_NOT_FOUND", status="not_found", severity="high"),
    ])
    assert result["score"] > 0
    assert result["status_counts"] == {"confirmed": 3, "not_found": 1, "inconclusive": 1, "error": 1}
    assert result["category_breakdown"]["malware_url"]["points"] > 0
    assert result["category_breakdown"]["email_exposure"]["points"] > 0


def test_duplicate_codes_do_not_inflate_score():
    one = compute_score([f("VT_MALICIOUS", "reputation", severity="high")])
    repeated = compute_score([f("VT_MALICIOUS", "reputation", severity="high") for _ in range(8)])
    assert one["score"] == repeated["score"]


def test_category_caps_at_weight():
    result = compute_score([f(f"DNS_RISK_{i}", severity="high") for i in range(30)])
    assert result["category_breakdown"]["domain_security"]["points"] <= 15


def test_level_thresholds():
    assert [level_for(s) for s in (0, 19, 20, 49, 50, 74, 75, 100)] == [
        "Low", "Low", "Moderate", "Moderate", "High", "High", "Critical", "Critical"]


def test_category_classification():
    assert category_for(f("XON_BREACH", "email")) == "email_exposure"
    assert category_for(f("ABUSEIPDB_HIGH", "reputation")) == "ip_abuse"
    assert category_for(f("VT_MALICIOUS", "reputation")) == "malware_url"


def test_weight_override_changes_only_requested_category_budget():
    findings = [f("VT_MALICIOUS", "reputation", severity="high"),
                f("DNS_DMARC_MISSING", severity="high")]
    default = compute_score(findings)
    alternative = dict(CATEGORY_WEIGHTS, malware_url=36, ip_abuse=23,
                       email_exposure=18, domain_security=14, threat_intel=9)
    shifted = compute_score(findings, weights=alternative)
    assert shifted["weights"] == alternative
    assert shifted["category_breakdown"]["malware_url"]["points"] > default["category_breakdown"]["malware_url"]["points"]
    assert compute_score(findings)["score"] == default["score"]
    assert "malware/URL 36" in shifted["method"]


def test_invalid_weight_overrides_are_rejected():
    import pytest
    for weights in (
        {"malware_url": 100},
        dict(CATEGORY_WEIGHTS, malware_url=-1),
        dict(CATEGORY_WEIGHTS, malware_url=29),
        dict(CATEGORY_WEIGHTS, malware_url=True),
    ):
        with pytest.raises(ValueError):
            compute_score([], weights=weights)
