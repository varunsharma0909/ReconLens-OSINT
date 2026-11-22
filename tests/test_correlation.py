from services.graph import build_case_graph


def test_shared_exact_identifier_is_candidate_not_ownership_claim():
    domain_scan = {
        "id": 11, "scan_type": "domain", "target": "example.com",
        "exposure_score": 0, "exposure_level": "Low",
        "findings": [{"status": "confirmed", "code": "DNS_HOST_IPS",
                      "severity": "info", "title": "Resolved IPs",
                      "value": "8.8.8.8", "source": "Public DNS",
                      "collected_at": "2026-01-01T00:00:00+00:00"}],
    }
    ip_scan = {"id": 12, "scan_type": "reputation", "target": "8.8.8.8",
               "exposure_score": 0, "exposure_level": "Low", "findings": []}
    graph = build_case_graph([domain_scan, ip_scan])
    shared = [n for n in graph["nodes"] if n["id"] == "ip:8.8.8.8"]
    assert len(shared) == 1
    assert shared[0]["ownership_verified"] is False
    assert shared[0]["confidence"] == 0.75
    assert graph["warnings"]
    assert graph["evidence_by_scan"]["11"][0]["source"] == "Public DNS"
