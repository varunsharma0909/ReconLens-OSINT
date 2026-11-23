"""Offline mocked tests for the four read-only threat-intelligence integrations.

No real API keys or external network calls are used.
"""
import pytest
import requests

from collectors.abuseipdb_collector import AbuseIPDBCollector
from collectors.malwarebazaar_collector import MalwareBazaarCollector
from collectors.threatfox_collector import ThreatFoxCollector
from collectors.urlhaus_collector import URLhausCollector

CFG = {"USER_AGENT": "ReconLens-test", "HTTP_TIMEOUT": 2,
       "ABUSE_CH_AUTH_KEY": "fake-test-key", "ABUSEIPDB_API_KEY": "fake-test-key"}


class Response:
    def __init__(self, payload=None, status=200):
        self.payload = payload or {}
        self.status_code = status

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def fake_post(monkeypatch, collector, body, status=200):
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response(body, status)
    monkeypatch.setattr(collector.session, "post", post)
    return calls


@pytest.mark.parametrize("collector_cls,target", [
    (URLhausCollector, "example.com"),
    (ThreatFoxCollector, "example.com"),
    (MalwareBazaarCollector, "a" * 64),
    (AbuseIPDBCollector, "8.8.8.8"),
])
def test_missing_keys_skip_without_network(collector_cls, target, monkeypatch):
    collector = collector_cls({"HTTP_TIMEOUT": 2})
    monkeypatch.setattr(collector.session, "post", lambda *a, **k: pytest.fail("network called"))
    monkeypatch.setattr(collector, "http_get", lambda *a, **k: pytest.fail("network called"))
    result = collector.run(target)
    assert result.status == "skipped"
    assert result.findings[0].status == "error"


def test_urlhaus_malicious_url(monkeypatch):
    collector = URLhausCollector(CFG)
    calls = fake_post(monkeypatch, collector, {
        "query_status": "ok", "url_status": "online", "threat": "malware_download",
        "tags": ["exe"], "url": "https://example.com/file.exe"
    })
    result = collector.run("https://example.com/file.exe")
    assert result.status == "ok"
    assert result.findings[0].code == "URLHAUS_MALICIOUS_URL"
    assert result.findings[0].severity == "high"
    assert calls[0][0].endswith("/url/")
    assert calls[0][1]["headers"]["Auth-Key"] == "fake-test-key"
    assert calls[0][1]["data"]["url"] == "https://example.com/file.exe"


def test_urlhaus_host_positive(monkeypatch):
    collector = URLhausCollector(CFG)
    calls = fake_post(monkeypatch, collector, {
        "query_status": "ok", "host": "example.com", "urls": [
            {"url_status": "online"}, {"url_status": "offline"}
        ]
    })
    findings = collector.collect("example.com")
    assert findings[0].code == "URLHAUS_HOST_MATCH"
    assert findings[0].details["online_count"] == 1
    assert calls[0][0].endswith("/host/")


def test_urlhaus_not_found(monkeypatch):
    collector = URLhausCollector(CFG)
    fake_post(monkeypatch, collector, {"query_status": "no_results"})
    assert collector.run("example.com").findings[0].status == "not_found"


def test_threatfox_ioc_match(monkeypatch):
    collector = ThreatFoxCollector(CFG)
    calls = fake_post(monkeypatch, collector, {
        "query_status": "ok", "data": [{
            "ioc": "8.8.8.8", "threat_type": "botnet_cc",
            "malware_printable": "ExampleFamily", "confidence_level": 90
        }]
    })
    finding = collector.run("8.8.8.8").findings[0]
    assert finding.code == "THREATFOX_IOC_MATCH"
    assert finding.severity == "high"
    assert calls[0][1]["json"]["query"] == "search_ioc"
    assert calls[0][1]["json"]["exact_match"] is True


def test_threatfox_hash_lookup(monkeypatch):
    collector = ThreatFoxCollector(CFG)
    calls = fake_post(monkeypatch, collector, {"query_status": "no_result"})
    assert collector.run("a" * 64).findings[0].code == "THREATFOX_NOT_FOUND"
    assert calls[0][1]["json"] == {"query": "search_hash", "hash": "a" * 64}


def test_threatfox_unknown_or_rate_limited(monkeypatch):
    collector = ThreatFoxCollector(CFG)
    fake_post(monkeypatch, collector, {}, status=429)
    assert collector.run("8.8.8.8").status == "error"


def test_malwarebazaar_positive(monkeypatch):
    collector = MalwareBazaarCollector(CFG)
    hash_value = "b" * 64
    calls = fake_post(monkeypatch, collector, {
        "query_status": "ok",
        "data": [{"sha256_hash": hash_value, "file_type": "exe",
                  "signature": "ExampleMalware", "first_seen": "2025-01-01"}]
    })
    finding = collector.run(hash_value).findings[0]
    assert finding.code == "MALWAREBAZAAR_HASH_MATCH"
    assert finding.details["sha256_hash"] == hash_value
    assert calls[0][1]["data"] == {"query": "get_info", "hash": hash_value}


def test_malwarebazaar_no_result(monkeypatch):
    collector = MalwareBazaarCollector(CFG)
    fake_post(monkeypatch, collector, {"query_status": "hash_not_found"})
    assert collector.run("a" * 32).findings[0].status == "not_found"


def test_abuseipdb_high_confidence(monkeypatch):
    collector = AbuseIPDBCollector(CFG)
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs))
        return Response({"data": {"ipAddress": "8.8.8.8",
                         "abuseConfidenceScore": 90, "totalReports": 12,
                         "countryCode": "US"}})
    monkeypatch.setattr(collector, "http_get", get)
    finding = collector.run("8.8.8.8").findings[0]
    assert finding.code == "ABUSEIPDB_REPORTED"
    assert finding.severity == "high"
    assert finding.details["total_reports"] == 12
    assert calls[0][1]["params"] == {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
    assert calls[0][1]["headers"]["Key"] == "fake-test-key"


def test_abuseipdb_no_reports(monkeypatch):
    collector = AbuseIPDBCollector(CFG)
    monkeypatch.setattr(collector, "http_get",
                        lambda *a, **k: Response({"data": {
                            "ipAddress": "8.8.8.8", "totalReports": 0,
                            "abuseConfidenceScore": 0}}))
    assert collector.run("8.8.8.8").findings[0].code == "ABUSEIPDB_NOT_FOUND"


@pytest.mark.parametrize("collector_cls,target", [
    (URLhausCollector, "https://example.com/"),
    (ThreatFoxCollector, "example.com"),
    (MalwareBazaarCollector, "a" * 64),
])
def test_abuse_ch_auth_rejection_is_error(monkeypatch, collector_cls, target):
    collector = collector_cls(CFG)
    fake_post(monkeypatch, collector, {"query_status": "invalid_auth_key"}, status=403)
    result = collector.run(target)
    assert result.status == "error"
    assert "key" in result.error.lower()


def test_abuseipdb_auth_rejection(monkeypatch):
    collector = AbuseIPDBCollector(CFG)
    monkeypatch.setattr(collector, "http_get",
                        lambda *a, **k: Response(status=403))
    assert collector.run("8.8.8.8").status == "error"


def test_abuseipdb_network_timeout(monkeypatch):
    collector = AbuseIPDBCollector(CFG)
    def timeout(*args, **kwargs):
        raise requests.Timeout()
    monkeypatch.setattr(collector, "http_get", timeout)
    result = collector.run("8.8.8.8")
    assert result.status == "error"
    assert "timeout" in result.error
