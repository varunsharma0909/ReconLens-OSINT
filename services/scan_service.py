"""
services/scan_service.py - Orchestrates scans and selects compatible collectors.
"""
from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor

from collectors import demo_data
from collectors.base import utc_now
from collectors.crtsh_collector import CrtshCollector
from collectors.dns_collector import DnsCollector
from collectors.xposedornot_collector import XposedOrNotCollector
from collectors.rdap_collector import RdapCollector
from collectors.tls_collector import TlsCollector
from collectors.username_collector import UsernameCollector
from collectors.vt_collector import VirusTotalCollector
from collectors.urlhaus_collector import URLhausCollector
from collectors.threatfox_collector import ThreatFoxCollector
from collectors.malwarebazaar_collector import MalwareBazaarCollector
from collectors.abuseipdb_collector import AbuseIPDBCollector

from .recommendations import build_recommendations
from .scoring import compute_score
from .validation import mask_email

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")

COLLECTORS = {
    "domain": [RdapCollector, DnsCollector, CrtshCollector, TlsCollector],
    "username": [UsernameCollector],
    "email": [XposedOrNotCollector],
    # Reputation collectors are selected by target type in collectors_for().
    "reputation": [],
}

LIMITATIONS = {
    "domain": [
        "RDAP/WHOIS data may be redacted for privacy; missing fields are labelled, not guessed.",
        "Domain age is shown only when the registry publishes a registration date.",
        "Hostnames from certificate-transparency logs may belong to systems that are no "
        "longer online. They indicate past certificate issuance, not current exposure.",
        "DNS answers reflect the resolver used at scan time and may be cached.",
        "The TLS check performs one standard HTTPS handshake on port 443 to read the certificate.",
        "No active scanning (ports, vulnerabilities) is performed - this is passive OSINT only.",
    ],
    "username": [
        "Only the platforms listed in collectors/sites.json are checked.",
        "A matching username does not prove the accounts belong to the same person.",
        "Platforms may block or rate-limit automated requests; such results are labelled inconclusive.",
        "Platforms that require login (e.g. Instagram, LinkedIn, X) are excluded by design.",
    ],
    "email": [
        "Results cover only exposure records available to XposedOrNot.",
        "'Not found' means no matching record was returned by this source; it does not prove the address was never exposed.",
        "Only check addresses you own or are authorised to assess.",
    ],
    "reputation": [
        "Reputation results are vendor intelligence, not proof that a target is malicious.",
        "Only existing records are queried. ReconLens does not submit URLs, files, IOCs or abuse reports.",
        "URLhaus checks URLs or hostnames; it does not provide file-hash lookup in this integration.",
        "ThreatFox checks exact IOC matches and supported file hashes. IOCs older than its retention window may not appear.",
        "MalwareBazaar is queried only for MD5, SHA1 or SHA256 hashes; no samples are downloaded.",
        "AbuseIPDB is queried only for public IP addresses, using a 90-day report window.",
        "A source returning no match does not prove the target is safe.",
        "VirusTotal public API quota is limited; its local guard allows at most 4 requests per minute.",
    ],
}


def target_kind(target: str, scan_type: str) -> str:
    if scan_type == "email":
        return "email"
    if HASH_RE.fullmatch(target):
        return "hash"
    if target.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain" if scan_type in ("domain", "reputation") else scan_type


def collectors_for(scan_type: str, target: str):
    if scan_type != "reputation":
        return COLLECTORS[scan_type]

    kind = target_kind(target, scan_type)
    if kind in ("domain", "url"):
        return [VirusTotalCollector, URLhausCollector, ThreatFoxCollector]
    if kind == "ip":
        return [VirusTotalCollector, ThreatFoxCollector, AbuseIPDBCollector]
    if kind == "hash":
        return [VirusTotalCollector, ThreatFoxCollector, MalwareBazaarCollector]
    return []


def run_collectors(scan_type: str, target: str, config: dict):
    classes = collectors_for(scan_type, target)
    if not classes:
        return []
    collectors = [cls(config) for cls in classes]
    with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
        return list(pool.map(lambda collector: collector.run(target), collectors))


def run_scan(scan_type: str, target: str, mode: str, config: dict,
             authorization: str | None = None) -> dict:
    started = utc_now()
    t0 = time.perf_counter()

    if mode == "demo":
        results = demo_data.get_demo_results(scan_type, target)
    else:
        results = run_collectors(scan_type, target, config)

    findings = [finding.to_dict() for result in results for finding in result.findings]
    kind = target_kind(target, scan_type)
    for finding in findings:
        finding["target_kind"] = kind

    scoring = compute_score(findings)
    module_states = {result.status for result in results}
    if not module_states or module_states <= {"error", "skipped"}:
        status = "failed"
    elif module_states & {"error", "skipped", "partial"}:
        status = "partial"
    else:
        status = "completed"

    limitations = list(LIMITATIONS[scan_type])
    if mode == "demo":
        limitations.insert(0, "DEMO MODE: all data in this report is fictional and was not "
                              "collected from any real source.")

    return {
        "scan_type": scan_type,
        "target": mask_email(target) if scan_type == "email" else target,
        "mode": mode,
        "status": status,
        "exposure_score": scoring["score"],
        "exposure_level": scoring["level"],
        "authorization": authorization,
        "started_at": started,
        "completed_at": utc_now(),
        "duration_ms": int((time.perf_counter() - t0) * 1000),
        "modules": [result.summary() for result in results],
        "findings": findings,
        "scoring": scoring,
        "recommendations": build_recommendations(scan_type, findings),
        "limitations": limitations,
    }
