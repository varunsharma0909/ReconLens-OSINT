"""
Read-only ThreatFox exact IOC and file-hash lookups.
"""
from __future__ import annotations

import re

from .base import BaseCollector, CollectorError

API = "https://threatfox-api.abuse.ch/api/v1/"
REFERENCE = "https://threatfox.abuse.ch/"


class ThreatFoxCollector(BaseCollector):
    module = "threatfox"
    source = "ThreatFox"

    def collect(self, target: str):
        key = self.config.get("ABUSE_CH_AUTH_KEY")
        if not key:
            raise CollectorError("abuse.ch Auth-Key not configured (ABUSE_CH_AUTH_KEY).",
                                 skipped=True)

        is_hash = bool(re.fullmatch(
            r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", target
        ))
        if is_hash:
            payload = {"query": "search_hash", "hash": target}
        else:
            payload = {"query": "search_ioc", "search_term": target, "exact_match": True}

        response = self.session.post(
            API, json=payload, headers={"Auth-Key": key, "Accept": "application/json"},
            timeout=self.config.get("HTTP_TIMEOUT", 10)
        )
        if response.status_code in (401, 403):
            raise CollectorError("ThreatFox rejected the abuse.ch Auth-Key.")
        if response.status_code == 429:
            raise CollectorError("ThreatFox rate limit reached (HTTP 429).")
        response.raise_for_status()
        body = response.json()
        query_status = str(body.get("query_status", "")).lower()
        if query_status in {"no_api_key", "invalid_auth_key", "auth_key_missing", "user_blacklisted"}:
            raise CollectorError("ThreatFox authentication failed: check ABUSE_CH_AUTH_KEY.")

        if query_status not in ("ok", "success"):
            return [self.finding(
                code="THREATFOX_NOT_FOUND", title="No ThreatFox IOC match",
                value=f"ThreatFox returned query status: {query_status or 'unknown'}.",
                status="not_found", source_url=REFERENCE)]

        records = body.get("data") or []
        if isinstance(records, dict):
            records = [records]
        if not records:
            return [self.finding(
                code="THREATFOX_NOT_FOUND", title="No ThreatFox IOC match",
                value="ThreatFox returned no matching indicators.",
                status="not_found", source_url=REFERENCE)]

        findings = []
        for item in records[:20]:
            threat_type = str(item.get("threat_type") or "unknown")
            ioc = str(item.get("ioc") or target)
            family = str(item.get("malware_printable") or item.get("malware") or "unknown")
            findings.append(self.finding(
                code="THREATFOX_IOC_MATCH",
                title=f"ThreatFox IOC match: {threat_type}",
                value=f"IOC: {ioc}. Malware family: {family}. "
                      f"First seen: {item.get('first_seen', 'unknown')}.",
                severity="high", source_url=REFERENCE,
                details={
                    "ioc": ioc, "ioc_type": item.get("ioc_type"),
                    "threat_type": threat_type, "malware": item.get("malware"),
                    "malware_printable": item.get("malware_printable"),
                    "confidence_level": item.get("confidence_level"),
                    "first_seen": item.get("first_seen"), "last_seen": item.get("last_seen"),
                    "reference": item.get("reference"), "tags": item.get("tags") or [],
                },
            ))
        return findings
