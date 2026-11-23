"""
Read-only AbuseIPDB public-IP reputation check.
"""
from __future__ import annotations

from .base import BaseCollector, CollectorError

API = "https://api.abuseipdb.com/api/v2/check"
REFERENCE = "https://www.abuseipdb.com/"


class AbuseIPDBCollector(BaseCollector):
    module = "abuseipdb"
    source = "AbuseIPDB"

    def collect(self, target: str):
        key = self.config.get("ABUSEIPDB_API_KEY")
        if not key:
            raise CollectorError("AbuseIPDB API key not configured (ABUSEIPDB_API_KEY).",
                                 skipped=True)

        response = self.http_get(
            API, params={"ipAddress": target, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        if response.status_code in (401, 403):
            raise CollectorError("AbuseIPDB rejected the API key.")
        if response.status_code == 429:
            raise CollectorError("AbuseIPDB daily API rate limit reached (HTTP 429).")
        response.raise_for_status()
        data = response.json().get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)

        if reports == 0 and score == 0:
            return [self.finding(
                code="ABUSEIPDB_NOT_FOUND", title="No recent abuse reports for this IP",
                value="AbuseIPDB returned no reports in the selected 90-day window.",
                status="not_found", source_url=REFERENCE,
                details={"ip_address": data.get("ipAddress"), "max_age_days": 90},
            )]

        severity = "high" if score >= 75 else "medium" if score >= 25 else "low" if score > 0 else "info"
        return [self.finding(
            code="ABUSEIPDB_REPORTED",
            title=f"Abuse confidence score: {score}/100",
            value=f"{reports} report(s) in the last 90 days. "
                  f"Country: {data.get('countryCode') or 'unknown'}. "
                  f"ISP: {data.get('isp') or 'unknown'}. "
                  f"Last reported: {data.get('lastReportedAt') or 'unknown'}.",
            severity=severity, source_url=REFERENCE,
            details={
                "ip_address": data.get("ipAddress"),
                "abuse_confidence_score": score, "total_reports": reports,
                "distinct_users": data.get("numDistinctUsers"),
                "country_code": data.get("countryCode"), "isp": data.get("isp"),
                "domain": data.get("domain"), "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"), "is_whitelisted": data.get("isWhitelisted"),
                "last_reported_at": data.get("lastReportedAt"), "max_age_days": 90,
            },
        )]
