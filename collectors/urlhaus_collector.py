"""
Read-only URLhaus URL and hostname lookups.
No URL submissions or payload downloads are performed.
"""
from __future__ import annotations

from .base import BaseCollector, CollectorError

API = "https://urlhaus-api.abuse.ch/v1"
REFERENCE = "https://urlhaus.abuse.ch/"


class URLhausCollector(BaseCollector):
    module = "urlhaus"
    source = "URLhaus"

    def collect(self, target: str):
        key = self.config.get("ABUSE_CH_AUTH_KEY")
        if not key:
            raise CollectorError("abuse.ch Auth-Key not configured (ABUSE_CH_AUTH_KEY).",
                                 skipped=True)

        if target.startswith(("http://", "https://")):
            endpoint, payload, label = f"{API}/url/", {"url": target}, "URL"
        else:
            endpoint, payload, label = f"{API}/host/", {"host": target}, "host"

        response = self.session.post(
            endpoint, data=payload, headers={"Auth-Key": key},
            timeout=self.config.get("HTTP_TIMEOUT", 10)
        )
        if response.status_code in (401, 403):
            raise CollectorError("URLhaus rejected the abuse.ch Auth-Key.")
        if response.status_code == 429:
            raise CollectorError("URLhaus rate limit reached (HTTP 429).")
        response.raise_for_status()
        body = response.json()
        query_status = str(body.get("query_status", "")).lower()

        if query_status not in ("ok", "success"):
            return [self.finding(
                code="URLHAUS_NOT_FOUND", title=f"No URLhaus {label} match",
                value=f"URLhaus returned query status: {query_status or 'unknown'}.",
                status="not_found", source_url=REFERENCE)]

        if label == "URL":
            status = str(body.get("url_status") or "unknown")
            tags = body.get("tags") or []
            return [self.finding(
                code="URLHAUS_MALICIOUS_URL",
                title=f"URL listed by URLhaus ({status})",
                value=f"Threat: {body.get('threat') or 'unknown'}. "
                      f"Status: {status}. Tags: {', '.join(map(str, tags)) or 'none'}.",
                severity="high" if status == "online" else "medium",
                source_url=REFERENCE,
                details={
                    "url": body.get("url"), "url_status": status,
                    "threat": body.get("threat"), "date_added": body.get("date_added"),
                    "reporter": body.get("reporter"), "tags": tags,
                },
            )]

        urls = body.get("urls") or []
        if not urls:
            return [self.finding(
                code="URLHAUS_NOT_FOUND", title="No malware URLs listed for this host",
                value="URLhaus returned no associated URL records.",
                status="not_found", source_url=REFERENCE)]
        online = sum(1 for item in urls if str(item.get("url_status", "")).lower() == "online")
        return [self.finding(
            code="URLHAUS_HOST_MATCH",
            title=f"Host associated with {len(urls)} URLhaus record(s)",
            value=f"{online} associated URL(s) are currently marked online.",
            severity="high" if online else "medium",
            source_url=REFERENCE,
            details={"host": body.get("host"), "url_count": len(urls),
                     "online_count": online, "urls": urls[:20]},
        )]
