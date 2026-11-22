"""
XposedOrNot email exposure collector.
Uses the public XposedOrNot email-check endpoint; no HIBP integration or key.
Only query email addresses you own or are authorised to assess.
"""
from __future__ import annotations

from urllib.parse import quote

from .base import BaseCollector, CollectorError, Finding

API = "https://api.xposedornot.com/v1/check-email/{}"
SOURCE_URL = "https://xposedornot.com/"


class XposedOrNotCollector(BaseCollector):
    module = "xposedornot"
    source = "XposedOrNot"

    def collect(self, email: str) -> list[Finding]:
        response = self.http_get(API.format(quote(email, safe="")),
                                 headers={"Accept": "application/json"})
        if response.status_code == 404:
            return [self.finding(
                code="XON_NO_BREACH", title="No exposure found by XposedOrNot",
                value=("XposedOrNot returned no matching breach records. This does not "
                       "prove the address has never been exposed."),
                status="not_found", source_url=SOURCE_URL)]
        if response.status_code == 429:
            raise CollectorError("XposedOrNot rate limit reached; try again later.")
        if response.status_code in (400, 422):
            raise CollectorError("XposedOrNot rejected the email address.")
        response.raise_for_status()
        payload = response.json()
        breaches = payload.get("breaches") or payload.get("ExposedBreaches") or []
        if isinstance(breaches, dict):
            breaches = breaches.get("breaches", [])
        if not isinstance(breaches, list):
            raise CollectorError("XposedOrNot returned an unexpected response format.")
        if not breaches:
            return [self.finding(
                code="XON_NO_BREACH", title="No exposure found by XposedOrNot",
                value=("No matching breach names were returned. This does not prove "
                       "the address has never been exposed."),
                status="not_found", source_url=SOURCE_URL)]
        names = []
        for item in breaches:
            if isinstance(item, dict):
                name = item.get("breach") or item.get("name") or item.get("Name") or str(item)
            else:
                name = str(item)
            names.append(name[:160])
        rows = [[name] for name in names]
        return [
            self.finding(
                code="XON_EXPOSURE_SUMMARY",
                title=f"Email appears in {len(names)} exposure record(s)",
                value="XposedOrNot returned matching breach records. Review the listed sources "
                      "and change reused passwords; enable MFA.",
                severity="high", source_url=SOURCE_URL,
                details={"table": {"columns": ["Breach / exposure"], "rows": rows},
                         "breach_count": len(names)}),
            *[self.finding(
                code="XON_BREACH", title=f"Exposure: {name}",
                value="This source lists the email in this exposure. The exact data fields "
                      "exposed may not be available from the public response.",
                severity="medium", source_url=SOURCE_URL)
              for name in names[:50]]
        ]
