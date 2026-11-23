"""
Read-only VirusTotal API v3 lookups for domains, IPs, URLs and file hashes.
No URL or file is submitted for analysis.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import quote

from .base import BaseCollector, CollectorError

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
PER_MINUTE = 4
_calls: deque = deque()
_lock = threading.Lock()


def reserve_quota(now: float | None = None) -> float:
    now = now or time.time()
    with _lock:
        while _calls and now - _calls[0] >= 60:
            _calls.popleft()
        if len(_calls) >= PER_MINUTE:
            return 60 - (now - _calls[0])
        _calls.append(now)
        return 0.0


def target_kind(target: str) -> str:
    if re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", target):
        return "hash"
    if target.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalCollector(BaseCollector):
    module = "virustotal"
    source = "VirusTotal"

    def collect(self, target: str):
        key = self.config.get("VIRUSTOTAL_API_KEY")
        if not key:
            raise CollectorError("VirusTotal API key not configured (VIRUSTOTAL_API_KEY).",
                                 skipped=True)
        wait = reserve_quota()
        if wait:
            raise CollectorError(
                f"Local quota guard: VirusTotal allows {PER_MINUTE} public API requests "
                f"per minute. Try again in {int(wait) + 1} s.")

        kind = target_kind(target)
        if kind == "url":
            encoded = url_id(target)
            endpoint, gui = f"{API}/urls/{encoded}", f"{GUI}/url/{encoded}"
        elif kind == "ip":
            endpoint, gui = f"{API}/ip_addresses/{target}", f"{GUI}/ip-address/{target}"
        elif kind == "hash":
            endpoint, gui = f"{API}/files/{quote(target)}", f"{GUI}/file/{quote(target)}"
        else:
            endpoint, gui = f"{API}/domains/{quote(target)}", f"{GUI}/domain/{target}"

        response = self.http_get(
            endpoint, headers={"x-apikey": key, "Accept": "application/json"}
        )
        if response.status_code == 404:
            return [self.finding(
                code="VT_NOT_FOUND", title="No VirusTotal report exists",
                value="VirusTotal has no existing report for this target. We do not submit "
                      "targets for analysis.", status="not_found", source_url=gui)]
        if response.status_code == 401:
            raise CollectorError("VirusTotal rejected the API key (HTTP 401).")
        if response.status_code == 429:
            raise CollectorError("VirusTotal quota exceeded (HTTP 429).")
        response.raise_for_status()
        return self.build_findings(
            response.json().get("data", {}).get("attributes", {}), gui, kind
        )

    def build_findings(self, attrs: dict, gui: str, kind: str):
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        engines = sum(v for v in stats.values() if isinstance(v, int))
        ts = attrs.get("last_analysis_date")
        analysed = (datetime.fromtimestamp(ts, timezone.utc).date().isoformat()
                    if isinstance(ts, (int, float)) else "unknown")
        note = "Vendor reputation is a signal, not proof of malicious activity."
        out = []

        if malicious:
            out.append(self.finding(
                code="VT_MALICIOUS",
                title=f"Flagged as malicious by {malicious} of {engines} engines",
                value=f"Last analysed {analysed}. {note}",
                severity="high", source_url=gui))
        if suspicious:
            out.append(self.finding(
                code="VT_SUSPICIOUS",
                title=f"Flagged as suspicious by {suspicious} of {engines} engines",
                value=f"Last analysed {analysed}. {note}",
                severity="medium", source_url=gui))
        if not malicious and not suspicious:
            out.append(self.finding(
                code="VT_CLEAN", title="No engine flagged this target",
                value=f"0 of {engines} engines reported it as malicious or suspicious "
                      f"(last analysed {analysed}).", source_url=gui))

        out.append(self.finding(
            code="VT_STATS", title="Engine verdict breakdown",
            value=", ".join(f"{k}: {v}" for k, v in stats.items()),
            source_url=gui,
            details={"chart": {k: v for k, v in stats.items() if isinstance(v, int)},
                     "table": {"columns": ["Verdict", "Engines"],
                               "rows": [[k, v] for k, v in stats.items()]}}))

        if "reputation" in attrs:
            rep = attrs["reputation"]
            out.append(self.finding(
                code="VT_COMMUNITY_SCORE", title="Community reputation score",
                value=f"{rep} (negative values mean the community voted it harmful)",
                severity="low" if isinstance(rep, int) and rep < 0 else "info",
                source_url=gui))

        cats = attrs.get("categories") or {}
        if cats:
            out.append(self.finding(
                code="VT_CATEGORIES", title="Vendor categories",
                value=", ".join(sorted(set(cats.values()))), source_url=gui))
        if kind == "ip" and (attrs.get("as_owner") or attrs.get("country")):
            out.append(self.finding(
                code="VT_NETWORK", title="Network owner",
                value=f"{attrs.get('as_owner', 'unknown')} ({attrs.get('country', '??')})",
                source_url=gui))
        if kind == "hash" and attrs.get("meaningful_name"):
            out.append(self.finding(
                code="VT_FILE_NAME", title="Known file name",
                value=str(attrs["meaningful_name"]), source_url=gui))
        return out
