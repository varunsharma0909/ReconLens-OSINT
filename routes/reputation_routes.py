"""
routes/reputation_routes.py - Read-only reputation lookups for domains, IPs,
URLs and file hashes.
"""
import ipaddress
import re

from flask import Blueprint, current_app

from extensions import limiter
from .common import ApiError, handle_scan

bp = Blueprint("reputation_api", __name__, url_prefix="/api/scan")
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def reputation_policy(target: str):
    """Require at least one configured provider that supports this target."""
    is_hash = bool(HASH_RE.fullmatch(target))
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    has_vt = bool(current_app.config.get("VIRUSTOTAL_API_KEY"))
    has_abuse_ch = bool(current_app.config.get("ABUSE_CH_AUTH_KEY"))
    has_abuseipdb = bool(current_app.config.get("ABUSEIPDB_API_KEY"))

    if is_ip:
        configured = has_vt or has_abuse_ch or has_abuseipdb
    else:
        configured = has_vt or has_abuse_ch

    if not configured:
        raise ApiError(
            400, "reputation_keys_missing",
            "No compatible reputation API key is configured. Add VIRUSTOTAL_API_KEY "
            "and/or ABUSE_CH_AUTH_KEY; add ABUSEIPDB_API_KEY for IP reputation."
        )


@bp.post("/reputation")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_reputation():
    return handle_scan("reputation", live_policy=reputation_policy)
