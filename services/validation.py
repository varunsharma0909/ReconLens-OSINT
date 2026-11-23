"""
services/validation.py - Strict input validation for scan targets.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


class ValidationError(ValueError):
    def __init__(self, message: str, field: str = "target"):
        super().__init__(message)
        self.field = field


LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,38}$")
EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _require_text(value, field="target", max_len=2048) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("A value is required.", field)
    value = value.strip()
    if len(value) > max_len:
        raise ValidationError(f"Input is too long (max {max_len} characters).", field)
    if any(ord(c) < 32 for c in value):
        raise ValidationError("Input contains control characters.", field)
    return value


def validate_domain(value) -> str:
    raw = _require_text(value, max_len=300).lower()
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    raw = raw.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if _as_ip(raw) is not None:
        raise ValidationError("Please enter a domain name, not an IP address.")
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValidationError("The domain contains invalid characters.")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2:
        raise ValidationError("Enter a full domain such as example.com.")
    if not all(LABEL_RE.match(label) for label in labels) or not TLD_RE.match(labels[-1]):
        raise ValidationError("That is not a valid domain name.")
    return domain


def validate_username(value) -> str:
    raw = _require_text(value, max_len=40).lstrip("@")
    if not USERNAME_RE.match(raw):
        raise ValidationError("Usernames must be 2-39 characters: letters, digits, '.', '_' or '-'.")
    return raw


def validate_email(value) -> str:
    raw = _require_text(value, max_len=254)
    if raw.count("@") != 1:
        raise ValidationError("Enter a single email address such as name@example.com.")
    local, domain = raw.rsplit("@", 1)
    if not EMAIL_LOCAL_RE.match(local) or local.startswith(".") or ".." in local:
        raise ValidationError("The part before '@' is not valid.")
    return f"{local.lower()}@{validate_domain(domain)}"


def validate_reputation_target(value) -> str:
    """Domain, public IP, http(s) URL, or MD5/SHA1/SHA256 file hash."""
    raw = _require_text(value, max_len=2048)
    if HASH_RE.fullmatch(raw):
        return raw.lower()
    if raw.lower().startswith(("http://", "https://")):
        parts = urlsplit(raw)
        if not parts.hostname:
            raise ValidationError("The URL has no host name.")
        host_ip = _as_ip(parts.hostname)
        if host_ip is not None and not host_ip.is_global:
            raise ValidationError("Private or internal addresses are not allowed.")
        if host_ip is None:
            validate_domain(parts.hostname)
        return raw
    ip = _as_ip(raw)
    if ip is None:
        if "://" in raw or "/" in raw:
            raise ValidationError("Only http:// and https:// URLs are supported.")
        return validate_domain(raw)
    if not ip.is_global:
        raise ValidationError("Private, loopback or reserved IP addresses are not allowed.")
    return str(ip)


def mask_email(email: str) -> str:
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    return f"{local[0]}***@{domain}"


VALIDATORS = {
    "domain": validate_domain,
    "username": validate_username,
    "email": validate_email,
    "reputation": validate_reputation_target,
}

EMAIL_SHAPE_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_SHAPE_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+/?$", re.IGNORECASE)
USERNAME_SHAPE_RE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._-]{1,38}$")


def detect_scan_type(value) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    q = value.strip()
    if EMAIL_SHAPE_RE.match(q):
        return "email"
    if HASH_RE.fullmatch(q):
        return "reputation"
    if q.lower().startswith(("http://", "https://")) or _as_ip(q) is not None:
        return "reputation"
    if DOMAIN_SHAPE_RE.match(q) or q.lower().startswith("www."):
        return "domain"
    if USERNAME_SHAPE_RE.match(q):
        return "username"
    return None
