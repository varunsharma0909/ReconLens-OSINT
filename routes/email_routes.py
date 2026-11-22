"""
POST /api/scan/email - live email exposure lookup through XposedOrNot.
"""
from flask import Blueprint, current_app
from extensions import limiter
from .common import ApiError, handle_scan

bp = Blueprint("email_api", __name__, url_prefix="/api/scan")


def email_policy(email: str):
    allowed = current_app.config["AUTHORIZED_EMAIL_DOMAINS"]
    domain = email.rsplit("@", 1)[1].lower()
    if allowed and domain not in allowed:
        raise ApiError(403, "domain_not_authorised",
                       "This server only allows live email checks for: " + ", ".join(allowed))


@bp.post("/email")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_email():
    return handle_scan("email", live_policy=email_policy)
