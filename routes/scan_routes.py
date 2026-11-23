"""
routes/scan_routes.py - Read/delete stored scans, statistics, health.

    GET    /api/health              server status and which API keys are configured
    GET    /api/demo-targets        fictional targets usable in demo mode
    GET    /api/scans?limit=&type=  scan history (newest first)
    GET    /api/scans/<id>          one scan with all findings
    DELETE /api/scans/<id>          delete a scan (data minimisation)
    GET    /api/stats               aggregate numbers for the dashboard charts
    GET    /api/scans/<id>/graph    relationship graph of one scan
    GET    /api/graph?limit=&ids=   correlated investigation graph across stored scans
"""
import csv
import io

from flask import Blueprint, Response, current_app, jsonify, request

from collectors.demo_data import DEMO_TARGETS
from database.db import delete_scan, get_scan, get_stats, list_scans
from services.graph import build_case_graph, build_graph
from services.report import safe_cell
from security import audit, current_user, require_scan_access

from .common import ApiError

bp = Blueprint("scan_api", __name__, url_prefix="/api")


def _visible_owner():
    user = current_user()
    return None if not user or user["role"] == "admin" else user["id"]



@bp.get("/health")
def health():
    cfg = current_app.config
    return jsonify({
        "ok": True,
        "live_mode_allowed": cfg["ALLOW_LIVE_MODE"],
        "xposedornot_available": True,
        "virustotal_key_configured": bool(cfg.get("VIRUSTOTAL_API_KEY")),
        "abuseipdb_key_configured": bool(cfg.get("ABUSEIPDB_API_KEY")),
        "abuse_ch_key_configured": bool(cfg.get("ABUSE_CH_AUTH_KEY")),
        "retention_days": cfg["RETENTION_DAYS"],
        "scan_rate_limit": cfg["SCAN_RATE_LIMIT"],
    })


@bp.get("/demo-targets")
def demo_targets():
    return jsonify({"ok": True, "demo_targets": DEMO_TARGETS})


@bp.get("/scans")
def scans():
    scan_type = request.args.get("type") or None
    if scan_type and scan_type not in DEMO_TARGETS:
        raise ApiError(400, "bad_type", "type must be domain, username, email or reputation.")
    try:
        limit = max(1, min(200, int(request.args.get("limit", 50))))
    except ValueError:
        raise ApiError(400, "bad_limit", "limit must be a number.")
    return jsonify({"ok": True, "scans": list_scans(limit, scan_type, owner_id=_visible_owner())})


@bp.get("/scans.csv")
def history_csv():
    """Download up to 200 newest scan summaries, with optional type filter.

    Uses the same bounds and validation as GET /api/scans; the CSV is
    formula-neutralised and includes only already-masked stored targets.
    """
    scan_type = request.args.get("type") or None
    if scan_type and scan_type not in DEMO_TARGETS:
        raise ApiError(400, "bad_type", "type must be domain, username, email or reputation.")
    try:
        limit = max(1, min(200, int(request.args.get("limit", 200))))
    except ValueError:
        raise ApiError(400, "bad_limit", "limit must be a number.")
    buf = io.StringIO()
    writer = csv.writer(buf)
    columns = ("id", "scan_type", "target", "mode", "status", "exposure_score",
               "exposure_level", "started_at", "completed_at", "duration_ms", "finding_count")
    writer.writerow(columns)
    for scan in list_scans(limit, scan_type):
        writer.writerow([safe_cell(scan.get(key)) for key in columns])
    response = Response("\ufeff" + buf.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="reconlens-scan-history.csv"'
    return response


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    require_scan_access(scan)
    scan["graph"] = build_graph(scan)
    return jsonify({"ok": True, "scan": scan})


@bp.get("/scans/<int:scan_id>/graph")
def scan_graph(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    require_scan_access(scan)
    return jsonify({"ok": True, "graph": build_graph(scan)})


@bp.get("/graph")
def case_graph():
    """Merge stored scans into one graph; shared entities link the scans together."""
    try:
        limit = max(1, min(50, int(request.args.get("limit", 20))))
    except ValueError:
        raise ApiError(400, "bad_limit", "limit must be a number.")
    raw_ids = request.args.get("ids", "").strip()
    if raw_ids:
        try:
            ids = [int(x) for x in raw_ids.split(",") if x.strip()][:50]
        except ValueError:
            raise ApiError(400, "bad_ids", "ids must be a comma-separated list of scan numbers.")
    else:
        ids = [s["id"] for s in list_scans(limit, owner_id=_visible_owner())]
    scans = [s for s in (get_scan(i) for i in ids) if s is not None and (not current_user() or current_user()["role"] == "admin" or s.get("owner_id") == current_user()["id"])]
    graph = build_case_graph(scans)
    graph["scans"] = [{"id": s["id"], "scan_type": s["scan_type"], "target": s["target"],
                       "exposure_score": s["exposure_score"],
                       "exposure_level": s["exposure_level"], "mode": s["mode"]} for s in scans]
    return jsonify({"ok": True, "graph": graph})


@bp.delete("/scans/<int:scan_id>")
def scan_delete(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    require_scan_access(scan)
    if not delete_scan(scan_id):
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    audit("scan_deleted", f"scan:{scan_id}")
    current_app.logger.info("scan id=%s deleted by operator", scan_id)
    return jsonify({"ok": True, "deleted": scan_id})


@bp.get("/stats")
def stats():
    return jsonify({"ok": True, "stats": get_stats(owner_id=_visible_owner())})
