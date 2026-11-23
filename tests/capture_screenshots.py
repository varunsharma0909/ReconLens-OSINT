"""Capture actual ReconLens demo UI and report screenshots for the README.

Requires Playwright + Chromium + PyMuPDF, installed by the screenshot workflow.
Only fictional .test targets are used; no live OSINT providers are queried.
"""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

# Set the database *before* importing config/app (config reads environment once).
os.environ["DATABASE_PATH"] = str(ROOT / "database" / "screenshots-demo.db")
os.environ["ALLOW_LIVE_MODE"] = "false"

from app import create_app  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402
import fitz  # noqa: E402


def main():
    app = create_app({"TESTING": True, "AUTH_TEST_BYPASS": True, "SECRET_KEY": "test-only-screenshot-secret",
                      "SCAN_RATE_LIMIT": "1000 per minute",
                      "DEFAULT_RATE_LIMIT": "1000 per hour"})
    client = app.test_client()
    selected = None
    for scan_type, target in [
        ("domain", "demo-corp.test"),
        ("email", "alice@demo-corp.test"),
        ("reputation", "phish-login.demo-corp.test"),
    ]:
        result = client.post(f"/api/scan/{scan_type}",
                             json={"target": target, "mode": "demo"})
        if result.status_code != 201:
            raise RuntimeError(f"Demo scan {target} returned HTTP {result.status_code}")
        if scan_type == "domain":
            selected = result.get_json()["scan"]["id"]
    assert selected is not None

    pdf = client.get(f"/api/scans/{selected}/report.pdf")
    if pdf.status_code != 200 or not pdf.data.startswith(b"%PDF"):
        raise RuntimeError("Could not obtain authentic PDF report")
    with fitz.open(stream=pdf.data, filetype="pdf") as document:
        page = document.load_page(0)
        page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False).save(
            OUT / "pdf-report.png"
        )

    server = make_server("127.0.0.1", 8793, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1000},
                                    device_scale_factor=1)
            page.goto("http://127.0.0.1:8793/", wait_until="networkidle")
            page.locator("#kpi-total").wait_for()
            page.screenshot(path=str(OUT / "dashboard.png"), animations="disabled")
            page.goto("http://127.0.0.1:8793/graph", wait_until="networkidle")
            graph = page.locator(".graph-page")
            graph.wait_for()
            page.wait_for_timeout(1800)
            if not page.locator("#case-graph canvas").count():
                raise RuntimeError("Graph canvas was not rendered; refusing empty screenshot")
            graph.screenshot(path=str(OUT / "graph.png"), animations="disabled")
            browser.close()
    finally:
        server.shutdown()
    for name in ("dashboard.png", "graph.png", "pdf-report.png"):
        path = OUT / name
        if path.stat().st_size < 3000:
            raise RuntimeError(f"Screenshot is unexpectedly small: {path}")
        print(f"Verified real demo screenshot: {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
