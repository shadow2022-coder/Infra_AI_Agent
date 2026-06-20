from __future__ import annotations

import base64
import json
import re
import tempfile
import time
from datetime import datetime, timezone
from html import escape
from pathlib import Path

import requests

from core.secret_masker import mask_text

HTML_CAPTURE_ROUTES = [
    ("/", "homepage.png", "Homepage screenshot"),
    ("/dashboard", "dashboard.png", "Dashboard screenshot"),
    ("/admin", "admin-route.png", "Admin route screenshot"),
    ("/debug", "debug-route.png", "Debug route screenshot"),
]
HEALTH_CAPTURE_ROUTES = [
    ("/api/health", "api-health-evidence.png", "API health evidence screenshot"),
    ("/health", "health-evidence.png", "Health evidence screenshot"),
]
READINESS_PATHS = ["/health", "/api/health", "/"]
RESPONSE_CAPTURE_STATUSES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}
ERROR_PATTERNS = (
    "Unhandled Runtime Error",
    "ReferenceError:",
    "TypeError:",
    "Traceback (most recent call last)",
    "SyntaxError:",
    "stack trace",
)
DOM_REDACTION_SCRIPT = r"""
() => {
  const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const tokenPattern = /\b(?:sk_(?:live|test)_[A-Za-z0-9]+|AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_\-]{10,}|[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b/g;
  const kvPattern = /\b(?:authorization|bearer|cookie|set-cookie|session|token|access_token|refresh_token|id_token|api_key|apikey|secret|password)\b\s*[:=]\s*["']?[^\s"'<>;]{3,}/gi;

  const redact = (value) => String(value || "")
    .replace(emailPattern, "[EMAIL_MASKED]")
    .replace(kvPattern, (match) => {
      const parts = match.split(/[:=]/, 2);
      return parts.length === 2 ? `${parts[0]}=${parts[0].toLowerCase().includes("cookie") ? "[COOKIE_MASKED]" : "[SECRET_MASKED]"}` : "[SECRET_MASKED]";
    })
    .replace(tokenPattern, "[TOKEN_MASKED]");

  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    node.textContent = redact(node.textContent);
  }

  for (const el of Array.from(document.querySelectorAll("input, textarea"))) {
    if ("value" in el && el.value) el.value = "[REDACTED]";
    if (el.placeholder) el.placeholder = redact(el.placeholder);
  }
}
"""


def _short_text(value: str, limit: int = 220) -> str:
    return re.sub(r"\s+", " ", mask_text(value or "")).strip()[:limit]


def _wait_until_app_ready(base_url: str, timeout_seconds: int = 90) -> tuple[bool, str, int]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        for path in READINESS_PATHS:
            try:
                response = requests.get(f"{base_url.rstrip('/')}{path}", timeout=4, allow_redirects=False)
            except requests.RequestException:
                continue
            if response.status_code in RESPONSE_CAPTURE_STATUSES:
                return True, path, response.status_code
        time.sleep(2)
    return False, "", 0


def discover_runtime_routes(raw_contents: dict[str, str]) -> list[str]:
    routes = ["/", "/dashboard", "/login", "/admin", "/debug"]
    merged = "\n".join(f"{path.lower()}\n{content[:3000].lower()}" for path, content in raw_contents.items())
    if "/api/health" in merged or "api/health" in merged or "health" in merged:
        routes.append("/api/health")
    routes.append("/health")
    seen: set[str] = set()
    ordered: list[str] = []
    for route in routes:
        if route not in seen:
            seen.add(route)
            ordered.append(route)
    return ordered


def _header_value(headers: dict[str, str], key: str) -> str:
    for header_name, header_value in headers.items():
        if header_name.lower() == key.lower():
            return header_value
    return ""


def _security_header_summary(headers: dict[str, str]) -> str:
    required = ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
    missing = [name for name in required if not _header_value(headers, name)]
    return "Missing: " + ", ".join(missing) if missing else "Baseline security headers detected."


def _cors_summary(headers: dict[str, str]) -> str:
    origin = _header_value(headers, "access-control-allow-origin")
    credentials = _header_value(headers, "access-control-allow-credentials")
    if origin == "*":
        return "Wildcard CORS detected" + (" with credentials" if credentials.lower() == "true" else "")
    if origin:
        return f"Restricted to {mask_text(origin)}"
    return "No CORS header detected"


def _render_json_evidence_page(route: str, status_code: int, headers: dict[str, str], body_text: str) -> str:
    safe_headers = [
        ("content-type", _header_value(headers, "content-type")),
        ("access-control-allow-origin", _header_value(headers, "access-control-allow-origin")),
        ("access-control-allow-credentials", _header_value(headers, "access-control-allow-credentials")),
        ("cache-control", _header_value(headers, "cache-control")),
    ]
    try:
        parsed_body = json.loads(body_text)
        pretty_body = json.dumps(parsed_body, indent=2)
    except Exception:
        pretty_body = body_text
    header_rows = "".join(
        f"<tr><td>{escape(mask_text(name))}</td><td>{escape(mask_text(value or 'N/A'))}</td></tr>" for name, value in safe_headers
    )
    return f"""
    <html>
      <body style="margin:0;background:#09121d;color:#eef6ff;font-family:Arial,sans-serif;padding:28px;">
        <div style="border:1px solid rgba(255,255,255,0.08);border-radius:22px;padding:24px;background:rgba(15,30,48,0.92);">
          <h1 style="margin-top:0;">Runtime API Evidence</h1>
          <p><strong>Route:</strong> {escape(mask_text(route))}</p>
          <p><strong>Status:</strong> {status_code}</p>
          <p><strong>Security headers:</strong> {escape(mask_text(_security_header_summary(headers)))}</p>
          <p><strong>CORS:</strong> {escape(mask_text(_cors_summary(headers)))}</p>
          <table style="width:100%;border-collapse:collapse;margin-top:18px;">
            <thead><tr><th align="left" style="padding:10px;border-bottom:1px solid rgba(255,255,255,0.08);">Header</th><th align="left" style="padding:10px;border-bottom:1px solid rgba(255,255,255,0.08);">Value</th></tr></thead>
            <tbody>{header_rows}</tbody>
          </table>
          <h2 style="margin-top:22px;">Sanitized body excerpt</h2>
          <pre style="white-space:pre-wrap;background:#10253a;border-radius:16px;padding:18px;overflow:auto;">{escape(mask_text(pretty_body[:3000]))}</pre>
        </div>
      </body>
    </html>
    """


def _write_png_data_url(output_path: Path) -> str:
    return f"data:image/png;base64,{base64.b64encode(output_path.read_bytes()).decode('ascii')}"


def _build_caption(route: str, status_code: int, timestamp: str, notes: str) -> str:
    return (
        f"Route tested: {mask_text(route)} | "
        f"Status code: {status_code} | "
        f"Timestamp: {mask_text(timestamp)} | "
        f"Sanitized notes: {mask_text(notes)}"
    )


def capture_runtime_evidence(base_url: str, routes: list[str], checks: list[dict]) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        detail = mask_text(str(exc))
        return {
            "available": False,
            "reason": "playwright_not_installed",
            "message": "Browser evidence capture failed.",
            "technical_detail": detail,
            "screenshots": [],
            "console_errors": [],
            "storage_summary": {"local_storage_keys": [], "session_storage_keys": []},
            "cookie_summary": [],
            "routes_captured": [],
            "timestamp": timestamp,
        }

    ready, readiness_route, readiness_status = _wait_until_app_ready(base_url, timeout_seconds=90)
    if not ready:
        return {
            "available": False,
            "reason": "app_not_reachable",
            "message": "Browser evidence capture failed.",
            "technical_detail": "Readiness probes did not confirm /health, /api/health, or / within 90 seconds.",
            "screenshots": [],
            "console_errors": [],
            "storage_summary": {"local_storage_keys": [], "session_storage_keys": []},
            "cookie_summary": [],
            "routes_captured": [],
            "timestamp": timestamp,
        }

    screenshots: list[dict] = []
    console_errors: list[str] = []
    storage_summary = {"local_storage_keys": [], "session_storage_keys": []}
    cookie_summary: list[dict] = []
    routes_captured: list[str] = []
    technical_errors: list[str] = []

    requested_routes: list[tuple[str, str, str]] = list(HTML_CAPTURE_ROUTES) + list(HEALTH_CAPTURE_ROUTES)

    try:
        with tempfile.TemporaryDirectory(prefix="infrared_runtime_evidence_") as temp_dir:
            temp_root = Path(temp_dir)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1000})
                page = context.new_page()
                page.set_default_timeout(15_000)
                page.on("console", lambda msg: console_errors.append(mask_text(msg.text)) if msg.type == "error" else None)
                health_captured = False

                for route, file_name, title in requested_routes:
                    if route in {"/api/health", "/health"} and health_captured:
                        continue
                    url = f"{base_url.rstrip('/')}{route}"
                    try:
                        response = requests.get(url, timeout=5, allow_redirects=False)
                    except requests.RequestException as exc:
                        technical_errors.append(f"{route}: {mask_text(str(exc))}")
                        continue
                    if response.status_code not in RESPONSE_CAPTURE_STATUSES:
                        continue

                    captured_at = datetime.now(timezone.utc).isoformat()
                    content_type = response.headers.get("content-type", "")
                    notes = ""
                    output_path = temp_root / file_name

                    try:
                        if "application/json" in content_type.lower():
                            evidence_html = _render_json_evidence_page(route, response.status_code, dict(response.headers), response.text)
                            page.set_content(evidence_html, wait_until="load")
                            page.wait_for_timeout(1200)
                            page.screenshot(path=str(output_path), full_page=True)
                            notes = "JSON runtime evidence rendered into a local browser proof page."
                        else:
                            page.goto(url, wait_until="domcontentloaded")
                            try:
                                page.wait_for_load_state("networkidle", timeout=4000)
                            except Exception:
                                pass
                            page.wait_for_timeout(1500)
                            page.evaluate(DOM_REDACTION_SCRIPT)
                            page.screenshot(path=str(output_path), full_page=True)
                            body_text = ""
                            try:
                                if page.locator("body").count():
                                    body_text = page.locator("body").inner_text(timeout=2_000)
                            except Exception:
                                body_text = ""
                            if not storage_summary.get("local_storage_keys") and not storage_summary.get("session_storage_keys"):
                                try:
                                    storage_summary = page.evaluate(
                                        """() => ({
                                            local_storage_keys: Object.keys(window.localStorage || {}).slice(0, 12),
                                            session_storage_keys: Object.keys(window.sessionStorage || {}).slice(0, 12)
                                        })"""
                                    )
                                except Exception:
                                    storage_summary = {"local_storage_keys": [], "session_storage_keys": []}
                            notes = body_text or title

                        caption = _build_caption(route, response.status_code, captured_at, notes)
                        screenshots.append(
                            {
                                "title": title,
                                "route": route,
                                "status_code": response.status_code,
                                "file_name": file_name,
                                "captured_at": captured_at,
                                "summary": _short_text(caption, 260),
                                "notes": _short_text(notes, 180),
                                "capture_type": "playwright_screenshot",
                                "image_data_url": _write_png_data_url(output_path),
                            }
                        )
                        routes_captured.append(route)
                        if route in {"/api/health", "/health"}:
                            health_captured = True
                    except Exception as exc:
                        technical_errors.append(f"{route}: {mask_text(str(exc))}")

                cookie_summary = [
                    {
                        "name": mask_text(cookie.get("name", "")),
                        "domain": mask_text(cookie.get("domain", "")),
                        "path": mask_text(cookie.get("path", "")),
                        "httpOnly": bool(cookie.get("httpOnly")),
                        "secure": bool(cookie.get("secure")),
                        "sameSite": mask_text(str(cookie.get("sameSite", ""))),
                    }
                    for cookie in context.cookies()
                ]
                browser.close()
    except Exception as exc:
        technical_errors.append(mask_text(str(exc)))

    if not screenshots:
        detail = " | ".join(technical_errors[:6]) or "No screenshot route completed successfully."
        return {
            "available": False,
            "reason": "screenshot_capture_failed",
            "message": "Browser evidence capture failed.",
            "technical_detail": detail,
            "screenshots": [],
            "console_errors": console_errors[:8],
            "storage_summary": {
                "local_storage_keys": [mask_text(str(item)) for item in storage_summary.get("local_storage_keys", [])[:12]],
                "session_storage_keys": [mask_text(str(item)) for item in storage_summary.get("session_storage_keys", [])[:12]],
            },
            "cookie_summary": cookie_summary[:10],
            "routes_captured": routes_captured,
            "timestamp": timestamp,
        }

    readiness_note = f"Readiness confirmed via {readiness_route} with status {readiness_status}."
    if technical_errors:
        console_errors.append(mask_text(" | ".join(technical_errors[:4])))
    return {
        "available": True,
        "reason": "",
        "message": "Real Playwright browser screenshots were captured from the Docker sandbox.",
        "technical_detail": readiness_note,
        "screenshots": screenshots,
        "console_errors": console_errors[:8],
        "storage_summary": {
            "local_storage_keys": [mask_text(str(item)) for item in storage_summary.get("local_storage_keys", [])[:12]],
            "session_storage_keys": [mask_text(str(item)) for item in storage_summary.get("session_storage_keys", [])[:12]],
        },
        "cookie_summary": cookie_summary[:10],
        "routes_captured": routes_captured,
        "timestamp": timestamp,
    }
