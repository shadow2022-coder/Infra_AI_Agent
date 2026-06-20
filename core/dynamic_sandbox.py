from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from html import escape
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import quote

import requests

from core.repair_agent import (
    apply_repair_plan,
    collect_text_contents,
    run_ai_repair_agent,
    run_deterministic_repair,
    should_attempt_repair,
)
from core.runtime_evidence import capture_runtime_evidence, discover_runtime_routes
from core.secret_masker import mask_text

SANDBOX_LOCK = threading.Lock()
PORT_CANDIDATES = [3000, 8000, 8080, 5000, 5173, 4173]
LOGIN_PATHS = ["/login", "/signin", "/auth/login", "/auth/signin"]
ADMIN_PATHS = ["/admin", "/dashboard/admin", "/api/admin", "/api/admin/users"]
SENSITIVE_PATHS = ["/api/admin", "/api/users", "/api/debug", "/api/internal", "/graphql", "/admin"]
VISIBLE_ERROR_PATTERNS = (
    "Unhandled Runtime Error",
    "ReferenceError:",
    "TypeError:",
    "ChunkLoadError",
    "Hydration failed",
    "Traceback (most recent call last)",
    "SyntaxError:",
)
STACKTRACE_PATTERNS = ("traceback", "stack trace", "exception:", "error:", "runtime error")
SECRET_HINT_PATTERNS = (
    re.compile(r"(?i)(service_role|stripe_secret|openai_api_key|database_url)\s*[:=]\s*['\"]?[^\s'\"<]{6,}"),
    re.compile(r"sk_(live|test)_[A-Za-z0-9]+"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)


def _base_result(project_name: str) -> dict:
    return {
        "enabled": True,
        "project_name": project_name,
        "docker_available": False,
        "status": "incomplete",
        "reason": "",
        "message": "",
        "technical_detail": "",
        "summary": "Dynamic sandbox testing did not complete.",
        "stack_strategy": "unsupported",
        "start_command": "",
        "detected_port": None,
        "runtime_agents": [],
        "findings": [],
        "checks": [],
        "evidence_cards": [],
        "screenshots": [],
        "proof_metadata": {},
        "cleanup_status": "pending",
        "timeline": [
            {"step": "Container created", "status": "pending", "detail": ""},
            {"step": "App started", "status": "pending", "detail": ""},
            {"step": "Repair Agent", "status": "pending", "detail": ""},
            {"step": "Routes tested", "status": "pending", "detail": ""},
            {"step": "Screenshots captured", "status": "pending", "detail": ""},
            {"step": "Container destroyed", "status": "pending", "detail": ""},
        ],
        "logs_excerpt": "",
        "confidence_cap": None,
        "confidence_penalty": 0,
        "error": "",
        "original_failure": {},
        "repair_attempted": False,
        "repair_status": "not_attempted",
        "repair_changes": [],
        "repair_skipped_reason": "",
        "repair_summary": "",
        "safetest_memory": {},
    }


def _run_command(args: list[str], timeout: int = 30, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=str(cwd) if cwd else None)


def _update_timeline(result: dict, step_name: str, status: str, detail: str = "") -> None:
    timeline = result.get("timeline", [])
    for item in timeline:
        if item.get("step") == step_name:
            item["status"] = status
            item["detail"] = _sanitize_excerpt(detail, 180) if detail else ""
            return


def check_docker_status() -> dict:
    try:
        result = _run_command(["docker", "info"], timeout=15)
    except FileNotFoundError as exc:
        detail = mask_text(str(exc))
        return {
            "available": False,
            "reason": "docker_not_installed",
            "message": "Docker Desktop is not installed or the docker CLI is unavailable. Install Docker Desktop, start it, then retry Dynamic Sandbox Testing. Static scan and AI review still work without Docker.",
            "technical_detail": detail,
        }
    except PermissionError as exc:
        detail = mask_text(str(exc))
        return {
            "available": False,
            "reason": "permission_denied",
            "message": "Docker is installed but InfraRed AI could not access it. Check Docker Desktop permissions, then retry Dynamic Sandbox Testing. Static scan and AI review still work without Docker.",
            "technical_detail": detail,
        }
    except Exception as exc:
        detail = mask_text(str(exc))
        return {
            "available": False,
            "reason": "unknown",
            "message": "InfraRed AI could not verify Docker availability. Static scan and AI review still work without Docker.",
            "technical_detail": detail,
        }
    if result.returncode != 0:
        detail = mask_text((result.stderr or result.stdout or "Docker not available.").strip())
        lowered = detail.lower()
        if "docker.sock" in lowered and "no such file or directory" in lowered:
            reason = "socket_missing"
            message = (
                "Docker Desktop is not running or its socket is unavailable. "
                "Start Docker Desktop, wait until it says \"Docker is running\", then retry Dynamic Sandbox Testing. "
                "Static scan and AI review still work without Docker."
            )
        elif "permission denied" in lowered:
            reason = "permission_denied"
            message = (
                "Docker is installed but InfraRed AI could not access it. "
                "Check Docker Desktop permissions, then retry Dynamic Sandbox Testing. "
                "Static scan and AI review still work without Docker."
            )
        elif "cannot connect" in lowered or "failed to connect" in lowered or "is the daemon running" in lowered:
            reason = "docker_not_running"
            message = (
                "Docker Desktop is not running. Start Docker Desktop, wait until it says \"Docker is running\", then retry Dynamic Sandbox Testing. "
                "Static scan and AI review still work without Docker."
            )
        elif "not found" in lowered:
            reason = "docker_not_installed"
            message = (
                "Docker Desktop is not installed or the docker CLI is unavailable. Install Docker Desktop, start it, then retry Dynamic Sandbox Testing. "
                "Static scan and AI review still work without Docker."
            )
        else:
            reason = "unknown"
            message = "InfraRed AI could not verify Docker availability. Static scan and AI review still work without Docker."
        return {
            "available": False,
            "reason": reason,
            "message": message,
            "technical_detail": detail,
        }
    return {
        "available": True,
        "reason": "",
        "message": "Docker is available.",
        "technical_detail": mask_text((result.stdout or "").strip())[:500],
    }


def docker_available() -> tuple[bool, str]:
    status = check_docker_status()
    return bool(status["available"]), str(status["technical_detail"] or status["message"])


def _safe_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "infrared"


def _detect_fastapi_target(raw_contents: dict[str, str]) -> str | None:
    for path, content in raw_contents.items():
        lower = path.lower()
        if not lower.endswith(".py"):
            continue
        if "fastapi(" in content.lower():
            module = path[:-3].replace("/", ".")
            for candidate in ("app", "api"):
                if re.search(rf"\b{candidate}\s*=\s*FastAPI\s*\(", content):
                    return f"{module}:{candidate}"
            return f"{module}:app"
    return None


def _detect_streamlit_entrypoint(raw_contents: dict[str, str]) -> str | None:
    for path, content in raw_contents.items():
        lower = path.lower()
        if not lower.endswith(".py"):
            continue
        content_lower = content.lower()
        if "import streamlit" in content_lower or "from streamlit import" in content_lower:
            return path
    return "app.py" if "app.py" in raw_contents else None


def _detect_strategy(project_root: Path, raw_contents: dict[str, str], stack: dict) -> dict | None:
    dockerfile_path = project_root / "Dockerfile"
    if dockerfile_path.exists():
        dockerfile_text = dockerfile_path.read_text(encoding="utf-8", errors="ignore")
        exposed_ports = [int(port) for port in re.findall(r"(?im)^\s*EXPOSE\s+(\d+)", dockerfile_text)]
        return {
            "kind": "dockerfile",
            "label": "Project Dockerfile sandbox",
            "ports": exposed_ports or ([3000, 8000, 8080, 5000, 5173, 4173, 80]),
            "dockerfile": dockerfile_text,
        }

    package_json = raw_contents.get("package.json")
    if package_json:
        try:
            package = json.loads(package_json)
        except json.JSONDecodeError:
            package = {}
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        dependencies = {}
        if isinstance(package, dict):
            dependencies.update(package.get("dependencies", {}) or {})
            dependencies.update(package.get("devDependencies", {}) or {})
        if isinstance(scripts, dict) or any(raw_contents.get(name) for name in ("server.js", "app.js", "index.js")):
            is_next = "next" in dependencies
            start_candidates = []
            if isinstance(scripts, dict) and "dev" in scripts:
                if is_next:
                    start_candidates.append("npm run dev -- --hostname 0.0.0.0 --port 3000")
                else:
                    start_candidates.extend(
                        [
                            "npm run dev -- --host 0.0.0.0 --port 3000",
                            "npm run dev -- --hostname 0.0.0.0 --port 3000",
                        ]
                    )
            if isinstance(scripts, dict) and "start" in scripts:
                start_candidates.extend(
                    [
                        "npm run start -- --host 0.0.0.0 --port 3000",
                        "npm run start -- --hostname 0.0.0.0 --port 3000",
                        "npm run start",
                    ]
                )
            for candidate in ("server.js", "app.js", "index.js"):
                if raw_contents.get(candidate):
                    start_candidates.append(f"node {candidate}")
            install_line = (
                "if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; "
                "else npm install --ignore-scripts --no-audit --no-fund; fi"
            )
            start_line = " || ".join(dict.fromkeys(start_candidates))
            return {
                "kind": "next" if is_next else "node",
                "label": "Next.js sandbox" if is_next else "Node/Express sandbox",
                "ports": [3000, 5173, 4173, 8080],
                "install_line": install_line,
                "start_command": start_line,
                "dockerfile": "\n".join(
                    [
                        "FROM node:20-bookworm-slim",
                        "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*",
                        "WORKDIR /app",
                        "COPY package*.json ./",
                        f"RUN {install_line}",
                        "COPY . .",
                        'CMD ["sh", "-lc", ' + json.dumps(start_line) + "]",
                    ]
                ),
            }

    fastapi_target = _detect_fastapi_target(raw_contents)
    if fastapi_target and ((project_root / "requirements.txt").exists() or (project_root / "pyproject.toml").exists()):
        start_candidates = [
            f"python -m uvicorn {fastapi_target} --host 0.0.0.0 --port 8000",
            "python app.py",
            "python main.py",
        ]
        start_line = " || ".join(start_candidates)
        return {
            "kind": "python",
            "label": "Python/FastAPI sandbox",
            "ports": [8000, 5000, 8080],
            "install_line": "pip install --no-cache-dir -r requirements.txt",
            "start_command": start_line,
            "dockerfile": "\n".join(
                [
                    "FROM python:3.11-slim",
                    "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*",
                    "WORKDIR /app",
                    "COPY requirements.txt ./",
                    "RUN pip install --no-cache-dir -r requirements.txt",
                    "COPY . .",
                    'CMD ["sh", "-lc", ' + json.dumps(start_line) + "]",
                ]
            ),
        }

    streamlit_entry = _detect_streamlit_entrypoint(raw_contents)
    requirements_text = raw_contents.get("requirements.txt", "")
    if streamlit_entry and ("streamlit" in requirements_text.lower() or "streamlit" in str(stack.get("label", "")).lower()):
        start_line = f"python -m streamlit run {streamlit_entry} --server.address 0.0.0.0 --server.port 8501 --browser.gatherUsageStats false"
        return {
            "kind": "streamlit",
            "label": "Python/Streamlit sandbox",
            "ports": [8501],
            "install_line": "pip install --no-cache-dir -r requirements.txt",
            "start_command": start_line,
            "dockerfile": "\n".join(
                [
                    "FROM python:3.11-slim",
                    "WORKDIR /app",
                    "COPY requirements.txt ./",
                    "RUN pip install --no-cache-dir -r requirements.txt",
                    "COPY . .",
                    "EXPOSE 8501",
                    'CMD ["sh", "-lc", ' + json.dumps(start_line) + "]",
                ]
            ),
        }

    return None


def _cleanup_container(name: str) -> bool:
    result = _run_command(["docker", "rm", "-f", name], timeout=20)
    stderr = (result.stderr or "").lower()
    return result.returncode == 0 or "no such container" in stderr


def _cleanup_image(tag: str) -> bool:
    result = _run_command(["docker", "image", "rm", "-f", tag], timeout=30)
    stderr = (result.stderr or "").lower()
    return result.returncode == 0 or "no such image" in stderr


def _container_logs(name: str, tail: int = 120) -> str:
    result = _run_command(["docker", "logs", "--tail", str(tail), name], timeout=20)
    return mask_text((result.stdout or result.stderr or "").strip())[:2500]


def _wait_for_port(container_name: str, ports: list[int], timeout_seconds: int = 90) -> int | None:
    deadline = time.time() + timeout_seconds
    probe_paths = ("/health", "/api/health", "/")
    while time.time() < deadline:
        for port in ports:
            host_port = _lookup_host_port(container_name, port)
            if host_port is None:
                continue
            for probe_path in probe_paths:
                try:
                    response = requests.get(f"http://127.0.0.1:{host_port}{probe_path}", timeout=3, allow_redirects=False)
                except requests.RequestException:
                    continue
                if response.status_code >= 100:
                    return port
        time.sleep(2)
    return None


def _docker_port_args(ports: list[int]) -> list[str]:
    args: list[str] = []
    for port in ports:
        args.extend(["-p", f"127.0.0.1::{port}"])
    return args


def _lookup_host_port(container_name: str, container_port: int) -> int | None:
    result = _run_command(["docker", "port", container_name, f"{container_port}/tcp"], timeout=10)
    line = (result.stdout or "").strip().splitlines()
    if not line:
        return None
    match = re.search(r":(\d+)\s*$", line[0])
    return int(match.group(1)) if match else None


def _short_container_id(container_name: str) -> str:
    result = _run_command(["docker", "inspect", "--format", "{{.Id}}", container_name], timeout=10)
    return mask_text((result.stdout or "").strip())[:12]


def _curl_request(container_name: str, port: int, path: str, timeout_seconds: int = 10) -> dict:
    host_port = _lookup_host_port(container_name, port)
    if host_port is None:
        return {
            "url": "",
            "status_code": 0,
            "headers": {},
            "body": "",
            "stderr": "Mapped localhost port was not available.",
        }
    url = f"http://127.0.0.1:{host_port}{path}"
    try:
        response = requests.get(url, timeout=timeout_seconds, allow_redirects=False)
        headers = {key: [value] for key, value in response.headers.items()}
        status = response.status_code
        body_text = response.text[:220_000]
        stderr = ""
    except requests.RequestException as exc:
        headers = {}
        status = 0
        body_text = ""
        stderr = mask_text(str(exc))
    return {
        "url": url,
        "status_code": status,
        "headers": headers,
        "body": body_text[:220_000],
        "stderr": stderr,
    }


def _sanitize_excerpt(text: str, limit: int = 220) -> str:
    cleaned = re.sub(r"\s+", " ", mask_text(text or "")).strip()
    return cleaned[:limit]


def _secret_exposure_level(text: str) -> str | None:
    lowered = text.lower()
    if "service_role" in lowered or "stripe_secret" in lowered or "database_url" in lowered:
        return "critical"
    if any(pattern.search(text) for pattern in SECRET_HINT_PATTERNS):
        return "high"
    return None


def _make_finding(check_id: str, title: str, severity: str, path: str, evidence: str, fix: str) -> dict:
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "path": path,
        "summary": _sanitize_excerpt(evidence, 160),
        "evidence": _sanitize_excerpt(evidence, 420),
        "fix": fix,
    }


def _find_script_paths(homepage_body: str) -> list[str]:
    matches = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", homepage_body, flags=re.I)
    return [match for match in matches if match.startswith("/")][:6]


def _build_snapshot_card(title: str, subtitle: str, body: str) -> dict:
    safe_title = escape(_sanitize_excerpt(title, 70))
    safe_subtitle = escape(_sanitize_excerpt(subtitle, 120))
    safe_body = escape(_sanitize_excerpt(body, 260))
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' width='720' height='420'>"
        "<rect width='100%' height='100%' rx='20' fill='#0f1e30'/>"
        "<rect x='24' y='24' width='672' height='44' rx='10' fill='#19314c'/>"
        "<text x='40' y='52' fill='#eef6ff' font-family='Arial, sans-serif' font-size='22' font-weight='700'>"
        f"{safe_title}</text>"
        "<text x='40' y='92' fill='#a2b8cf' font-family='Arial, sans-serif' font-size='18'>"
        f"{safe_subtitle}</text>"
        "<foreignObject x='40' y='124' width='640' height='240'>"
        "<div xmlns='http://www.w3.org/1999/xhtml' style='color:#eef6ff;font-family:Arial,sans-serif;"
        "font-size:18px;line-height:1.5;white-space:pre-wrap;'>"
        f"{safe_body}</div></foreignObject></svg>"
    )
    return {
        "title": title,
        "summary": _sanitize_excerpt(body, 200),
        "image_data_url": f"data:image/svg+xml;charset=utf-8,{quote(svg)}",
    }


def _run_runtime_checks(container_name: str, port: int, raw_contents: dict[str, str]) -> tuple[list[dict], list[dict], list[dict]]:
    checks = []
    findings = []

    homepage = _curl_request(container_name, port, "/")
    checks.append({"id": "D001", "title": "Homepage reachable", "path": "/", "status": "pass" if 200 <= homepage["status_code"] < 400 else "review", "severity": "medium", "evidence": homepage["body"] or homepage["stderr"]})
    if homepage["status_code"] < 200 or homepage["status_code"] >= 400:
        findings.append(_make_finding("D001", "Homepage not reachable inside sandbox", "medium", "/", homepage["stderr"] or homepage["body"], "Confirm the app starts in the sandbox with a safe default local command."))

    auth_hints = any(token in path.lower() for path in raw_contents for token in ("auth", "login", "session", "middleware"))
    login_found = False
    for path in LOGIN_PATHS:
        response = _curl_request(container_name, port, path)
        if response["status_code"] in {200, 302, 303, 307, 308, 401, 403}:
            login_found = True
            checks.append({"id": "D002", "title": "Login page reachable", "path": path, "status": "pass", "severity": "low", "evidence": response["body"]})
            break
    if not login_found:
        status = "review" if auth_hints else "pass"
        checks.append({"id": "D002", "title": "Login page reachable", "path": "/login", "status": status, "severity": "low", "evidence": "No common login route responded."})
        if auth_hints:
            findings.append(_make_finding("D002", "Login route was not reachable in sandbox", "low", "/login", "No common login route responded after startup.", "Check the auth entry route and sandbox start command."))  # noqa: E501

    admin_response = _curl_request(container_name, port, "/admin")
    admin_status = admin_response["status_code"]
    if admin_status in {401, 403, 302, 303, 307, 308}:
        checks.append({"id": "D003", "title": "Admin route blocks unauthenticated access", "path": "/admin", "status": "pass", "severity": "low", "evidence": str(admin_status)})
    elif admin_status == 200:
        checks.append({"id": "D003", "title": "Admin route blocks unauthenticated access", "path": "/admin", "status": "fail", "severity": "high", "evidence": admin_response["body"]})
        findings.append(_make_finding("D003", "Admin route was reachable without authentication", "high", "/admin", admin_response["body"], "Require authentication and role checks before serving admin pages or APIs."))
    else:
        checks.append({"id": "D003", "title": "Admin route blocks unauthenticated access", "path": "/admin", "status": "review", "severity": "medium", "evidence": str(admin_status)})
        findings.append(_make_finding("D003", "Admin route behavior was inconclusive", "medium", "/admin", f"Received status {admin_status}.", "Verify unauthenticated admin access is blocked or redirected."))  # noqa: E501

    homepage_headers = {key.lower(): values for key, values in homepage["headers"].items()}
    missing_headers = [name for name in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy") if name not in homepage_headers]
    if missing_headers:
        findings.append(_make_finding("D004", "Security headers were missing at runtime", "medium", "/", ", ".join(missing_headers), "Add baseline security headers for browser responses."))
        checks.append({"id": "D004", "title": "Security headers", "path": "/", "status": "review", "severity": "medium", "evidence": ", ".join(missing_headers)})
    else:
        checks.append({"id": "D004", "title": "Security headers", "path": "/", "status": "pass", "severity": "low", "evidence": "Baseline browser headers detected."})

    cors_values = homepage_headers.get("access-control-allow-origin", [])
    credentials_values = homepage_headers.get("access-control-allow-credentials", [])
    if "*" in " ".join(cors_values):
        severity = "high" if any(value.lower() == "true" for value in credentials_values) else "medium"
        findings.append(_make_finding("D005", "Runtime CORS policy allowed wildcard origins", severity, "/", "Wildcard origin header detected.", "Restrict CORS origins to the trusted frontend domains only."))
        checks.append({"id": "D005", "title": "CORS policy", "path": "/", "status": "fail" if severity == "high" else "review", "severity": severity, "evidence": " ".join(cors_values)})
    else:
        checks.append({"id": "D005", "title": "CORS policy", "path": "/", "status": "pass", "severity": "low", "evidence": "No wildcard CORS header detected on the homepage response."})

    cookie_headers = homepage_headers.get("set-cookie", [])
    if cookie_headers:
        insecure_cookies = []
        for cookie in cookie_headers:
            lowered = cookie.lower()
            missing = []
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if "secure" not in lowered:
                missing.append("Secure")
            if missing:
                insecure_cookies.append(f"{cookie.split('=', 1)[0]} missing {', '.join(missing)}")
        if insecure_cookies:
            findings.append(_make_finding("D006", "Runtime cookies were missing security flags", "medium", "/", "; ".join(insecure_cookies), "Set HttpOnly, SameSite, and Secure flags on auth and session cookies where applicable."))
            checks.append({"id": "D006", "title": "Cookie flags", "path": "/", "status": "review", "severity": "medium", "evidence": "; ".join(insecure_cookies)})
        else:
            checks.append({"id": "D006", "title": "Cookie flags", "path": "/", "status": "pass", "severity": "low", "evidence": "Observed cookies included baseline security flags."})
    else:
        checks.append({"id": "D006", "title": "Cookie flags", "path": "/", "status": "review", "severity": "low", "evidence": "No cookies were set during the homepage request."})

    page_text = f"{homepage['body']} {admin_response['body']}".lower()
    if any(pattern.lower() in page_text for pattern in VISIBLE_ERROR_PATTERNS):
        findings.append(_make_finding("D007", "Visible runtime error text was exposed", "medium", "/", page_text, "Hide framework error overlays and return generic external error pages in production."))  # noqa: E501
        checks.append({"id": "D007", "title": "Visible runtime errors", "path": "/", "status": "review", "severity": "medium", "evidence": page_text})
    else:
        checks.append({"id": "D007", "title": "Visible runtime errors", "path": "/", "status": "pass", "severity": "low", "evidence": "No obvious runtime error overlay text detected."})

    if any(pattern in page_text for pattern in STACKTRACE_PATTERNS):
        findings.append(_make_finding("D008", "Visible stack trace or exception detail was exposed", "high", "/", page_text, "Disable stack traces in external responses and keep exception detail server-side only."))  # noqa: E501
        checks.append({"id": "D008", "title": "Visible stack traces", "path": "/", "status": "fail", "severity": "high", "evidence": page_text})
    else:
        checks.append({"id": "D008", "title": "Visible stack traces", "path": "/", "status": "pass", "severity": "low", "evidence": "No visible traceback or stack trace text detected."})

    script_paths = _find_script_paths(homepage["body"])
    fetched_scripts = []
    source_map_found = False
    for script_path in script_paths[:4]:
        script_response = _curl_request(container_name, port, script_path)
        fetched_scripts.append(script_response["body"])
        if script_path.endswith(".js"):
            map_response = _curl_request(container_name, port, f"{script_path}.map")
            if map_response["status_code"] == 200:
                source_map_found = True
    visible_bundle = "\n".join(fetched_scripts)
    exposure_level = _secret_exposure_level(visible_bundle + "\n" + homepage["body"])
    if exposure_level:
        findings.append(_make_finding("D009", "Frontend HTML or JavaScript exposed a secret-like value", exposure_level, "/", visible_bundle or homepage["body"], "Remove secrets from frontend bundles and keep privileged keys server-side only."))
        checks.append({"id": "D009", "title": "Frontend secret exposure", "path": "/", "status": "fail", "severity": exposure_level, "evidence": visible_bundle or homepage["body"]})
    else:
        checks.append({"id": "D009", "title": "Frontend secret exposure", "path": "/", "status": "pass", "severity": "low", "evidence": "No obvious secret pattern was detected in the homepage HTML or fetched scripts."})

    if source_map_found:
        findings.append(_make_finding("D010", "Source map was reachable in runtime output", "low", "/", "A JavaScript source map responded with HTTP 200.", "Disable public source maps or gate them from production builds."))
        checks.append({"id": "D010", "title": "Source map exposure", "path": "/", "status": "review", "severity": "low", "evidence": "A source map responded with HTTP 200."})
    else:
        checks.append({"id": "D010", "title": "Source map exposure", "path": "/", "status": "pass", "severity": "low", "evidence": "No obvious public source map was detected from the homepage scripts."})

    for path in SENSITIVE_PATHS:
        sensitive = _curl_request(container_name, port, path)
        if sensitive["status_code"] == 200 and path != "/admin":
            findings.append(_make_finding("D011", "Potentially sensitive route responded publicly", "high", path, sensitive["body"], "Require authentication, authorization, or route removal for internal-only runtime paths."))
            checks.append({"id": "D011", "title": "Public sensitive routes", "path": path, "status": "fail", "severity": "high", "evidence": sensitive["body"]})
            break
    else:
        checks.append({"id": "D011", "title": "Public sensitive routes", "path": "/api/admin", "status": "pass", "severity": "low", "evidence": "No obvious sensitive route returned HTTP 200 without auth from the tested path set."})

    evidence_cards = [
        _build_snapshot_card("Homepage runtime evidence card", f"Sandbox localhost:{port}/", homepage["body"] or "Homepage content was not available."),
        _build_snapshot_card("Admin route runtime evidence card", f"Sandbox localhost:{port}/admin", admin_response["body"] or f"Status {admin_response['status_code']}"),
    ]
    if findings:
        evidence_cards.append(_build_snapshot_card("Runtime finding evidence card", "Sanitized dynamic evidence", "\n".join(finding["summary"] for finding in findings[:4])))
    return checks, findings, evidence_cards


def _build_runtime_agents(strategy: dict, status: str, summary: str, findings: list[dict], checks: list[dict], port: int | None, logs_excerpt: str) -> list[dict]:
    setup_risks = []
    if status != "completed":
        setup_risks.append(f"Sandbox setup was incomplete: {summary}")
    browser_findings = [item for item in findings if item["id"] in {"D001", "D002", "D007", "D008", "D009", "D010"}]
    auth_findings = [item for item in findings if item["id"] in {"D003", "D004", "D005", "D006", "D011"}]
    setup_card = {
        "agent": "Sandbox Setup Agent",
        "status": "SAFE" if status == "completed" else "REVIEW",
        "one_line_summary": summary,
        "top_risks": setup_risks[:2],
        "top_fix": "Use a supported stack with a safe detected startup command and Docker available locally.",
        "in_depth": {
            "evidence_used": f"Strategy: {strategy.get('label', 'Unsupported')} | Port: {port or 'Not detected'}",
            "business_impact": "Incomplete sandbox testing reduces confidence in the deployment decision." if status != "completed" else "Sandbox runtime checks completed inside Docker without host execution.",
            "assumptions": ["Dynamic testing stayed inside Docker and did not execute uploaded code on the host."],
        },
        "output_valid": True,
    }
    browser_card = {
        "agent": "Browser Runtime Auditor Agent",
        "status": "SAFE" if not browser_findings else "RISK_FOUND",
        "one_line_summary": "Checked browser-visible runtime output for leaks, stack traces, and error overlays.",
        "top_risks": [item["title"] for item in browser_findings[:2]],
        "top_fix": browser_findings[0]["fix"] if browser_findings else "Keep production browser output free of secrets, stack traces, and source maps.",
        "in_depth": {
            "evidence_used": " | ".join(item["evidence"] for item in browser_findings[:3])[:500] or "No browser-visible leak was detected from the tested routes.",
            "business_impact": "Browser-visible leaks can expose secrets or internal architecture to any unauthenticated visitor." if browser_findings else "No obvious browser-visible leak was detected from the sandbox checks.",
            "assumptions": ["Checks used safe HTTP/runtime inspection instead of exploit payloads or brute force."],
        },
        "output_valid": True,
    }
    auth_card = {
        "agent": "Runtime Auth/API Auditor Agent",
        "status": "SAFE" if not auth_findings else "RISK_FOUND",
        "one_line_summary": "Checked unauthenticated runtime access controls, headers, CORS, and cookie behavior.",
        "top_risks": [item["title"] for item in auth_findings[:2]],
        "top_fix": auth_findings[0]["fix"] if auth_findings else "Keep admin and sensitive routes gated behind authentication and explicit policy checks.",
        "in_depth": {
            "evidence_used": " | ".join(item["evidence"] for item in auth_findings[:3])[:500] or "No obvious unauthenticated runtime route exposure was detected.",
            "business_impact": "Runtime auth and API gaps can expose sensitive data or privileged actions to unauthenticated users." if auth_findings else "No obvious unauthenticated runtime route exposure was detected from the tested path set.",
            "assumptions": ["Only safe localhost routes inside the sandbox were probed."],
        },
        "output_valid": True,
    }
    if logs_excerpt and status != "completed":
        setup_card["in_depth"]["evidence_used"] += f" | Logs: {logs_excerpt[:260]}"
    return [setup_card, browser_card, auth_card]


def _successful_status(status: str) -> bool:
    return status in {"completed", "completed_after_repair"}


def _build_repair_agent_card(dynamic_result: dict) -> dict:
    changes = dynamic_result.get("repair_changes", []) if isinstance(dynamic_result.get("repair_changes"), list) else []
    return {
        "agent": "Repair Agent",
        "status": "SAFE" if _successful_status(str(dynamic_result.get("status", ""))) and changes else "REVIEW",
        "one_line_summary": dynamic_result.get("repair_summary") or dynamic_result.get("repair_skipped_reason") or "Repair Agent was not used.",
        "top_risks": [change.get("summary", "") for change in changes[:2] if isinstance(change, dict)],
        "top_fix": changes[0].get("summary", "") if changes and isinstance(changes[0], dict) else "Repair Agent only changes the temporary sandbox copy when startup is fixable.",
        "in_depth": {
            "evidence_used": dynamic_result.get("original_failure", {}).get("message", ""),
            "business_impact": "Repair changes were used only to make the temporary sandbox copy runnable for evidence capture.",
            "assumptions": ["The original uploaded ZIP was not modified."],
        },
        "output_valid": True,
    }


def _copy_project_to_temp(project_root: Path, temp_root: Path) -> Path:
    target = temp_root / "sandbox_project"
    shutil.copytree(project_root, target)
    return target


def _run_single_sandbox_attempt(project_root: Path, source_name: str, stack: dict, raw_contents: dict[str, str], timeout_seconds: int, image_tag: str, container_name: str) -> dict:
    result = _base_result(Path(source_name).stem)
    result["stack_strategy"] = "unsupported"
    result["proof_metadata"] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "docker_image_name": image_tag,
        "container_id_short": "",
        "tested_url": "",
        "routes_tested": [],
        "screenshot_count": 0,
        "cleanup_status": "pending",
        "readiness_note": "",
    }
    container_started = False
    try:
        strategy = _detect_strategy(project_root, raw_contents, stack)
        if not strategy:
            result["status"] = "unsupported"
            result["reason"] = "unsupported_startup"
            result["message"] = "No safe detected startup strategy was available for this stack. Static scan and AI review still work."
            result["summary"] = "Dynamic Sandbox Testing was skipped because no safe startup strategy was detected. Add a Dockerfile and README run command to enable sandbox testing."
            result["runtime_agents"] = _build_runtime_agents({"label": "Unsupported stack"}, result["status"], result["summary"], [], [], None, "")
            return result

        result["stack_strategy"] = strategy["label"]
        result["start_command"] = strategy.get("start_command", "Project Dockerfile entrypoint")

        with tempfile.TemporaryDirectory(prefix="infrared_dynamic_") as temp_dir:
            dockerfile_path = Path(temp_dir) / "Dockerfile"
            dockerfile_path.write_text(strategy["dockerfile"], encoding="utf-8")
            build = _run_command(
                ["docker", "build", "-f", str(dockerfile_path), "-t", image_tag, str(project_root)],
                timeout=max(60, min(timeout_seconds - 60, 240)),
            )
            if build.returncode != 0:
                result["status"] = "failed"
                result["reason"] = "app_not_reachable"
                result["message"] = "Sandbox image build failed. Static scan and AI review still work."
                result["summary"] = "Sandbox image build failed. Static scan still works."
                result["error"] = mask_text((build.stderr or build.stdout or "").strip())[:1500]
                result["runtime_agents"] = _build_runtime_agents(strategy, result["status"], result["summary"], [], [], None, result["error"])
                return result

        started = _run_command(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--cpus",
                "2",
                "--memory",
                "4096m",
                "--network",
                "bridge",
                *_docker_port_args(strategy["ports"]),
                image_tag,
            ],
            timeout=30,
        )
        if started.returncode != 0:
            result["status"] = "failed"
            result["reason"] = "app_not_reachable"
            result["message"] = "Sandbox container could not start. Static scan and AI review still work."
            result["summary"] = "Sandbox container could not start. Static scan still works."
            result["error"] = mask_text((started.stderr or started.stdout or "").strip())[:1500]
            result["runtime_agents"] = _build_runtime_agents(strategy, result["status"], result["summary"], [], [], None, result["error"])
            return result
        container_started = True
        _update_timeline(result, "Container created", "completed", "Disposable Docker container started with CPU and memory limits on Docker bridge networking.")
        result["proof_metadata"]["container_id_short"] = _short_container_id(container_name)

        port = _wait_for_port(container_name, strategy["ports"], timeout_seconds=90)
        logs_excerpt = _container_logs(container_name)
        result["logs_excerpt"] = logs_excerpt
        if port is None:
            result["status"] = "incomplete"
            result["reason"] = "app_not_reachable"
            result["message"] = "Sandbox container started, but InfraRed AI could not confirm a safe localhost app port within the timeout."
            result["summary"] = "Sandbox container started, but no safe localhost app port became reachable within the timeout."
            result["runtime_agents"] = _build_runtime_agents(strategy, result["status"], result["summary"], [], [], None, logs_excerpt)
            return result
        host_port = _lookup_host_port(container_name, port)
        if host_port is None:
            result["status"] = "incomplete"
            result["reason"] = "app_not_reachable"
            result["message"] = "Sandbox app started internally, but InfraRed AI could not map a safe localhost port for browser proof."
            result["summary"] = "Sandbox app started internally, but localhost browser proof could not be established."
            result["runtime_agents"] = _build_runtime_agents(strategy, result["status"], result["summary"], [], [], port, logs_excerpt)
            return result
        tested_url = f"http://127.0.0.1:{host_port}"
        result["proof_metadata"]["tested_url"] = tested_url
        result["tested_url"] = tested_url
        result["detected_port"] = host_port
        _update_timeline(result, "App started", "completed", f"App became reachable at {tested_url}.")

        checks, findings, evidence_cards = _run_runtime_checks(container_name, port, raw_contents)
        _update_timeline(result, "Routes tested", "completed", "Minimal localhost runtime routes were tested inside the sandbox.")
        routes = discover_runtime_routes(raw_contents)
        evidence = capture_runtime_evidence(tested_url, routes, checks)
        result["proof_metadata"]["routes_tested"] = routes
        result["proof_metadata"]["timestamp"] = evidence.get("timestamp", result["proof_metadata"]["timestamp"])
        result["checks"] = checks
        result["findings"] = findings
        result["screenshots"] = evidence.get("screenshots", [])
        result["proof_metadata"]["screenshot_count"] = len(result["screenshots"])
        result["proof_metadata"]["routes_captured"] = evidence.get("routes_captured", [])
        result["proof_metadata"]["console_error_count"] = len(evidence.get("console_errors", []))
        result["proof_metadata"]["cookie_summary"] = evidence.get("cookie_summary", [])
        result["proof_metadata"]["storage_summary"] = evidence.get("storage_summary", {})
        result["proof_metadata"]["playwright_message"] = evidence.get("message", "")
        result["proof_metadata"]["readiness_note"] = evidence.get("technical_detail", "")
        if evidence.get("console_errors"):
            checks.append(
                {
                    "id": "D012",
                    "title": "Console errors",
                    "path": "/",
                    "status": "review",
                    "severity": "medium",
                    "evidence": " | ".join(evidence["console_errors"][:3]),
                }
            )
            findings.append(
                _make_finding(
                    "D012",
                    "Browser console errors were captured during runtime proof",
                    "medium",
                    "/",
                    " | ".join(evidence["console_errors"][:3]),
                    "Review the client-side error path and remove production-facing runtime errors before deployment.",
                )
            )
        if evidence.get("available"):
            result["status"] = "completed"
            result["summary"] = (
                f"Dynamic sandbox testing completed inside Docker at {tested_url} with {len(findings)} non-passing runtime finding(s). "
                "Real sandbox evidence captured inside a disposable local Docker container."
            )
            result["evidence_cards"] = evidence_cards
            _update_timeline(result, "Screenshots captured", "completed", f"{len(result['screenshots'])} real Playwright screenshot(s) captured.")
        else:
            result["status"] = "incomplete"
            result["reason"] = evidence.get("reason", "screenshot_capture_failed")
            result["message"] = evidence.get("message", "Browser evidence capture failed.")
            result["technical_detail"] = evidence.get("technical_detail", "")
            result["summary"] = "Runtime HTTP checks completed, but real browser proof was incomplete because Playwright screenshots were not captured."
            result["evidence_cards"] = evidence_cards
            _update_timeline(result, "Screenshots captured", "failed", result["message"])
        result["runtime_agents"] = _build_runtime_agents(strategy, result["status"], result["summary"], findings, checks, host_port, logs_excerpt)
        if findings:
            highest = max(({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(item["severity"], 0) for item in findings), default=0)
            result["confidence_penalty"] = 25 if highest >= 4 else 15 if highest == 3 else 8 if highest == 2 else 3
        return result
    except subprocess.TimeoutExpired:
        result["status"] = "incomplete"
        result["reason"] = "app_not_reachable"
        result["message"] = "Dynamic sandbox testing timed out and stopped safely."
        result["summary"] = "Dynamic sandbox testing hit the timeout and stopped safely."
        result["runtime_agents"] = _build_runtime_agents({"label": "Timed out"}, result["status"], result["summary"], [], [], None, "")
        return result
    except Exception as exc:
        result["status"] = "failed"
        result["reason"] = "unexpected_error"
        result["message"] = "Dynamic sandbox testing failed safely without crashing the app."
        result["summary"] = "Dynamic sandbox testing failed safely without crashing the app."
        result["error"] = mask_text(str(exc))[:1500]
        result["runtime_agents"] = _build_runtime_agents({"label": "Dynamic sandbox failure"}, result["status"], result["summary"], [], [], None, result["error"])
        return result
    finally:
        container_ok = _cleanup_container(container_name)
        image_ok = _cleanup_image(image_tag)
        if container_started:
            if container_ok and image_ok:
                result["cleanup_status"] = "Sandbox destroyed"
                _update_timeline(result, "Container destroyed", "completed", "Container and image cleanup completed.")
            else:
                result["cleanup_status"] = "Cleanup failed - manual cleanup required"
                _update_timeline(result, "Container destroyed", "failed", "One or more Docker cleanup steps failed.")
        else:
            result["cleanup_status"] = "No sandbox created"
            _update_timeline(result, "Container destroyed", "skipped", "Sandbox was not created.")
        if isinstance(result.get("proof_metadata"), dict):
            result["proof_metadata"]["cleanup_status"] = result["cleanup_status"]


def run_dynamic_sandbox(project_root: Path, source_name: str, stack: dict, raw_contents: dict[str, str], timeout_seconds: int = 300, client=None, safetest_memory: dict | None = None) -> dict:
    project_name = Path(source_name).stem
    result = _base_result(project_name)
    acquired = SANDBOX_LOCK.acquire(blocking=False)
    if not acquired:
        result["reason"] = "sandbox_busy"
        result["message"] = "Another sandbox test is already running. Try again after it completes."
        result["summary"] = "Another sandbox test is already running. Try again after it completes."
        result["error"] = result["summary"]
        result["confidence_cap"] = 69
        result["runtime_agents"] = _build_runtime_agents({"label": "Sandbox lock"}, result["status"], result["summary"], [], [], None, "")
        return result

    image_tag = f"infrared-sandbox-{_safe_slug(project_name)}-{int(time.time())}"
    try:
        docker_status = check_docker_status()
        result["docker_available"] = bool(docker_status["available"])
        if not docker_status["available"]:
            result["status"] = "skipped"
            result["reason"] = "docker_unavailable"
            result["message"] = docker_status["message"]
            result["technical_detail"] = docker_status["technical_detail"]
            result["summary"] = "Dynamic sandbox testing was not completed because Docker was unavailable. Static analysis and AI contextual review were completed."
            result["error"] = docker_status["technical_detail"]
            result["confidence_cap"] = 69
            result["runtime_agents"] = _build_runtime_agents({"label": "Docker unavailable"}, result["status"], result["summary"], [], [], None, "")
            return result

        with tempfile.TemporaryDirectory(prefix="infrared_repair_workspace_") as temp_root:
            working_project = _copy_project_to_temp(project_root, Path(temp_root))
            current_raw_contents = collect_text_contents(working_project)
            startup_candidates = []
            detected_strategy = _detect_strategy(working_project, current_raw_contents, stack)
            if detected_strategy:
                startup_candidates.append(detected_strategy.get("label", "Detected strategy"))
                if detected_strategy.get("start_command"):
                    startup_candidates.append(detected_strategy["start_command"])
            if isinstance(safetest_memory, dict):
                safetest_memory["startup_strategy_candidates"] = startup_candidates[:6]

            first_attempt = _run_single_sandbox_attempt(
                working_project,
                source_name,
                stack,
                current_raw_contents,
                min(timeout_seconds, 300),
                image_tag,
                f"{image_tag}-attempt1",
            )
            if isinstance(safetest_memory, dict):
                safetest_memory.setdefault("sandbox_attempts", []).append(
                    {"attempt": 1, "status": first_attempt.get("status"), "reason": first_attempt.get("reason", ""), "summary": first_attempt.get("summary", "")}
                )
            if _successful_status(str(first_attempt.get("status", ""))):
                first_attempt["safetest_memory"] = safetest_memory or {}
                return first_attempt

            result = dict(first_attempt)
            result["original_failure"] = {
                "reason": first_attempt.get("reason", ""),
                "message": first_attempt.get("message", ""),
                "summary": first_attempt.get("summary", ""),
            }
            repair_decision = should_attempt_repair(first_attempt, stack, list(current_raw_contents.keys()))
            if not repair_decision.get("attempt"):
                result["repair_attempted"] = False
                result["repair_status"] = "skipped"
                result["repair_skipped_reason"] = str(repair_decision.get("reason", "Repair Agent was skipped because the failure type was not safely repairable."))
                result["repair_summary"] = result["repair_skipped_reason"]
                result["runtime_agents"] = list(result.get("runtime_agents", [])) + [_build_repair_agent_card(result)]
                result["safetest_memory"] = safetest_memory or {}
                return result

            result["repair_attempted"] = True
            result["repair_status"] = "running"
            _update_timeline(result, "Repair Agent", "completed", "Repair Agent evaluated the temporary sandbox copy for safe startup fixes.")

            repair_result = run_deterministic_repair(working_project, first_attempt, stack)
            repair_changes = list(repair_result.get("changes", []))
            current_raw_contents = repair_result.get("raw_contents", current_raw_contents)

            if not repair_changes and client is not None:
                # Keep the repair context compressed to control token use in SafeTestAgents.
                ai_plan = run_ai_repair_agent(
                    {
                        "project_name": project_name,
                        "detected_stack": stack.get("label", ""),
                        "failure_reason": first_attempt.get("reason", ""),
                        "failure_summary": first_attempt.get("summary", ""),
                        "startup_strategy_candidates": startup_candidates[:6],
                        "files": list(current_raw_contents.keys())[:30],
                        "snippets": {path: mask_text(text[:600]) for path, text in list(current_raw_contents.items())[:8]},
                    },
                    client=client,
                )
                repair_changes.extend(apply_repair_plan(working_project, ai_plan))
                current_raw_contents = collect_text_contents(working_project)

            result["repair_changes"] = repair_changes
            result["repair_status"] = "attempted" if repair_changes else "no_safe_change"
            result["repair_summary"] = (
                "Repair Agent patched a temporary sandbox copy and retried runtime testing."
                if repair_changes
                else "Repair Agent found no safe minimal startup patch to apply."
            )
            if isinstance(safetest_memory, dict):
                safetest_memory["repair_attempted"] = True
                safetest_memory["repair_changes"] = repair_changes

            if not repair_changes:
                result["repair_skipped_reason"] = "Repair Agent was skipped because the failure type was not safely repairable." if not repair_decision.get("attempt") else "Repair Agent found no safe minimal startup patch to apply."
                result["runtime_agents"] = list(result.get("runtime_agents", [])) + [_build_repair_agent_card(result)]
                result["safetest_memory"] = safetest_memory or {}
                return result

            second_attempt = _run_single_sandbox_attempt(
                working_project,
                source_name,
                stack,
                current_raw_contents,
                min(timeout_seconds, 180),
                f"{image_tag}-repair",
                f"{image_tag}-attempt2",
            )
            if isinstance(safetest_memory, dict):
                safetest_memory.setdefault("sandbox_attempts", []).append(
                    {"attempt": 2, "status": second_attempt.get("status"), "reason": second_attempt.get("reason", ""), "summary": second_attempt.get("summary", "")}
                )
            second_attempt["repair_attempted"] = True
            second_attempt["repair_changes"] = repair_changes
            second_attempt["original_failure"] = result["original_failure"]
            second_attempt["repair_status"] = "succeeded" if _successful_status(str(second_attempt.get("status", ""))) else "failed"
            second_attempt["repair_summary"] = result["repair_summary"]
            second_attempt["safetest_memory"] = safetest_memory or {}
            if _successful_status(str(second_attempt.get("status", ""))):
                second_attempt["status"] = "completed_after_repair"
                second_attempt["summary"] = "Sandbox testing initially failed, but the Repair Agent patched a temporary sandbox copy and completed runtime testing."
                second_attempt["runtime_agents"] = list(second_attempt.get("runtime_agents", [])) + [_build_repair_agent_card(second_attempt)]
                return second_attempt

            second_attempt["repair_skipped_reason"] = ""
            second_attempt["summary"] = "Sandbox testing could not be completed automatically."
            second_attempt["runtime_agents"] = list(second_attempt.get("runtime_agents", [])) + [_build_repair_agent_card(second_attempt)]
            return second_attempt
    except subprocess.TimeoutExpired:
        result["status"] = "incomplete"
        result["reason"] = "app_not_reachable"
        result["message"] = "Dynamic sandbox testing timed out and stopped safely."
        result["summary"] = "Dynamic sandbox testing hit the timeout and stopped safely."
        result["confidence_cap"] = 69
        result["runtime_agents"] = _build_runtime_agents({"label": "Timed out"}, result["status"], result["summary"], [], [], None, "")
        return result
    except Exception as exc:
        result["status"] = "failed"
        result["reason"] = "unexpected_error"
        result["message"] = "Dynamic sandbox testing failed safely without crashing the app."
        result["summary"] = "Dynamic sandbox testing failed safely without crashing the app."
        result["error"] = mask_text(str(exc))[:1500]
        result["confidence_cap"] = 69
        result["runtime_agents"] = _build_runtime_agents({"label": "Dynamic sandbox failure"}, result["status"], result["summary"], [], [], None, result["error"])
        return result
    finally:
        SANDBOX_LOCK.release()
