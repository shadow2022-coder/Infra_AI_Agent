from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from core.secret_masker import mask_text

SAFE_TEXT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".md", ".txt", ".yml", ".yaml", ".env", ".toml"}
SAFE_TEXT_NAMES = {"Dockerfile", ".dockerignore", "package.json", "requirements.txt", "README.md"}
REPAIR_AGENT_PROMPT = (
    "You are Repair Agent for InfraRed AI. Return only valid JSON. "
    "Your job is only to make a temporary sandbox copy runnable for safe runtime testing. "
    "Never remove security findings. Never hide .env evidence. Never change auth or security logic except the minimum needed for app startup. "
    "Allowed actions: create/fix Dockerfile, add/fix package.json start script, bind to 0.0.0.0, set PORT default, add minimal /health route if safe. "
    "Return JSON as {summary, changes:[{file, change_type, reason, summary, content}]}. "
    "Keep output minimal and safe."
)


def _detect_streamlit_entrypoint(raw_contents: dict[str, str]) -> Optional[str]:
    for path, content in raw_contents.items():
        if not path.endswith(".py"):
            continue
        lowered = content.lower()
        if "import streamlit" in lowered or "from streamlit import" in lowered:
            return path
    return "app.py" if "app.py" in raw_contents else None


def build_safetest_memory(
    project_id: str,
    project_name: str,
    detected_stack: str,
    static_summary: dict,
    agent_outputs: list[dict],
    masked_evidence: dict[str, str],
    startup_strategy_candidates: list[str],
) -> dict:
    # Keep the context compressed to save tokens in SafeTestAgents follow-up calls.
    agent_summaries = []
    for agent in agent_outputs:
        if not isinstance(agent, dict):
            continue
        agent_summaries.append(
            {
                "agent": agent.get("agent", "Agent"),
                "status": agent.get("status", "REVIEW"),
                "summary": agent.get("summary", ""),
                "top_risks": [
                    risk.get("title", "")
                    for risk in (agent.get("new_contextual_risks", []) if isinstance(agent.get("new_contextual_risks"), list) else [])
                    if isinstance(risk, dict)
                ][:2],
            }
        )
    return {
        "project_id": project_id,
        "project_name": project_name,
        "detected_stack": detected_stack,
        "static_summary": static_summary,
        "agent_summaries": agent_summaries,
        "startup_strategy_candidates": startup_strategy_candidates[:6],
        "masked_evidence": {path: mask_text(content[:1200]) for path, content in list(masked_evidence.items())[:10]},
        "sandbox_attempts": [],
        "repair_attempted": False,
        "repair_changes": [],
        "runtime_checks": [],
        "screenshots": [],
        "final_context": {},
    }


def collect_text_contents(project_root: Path) -> dict[str, str]:
    contents: dict[str, str] = {}
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {"node_modules", ".git", "__pycache__", ".venv"} for part in path.parts):
            continue
        if path.suffix.lower() not in SAFE_TEXT_SUFFIXES and path.name not in SAFE_TEXT_NAMES:
            continue
        try:
            contents[path.relative_to(project_root).as_posix()] = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
    return contents


def should_attempt_repair(sandbox_error: dict, detected_stack: dict, project_files: list[str]) -> dict:
    reason = str(sandbox_error.get("reason", ""))
    lowered_files = " ".join(item.lower() for item in project_files)
    stack_label = str(detected_stack.get("label", "")).lower()
    if reason in {"docker_unavailable", "playwright_not_installed", "screenshot_capture_failed", "unexpected_error", "sandbox_busy"}:
        return {"attempt": False, "reason": "Repair Agent was skipped because the failure type was not safely repairable."}
    if reason not in {"unsupported_startup", "app_not_reachable"}:
        return {"attempt": False, "reason": "Repair Agent was skipped because the failure type was not safely repairable."}
    if not any(token in lowered_files or token in stack_label for token in ("package.json", "server.js", "next", "fastapi", "requirements.txt", "main.py", "app.py", "streamlit")):
        return {"attempt": False, "reason": "Repair Agent was skipped because the runtime was not clearly identifiable."}
    return {"attempt": True, "reason": "Startup issue looks safely repairable in a temporary sandbox copy."}


def _change_record(file: str, change_type: str, reason: str, summary: str, before: str, after: str) -> dict:
    return {
        "file": file,
        "change_type": change_type,
        "reason": reason,
        "summary": summary,
        "before": mask_text(before[:240] if before else "No prior content detected"),
        "after": mask_text(after[:240] if after else "Updated in temporary sandbox copy"),
        "security_impact": "No production security issue was fixed; change only enabled runtime testing",
    }


def _node_entrypoint(raw_contents: dict[str, str]) -> Optional[str]:
    for candidate in ("server.js", "app.js", "index.js"):
        if candidate in raw_contents:
            return candidate
    return None


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _ensure_dockerignore(project_root: Path, changes: list[dict]) -> None:
    path = project_root / ".dockerignore"
    if path.exists():
        return
    content = "\n".join(["node_modules", ".git", "__pycache__", "*.html", "*.png", "*.zip", ".venv"]) + "\n"
    _write_text(path, content)
    changes.append(
        _change_record(
            ".dockerignore",
            "created",
            "Needed safer and smaller sandbox Docker context",
            "Added minimal .dockerignore for temporary sandbox build",
            "No .dockerignore detected",
            content,
        )
    )


def _ensure_package_start(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    package_path = project_root / "package.json"
    if not package_path.exists():
        return False
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    scripts = package.get("scripts", {}) if isinstance(package.get("scripts"), dict) else {}
    if "start" in scripts:
        return False
    entrypoint = _node_entrypoint(raw_contents)
    if not entrypoint:
        return False
    before = package_path.read_text(encoding="utf-8", errors="ignore")
    package.setdefault("scripts", {})
    package["scripts"]["start"] = f"node {entrypoint}"
    after = json.dumps(package, indent=2) + "\n"
    _write_text(package_path, after)
    changes.append(
        _change_record(
            "package.json",
            "modified",
            "Needed a safe start script for sandbox startup",
            f"Added npm start script using {entrypoint}",
            before,
            after,
        )
    )
    return True


def _ensure_node_dockerfile(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    package_json = raw_contents.get("package.json")
    if not package_json:
        return False
    dockerfile_path = project_root / "Dockerfile"
    entrypoint = _node_entrypoint(raw_contents) or "server.js"
    before = dockerfile_path.read_text(encoding="utf-8", errors="ignore") if dockerfile_path.exists() else "No Dockerfile detected"
    content = "\n".join(
        [
            "FROM node:20-alpine",
            "WORKDIR /app",
            "COPY package*.json ./",
            "RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; else npm install --ignore-scripts --no-audit --no-fund; fi",
            "COPY . .",
            "EXPOSE 3000",
            'CMD ["sh", "-lc", "npm run start || node ' + entrypoint + '"]',
            "",
        ]
    )
    if before == content:
        return False
    _write_text(dockerfile_path, content)
    changes.append(
        _change_record(
            "Dockerfile",
            "created" if "No Dockerfile detected" in before else "modified",
            "Needed safe Docker startup for sandbox testing",
            "Added or refreshed a minimal Node runtime Dockerfile",
            before,
            content,
        )
    )
    return True


def _ensure_fastapi_dockerfile(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    py_files = {path: content for path, content in raw_contents.items() if path.endswith(".py")}
    target = None
    for path, content in py_files.items():
        if "fastapi(" in content.lower():
            module = path[:-3].replace("/", ".")
            target = f"{module}:app"
            match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FastAPI\s*\(", content)
            if match:
                target = f"{module}:{match.group(1)}"
            break
    if not target:
        return False
    req_path = project_root / "requirements.txt"
    if not req_path.exists():
        requirements = "fastapi\nuvicorn\n"
        _write_text(req_path, requirements)
        changes.append(
            _change_record(
                "requirements.txt",
                "created",
                "Needed safe dependency inference for FastAPI sandbox startup",
                "Added minimal FastAPI runtime dependencies",
                "No requirements.txt detected",
                requirements,
            )
        )
    dockerfile_path = project_root / "Dockerfile"
    before = dockerfile_path.read_text(encoding="utf-8", errors="ignore") if dockerfile_path.exists() else "No Dockerfile detected"
    content = "\n".join(
        [
            "FROM python:3.11-slim",
            "WORKDIR /app",
            "COPY requirements.txt ./",
            "RUN pip install --no-cache-dir -r requirements.txt",
            "COPY . .",
            "EXPOSE 8000",
            f'CMD ["python", "-m", "uvicorn", "{target}", "--host", "0.0.0.0", "--port", "8000"]',
            "",
        ]
    )
    if before == content:
        return False
    _write_text(dockerfile_path, content)
    changes.append(
        _change_record(
            "Dockerfile",
            "created" if "No Dockerfile detected" in before else "modified",
            "Needed safe Docker startup for sandbox testing",
            "Added or refreshed a minimal FastAPI runtime Dockerfile",
            before,
            content,
        )
    )
    return True


def _ensure_streamlit_dockerfile(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    entrypoint = _detect_streamlit_entrypoint(raw_contents)
    requirements = raw_contents.get("requirements.txt", "")
    if not entrypoint or "streamlit" not in requirements.lower():
        return False
    dockerfile_path = project_root / "Dockerfile"
    before = dockerfile_path.read_text(encoding="utf-8", errors="ignore") if dockerfile_path.exists() else "No Dockerfile detected"
    content = "\n".join(
        [
            "FROM python:3.11-slim",
            "WORKDIR /app",
            "COPY requirements.txt ./",
            "RUN pip install --no-cache-dir -r requirements.txt",
            "COPY . .",
            "EXPOSE 8501",
            f'CMD ["python", "-m", "streamlit", "run", "{entrypoint}", "--server.address", "0.0.0.0", "--server.port", "8501", "--browser.gatherUsageStats", "false"]',
            "",
        ]
    )
    if before == content:
        return False
    _write_text(dockerfile_path, content)
    changes.append(
        _change_record(
            "Dockerfile",
            "created" if "No Dockerfile detected" in before else "modified",
            "Needed safe Streamlit startup for sandbox testing",
            "Added or refreshed a minimal Streamlit runtime Dockerfile",
            before,
            content,
        )
    )
    return True


def _replace_localhost_bindings(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    updated = False
    patterns = ['"127.0.0.1"', "'127.0.0.1'", '"localhost"', "'localhost'"]
    for rel_path, content in raw_contents.items():
        if not rel_path.endswith((".js", ".py", ".ts")):
            continue
        new_content = content
        for pattern in patterns:
            new_content = new_content.replace(pattern, '"0.0.0.0"' if pattern.startswith('"') else "'0.0.0.0'")
        if new_content == content:
            continue
        _write_text(project_root / rel_path, new_content)
        changes.append(
            _change_record(
                rel_path,
                "modified",
                "Needed app binding reachable from Docker localhost port mapping",
                "Replaced localhost-only binding with 0.0.0.0 in temporary sandbox copy",
                content,
                new_content,
            )
        )
        updated = True
    return updated


def _ensure_health_route(project_root: Path, raw_contents: dict[str, str], changes: list[dict]) -> bool:
    if any("/health" in content or "/api/health" in content for content in raw_contents.values()):
        return False
    if "server.js" in raw_contents and "express" in raw_contents["server.js"] and "app.get(" in raw_contents["server.js"]:
        before = raw_contents["server.js"]
        after = before + '\napp.get("/health", (_req, res) => res.json({ ok: true, sandboxReady: true }));\n'
        _write_text(project_root / "server.js", after)
        changes.append(
            _change_record(
                "server.js",
                "modified",
                "Needed a minimal readiness route for sandbox probing",
                "Added /health route to temporary Express sandbox copy",
                before,
                after,
            )
        )
        return True
    for rel_path, content in raw_contents.items():
        if rel_path.endswith(".py") and "fastapi(" in content.lower():
            before = content
            after = before + '\n\n@app.get("/health")\ndef health():\n    return {"ok": True, "sandboxReady": True}\n'
            _write_text(project_root / rel_path, after)
            changes.append(
                _change_record(
                    rel_path,
                    "modified",
                    "Needed a minimal readiness route for sandbox probing",
                    "Added /health route to temporary FastAPI sandbox copy",
                    before,
                    after,
                )
            )
            return True
    return False


def run_deterministic_repair(temp_project_dir: Path, startup_error: dict, detected_stack: dict) -> dict:
    raw_contents = collect_text_contents(temp_project_dir)
    changes: list[dict] = []
    _ensure_dockerignore(temp_project_dir, changes)
    changed = False
    changed |= _ensure_package_start(temp_project_dir, raw_contents, changes)
    raw_contents = collect_text_contents(temp_project_dir)
    changed |= _replace_localhost_bindings(temp_project_dir, raw_contents, changes)
    raw_contents = collect_text_contents(temp_project_dir)
    changed |= _ensure_health_route(temp_project_dir, raw_contents, changes)
    raw_contents = collect_text_contents(temp_project_dir)
    changed |= _ensure_node_dockerfile(temp_project_dir, raw_contents, changes)
    raw_contents = collect_text_contents(temp_project_dir)
    changed |= _ensure_fastapi_dockerfile(temp_project_dir, raw_contents, changes)
    raw_contents = collect_text_contents(temp_project_dir)
    changed |= _ensure_streamlit_dockerfile(temp_project_dir, raw_contents, changes)
    return {
        "attempted": True,
        "changes": changes,
        "summary": "Deterministic sandbox-enablement repair applied." if changes else "Deterministic repair found no safe minimal change to apply.",
        "raw_contents": collect_text_contents(temp_project_dir),
        "changed": changed,
    }


def run_ai_repair_agent(sanitized_context: dict, client=None) -> dict:
    if client is None:
        return {"summary": "AI repair was not called.", "changes": []}
    try:
        return client.chat_json(REPAIR_AGENT_PROMPT, sanitized_context)
    except Exception:
        return {"summary": "AI repair plan generation failed.", "changes": []}


def apply_repair_plan(temp_project_dir: Path, repair_plan: dict) -> list[dict]:
    changes: list[dict] = []
    plan_changes = repair_plan.get("changes", []) if isinstance(repair_plan, dict) else []
    for item in plan_changes[:4]:
        if not isinstance(item, dict):
            continue
        file_path = str(item.get("file", "")).strip()
        content = item.get("content")
        if not file_path or not isinstance(content, str):
            continue
        if file_path not in {"Dockerfile", ".dockerignore", "package.json", "server.js", "app.js", "index.js", "main.py", "app.py", "requirements.txt"}:
            continue
        path = temp_project_dir / file_path
        before = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else "No prior content detected"
        _write_text(path, content)
        changes.append(
            _change_record(
                file_path,
                str(item.get("change_type", "modified")),
                str(item.get("reason", "Needed safe startup for sandbox testing")),
                str(item.get("summary", "Applied AI-generated temporary sandbox repair")),
                before,
                content,
            )
        )
    return changes
