from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime as dt
from pathlib import Path
from typing import Optional

import streamlit as st

from core.agent_runner import normalize_agent_outputs_list, run_final_reporter, run_specialist_agents
from core.context_builder import build_context
from core.dynamic_sandbox import run_dynamic_sandbox
from core.file_filter import scan_project
from core.llm_client import LLMClient
from core.repair_agent import build_safetest_memory
from core.report_renderer import render_fix_brief_markdown, render_report_html
from core.risk_scoring import build_fallback_report, get_risk_level, get_score_band, normalize_report, report_has_required_shape
from core.rule_engine import run_rules
from core.secret_masker import summarize_masking
from core.stack_detector import detect_stack
from core.zip_loader import extract_zip_bytes

ROOT = Path(__file__).parent
TEMPLATE_PATH = ROOT / "templates" / "report_template.html"
ZIP_PROMPT = """Create a small demo web application ZIP for defensive security scanner testing.

Goal:
Generate a DIFFERENT usable demo application each time. Do not repeat the same theme unless I ask. Pick one practical app idea with UI, for example: meal prep planner, fitness tracker, budget tracker, habit tracker, task manager, travel planner, study planner, invoice tool, event planner, inventory tracker, recipe finder, job application tracker, or similar.

Requirements:

1. Tech stack:

* Use one of these only: Node/Express, Python/FastAPI, or Next.js.
* Keep it small and easy to run.
* App must run locally on one port.
* Print the port clearly at startup.
* Include a health route: `/health` or `/api/health`.

2. Files to include:

* `README.md` with exact local run command.
* `package.json` or `requirements.txt`.
* `Dockerfile`.
* `.env` file with fake demo secrets only.
* App source code.
* Basic UI assets/images if useful.
* Output as a ZIP file.

3. App quality:

* Make it feel like a real usable MVP, not a blank toy app.
* Include a clean UI.
* Include sample data.
* Include at least 3 working user flows.
* Do not call real third-party APIs.
* Any “AI” or “internet” feature must be mocked locally with fake/sample responses.

4. Intentional safe demo security issues:
   Add 3 to 5 intentional but safe security issues from this list:

* committed `.env` with fake API key only
* wildcard CORS
* missing security headers
* visible fake frontend env value
* unprotected `/admin` route
* unprotected `/debug` route
* verbose error messages
* fake exposed internal config endpoint
* insecure demo cookie flag
* client-side-only fake auth

Important:

* Use fake secrets only.
* Clearly label fake/demo secrets.
* Never include real API keys.
* Do not include malware, destructive code, crypto miners, reverse shells, scanners, brute force, exploit code, credential theft, persistence, or external attack behavior.
* Do not make network calls to real third-party services.
* This is only for testing a defensive security scanner.

5. README requirements:
   The README must include:

* Project name and theme.
* What the app does.
* Exact local run commands.
* Docker run commands.
* Port number.
* Health endpoint.
* List of intentional safe demo security issues.
* Clear warning that all secrets are fake and the app is intentionally insecure for scanner testing.

6. Final output:

* Create the project folder.
* Verify it runs or at least syntax-check the code.
* Zip the folder.
* Give me the ZIP file.
"""

PROVIDER_CONFIG = {
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "models": [
            {"label": "GPT-4.1 Mini", "value": "gpt-4.1-mini"},
            {"label": "GPT-4o Mini", "value": "gpt-4o-mini"},
            {"label": "GPT-4.1", "value": "gpt-4.1"},
            {"label": "GPT-4o", "value": "gpt-4o"},
        ],
        "provider_note": "Uses OpenAI directly from the backend.",
    },
    "Optimized Model": {
        "base_url": "https://openrouter.ai/api/v1",
        "models": [
            {"label": "Claude 4.6 Sonnet", "value": "anthropic/claude-4.6-sonnet"},
        ],
        "provider_note": "Uses the FastRouter backend with a FastRouter-compatible API key.",
    },
}

API_KEY_CANDIDATES = {
    "OpenAI": ["INFRARED_OPENAI_API_KEY", "OPENAI_API_KEY", "INFRARED_API_KEY"],
    "Optimized Model": ["INFRARED_FASTROUTER_API_KEY", "OPENROUTER_API_KEY", "FASTROUTER_API_KEY", "INFRARED_API_KEY"],
}


def _resolve_sample_root() -> Path:
    candidates = [
        ROOT / "sample_project" / "insecure_next_supabase_app",
        ROOT / "demo_inputs" / "fittrack_ai_vibecode",
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return candidates[0]


SAMPLE_ROOT = _resolve_sample_root()


def _load_local_env_files(paths: Optional[list[Path]] = None) -> dict[str, str]:
    loaded: dict[str, str] = {}
    env_paths = paths or [ROOT / ".env", ROOT / ".env.local"]
    for path in env_paths:
        if not path.exists() or not path.is_file():
            continue
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if value and value[0] in {"'", '"'} and value[-1:] == value[0]:
                value = value[1:-1]
            elif " #" in value:
                value = value.split(" #", 1)[0].rstrip()
            if key not in os.environ:
                os.environ[key] = value
                loaded[key] = path.name
    return loaded


LOCAL_ENV_SOURCES = _load_local_env_files()


def _secret_value(name: str) -> str:
    try:
        value = st.secrets.get(name, "")
    except Exception:
        value = ""
    return str(value).strip() if value else ""


def _expected_api_key_names(provider: str) -> list[str]:
    return list(API_KEY_CANDIDATES.get(provider, API_KEY_CANDIDATES["Optimized Model"]))


def _configured_api_key(provider: str) -> tuple[str, str]:
    for name in _expected_api_key_names(provider):
        value = _secret_value(name)
        if value:
            return value, f"Streamlit secret `{name}`"
    for name in _expected_api_key_names(provider):
        value = os.environ.get(name, "").strip()
        if value:
            if name in LOCAL_ENV_SOURCES:
                return value, f"`{LOCAL_ENV_SOURCES[name]}` entry `{name}`"
            return value, f"environment variable `{name}`"
    return "", ""


def _dynamic_disabled_result(mode: str) -> dict:
    return {
        "enabled": False,
        "attempted": False,
        "mode": mode,
        "status": "not_enabled",
        "reason": "sandbox_disabled_in_demo_fallback" if mode == "Demo Fallback" else "",
        "friendly_message": "Sandbox testing and Repair Agent are disabled in Demo Fallback mode. Use SafeTestAgents for runtime sandbox testing." if mode == "Demo Fallback" else "Dynamic sandbox testing was not enabled.",
        "summary": "Sandbox testing and Repair Agent are disabled in Demo Fallback mode. Use SafeTestAgents for runtime sandbox testing." if mode == "Demo Fallback" else "Dynamic sandbox testing was not enabled.",
        "runtime_agents": [],
        "evidence_cards": [],
        "screenshots": [],
        "findings": [],
        "checks": [],
        "proof_metadata": {},
        "routes_tested": [],
        "screenshot_count": 0,
        "cleanup_status": "No sandbox created",
        "docker_error_sanitized": "",
        "repair_attempted": False,
        "repair_changes": [],
    }


def _augment_dynamic_result(dynamic_result: Optional[dict], mode: str) -> dict:
    result = dict(dynamic_result or {})
    result.setdefault("enabled", mode == "SafeTestAgents")
    result["attempted"] = bool(mode == "SafeTestAgents" and result.get("status") not in {None, "not_enabled"})
    result["mode"] = mode
    result.setdefault("friendly_message", result.get("message", result.get("summary", "")))
    result["tested_url"] = (result.get("proof_metadata", {}) if isinstance(result.get("proof_metadata"), dict) else {}).get("tested_url", "")
    result["routes_tested"] = (result.get("proof_metadata", {}) if isinstance(result.get("proof_metadata"), dict) else {}).get("routes_tested", [])
    result["screenshot_count"] = len(result.get("screenshots", [])) if isinstance(result.get("screenshots"), list) else int(result.get("screenshot_count", 0) or 0)
    result["docker_error_sanitized"] = result.get("technical_detail", result.get("error", ""))
    return result


def _sandbox_fix_guidance(dynamic_result: dict) -> str:
    reason = str(dynamic_result.get("reason", ""))
    if reason == "docker_unavailable":
        return "Docker Desktop was not running or not reachable. Open Docker Desktop, wait until it says running, confirm `docker info` works, then rerun SafeTestAgents."
    if reason == "unsupported_startup":
        return "No safe startup strategy was detected. Ask your coding agent to add a Dockerfile, package.json or requirements.txt, README.md with exact run command, and a /health route."
    if reason == "app_not_reachable":
        return "The container started but the app did not become reachable. Check that the app binds to 0.0.0.0, prints or documents its port, and exposes /health or /api/health."
    if reason in {"playwright_not_installed", "screenshot_capture_failed"}:
        return "Browser evidence capture failed. Run `python -m playwright install chromium`, confirm the app renders cleanly in the sandbox, then rerun SafeTestAgents."
    return "Review the sanitized sandbox error, fix the startup or runtime issue, then rerun SafeTestAgents."


def _init_state() -> None:
    st.session_state.setdefault("ai_cache", {})
    st.session_state.setdefault("dynamic_cache", {})
    st.session_state.setdefault("safetest_memory", {})
    st.session_state.setdefault("last_project_choice", "upload")
    st.session_state.setdefault("mvp_notice_dismissed", False)
    st.session_state.setdefault("scan_history", [])


def _analyze_root(project_root: Path, source_name: str, source_type: str, extracted_files: Optional[int] = None) -> dict:
    scan = scan_project(project_root)
    masking = summarize_masking(scan["raw_contents"])
    stack = detect_stack(scan["useful_files"], scan["raw_contents"])
    rules = run_rules(scan)
    context = build_context(scan, stack, rules, masking["masked_contents"])
    hash_payload = {
        "useful_files": scan["useful_files"],
        "masked_contents": {path: masking["masked_contents"].get(path, "") for path in scan["useful_files"][:40]},
        "rule_results": [{"id": item["id"], "status": item["status"], "severity": item["severity"], "file": item["file"]} for item in rules["results"]],
    }
    project_hash = hashlib.sha256(json.dumps(hash_payload, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "source_name": source_name,
        "source_type": source_type,
        "extracted_files": extracted_files if extracted_files is not None else len(scan["all_files"]),
        "scan": scan,
        "masking": masking,
        "stack": stack,
        "rules": rules,
        "context": context,
        "project_hash": project_hash,
    }


def _analyze_uploaded_file(uploaded_file) -> dict:
    extraction = extract_zip_bytes(uploaded_file.getvalue(), uploaded_file.name)
    return _analyze_root(extraction["project_root"], extraction["source_name"], extraction["source_type"], extraction["extracted_files"])


def _analyze_sample() -> dict:
    return _analyze_root(SAMPLE_ROOT, SAMPLE_ROOT.name, "sample")


def _selected_model(provider: str, preset: str) -> str:
    model_options = PROVIDER_CONFIG[provider]["models"]
    for option in model_options:
        if option["value"] == preset:
            return option["value"]
    return model_options[0]["value"]


def _model_label(provider: str, model_value: str) -> str:
    for option in PROVIDER_CONFIG[provider]["models"]:
        if option["value"] == model_value:
            return option["label"]
    return model_value


def _render_badges(badges: list[str]) -> None:
    st.markdown(" ".join(f"`{badge}`" for badge in badges) if badges else "No strong stack signals detected.")


def _short(text: str, limit: int = 120) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else f"{text[:limit - 1]}…"


def make_safe_report_base_name(uploaded_filename: Optional[str], fallback: str = "infrared_scan") -> str:
    candidate = Path(uploaded_filename or "").name
    if candidate.lower().endswith(".zip"):
        candidate = candidate[:-4]
    candidate = re.sub(r"[^A-Za-z0-9_-]+", "_", candidate).strip("._-")
    if candidate:
        return candidate
    safe_fallback = re.sub(r"[^A-Za-z0-9_-]+", "_", fallback).strip("._-")
    return safe_fallback or "infrared_scan"


def render_score_meter(score: int, decision: str) -> str:
    clamped = max(0, min(100, int(score)))
    band = get_score_band(clamped)
    color = "#ff6b7a" if clamped <= 39 else "#ffcf5a" if clamped <= 69 else "#f39c4a" if clamped <= 84 else "#62cf88"
    label = str(decision).replace("_", " ")
    return f"""
    <div style="border:1px solid rgba(255,255,255,0.12);border-radius:18px;padding:18px;background:rgba(255,255,255,0.03);display:flex;align-items:center;gap:18px;flex-wrap:wrap;">
      <div style="width:138px;height:138px;border-radius:50%;background:conic-gradient({color} 0 {clamped}%, rgba(255,255,255,0.08) {clamped}% 100%);display:flex;align-items:center;justify-content:center;flex:0 0 auto;">
        <div style="width:96px;height:96px;border-radius:50%;background:#09121d;display:flex;flex-direction:column;align-items:center;justify-content:center;border:1px solid rgba(255,255,255,0.08);">
          <div style="font-size:1.75rem;font-weight:800;line-height:1;">{clamped}</div>
          <div style="font-size:0.75rem;opacity:0.78;">/ 100</div>
        </div>
      </div>
      <div style="display:grid;gap:8px;min-width:220px;">
        <div style="font-size:0.85rem;opacity:0.8;">Confidence Score</div>
        <strong style="font-size:1.05rem;">{clamped} / 100</strong>
        <span>Status: {band}</span>
        <span>Decision: {label}</span>
      </div>
    </div>
    """


def render_risk_level_badge(risk_level: str) -> str:
    colors = {
        "Low Risk": ("#62cf88", "rgba(98,207,136,0.16)"),
        "Medium Risk": ("#ffcf5a", "rgba(255,207,90,0.16)"),
        "High Risk": ("#ff8b5e", "rgba(255,139,94,0.18)"),
        "Critical Risk": ("#ff6b7a", "rgba(255,107,122,0.18)"),
    }
    ink, bg = colors.get(risk_level, ("#ffcf5a", "rgba(255,207,90,0.16)"))
    return (
        f"<div style='display:inline-flex;align-items:center;padding:8px 12px;border-radius:999px;"
        f"background:{bg};color:{ink};font-weight:700;border:1px solid rgba(255,255,255,0.08);'>"
        f"Risk Level: {risk_level}</div>"
    )


def _record_scan_history(result: dict) -> None:
    report = result.get("final_report", {})
    agent_outputs = result.get("agent_outputs", [])
    entry = {
        "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
        "project_name": report.get("project_name", "infrared_scan"),
        "detected_stack": report.get("detected_stack", "Unknown stack"),
        "decision": report.get("decision", "REVIEW"),
        "confidence_score": int(report.get("confidence_score", report.get("risk_score", 0)) or 0),
        "confidence_status": str(report.get("confidence_status", report.get("score_band", ""))),
        "risk_level": str(report.get("risk_level", "Medium Risk")),
        "rules": {
            "pass": int(report.get("passed_tests_count", 0) or 0),
            "fail": int(report.get("failed_tests_count", 0) or 0),
            "review": int(report.get("review_tests_count", 0) or 0),
            "not_used": int(report.get("rules_not_used_count", 0) or 0),
        },
        "ai_agents": {
            "completed": max(0, int(report.get("agents_completed_count", 0) or 0) - int(report.get("incomplete_agent_count", 0) or 0)),
            "review_required": int(report.get("incomplete_agent_count", 0) or 0),
            "risk_found": sum(1 for agent in agent_outputs if isinstance(agent, dict) and agent.get("status") == "RISK_FOUND"),
            "safe": sum(1 for agent in agent_outputs if isinstance(agent, dict) and agent.get("status") == "SAFE"),
        },
        "top_risks": [
            {"title": str(item.get("title", "")), "severity": str(item.get("severity", ""))}
            for item in report.get("top_risks", [])[:3]
            if isinstance(item, dict) and item.get("title")
        ],
        "html_filename": result.get("html_filename", "report.html"),
        "md_filename": result.get("md_filename", "infrared_report.md"),
    }
    dynamic = report.get("dynamic_testing", {}) if isinstance(report.get("dynamic_testing"), dict) else {}
    if dynamic:
        entry["dynamic_testing"] = {
            "enabled": bool(dynamic.get("enabled")),
            "status": str(dynamic.get("status", "not_enabled")),
            "reason": str(dynamic.get("reason", "")),
            "repair_attempted": bool(dynamic.get("repair_attempted")),
        }
    history = st.session_state["scan_history"]
    replaced = False
    for index in range(len(history) - 1, -1, -1):
        if history[index].get("html_filename") == entry["html_filename"]:
            history[index] = entry
            replaced = True
            break
    if not replaced:
        history.append(entry)
        st.session_state["scan_history"] = history[-8:]


def _render_mvp_notice() -> None:
    if st.session_state.get("mvp_notice_dismissed"):
        return

    notice_col, dismiss_col = st.columns([12, 1])
    with notice_col:
        st.info(
            "This is an MVP demo of InfraRed AI. In this share-safe build, live AI keys load only from server-side "
            "secrets or environment variables and are never entered in the UI. Do not commit real secrets."
        )
    with dismiss_col:
        if st.button("X", key="dismiss_mvp_notice", help="Dismiss this MVP notice"):
            st.session_state["mvp_notice_dismissed"] = True
            st.rerun()


def _dynamic_summary_for_ai(dynamic_result: Optional[dict]) -> Optional[dict]:
    if not isinstance(dynamic_result, dict):
        return None
    return {
        "enabled": bool(dynamic_result.get("enabled")),
        "attempted": bool(dynamic_result.get("attempted")),
        "mode": dynamic_result.get("mode", ""),
        "status": dynamic_result.get("status", "not_enabled"),
        "reason": dynamic_result.get("reason", ""),
        "friendly_message": dynamic_result.get("friendly_message", ""),
        "summary": dynamic_result.get("summary", ""),
        "tested_url": dynamic_result.get("tested_url", ""),
        "screenshot_count": dynamic_result.get("screenshot_count", 0),
        "routes_tested": dynamic_result.get("routes_tested", []),
        "detected_port": dynamic_result.get("detected_port"),
        "original_failure": dynamic_result.get("original_failure", {}),
        "repair_attempted": bool(dynamic_result.get("repair_attempted")),
        "repair_status": dynamic_result.get("repair_status", ""),
        "repair_changes": [
            {
                "file": item.get("file"),
                "change_type": item.get("change_type"),
                "reason": item.get("reason"),
                "summary": item.get("summary"),
                "security_impact": item.get("security_impact"),
            }
            for item in (dynamic_result.get("repair_changes", []) if isinstance(dynamic_result.get("repair_changes"), list) else [])
            if isinstance(item, dict)
        ][:8],
        "findings": dynamic_result.get("findings", [])[:5] if isinstance(dynamic_result.get("findings"), list) else [],
        "checks": dynamic_result.get("checks", [])[:10] if isinstance(dynamic_result.get("checks"), list) else [],
        "screenshots": [
            {
                "title": item.get("title"),
                "route": item.get("route"),
                "file_name": item.get("file_name"),
                "summary": item.get("summary"),
                "status_code": item.get("status_code"),
                "captured_at": item.get("captured_at"),
            }
            for item in (dynamic_result.get("screenshots", []) if isinstance(dynamic_result.get("screenshots"), list) else [])
            if isinstance(item, dict)
        ][:6],
        "runtime_agents": [
            {
                "agent": item.get("agent"),
                "status": item.get("status"),
                "summary": item.get("one_line_summary"),
                "top_risks": item.get("top_risks", [])[:2],
            }
            for item in (dynamic_result.get("runtime_agents", []) if isinstance(dynamic_result.get("runtime_agents"), list) else [])
            if isinstance(item, dict)
        ],
    }


def _dynamic_status_label(dynamic_result: Optional[dict], enabled: bool = False) -> str:
    if not enabled and not isinstance(dynamic_result, dict):
        return "Not enabled"
    if enabled and not isinstance(dynamic_result, dict):
        return "Ready"
    if not isinstance(dynamic_result, dict):
        return "Not enabled"
    status = str(dynamic_result.get("status", "not_enabled"))
    reason = str(dynamic_result.get("reason", ""))
    if status == "completed":
        return "Completed"
    if status == "completed_after_repair":
        return "Completed after repair"
    if status == "repair_attempted":
        return "Repair attempted"
    if status in {"running"}:
        return "Running"
    if status == "skipped" and reason == "docker_unavailable":
        return "Docker unavailable"
    if status == "unsupported" or reason == "unsupported_startup":
        return "Unsupported startup"
    if status == "failed":
        return "Failed"
    if status == "incomplete":
        return "Failed"
    if status == "not_enabled":
        return "Not enabled"
    return status.replace("_", " ").title()


def _mode_run_label(ai_mode: str) -> str:
    return "Run SafeTestAgents Review" if ai_mode == "SafeTestAgents" else "Run Demo Fallback Review"


def _render_zip_prompt_card() -> None:
    with st.container(border=True):
        st.subheader("Need a test project ZIP?")
        st.write("Generate a small Claude/Cursor/Replit test ZIP, then upload it here.")
        with st.expander("Open test-project prompt"):
            st.code(ZIP_PROMPT, language="text")
        st.caption("Copy prompt -> generate ZIP in your AI coding tool -> upload ZIP here.")


def _refresh_cached_ai_result(analysis: dict, dynamic_result: dict) -> None:
    cached = st.session_state["ai_cache"].get(analysis["project_hash"])
    if not cached:
        return
    agent_outputs = normalize_agent_outputs_list(cached.get("agent_outputs", []))
    fallback_report = build_fallback_report(analysis["stack"], analysis["rules"], agent_outputs, dynamic_result)
    reporter_output = cached.get("final_report") if isinstance(cached.get("final_report"), dict) else None
    final_report = normalize_report(reporter_output, fallback_report)
    for key in (
        "decision",
        "risk_score",
        "confidence_score",
        "severity_counts",
        "top_risks",
        "what_to_fix_first",
        "exact_fixes",
        "attack_chain",
        "risk_level",
        "score_band",
        "confidence_status",
        "audit_process",
        "passed_tests_count",
        "failed_tests_count",
        "review_tests_count",
        "rules_not_used_count",
        "ai_contextual_risks",
        "agent_cards",
        "safe_areas",
        "agents_completed_count",
        "agents_expected_count",
        "incomplete_agent_count",
        "dynamic_testing",
    ):
        final_report[key] = fallback_report[key]
    final_report["project_name"] = reporter_output.get("project_name", "infrared_scan") if isinstance(reporter_output, dict) else "infrared_scan"
    final_report["rule_summary"] = analysis["rules"]["summary"]
    cached["agent_outputs"] = agent_outputs
    cached["final_report"] = final_report
    cached["report_html"] = render_report_html(TEMPLATE_PATH, final_report, analysis["rules"]["results"])
    cached["fix_brief_markdown"] = render_fix_brief_markdown(final_report, analysis["rules"]["results"], agent_outputs, analysis["stack"]["label"])
    st.session_state["ai_cache"][analysis["project_hash"]] = cached
    _record_scan_history(cached)


def _run_ai_board(analysis: dict, provider: str, api_key: str, model: str, base_url: str, ai_mode: str) -> dict:
    cached = st.session_state["ai_cache"].get(analysis["project_hash"])
    dynamic_result = st.session_state["dynamic_cache"].get(analysis["project_hash"])
    if ai_mode == "Demo Fallback":
        dynamic_result = _dynamic_disabled_result(ai_mode)
    elif isinstance(dynamic_result, dict):
        dynamic_result = _augment_dynamic_result(dynamic_result, ai_mode)
        if dynamic_result.get("status") != "completed":
            cached = None
            st.session_state["ai_cache"].pop(analysis["project_hash"], None)
    dynamic_summary = _dynamic_summary_for_ai(dynamic_result)
    safe_base = make_safe_report_base_name(
        analysis["source_name"] if analysis["source_type"] == "upload" else SAMPLE_ROOT.name,
        fallback="infrared_scan",
    )
    html_filename = f"{safe_base}_report.html"
    md_filename = f"{safe_base}_report.md"
    if cached:
        cached["agent_outputs"] = normalize_agent_outputs_list(cached.get("agent_outputs", []))
        cached.setdefault("html_filename", html_filename)
        cached.setdefault("md_filename", md_filename)
        if isinstance(cached.get("final_report"), dict):
            cached["final_report"]["project_name"] = safe_base
            cached["final_report"]["rule_summary"] = analysis["rules"]["summary"]
            cached["final_report"]["confidence_score"] = cached["final_report"].get("confidence_score", cached["final_report"].get("risk_score", 0))
            cached["final_report"]["score_band"] = cached["final_report"].get("score_band") or get_score_band(int(cached["final_report"].get("risk_score", 0) or 0))
            cached["final_report"]["confidence_status"] = cached["final_report"].get("confidence_status") or cached["final_report"]["score_band"]
            cached["final_report"]["risk_level"] = cached["final_report"].get("risk_level") or get_risk_level(
                cached["final_report"].get("decision", "REVIEW"),
                cached["final_report"].get("severity_counts"),
                cached["final_report"].get("ai_contextual_risks"),
            )
            if dynamic_result:
                cached["final_report"]["dynamic_testing"] = dynamic_result
    if cached and report_has_required_shape(cached.get("final_report")) and len(cached.get("agent_outputs", [])) == 5:
        cached["cached"] = True
        return cached
    if cached:
        st.session_state["ai_cache"].pop(analysis["project_hash"], None)

    client = None
    if ai_mode == "SafeTestAgents" and api_key.strip():
        client = LLMClient(api_key=api_key.strip(), model=model.strip(), base_url=base_url.strip())

    agent_outputs = run_specialist_agents(analysis["context"], ai_mode, client)
    ai_contextual_risks = [
        risk
        for agent in agent_outputs
        if isinstance(agent, dict)
        for risk in (agent.get("new_contextual_risks", []) if isinstance(agent.get("new_contextual_risks", []), list) else [])
    ]
    safetest_memory = build_safetest_memory(
        analysis["project_hash"],
        safe_base,
        analysis["stack"]["label"],
        analysis["rules"]["summary"],
        agent_outputs,
        analysis["masking"]["masked_contents"],
        [],
    )
    st.session_state["safetest_memory"][analysis["project_hash"]] = safetest_memory

    if ai_mode == "SafeTestAgents":
        if not isinstance(dynamic_result, dict) or dynamic_result.get("status") == "not_enabled":
            dynamic_result = _augment_dynamic_result(
                run_dynamic_sandbox(
                    analysis["scan"]["project_root"],
                    analysis["source_name"],
                    analysis["stack"],
                    analysis["masking"]["masked_contents"],
                    timeout_seconds=480,
                    client=client,
                    safetest_memory=safetest_memory,
                ),
                ai_mode,
            )
            st.session_state["dynamic_cache"][analysis["project_hash"]] = dynamic_result
        dynamic_summary = _dynamic_summary_for_ai(dynamic_result)
        safetest_memory["runtime_checks"] = dynamic_summary.get("checks", []) if isinstance(dynamic_summary, dict) else []
        safetest_memory["screenshots"] = dynamic_summary.get("screenshots", []) if isinstance(dynamic_summary, dict) else []
        safetest_memory["repair_attempted"] = bool(dynamic_result.get("repair_attempted"))
        safetest_memory["repair_changes"] = dynamic_result.get("repair_changes", []) if isinstance(dynamic_result.get("repair_changes"), list) else []

    agent_context = dict(analysis["context"], dynamic_testing=dynamic_summary) if dynamic_summary else analysis["context"]
    reporter_payload = {
        "context": agent_context,
        "rule_summary": analysis["rules"]["summary"],
        "failed_findings": [item for item in analysis["rules"]["results"] if item["status"] == "fail"][:25],
        "review_findings": [item for item in analysis["rules"]["results"] if item["status"] == "review"][:25],
        "specialist_agents": agent_outputs,
        "ai_contextual_risks": ai_contextual_risks,
        "safe_areas": [item for agent in agent_outputs for item in (agent.get("safe_areas", []) if isinstance(agent.get("safe_areas", []), list) else [])],
        "assumptions": [item for agent in agent_outputs for item in (agent.get("assumptions", []) if isinstance(agent.get("assumptions", []), list) else [])],
        "detected_stack": analysis["stack"]["label"],
        "file_inventory_summary": analysis["scan"]["useful_files"][:40],
        "dynamic_testing": dynamic_summary,
        "repair_changes": dynamic_result.get("repair_changes", []) if isinstance(dynamic_result, dict) else [],
        "safetest_memory": {"project_name": safetest_memory["project_name"], "agent_summaries": safetest_memory["agent_summaries"], "sandbox_attempts": safetest_memory["sandbox_attempts"]},
    }
    safetest_memory["final_context"] = {
        "dynamic_testing": reporter_payload["dynamic_testing"],
        "repair_changes": reporter_payload["repair_changes"],
        "agent_summaries": safetest_memory["agent_summaries"],
    }

    reporter_output = None
    reporter_error = None
    try:
        reporter_output = run_final_reporter(client, ai_mode, reporter_payload)
    except Exception as exc:
        reporter_error = str(exc)

    fallback_report = build_fallback_report(analysis["stack"], analysis["rules"], agent_outputs, dynamic_result)
    final_report = normalize_report(reporter_output, fallback_report)
    for key in (
        "decision",
        "risk_score",
        "confidence_score",
        "severity_counts",
        "top_risks",
        "what_to_fix_first",
        "exact_fixes",
        "attack_chain",
        "risk_level",
        "score_band",
        "confidence_status",
        "audit_process",
        "passed_tests_count",
        "failed_tests_count",
        "review_tests_count",
        "rules_not_used_count",
        "ai_contextual_risks",
        "agent_cards",
        "safe_areas",
        "agents_completed_count",
        "agents_expected_count",
        "incomplete_agent_count",
        "dynamic_testing",
    ):
        final_report[key] = fallback_report[key]
    final_report["project_name"] = safe_base
    final_report["rule_summary"] = analysis["rules"]["summary"]
    final_report["dynamic_testing"] = dynamic_result or final_report.get("dynamic_testing") or _dynamic_disabled_result(ai_mode)
    report_html = render_report_html(TEMPLATE_PATH, final_report, analysis["rules"]["results"])
    fix_brief = render_fix_brief_markdown(final_report, analysis["rules"]["results"], agent_outputs, analysis["stack"]["label"])
    result = {
        "cached": False,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "ai_mode": ai_mode,
        "agent_outputs": agent_outputs,
        "final_report": final_report,
        "report_html": report_html,
        "fix_brief_markdown": fix_brief,
        "reporter_error": reporter_error,
        "html_filename": html_filename,
        "md_filename": md_filename,
    }
    st.session_state["ai_cache"][analysis["project_hash"]] = result
    _record_scan_history(result)
    return result


def _render_agent_cards(agent_cards: list[dict]) -> None:
    cols = st.columns(len(agent_cards))
    for idx, card in enumerate(agent_cards):
        with cols[idx]:
            st.markdown(f"**{card['agent']}**")
            st.caption(card["status"])
            st.write(_short(card.get("one_line_summary", ""), 110))
            st.caption("Fallback-normalized review output" if card.get("output_valid") is False else "Valid normalized output")
            risks = card.get("top_risks", [])[:2]
            if risks:
                for risk in risks:
                    st.write(f"- {_short(risk, 70)}")
            else:
                st.write("- No major contextual risk highlighted.")
            st.caption(f"Top fix: {_short(card.get('top_fix', ''), 80)}")
            with st.expander("In-depth analysis"):
                in_depth = card.get("in_depth", {})
                st.write("Evidence used")
                st.caption(in_depth.get("evidence_used", ""))
                if in_depth.get("rule_findings_used"):
                    st.write("Rule findings used")
                    st.write(in_depth["rule_findings_used"])
                st.write("Why the rule engine may have missed it")
                st.caption(in_depth.get("why_rule_engine_may_have_missed_it", ""))
                st.write("Business impact")
                st.caption(in_depth.get("business_impact", ""))
                st.write("Exact fix")
                st.caption(in_depth.get("exact_fix", ""))
                if in_depth.get("assumptions"):
                    st.write("Assumptions")
                    st.write(in_depth["assumptions"])


def _render_attack_chain(chain: dict) -> None:
    steps = chain.get("steps", []) if isinstance(chain, dict) else []
    st.write(chain.get("plain_english_summary", ""))
    if not steps:
        st.caption("No complete attack chain found from the available evidence.")
        return
    cols = st.columns(len(steps))
    for idx, step in enumerate(steps):
        with cols[idx]:
            st.markdown(f"**{step.get('label', f'Step {idx + 1}')}**")
            st.caption(step.get("description", ""))
            if step.get("related_finding"):
                st.write(f"`{step['related_finding']}`")


def _render_attack_coverage_matrix(items: list[dict]) -> None:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "Category": item.get("category", "Attack surface"),
                "Status": item.get("status", "Manual review"),
                "Why": item.get("reason", ""),
            }
        )
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)


def _render_dynamic_testing(dynamic_result: Optional[dict], enabled: bool = False) -> None:
    status_label = _dynamic_status_label(dynamic_result, enabled)
    if not enabled and not isinstance(dynamic_result, dict):
        st.caption("Dynamic Sandbox Testing: Not enabled.")
        return
    if enabled and not isinstance(dynamic_result, dict):
        st.caption("Dynamic Sandbox Testing: Ready. Use the sidebar button to run it.")
        return
    if not isinstance(dynamic_result, dict):
        st.caption("Dynamic Sandbox Testing: Not enabled.")
        return
    if dynamic_result.get("mode") == "Demo Fallback":
        st.caption("Sandbox testing is disabled in Demo Fallback mode. Use SafeTestAgents for runtime sandbox testing.")
        return
    status = str(dynamic_result.get("status", "not_enabled"))
    reason = str(dynamic_result.get("reason", ""))
    if status == "skipped" and reason == "docker_unavailable":
        st.warning("Dynamic Sandbox Testing needs Docker Desktop")
        st.markdown(
            "1. Open Docker Desktop.\n"
            "2. Wait until Docker says it is running.\n"
            "3. Return to InfraRed AI.\n"
            "4. Click `Retry Dynamic Sandbox Testing`."
        )
        st.caption("Static scan, rule checks, AI agents, HTML report, and Markdown report still work without Docker.")
        st.write(dynamic_result.get("message", "Docker Desktop is not running or Docker socket is unavailable."))
        with st.expander("Technical detail"):
            if dynamic_result.get("technical_detail"):
                st.code(dynamic_result["technical_detail"])
            st.code("docker version\ndocker info", language="bash")
        return
    if status == "unsupported" or reason == "unsupported_startup":
        st.info("Sandbox skipped: no safe startup strategy was detected for this project. Add a Dockerfile and README run command, then retry.")
        st.caption(_sandbox_fix_guidance(dynamic_result))
        return
    if status in {"failed", "incomplete"}:
        st.warning(dynamic_result.get("message", "Dynamic sandbox testing failed safely without crashing the app."))
        st.caption(_sandbox_fix_guidance(dynamic_result))
        if dynamic_result.get("repair_changes"):
            st.info("These changes were applied only to a temporary sandbox copy. The original uploaded project ZIP was not modified.")
            st.dataframe(dynamic_result["repair_changes"], use_container_width=True, hide_index=True)
        with st.expander("Technical detail"):
            if dynamic_result.get("technical_detail"):
                st.code(dynamic_result["technical_detail"])
            elif dynamic_result.get("error"):
                st.code(dynamic_result["error"])
        return
    if status not in {"completed", "completed_after_repair"}:
        st.caption(f"Dynamic Sandbox Testing: {status_label}.")
        return
    st.write(dynamic_result.get("summary", "No dynamic sandbox result available."))
    a, b, c, d = st.columns(4)
    a.metric("Status", status_label)
    b.metric("Runtime findings", len(dynamic_result.get("findings", [])) if isinstance(dynamic_result.get("findings"), list) else 0)
    c.metric("Detected localhost port", dynamic_result.get("detected_port") or "N/A")
    d.metric("Cleanup", dynamic_result.get("cleanup_status", "pending"))
    timeline = dynamic_result.get("timeline", []) if isinstance(dynamic_result.get("timeline"), list) else []
    if timeline:
        st.caption("Sandbox status timeline")
        for item in timeline:
            if not isinstance(item, dict):
                continue
            detail = f" - {item.get('detail')}" if item.get("detail") else ""
            st.write(f"{item.get('step', 'Step')}: {item.get('status', 'pending')}{detail}")
    proof_metadata = dynamic_result.get("proof_metadata", {}) if isinstance(dynamic_result.get("proof_metadata"), dict) else {}
    if proof_metadata:
        with st.expander("Sandbox Proof / Runtime Evidence"):
            st.write("Real sandbox evidence captured inside a disposable local Docker container." if dynamic_result.get("screenshots") else "Runtime proof metadata from the disposable Docker sandbox.")
            st.write(f"Tested URL: {proof_metadata.get('tested_url', 'N/A')}")
            st.write(f"Timestamp: {proof_metadata.get('timestamp', 'N/A')}")
            st.write(f"Docker image name: {proof_metadata.get('docker_image_name', 'N/A')}")
            st.write(f"Short container id: {proof_metadata.get('container_id_short', 'N/A')}")
            st.write(f"Routes tested: {', '.join(proof_metadata.get('routes_tested', []) or []) or 'N/A'}")
            st.write(f"Routes captured: {', '.join(proof_metadata.get('routes_captured', []) or []) or 'N/A'}")
            st.write(f"Screenshot count: {proof_metadata.get('screenshot_count', 0)}")
            if proof_metadata.get("readiness_note"):
                st.write(f"Readiness: {proof_metadata.get('readiness_note')}")
            st.write(f"Cleanup status: {proof_metadata.get('cleanup_status', dynamic_result.get('cleanup_status', 'pending'))}")
    runtime_agents = dynamic_result.get("runtime_agents", [])
    if runtime_agents:
        st.caption("Runtime agents")
        _render_agent_cards(runtime_agents)
    repair_changes = dynamic_result.get("repair_changes", [])
    if repair_changes:
        st.caption("Changes Made to Enable Sandbox Testing")
        st.info("These changes were applied only to a temporary sandbox copy. The original uploaded project ZIP was not modified.")
        st.dataframe(repair_changes, use_container_width=True, hide_index=True)
    screenshots = dynamic_result.get("screenshots", [])
    if screenshots:
        st.caption("Real Playwright browser screenshots")
        cols = st.columns(min(3, len(screenshots)))
        for index, shot in enumerate(screenshots[:6]):
            with cols[index % len(cols)]:
                if shot.get("image_data_url"):
                    st.image(shot["image_data_url"], caption=shot.get("title", "Browser screenshot"), use_container_width=True)
                else:
                    st.write("Thumbnail unavailable")
                st.caption(shot.get("summary", ""))
                with st.expander("View full screenshot"):
                    if shot.get("image_data_url"):
                        st.image(shot["image_data_url"], caption=shot.get("title", "Browser screenshot"))
                    st.caption(f"Route tested: {shot.get('route', '/')} | Status code: {shot.get('status_code', 0)} | Timestamp: {shot.get('captured_at', '')}")
    elif status in {"completed", "completed_after_repair"}:
        st.caption("No browser screenshots captured.")
    evidence_cards = dynamic_result.get("evidence_cards", [])
    if evidence_cards and not screenshots:
        st.caption("Runtime Evidence Cards")
        cols = st.columns(min(3, len(evidence_cards)))
        for index, card in enumerate(evidence_cards[:3]):
            with cols[index % len(cols)]:
                if card.get("image_data_url"):
                    st.image(card["image_data_url"], caption=card.get("title", "Sanitized evidence card"), use_container_width=True)
                st.write(f"**{card.get('title', 'Sanitized evidence card')}**")
                st.caption(card.get("summary", ""))
    checks = dynamic_result.get("checks", [])
    if checks:
        with st.expander("Runtime checks table"):
            st.dataframe(checks, use_container_width=True, hide_index=True)
    findings = dynamic_result.get("findings", [])
    if findings:
        with st.expander("Dynamic runtime findings"):
            st.dataframe(findings, use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(page_title="InfraRed AI", page_icon=":shield:", layout="wide")
    _init_state()

    st.title("Review an AI-built app before you ship it.")
    st.caption("Start with the decision, then open the technical evidence only when you need it.")
    _render_mvp_notice()
    _render_zip_prompt_card()

    with st.sidebar:
        st.header("Settings")
        st.subheader("API")
        provider = st.selectbox("AI Provider", list(PROVIDER_CONFIG.keys()))
        api_key, api_key_source = _configured_api_key(provider)
        model_options = PROVIDER_CONFIG[provider]["models"]
        model_preset = st.selectbox(
            "Model",
            [option["value"] for option in model_options],
            key=f"{provider}_preset",
            format_func=lambda value: _model_label(provider, value),
        )
        model = _selected_model(provider, model_preset)
        ai_mode = st.radio("AI Mode", ["SafeTestAgents", "Demo Fallback"])
        if api_key:
            st.success(f"Live AI key loaded from {api_key_source}. The key is hidden from all app users.")
        else:
            expected_names = ", ".join(f"`{name}`" for name in _expected_api_key_names(provider))
            st.warning("No live AI key is configured for this provider.")
            st.caption(f"For Codespaces or hosted demos, set one of these server-side secret names: {expected_names}")
        st.caption(PROVIDER_CONFIG[provider].get("provider_note", ""))
        if ai_mode == "SafeTestAgents":
            st.caption("SafeTestAgents: Runs real parallel AI agents and attempts disposable Docker sandbox testing with browser evidence.")
        else:
            st.caption("Demo Fallback: Fast demo mode. Uses fallback AI-agent style output only. Sandbox testing and Repair Agent are disabled.")
        st.radio("Context Mode", ["Compressed"], index=0)
        st.caption(
            f"Selected model: `{_model_label(provider, model)}`. API keys are loaded server-side only and are never shown in the UI."
        )
        st.divider()
        st.subheader("Recent Scans This Session")
        if st.button("Clear history", use_container_width=True):
            st.session_state["scan_history"] = []
        history = list(reversed(st.session_state["scan_history"]))
        if not history:
            st.caption("No completed scans yet in this session.")
        for item in history:
            with st.expander(f"{item['project_name']} · {item['decision']} · Confidence Score {item['confidence_score']}/100"):
                st.caption(item["timestamp"])
                st.write(f"Stack: {item['detected_stack']}")
                st.write(f"Confidence Score: {item['confidence_score']} / 100")
                st.write(f"Status: {item['confidence_status']}")
                st.write(f"Risk Level: {item['risk_level']}")
                st.write(
                    f"Applicable Issues: {item['rules']['fail'] + item['rules']['review']} "
                    f"({item['rules']['fail']} fail, {item['rules']['review']} review)"
                )
                st.write(f"Passed Rules: {item['rules']['pass']}")
                st.write(f"Not Used Rules: {item['rules']['not_used']}")
                st.write(
                    f"AI agents: {item['ai_agents']['completed']} completed / "
                    f"{item['ai_agents']['review_required']} review required"
                )
                dynamic = item.get("dynamic_testing", {})
                if dynamic.get("enabled"):
                    label = "Skipped - Docker unavailable" if dynamic.get("status") == "skipped" and dynamic.get("reason") == "docker_unavailable" else str(dynamic.get("status", "unknown"))
                    st.write(f"Dynamic Sandbox Testing: {label}")
                    if dynamic.get("reason"):
                        st.caption(f"Reason: {dynamic.get('reason')}")
                for risk in item["top_risks"]:
                    st.caption(f"{risk['severity']}: {risk['title']}")

    st.subheader("Upload Project")
    upload_col, sample_col = st.columns([3, 1])
    sample_available = SAMPLE_ROOT.exists() and SAMPLE_ROOT.is_dir()
    with upload_col:
        uploaded_file = st.file_uploader("Upload a full project ZIP", type=["zip"])
    with sample_col:
        use_sample = st.button("Use built-in demo", use_container_width=True, disabled=not sample_available)
    if not sample_available:
        st.warning("The built-in demo project is missing from this checkout, so only ZIP upload is available.")

    analysis = None
    if use_sample:
        st.session_state["last_project_choice"] = "sample"
        analysis = _analyze_sample()
    elif uploaded_file is not None:
        st.session_state["last_project_choice"] = "upload"
        analysis = _analyze_uploaded_file(uploaded_file)
    elif st.session_state["last_project_choice"] == "sample":
        analysis = _analyze_sample()

    if not analysis:
        st.info("Upload a ZIP or use the built-in demo project to start the review.")
        return

    dynamic_result = st.session_state["dynamic_cache"].get(analysis["project_hash"])

    scan = analysis["scan"]
    masking = analysis["masking"]
    rules = analysis["rules"]

    st.subheader("File Extraction Summary")
    a, b, c = st.columns(3)
    a.metric("Files discovered", len(scan["all_files"]))
    b.metric("Files scanned", scan["scanned_file_count"])
    c.metric("Junk ignored", len(scan["ignored_files"]))
    st.caption(f"Source: {analysis['source_name']} ({analysis['source_type']})")
    with st.expander("Useful files detected"):
        st.write(scan["useful_files"][:40])

    st.subheader("Detected Stack")
    _render_badges(analysis["stack"]["badges"])

    st.subheader("Secret Masking Status")
    st.success(f"Masking active. {masking['masked_file_count']} file(s) had secrets or sensitive tokens masked before display, reporting, or AI context assembly.")

    st.subheader("Rule-Based Security Tests")
    d, e, f, g, h = st.columns(5)
    applicable_issues = [item for item in rules["results"] if item["status"] in {"fail", "review"}]
    passed_rules = [item for item in rules["results"] if item["status"] == "pass"]
    not_used_rules = [item for item in rules["results"] if item["status"] == "not_applicable"]
    d.metric("Applicable Issues", len(applicable_issues))
    e.metric("Failed", rules["summary"]["failed"])
    f.metric("Review", rules["summary"]["review"])
    g.metric("Passed Rules", rules["summary"]["passed"])
    h.metric("Not Used Rules", rules["summary"].get("not_applicable", 0))
    st.caption("Default view shows only applicable rules that did not pass.")
    if applicable_issues:
        st.dataframe(applicable_issues[:50], use_container_width=True, hide_index=True)
    else:
        st.success("No applicable issues found in deterministic rule checks.")
    with st.expander("Passed Rules"):
        st.dataframe(passed_rules, use_container_width=True, hide_index=True)
    with st.expander("Not Used / Not Applicable Rules"):
        st.caption("These checks were not used because the required stack, file, or condition was not present.")
        st.dataframe(not_used_rules, use_container_width=True, hide_index=True)
    with st.expander("All Rule Results"):
        st.dataframe(rules["results"], use_container_width=True, hide_index=True)

    st.subheader("AI Security Board")
    st.info("This will run 5 specialist agent calls + 1 final reporter call. Secrets are masked. Context is compressed.")
    if analysis["project_hash"] in st.session_state["ai_cache"]:
        st.caption("Cached AI result available for this masked project hash.")
    can_run_real = ai_mode == "Demo Fallback" or bool(api_key)
    run_ai = st.button(_mode_run_label(ai_mode), type="primary", disabled=not can_run_real)
    if ai_mode == "SafeTestAgents" and not api_key:
        expected_names = ", ".join(_expected_api_key_names(provider))
        st.caption(f"Configure a server-side key to enable SafeTestAgents. Accepted names: {expected_names}.")

    ai_result = st.session_state["ai_cache"].get(analysis["project_hash"])
    if ai_result:
        ai_result["agent_outputs"] = normalize_agent_outputs_list(ai_result.get("agent_outputs", []))
    if ai_result and not report_has_required_shape(ai_result.get("final_report")):
        st.session_state["ai_cache"].pop(analysis["project_hash"], None)
        ai_result = None
    if run_ai:
        status_box = st.status("Running SafeTestAgents" if ai_mode == "SafeTestAgents" else "Running Demo Fallback", expanded=True)
        for message in (
            "Running Infra Auditor Agent...",
            "Running Database Auditor Agent...",
            "Running AppSec Agent...",
            "Running Secrets/Supply Chain Agent...",
            "Running Red-Team Chain Agent...",
            *(
                (
                    "Attempting dynamic Docker sandbox testing...",
                    "Running Playwright browser runtime checks...",
                    "Capturing sanitized runtime screenshots...",
                )
                if ai_mode == "SafeTestAgents"
                else ()
            ),
            "Final Reporter Agent...",
        ):
            status_box.write(message)
        with st.spinner("Running masked parallel agent review..."):
            ai_result = _run_ai_board(analysis, provider, api_key, model, PROVIDER_CONFIG[provider]["base_url"], ai_mode)
        completed = ai_result["final_report"].get("agents_completed_count", len(ai_result.get("agent_outputs", [])))
        expected = ai_result["final_report"].get("agents_expected_count", 5)
        incomplete = ai_result["final_report"].get("incomplete_agent_count", 0)
        status_box.update(label=f"{completed}/{expected} agents completed" if incomplete == 0 else f"{completed - incomplete}/{expected} agents completed, {incomplete} requires review", state="complete")
    if not ai_result:
        return

    st.caption(
        f"Provider: {ai_result['provider']} | Model: {_model_label(ai_result['provider'], ai_result['model'])} | Mode: {ai_result['ai_mode']}"
        + (" | Using cached result" if ai_result["cached"] else "")
    )

    report = ai_result["final_report"]
    st.subheader("Final Reporter")
    st.markdown(render_score_meter(report["confidence_score"], report["decision"]), unsafe_allow_html=True)
    st.markdown(render_risk_level_badge(report.get("risk_level", "Medium Risk")), unsafe_allow_html=True)
    p, q, r = st.columns(3)
    p.metric("Decision", str(report["decision"]).replace("_", " "))
    q.metric("Confidence Score", report["confidence_score"])
    r.metric("Critical findings", report["severity_counts"]["critical"])
    st.subheader("Current Scan Summary")
    st.write(f"Project name: `{report.get('project_name', 'infrared_scan')}`")
    st.write(f"Detected stack: {report.get('detected_stack', analysis['stack']['label'])}")
    st.write(f"Scan Confidence: {report.get('scan_confidence', 'Medium')}")
    st.write(f"Confidence Score: {report.get('confidence_score', report.get('risk_score', 0))} / 100")
    st.write(f"Status: {report.get('confidence_status', report.get('score_band', ''))}")
    st.write(f"Risk Level: {report.get('risk_level', 'Medium Risk')}")
    st.write(
        f"Applicable Issues: {rules['summary']['failed'] + rules['summary']['review']} "
        f"({rules['summary']['failed']} fail, {rules['summary']['review']} review)"
    )
    st.write(f"Passed Rules: {rules['summary']['passed']}")
    st.write(f"Not Used Rules: {rules['summary'].get('not_applicable', 0)}")
    st.write(
        f"AI agents: {max(0, report.get('agents_completed_count', 0) - report.get('incomplete_agent_count', 0))} completed / "
        f"{report.get('incomplete_agent_count', 0)} review required"
    )
    summary = report["executive_summary"]
    st.write(summary.get("plain_english", ""))
    st.caption(summary.get("why_this_decision", ""))
    st.caption(summary.get("recommended_next_step", ""))
    st.caption(
        f"Applicable Issues: {rules['summary']['failed'] + rules['summary']['review']} | "
        f"Passed Rules: {rules['summary']['passed']} | Not Used Rules: {rules['summary'].get('not_applicable', 0)}"
    )
    reliable_agents = max(0, report.get("agents_completed_count", 0) - report.get("incomplete_agent_count", 0))
    if report.get("incomplete_agent_count", 0):
        st.caption(f"AI agents: {reliable_agents}/{report.get('agents_expected_count', 5)} completed, {report.get('incomplete_agent_count', 0)} requires review")
    else:
        st.caption(f"AI agents: {reliable_agents}/{report.get('agents_expected_count', 5)} completed")
    with st.expander("Audit process"):
        for step in report.get("audit_process", []):
            st.write(f"**{step.get('step', '')}**")
            st.caption(step.get("what_happened", ""))

    st.subheader("Why This Decision")
    st.write(summary.get("why_this_decision", ""))
    st.caption(summary.get("recommended_next_step", ""))
    with st.expander("Attack chain"):
        _render_attack_chain(report.get("attack_chain", {}))
    with st.expander("What to fix first"):
        for item in report.get("what_to_fix_first", [])[:5]:
            st.write(f"{item.get('priority', 0)}. {item.get('fix', '')}")
            st.caption(f"{item.get('why_first', '')} | Effort: {item.get('estimated_effort', '')} | Files: {', '.join(item.get('files', [])) or 'N/A'}")
    with st.expander("Attack Coverage Matrix"):
        _render_attack_coverage_matrix(report.get("attack_coverage_matrix", []))

    st.subheader("Top Risks")
    for risk in report.get("top_risks", [])[:6]:
        with st.container(border=True):
            st.markdown(f"**{risk.get('title', '')}**")
            st.caption(f"{risk.get('severity', '').upper()} | {risk.get('simple_explanation', '')}")
            st.write(risk.get("fix_summary", ""))
            with st.expander("View technical details"):
                deep = risk.get("deep_dive", {})
                st.write("Affected files")
                st.write(risk.get("affected_files", []))
                st.write("Business impact")
                st.caption(risk.get("business_impact", ""))
                st.write("Technical details")
                st.caption(deep.get("technical_details", ""))
                st.write("Evidence")
                st.caption(deep.get("evidence", ""))
                st.write("Exact fix")
                st.caption(deep.get("exact_fix", ""))

    st.subheader("Safe Areas")
    for item in report.get("safe_areas", [])[:6]:
        title = item.get("title", "Safe area") if isinstance(item, dict) else "Safe area"
        text = item.get("simple_explanation", "") if isinstance(item, dict) else str(item)
        assumption = item.get("assumption", "") if isinstance(item, dict) else ""
        st.write(f"**{title}**")
        st.caption(text)
        if assumption:
            st.caption(f"Assumption: {assumption}")

    st.subheader("AI Security Board")
    _render_agent_cards(report.get("agent_cards", []))

    dynamic_result = report.get("dynamic_testing", dynamic_result)
    _render_dynamic_testing(dynamic_result, ai_mode == "SafeTestAgents")

    with st.expander("Detailed rules"):
        st.dataframe([item for item in rules["results"] if item["status"] in {"fail", "review"}], use_container_width=True, hide_index=True)
        if ai_result.get("reporter_error"):
            st.caption(f"Reporter fallback used: {ai_result['reporter_error']}")

    st.subheader("Downloads")
    st.download_button(
        f"Download {ai_result['html_filename']}",
        data=ai_result["report_html"],
        file_name=ai_result["html_filename"],
        mime="text/html",
    )
    st.download_button(
        f"Download {ai_result['md_filename']}",
        data=ai_result["fix_brief_markdown"],
        file_name=ai_result["md_filename"],
        mime="text/markdown",
    )


if __name__ == "__main__":
    main()
