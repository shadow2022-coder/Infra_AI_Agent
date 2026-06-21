from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from core.demo_outputs import AGENT_NAMES, build_demo_agents
from core.llm_client import LLMClient

STRICT_AGENT_INSTRUCTIONS = (
    "Return only valid JSON. "
    "Do not use markdown. "
    "Do not wrap output in ```json. "
    "Do not return plain text. "
    "new_contextual_risks must always be a list of objects, never strings. "
    "If no risk is found, return status SAFE and an empty new_contextual_risks list. "
    "Deterministic rules may miss contextual vulnerabilities. Independently inspect the sanitized evidence for risks in your domain. "
    "A project with zero failed rules can still be unsafe."
)

AGENT_PROMPTS = {
    "Infra Auditor Agent": (
        "You are Infra Auditor Agent. Review sanitized static-analysis evidence only. "
        "Focus on infra, deployment, and production exposure. "
        f"{STRICT_AGENT_INSTRUCTIONS}"
    ),
    "Database Auditor Agent": (
        "You are Database Auditor Agent. Focus on data exposure, RLS, schema risk, secrets in DB tooling. "
        f"{STRICT_AGENT_INSTRUCTIONS}"
    ),
    "AppSec Agent": (
        "You are AppSec Agent. Focus on auth, sessions, routing, headers, and input handling. "
        f"{STRICT_AGENT_INSTRUCTIONS}"
    ),
    "Secrets/Supply Chain Agent": (
        "You are Secrets/Supply Chain Agent. Focus on secrets, CI/CD, dependency scripts, and package trust. "
        f"{STRICT_AGENT_INSTRUCTIONS}"
    ),
    "Red-Team Chain Agent": (
        "You are Red-Team Chain Agent. Explain likely attack chains from sanitized evidence only, "
        "without exploit payloads or live instructions. "
        f"{STRICT_AGENT_INSTRUCTIONS}"
    ),
}

FINAL_REPORTER_PROMPT = (
    "You are the Final Reporter Agent for InfraRed AI. "
    "Return only valid JSON. No markdown. No HTML. "
    "Use this exact shape: "
    "{product, detected_stack, decision, risk_score, executive_summary:{plain_english, why_this_decision, business_risk, recommended_next_step}, "
    "audit_process:[{step, what_happened}], top_risks:[{title, severity, simple_explanation, affected_files, business_impact, fix_summary, deep_dive:{technical_details, evidence, agent_reasoning_summary, exact_fix}}], "
    "safe_areas:[{title, simple_explanation, assumption}], attack_chain:{title, plain_english_summary, steps:[{label, description, related_finding}]}, "
    "what_to_fix_first:[{priority, fix, why_first, files, estimated_effort}], agent_cards:[{agent, status, one_line_summary, top_risks, top_fix, in_depth:{evidence_used, business_impact, assumptions}}]}. "
    "Keep summaries short and simple first."
)

VALID_STATUSES = {"RISK_FOUND", "SAFE", "REVIEW"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _review_fallback(agent_name: str, summary: str, assumption: str) -> dict:
    return {
        "agent": agent_name,
        "status": "REVIEW",
        "summary": summary,
        "new_contextual_risks": [
            {
                "title": f"{agent_name} could not complete reliable analysis",
                "severity": "medium",
                "evidence_used": "LLM output parsing/validation failed",
                "why_rule_engine_missed_it": "This is an AI workflow reliability issue, not a deterministic rule finding.",
                "business_impact": "The app cannot confidently claim PASS because one security specialist did not complete.",
                "fix": "Inspect the raw sanitized evidence and retry the AI Security Board.",
            }
        ],
        "safe_areas": [],
        "assumptions": [assumption],
        "normalization_status": "fallback_review",
        "output_valid": False,
    }


def extract_json_payload(raw_output) -> object:
    if isinstance(raw_output, (dict, list)):
        return raw_output
    if not isinstance(raw_output, str):
        raise ValueError("Model response was not a string or JSON object.")

    text = raw_output.strip()
    if not text:
        raise ValueError("Model response was empty.")

    fenced_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fenced_match:
        text = fenced_match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "{[":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
            return parsed
        except json.JSONDecodeError:
            continue

    raise ValueError("Could not extract valid JSON from model response.")


def _normalize_risk_item(item) -> Optional[dict]:
    if isinstance(item, dict):
        title = str(item.get("title") or "Untitled contextual risk").strip()
        severity = str(item.get("severity") or "medium").lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        return {
            "title": title,
            "severity": severity,
            "evidence_used": str(item.get("evidence_used") or "Agent did not provide structured evidence.").strip(),
            "why_rule_engine_missed_it": str(item.get("why_rule_engine_missed_it") or "The risk required contextual interpretation beyond deterministic rules.").strip(),
            "business_impact": str(item.get("business_impact") or "Needs manual validation.").strip(),
            "fix": str(item.get("fix") or "Review the related code path and apply least-privilege/security controls.").strip(),
        }
    if isinstance(item, str) and item.strip():
        return {
            "title": item.strip(),
            "severity": "medium",
            "evidence_used": "Agent-provided textual risk without structured evidence.",
            "why_rule_engine_missed_it": "The risk was returned in unstructured form.",
            "business_impact": "Needs manual validation.",
            "fix": "Review the related code path and apply least-privilege/security controls.",
        }
    return None


def normalize_agent_output(raw_output, agent_name: str) -> dict:
    try:
        payload = extract_json_payload(raw_output)
    except Exception:
        return _review_fallback(
            agent_name,
            "Agent returned an unstructured response. Manual review recommended.",
            "The model response could not be parsed into the expected schema.",
        )

    if not isinstance(payload, dict):
        return _review_fallback(
            agent_name,
            "Agent returned a non-object JSON payload. Manual review recommended.",
            "The model response was parsed but did not match the expected object schema.",
        )

    status = str(payload.get("status") or "REVIEW").strip().upper()
    if status not in VALID_STATUSES:
        status = "REVIEW"

    summary = str(payload.get("summary") or ("SAFE" if status == "SAFE" else "Agent completed with review-worthy findings.")).strip()
    safe_areas = payload.get("safe_areas", [])
    assumptions = payload.get("assumptions", [])
    risks = payload.get("new_contextual_risks", [])

    if not isinstance(safe_areas, list):
        safe_areas = [str(safe_areas)]
    if not isinstance(assumptions, list):
        assumptions = [str(assumptions)]
    if not isinstance(risks, list):
        risks = [risks]

    normalized_risks = []
    for item in risks:
        normalized = _normalize_risk_item(item)
        if normalized:
            normalized_risks.append(normalized)

    if status == "SAFE":
        normalized_risks = []
        if not summary:
            summary = "SAFE"
    elif normalized_risks and status == "SAFE":
        status = "RISK_FOUND"
    elif normalized_risks and status == "REVIEW":
        status = "RISK_FOUND"

    return {
        "agent": agent_name,
        "status": status,
        "summary": summary or "Agent completed with review-worthy findings.",
        "new_contextual_risks": normalized_risks,
        "safe_areas": [str(item).strip() for item in safe_areas if str(item).strip()],
        "assumptions": [str(item).strip() for item in assumptions if str(item).strip()],
        "normalization_status": "normalized_ok",
        "output_valid": True,
    }


def normalize_agent_outputs_list(raw_outputs) -> list[dict]:
    normalized_outputs = []
    if isinstance(raw_outputs, list):
        for index, item in enumerate(raw_outputs):
            agent_name = AGENT_NAMES[index] if index < len(AGENT_NAMES) else f"Agent {index + 1}"
            if isinstance(item, dict) and item.get("agent"):
                agent_name = str(item.get("agent"))
            normalized_outputs.append(normalize_agent_output(item, agent_name))
    return normalized_outputs


def _run_single_agent(client: LLMClient, agent_name: str, context: dict) -> dict:
    payload = {
        "agent": agent_name,
        "instructions": (
            "Use the sanitized context only. Return `agent`, `status`, `summary`, "
            "`new_contextual_risks`, `safe_areas`, and `assumptions`. "
            "Do not assume the project is safe just because deterministic findings are empty. "
            f"{STRICT_AGENT_INSTRUCTIONS}"
        ),
        "context": context,
    }
    raw_output = client.chat_completion(AGENT_PROMPTS[agent_name], payload)
    return normalize_agent_output(raw_output, agent_name)


def run_specialist_agents(context: dict, ai_mode: str, client: Optional[LLMClient] = None) -> list[dict]:
    if ai_mode == "Demo Fallback" or client is None:
        return normalize_agent_outputs_list(build_demo_agents(context))

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_run_single_agent, client, name, context): name for name in AGENT_NAMES}
        for future in as_completed(futures):
            agent_name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    _review_fallback(
                        agent_name,
                        "Agent call failed. Manual review recommended.",
                        f"The model call failed or timed out: {exc}",
                    )
                )

    by_name = {item.get("agent"): normalize_agent_output(item, item.get("agent", "Unknown Agent")) for item in results if isinstance(item, dict)}
    return [
        by_name.get(
            name,
            _review_fallback(
                name,
                "Agent did not return a usable response. Manual review recommended.",
                "No valid normalized output was available for this agent.",
            ),
        )
        for name in AGENT_NAMES
    ]


def run_final_reporter(client: Optional[LLMClient], ai_mode: str, payload: dict) -> Optional[dict]:
    if ai_mode == "Demo Fallback" or client is None:
        return None
    raw_output = client.chat_completion(FINAL_REPORTER_PROMPT, payload)
    parsed = extract_json_payload(raw_output)
    return parsed if isinstance(parsed, dict) else None
