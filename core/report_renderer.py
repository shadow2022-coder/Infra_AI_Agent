from __future__ import annotations

import json
from pathlib import Path

from core.secret_masker import mask_json_payload


def _dynamic_status_line(dynamic_testing: dict) -> str:
    status = str(dynamic_testing.get("status", "not_enabled"))
    reason = str(dynamic_testing.get("reason", ""))
    if not dynamic_testing.get("enabled"):
        return "Dynamic Sandbox Testing: Not enabled"
    if status == "skipped" and reason == "docker_unavailable":
        return "Dynamic Sandbox Testing: Skipped - Docker unavailable"
    if status == "unsupported" or reason == "unsupported_startup":
        return "Dynamic Sandbox Testing: Skipped - Unsupported startup"
    if status in {"completed", "completed_after_repair"}:
        return "Dynamic Sandbox Testing: Completed"
    return f"Dynamic Sandbox Testing: {status.replace('_', ' ').title()}"


def _dynamic_reason_line(dynamic_testing: dict) -> str:
    reason = str(dynamic_testing.get("reason", ""))
    if reason == "docker_unavailable":
        return "Reason: Docker Desktop is not running or Docker socket is unavailable."
    if reason == "unsupported_startup":
        return "Reason: No safe startup strategy was detected. Add a Dockerfile and README run command to enable sandbox testing."
    if reason == "sandbox_disabled_in_demo_fallback":
        return "Reason: Sandbox testing is disabled in Demo Fallback mode."
    if reason == "app_not_reachable":
        return "Reason: The sandbox app did not become safely reachable on localhost in time."
    if reason in {"playwright_not_installed", "screenshot_capture_failed"}:
        return "Reason: Browser evidence capture failed."
    if reason:
        return f"Reason: {reason.replace('_', ' ')}."
    return ""


def _sandbox_fix_guidance(dynamic_testing: dict) -> str:
    reason = str(dynamic_testing.get("reason", ""))
    if reason == "docker_unavailable":
        return "Docker Desktop was not running or not reachable. Open Docker Desktop, wait until it says running, confirm `docker info` works, then rerun SafeTestAgents."
    if reason == "unsupported_startup":
        return "No safe startup strategy was detected. Ask your coding agent to add a Dockerfile, package.json or requirements.txt, README.md with exact run command, and a /health route."
    if reason == "app_not_reachable":
        return "The container started but the app did not become reachable. Check that the app binds to 0.0.0.0, prints or documents its port, and exposes /health or /api/health."
    if reason in {"playwright_not_installed", "screenshot_capture_failed"}:
        return "Browser evidence capture failed. Run `python -m playwright install chromium`, confirm the app renders cleanly in the sandbox, then rerun SafeTestAgents."
    return "Review the sanitized sandbox error, fix the issue, then rerun SafeTestAgents."


def render_report_html(template_path: Path, report_payload: dict, rules: list[dict]) -> str:
    template = template_path.read_text(encoding="utf-8")
    data = {
        "report": mask_json_payload(report_payload),
        "rules": mask_json_payload(rules),
    }
    safe_json = (
        json.dumps(data)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    return template.replace("__REPORT_DATA__", safe_json)


def render_fix_brief_markdown(report_data: dict, rule_results: list[dict], agent_outputs: list[dict], detected_stack: str) -> str:
    masked_report = mask_json_payload(report_data)
    findings = [item for item in mask_json_payload(rule_results) if item["status"] in {"fail", "review"}][:6]
    ai_risks = masked_report.get("ai_contextual_risks", []) if isinstance(masked_report.get("ai_contextual_risks"), list) else []
    rules_summary = masked_report.get("rule_summary", {})
    dynamic_testing = masked_report.get("dynamic_testing", {}) if isinstance(masked_report.get("dynamic_testing"), dict) else {}
    dynamic_findings = dynamic_testing.get("findings", []) if isinstance(dynamic_testing.get("findings"), list) else []
    dynamic_checks = dynamic_testing.get("checks", []) if isinstance(dynamic_testing.get("checks"), list) else []
    screenshots = dynamic_testing.get("screenshots", []) if isinstance(dynamic_testing.get("screenshots"), list) else []
    proof_metadata = dynamic_testing.get("proof_metadata", {}) if isinstance(dynamic_testing.get("proof_metadata"), dict) else {}
    timeline = dynamic_testing.get("timeline", []) if isinstance(dynamic_testing.get("timeline"), list) else []
    dynamic_status_line = _dynamic_status_line(dynamic_testing)
    dynamic_reason_line = _dynamic_reason_line(dynamic_testing)
    completed_dynamic = dynamic_testing.get("status") in {"completed", "completed_after_repair"}
    dynamic_mode = str(dynamic_testing.get("mode", ""))
    repair_changes = dynamic_testing.get("repair_changes", []) if isinstance(dynamic_testing.get("repair_changes"), list) else []
    lines = [
        "# InfraRed AI Fix Brief",
        "",
        "## Project",
        str(masked_report.get("project_name", "infrared_scan")),
        "",
        "## Goal",
        "Fix the security issues found by InfraRed AI without rewriting the app.",
        "",
        "## Detected Stack",
        detected_stack or masked_report.get("detected_stack", "Unknown stack"),
        "",
        "## Deployment Decision",
        str(masked_report.get("decision", "REVIEW")),
        "",
        "## Confidence Score",
        f"{masked_report.get('confidence_score', masked_report.get('risk_score', 0))} / 100",
        f"Status: {masked_report.get('confidence_status', masked_report.get('score_band', ''))}",
        "",
        "## Risk Level",
        str(masked_report.get("risk_level", "Medium Risk")),
        "",
        "## Scan Confidence",
        str(masked_report.get("scan_confidence", "Medium")),
        "",
        "## Deterministic Rule Summary",
        f"- Applicable Issues: {rules_summary.get('failed', masked_report.get('failed_tests_count', 0)) + rules_summary.get('review', masked_report.get('review_tests_count', 0))}",
        f"- Failed Applicable Rules: {rules_summary.get('failed', masked_report.get('failed_tests_count', 0))}",
        f"- Review Applicable Rules: {rules_summary.get('review', masked_report.get('review_tests_count', 0))}",
        f"- Passed Rules: {rules_summary.get('passed', masked_report.get('passed_tests_count', 0))}",
        f"- Not Used Rules: {rules_summary.get('not_applicable', masked_report.get('rules_not_used_count', 0))}",
        "",
        "## AI Security Board Summary",
        f"- Agents completed: {masked_report.get('agents_completed_count', 0)}/{masked_report.get('agents_expected_count', 5)}",
        f"- Agents requiring review: {masked_report.get('incomplete_agent_count', 0)}",
        f"- Contextual risks found: {len(ai_risks)}",
        "",
        "## Dynamic Sandbox Testing",
        f"- {dynamic_status_line}",
        *( [f"- {dynamic_reason_line}"] if dynamic_reason_line else [] ),
        f"- Summary: {dynamic_testing.get('summary', 'Dynamic sandbox testing was not enabled.')}",
        f"- Runtime findings: {len(dynamic_findings)}",
        "",
        "## Rules For The Coding Agent",
        "- Do not rewrite the whole project.",
        "- Do not remove existing business logic.",
        "- Do not expose secrets in frontend code.",
        "- Do not hardcode new secrets.",
        "- Do not disable authentication or authorization.",
        "- Do not weaken validation to make tests pass.",
        "- Keep fixes minimal and targeted.",
        "- After changes, run the validation checklist.",
        "",
    ]
    coverage_matrix = masked_report.get("attack_coverage_matrix", []) if isinstance(masked_report.get("attack_coverage_matrix"), list) else []
    if coverage_matrix:
        lines.extend(["## Attack Coverage Matrix"])
        for item in coverage_matrix:
            if not isinstance(item, dict):
                continue
            lines.append(f"- {item.get('category', 'Attack surface')}: {item.get('status', 'Manual review')} - {item.get('reason', '')}")
        lines.append("")
    if masked_report.get("decision") == "PASS":
        lines.extend(
            [
                "## Notes",
                "No deployment-blocking issues were found. Review the safe-area assumptions and run normal pre-deployment checks.",
                "",
            ]
        )
    elif masked_report.get("decision") == "GO_WITH_CAUTION":
        lines.extend(
            [
                "## Deployment Note",
                "No deployment-blocking issues were found, but low-impact issues or assumptions remain. Deploy only if these risks are acceptable for the current demo/staging environment, and fix them before production.",
                "",
            ]
        )
    else:
        lines.extend(["## Applicable Issues"])
        for item in masked_report.get("what_to_fix_first", [])[:5]:
            if isinstance(item, dict):
                lines.append(f"{item.get('priority', 1)}. {item.get('fix', '')}")
        lines.extend(["", "## Files To Inspect First"])
        seen_files = []
        for finding in findings:
            for file_path in ([finding["file"]] if finding["file"] != "N/A" else []):
                if file_path not in seen_files:
                    seen_files.append(file_path)
        for file_path in seen_files[:8]:
            lines.append(f"- `{file_path}`")
        lines.append("")
        lines.append("## Required Fixes")
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    "",
                    f"### {index}. {finding['title']}",
                    f"Severity: {finding['severity']}",
                    "Affected files:",
                    f"- `{finding['file']}`" if finding["file"] != "N/A" else "- `N/A`",
                    "",
                    "Problem:",
                    finding["why_it_matters"],
                    "",
                    "Required change:",
                    finding["fix"],
                    "",
                    "Safe implementation guidance:",
                    "Keep the fix targeted, preserve business logic, and prefer server-side least-privilege controls.",
                    "",
                    "Validation:",
                    f"Re-run InfraRed AI and confirm `{finding['id']}` no longer fails.",
                ]
            )
        for index, risk in enumerate(ai_risks[:4], start=len(findings) + 1):
            if not isinstance(risk, dict):
                continue
            lines.extend(
                [
                    "",
                    f"### {index}. {risk.get('title', 'AI contextual risk')}",
                    f"Severity: {risk.get('severity', 'medium')}",
                    "Affected files:",
                    "- `Contextual review`",
                    "",
                    "Problem:",
                    risk.get("business_impact", "AI review found a contextual security concern."),
                    "",
                    "Required change:",
                    risk.get("fix", "Inspect the related control path and apply a targeted fix."),
                    "",
                    "Safe implementation guidance:",
                    risk.get("why_rule_engine_missed_it", "This issue needed contextual review beyond deterministic rules."),
                    "",
                    "Validation:",
                    "Re-run InfraRed AI and confirm the AI Security Board no longer reports this risk.",
                ]
            )
        if masked_report.get("incomplete_agent_count", 0):
            lines.extend(
                [
                    "",
                    "## Manual Review Required",
                    "One or more AI specialist agents did not complete reliable analysis. Do not treat this scan as PASS.",
                ]
            )
    if dynamic_findings:
        lines.extend(["", "## Dynamic Runtime Findings"])
        for index, finding in enumerate(dynamic_findings[:5], start=1):
            if not isinstance(finding, dict):
                continue
            lines.extend(
                [
                    "",
                    f"### Runtime {index}. {finding.get('title', 'Dynamic runtime finding')}",
                    f"Severity: {finding.get('severity', 'medium')}",
                    "Affected path:",
                    f"- `{finding.get('path', '/')}`",
                    "",
                    "Problem:",
                    finding.get("summary", "Runtime sandbox testing found a deployment concern."),
                    "",
                    "Evidence:",
                    finding.get("evidence", ""),
                    "",
                    "Required change:",
                    finding.get("fix", "Harden the affected runtime behavior."),
                ]
            )
    runtime_agents = dynamic_testing.get("runtime_agents", []) if isinstance(dynamic_testing.get("runtime_agents"), list) else []
    if runtime_agents:
        lines.extend(["", "## Runtime Agents"])
        for agent in runtime_agents:
            if not isinstance(agent, dict):
                continue
            lines.extend(
                [
                    f"- {agent.get('agent', 'Runtime Agent')}: {agent.get('status', 'REVIEW')} - {agent.get('one_line_summary', '')}",
                ]
            )
    if completed_dynamic:
        lines.extend(
            [
                "",
                "## Sandbox Proof / Runtime Evidence",
                "Real sandbox evidence captured inside a disposable local Docker container.",
                f"- Tested URL: {proof_metadata.get('tested_url', 'N/A')}",
                f"- Timestamp: {proof_metadata.get('timestamp', 'N/A')}",
                f"- Docker image name: {proof_metadata.get('docker_image_name', 'N/A')}",
                f"- Short container id: {proof_metadata.get('container_id_short', 'N/A')}",
                f"- Routes tested: {', '.join(proof_metadata.get('routes_tested', []) or []) or 'N/A'}",
                f"- Screenshot count: {proof_metadata.get('screenshot_count', 0)}",
                f"- Readiness: {proof_metadata.get('readiness_note', 'N/A')}",
                f"- Cleanup status: {dynamic_testing.get('cleanup_status', proof_metadata.get('cleanup_status', 'pending'))}",
            ]
        )
    if repair_changes:
        lines.extend(
            [
                "",
                "## Changes Made to Enable Sandbox Testing",
                "These changes were applied only to a temporary sandbox copy. The original uploaded project ZIP was not modified.",
                f"- Original sandbox failure: {dynamic_testing.get('original_failure', {}).get('message', dynamic_testing.get('reason', 'Unknown failure'))}",
                f"- Repair result: {dynamic_testing.get('repair_status', 'attempted')}",
                f"- Screenshots captured after repair: {'yes' if screenshots else 'no'}",
            ]
        )
        for change in repair_changes[:8]:
            if not isinstance(change, dict):
                continue
            lines.append(
                f"- {change.get('file', 'file')}: {change.get('change_type', 'modified')} | {change.get('reason', '')} | {change.get('summary', '')} | {change.get('security_impact', '')}"
            )
    if dynamic_mode == "SafeTestAgents" and not completed_dynamic:
        lines.extend(
            [
                "",
                "## How to Get Sandbox Testing Done",
                _sandbox_fix_guidance(dynamic_testing),
            ]
        )
    if completed_dynamic and timeline:
        lines.extend(["", "## Sandbox Status Timeline"])
        for item in timeline:
            if not isinstance(item, dict):
                continue
            lines.append(f"- {item.get('step', 'Step')}: {item.get('status', 'pending')} {item.get('detail', '')}".strip())
    if completed_dynamic and screenshots:
        lines.extend(["", "## Real Playwright Screenshot Proof"])
        for shot in screenshots[:6]:
            if not isinstance(shot, dict):
                continue
            lines.append(
                f"- {shot.get('file_name', 'screenshot.png')}: {shot.get('title', 'Real Playwright screenshot')} | route={shot.get('route', '/')} | status={shot.get('status_code', 0)} | timestamp={shot.get('captured_at', '')}"
            )
    if completed_dynamic and dynamic_checks:
        lines.extend(["", "## Runtime Checks Table"])
        for item in dynamic_checks[:10]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- {item.get('title', 'Check')} | path={item.get('path', '/')} | status={item.get('status', 'review')} | severity={item.get('severity', 'medium')} | evidence={item.get('evidence', '')}"
            )
    evidence_cards = dynamic_testing.get("evidence_cards", []) if isinstance(dynamic_testing.get("evidence_cards"), list) else []
    if completed_dynamic and evidence_cards:
        lines.extend(["", "## Runtime Evidence Card Summaries"])
        for card in evidence_cards[:4]:
            if not isinstance(card, dict):
                continue
            lines.append(f"- {card.get('title', 'Sandbox evidence card')}: {card.get('summary', '')}")
    lines.extend(
        [
            "",
            "## Security Validation Checklist",
            "- [ ] No raw secrets in frontend files.",
            "- [ ] No service role keys in client code.",
            "- [ ] Sensitive API routes verify authentication.",
            "- [ ] Authorization checks verify ownership/role.",
            "- [ ] Stripe/webhook signatures are verified.",
            "- [ ] RLS is enabled for sensitive Supabase tables.",
            "- [ ] Rate limits exist on auth/payment/webhook routes.",
            "- [ ] Reported issues are fixed without unrelated rewrites.",
            "",
            "## Passed Rules",
            f"{rules_summary.get('passed', masked_report.get('passed_tests_count', 0))} deterministic checks passed.",
            "",
            "## Not Used Rules",
            "Some checks were not applicable because the project did not contain the required files, stack, or feature for those checks." if rules_summary.get("not_applicable", masked_report.get("rules_not_used_count", 0)) else "All deterministic rules were applicable for this scan.",
            "",
            "## Notes",
            "This brief was generated from sanitized InfraRed AI findings. Raw secrets were not included.",
        ]
    )
    return "\n".join(lines) + "\n"
