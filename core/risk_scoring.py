from __future__ import annotations

from typing import Optional


def compute_risk_score(summary: dict) -> int:
    score = 100
    score -= summary.get("critical", 0) * 25
    score -= summary.get("high", 0) * 15
    score -= summary.get("medium", 0) * 8
    score -= summary.get("low", 0) * 3
    return max(0, min(100, score))


def get_score_band(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Strong"
    if score >= 70:
        return "Good with caution"
    if score >= 40:
        return "Needs review"
    return "Unsafe / Block"


def get_risk_level(decision: str, severity_counts: Optional[dict] = None, ai_risks: Optional[list[dict]] = None) -> str:
    severity_counts = severity_counts or {}
    ai_risks = ai_risks or []
    if str(decision).upper() == "BLOCK" or severity_counts.get("critical", 0) > 0 or any(str(risk.get("severity", "")).lower() == "critical" for risk in ai_risks if isinstance(risk, dict)):
        return "Critical Risk"
    if severity_counts.get("high", 0) > 0 or any(str(risk.get("severity", "")).lower() == "high" for risk in ai_risks if isinstance(risk, dict)):
        return "High Risk"
    if severity_counts.get("medium", 0) > 0 or str(decision).upper() == "REVIEW" or any(str(risk.get("severity", "")).lower() == "medium" for risk in ai_risks if isinstance(risk, dict)):
        return "Medium Risk"
    return "Low Risk"


def _collect_ai_risks(agent_outputs: list[dict]) -> list[dict]:
    ai_risks = []
    for agent in agent_outputs:
        if not isinstance(agent, dict):
            continue
        for risk in agent.get("new_contextual_risks", []) if isinstance(agent.get("new_contextual_risks"), list) else []:
            if isinstance(risk, dict):
                ai_risks.append(dict(risk, agent=agent.get("agent", "Unknown Agent")))
    return ai_risks


def _incomplete_agent_count(agent_outputs: list[dict]) -> int:
    count = 0
    for agent in agent_outputs:
        if not isinstance(agent, dict):
            count += 1
            continue
        if not agent.get("output_valid", True) or agent.get("status") == "REVIEW":
            count += 1
    return count


def fallback_decision(summary: dict, agent_outputs: list[dict]) -> str:
    ai_risks = _collect_ai_risks(agent_outputs)
    incomplete_agents = _incomplete_agent_count(agent_outputs)
    ai_critical = any(str(risk.get("severity", "")).lower() == "critical" for risk in ai_risks)
    ai_high = any(str(risk.get("severity", "")).lower() == "high" for risk in ai_risks)
    ai_medium = any(str(risk.get("severity", "")).lower() == "medium" for risk in ai_risks)
    all_agents_completed = len(agent_outputs) == 5 and incomplete_agents == 0

    if summary.get("critical", 0) > 0 or ai_critical:
        return "BLOCK"
    if summary.get("high", 0) > 0 or ai_high:
        return "BLOCK" if summary.get("high", 0) > 0 or len([risk for risk in ai_risks if str(risk.get("severity", "")).lower() in {"high", "critical"}]) > 1 else "REVIEW"
    if incomplete_agents > 0:
        return "REVIEW"
    if summary.get("medium", 0) > 0 or ai_medium:
        return "REVIEW"
    if not all_agents_completed:
        return "REVIEW"
    if summary.get("low", 0) > 0 or any(str(risk.get("severity", "")).lower() == "low" for risk in ai_risks):
        return "GO_WITH_CAUTION"
    return "PASS"


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity).lower(), 0)


def _decision_rank(decision: str) -> int:
    return {"PASS": 0, "GO_WITH_CAUTION": 1, "REVIEW": 2, "BLOCK": 3}.get(str(decision).upper(), 2)


def _rule_to_top_risk(item: dict) -> dict:
    return {
        "title": item["title"],
        "severity": item["severity"],
        "simple_explanation": item["why_it_matters"],
        "affected_files": [item["file"]] if item["file"] != "N/A" else [],
        "business_impact": item["why_it_matters"],
        "fix_summary": item["fix"],
        "deep_dive": {
            "technical_details": item["evidence"],
            "evidence": item["evidence"],
            "agent_reasoning_summary": "This finding came from the deterministic rule engine.",
            "exact_fix": item["fix"],
        },
    }


def _agent_to_card(agent: dict) -> dict:
    risks = agent.get("new_contextual_risks", []) if isinstance(agent.get("new_contextual_risks"), list) else []
    top_risks = []
    for risk in risks[:2]:
        if isinstance(risk, dict):
            title = risk.get("title")
            if title:
                top_risks.append(str(title))
        elif isinstance(risk, str) and risk.strip():
            top_risks.append(risk.strip())
    top_fix = ""
    if risks and isinstance(risks[0], dict):
        top_fix = str(risks[0].get("fix") or "")
    safe_areas = agent.get("safe_areas", []) if isinstance(agent.get("safe_areas"), list) else []
    assumptions = agent.get("assumptions", []) if isinstance(agent.get("assumptions"), list) else []
    return {
        "agent": agent.get("agent", "Unknown Agent"),
        "status": agent.get("status", "REVIEW"),
        "one_line_summary": agent.get("summary", "Manual review recommended."),
        "top_risks": top_risks,
        "top_fix": top_fix or "Review the highest-confidence finding first and apply least-privilege controls.",
        "in_depth": {
            "evidence_used": " | ".join(str(risk.get("evidence_used", "")) for risk in risks if isinstance(risk, dict))[:500],
            "rule_findings_used": top_risks,
            "why_rule_engine_may_have_missed_it": " | ".join(str(risk.get("why_rule_engine_missed_it", "")) for risk in risks if isinstance(risk, dict))[:500],
            "business_impact": " | ".join(str(risk.get("business_impact", "")) for risk in risks if isinstance(risk, dict))[:500],
            "exact_fix": top_fix or "Review the related code path and harden access controls.",
            "assumptions": [str(item) for item in assumptions if str(item).strip()],
            "safe_areas": [str(item) for item in safe_areas if str(item).strip()],
        },
        "normalization_status": agent.get("normalization_status", "normalized_ok"),
        "output_valid": bool(agent.get("output_valid", True)),
    }


def _build_attack_chain(findings: list[dict], agent_outputs: list[dict]) -> dict:
    ai_risks = _collect_ai_risks(agent_outputs)
    if ai_risks:
        first_ai = sorted(ai_risks, key=lambda item: _severity_rank(item.get("severity", "")), reverse=True)[0]
        description = str(first_ai.get("title", "Contextual risk"))
        return {
            "title": "Most likely breach path",
            "plain_english_summary": f"Deterministic checks may look clean, but the AI review identified a contextual path starting with {description.lower()}.",
            "steps": [
                {"label": "Entry point", "description": description, "related_finding": first_ai.get("agent", "")},
                {"label": "Weak control", "description": str(first_ai.get("why_rule_engine_missed_it", "Context was needed beyond deterministic rules.")), "related_finding": first_ai.get("agent", "")},
                {"label": "Data/API exposed", "description": str(first_ai.get("evidence_used", "Sanitized evidence suggested risky access or exposure.")), "related_finding": first_ai.get("agent", "")},
                {"label": "Business impact", "description": str(first_ai.get("business_impact", "Business impact needs manual validation.")), "related_finding": first_ai.get("agent", "")},
                {"label": "Fix first", "description": str(first_ai.get("fix", "Review the related control path first.")), "related_finding": first_ai.get("agent", "")},
            ],
        }

    prioritized = sorted(findings, key=lambda item: (_severity_rank(item["severity"]), item["status"] == "fail"), reverse=True)
    if not prioritized:
        return {
            "title": "Most likely breach path",
            "plain_english_summary": "No complete attack chain found from the available evidence. The project may still have review items, but no clear breach path was established.",
            "steps": [],
        }

    first = prioritized[0]
    second = prioritized[1] if len(prioritized) > 1 else first
    third = prioritized[2] if len(prioritized) > 2 else second
    impact = next((risk for risk in prioritized if risk["severity"] in {"critical", "high"}), first)
    return {
        "title": "Most likely breach path",
        "plain_english_summary": f"{first['title']} can combine with weak controls to expose sensitive data or privileged actions before deployment.",
        "steps": [
            {"label": "Entry point", "description": first["title"], "related_finding": first["id"]},
            {"label": "Weak control", "description": second["fix"], "related_finding": second["id"]},
            {"label": "Data/API exposed", "description": third["why_it_matters"], "related_finding": third["id"]},
            {"label": "Business impact", "description": impact["why_it_matters"], "related_finding": impact["id"]},
            {"label": "Fix first", "description": first["fix"], "related_finding": first["id"]},
        ],
    }


def _build_safe_areas(agent_outputs: list[dict]) -> list[dict]:
    safe_areas = []
    for agent in agent_outputs:
        if not isinstance(agent, dict):
            continue
        for item in agent.get("safe_areas", []) if isinstance(agent.get("safe_areas"), list) else []:
            text = str(item).strip()
            if text:
                safe_areas.append({"title": agent.get("agent", "Agent review"), "simple_explanation": text, "assumption": (agent.get("assumptions") or [""])[0] if isinstance(agent.get("assumptions"), list) and agent.get("assumptions") else ""})
    return safe_areas[:8]


def _build_fix_priorities(findings: list[dict]) -> list[dict]:
    priorities = []
    for index, finding in enumerate(sorted(findings, key=lambda item: _severity_rank(item["severity"]), reverse=True)[:5], start=1):
        priorities.append(
            {
                "priority": index,
                "fix": finding["fix"],
                "why_first": finding["why_it_matters"],
                "files": [finding["file"]] if finding["file"] != "N/A" else [],
                "estimated_effort": "small" if finding["severity"] in {"low", "medium"} else "medium",
            }
        )
    return priorities


def _ai_risk_to_top_risk(risk: dict) -> dict:
    return {
        "title": risk.get("title", "Contextual AI finding"),
        "severity": risk.get("severity", "medium"),
        "simple_explanation": risk.get("why_rule_engine_missed_it", "This issue required contextual review beyond deterministic rules."),
        "affected_files": [],
        "business_impact": risk.get("business_impact", "Needs manual validation."),
        "fix_summary": risk.get("fix", "Review the related code path and apply least-privilege controls."),
        "deep_dive": {
            "technical_details": risk.get("evidence_used", ""),
            "evidence": risk.get("evidence_used", ""),
            "agent_reasoning_summary": risk.get("why_rule_engine_missed_it", ""),
            "exact_fix": risk.get("fix", ""),
        },
    }


def _dynamic_risk_to_top_risk(risk: dict) -> dict:
    return {
        "title": risk.get("title", "Dynamic runtime finding"),
        "severity": risk.get("severity", "medium"),
        "simple_explanation": risk.get("summary", "Runtime sandbox testing found a deployment risk."),
        "affected_files": [risk.get("path")] if risk.get("path") else [],
        "business_impact": risk.get("summary", "Runtime exposure needs manual validation."),
        "fix_summary": risk.get("fix", "Harden the affected route or runtime configuration."),
        "deep_dive": {
            "technical_details": risk.get("evidence", ""),
            "evidence": risk.get("evidence", ""),
            "agent_reasoning_summary": "This finding came from deterministic runtime sandbox checks.",
            "exact_fix": risk.get("fix", ""),
        },
    }


def _dynamic_incomplete(dynamic_result: Optional[dict]) -> bool:
    if not isinstance(dynamic_result, dict) or not dynamic_result.get("enabled"):
        return False
    return dynamic_result.get("status") in {"skipped", "unsupported", "failed", "incomplete"}


def _scan_confidence_label(dynamic_result: Optional[dict], incomplete_agents: int) -> str:
    if incomplete_agents > 0 or _dynamic_incomplete(dynamic_result):
        return "Low"
    if isinstance(dynamic_result, dict) and dynamic_result.get("status") in {"completed", "completed_after_repair"}:
        return "High"
    return "Medium"


def _attack_coverage_matrix(rules: dict, dynamic_result: Optional[dict]) -> list[dict]:
    results = {item.get("id"): item for item in rules.get("results", []) if isinstance(item, dict)}
    dynamic_checks = dynamic_result.get("checks", []) if isinstance(dynamic_result, dict) and isinstance(dynamic_result.get("checks"), list) else []
    dynamic_attempted = bool(isinstance(dynamic_result, dict) and dynamic_result.get("attempted"))

    def has_dynamic_signal(*needles: str) -> bool:
        lowered = " ".join(
            " ".join(str(item.get(key, "")) for key in ("title", "path", "evidence", "summary"))
            for item in dynamic_checks
            if isinstance(item, dict)
        ).lower()
        return any(needle.lower() in lowered for needle in needles)

    def category_status(rule_ids: list[str], dynamic_hit: bool = False, manual_if_present: bool = False) -> str:
        category_rules = [results.get(rule_id) for rule_id in rule_ids if results.get(rule_id)]
        if category_rules and all(item.get("status") == "not_applicable" for item in category_rules):
            return "Not applicable"
        if dynamic_attempted and dynamic_hit:
            return "Checked in sandbox"
        if any(item.get("status") != "not_applicable" for item in category_rules):
            return "Checked statically"
        return "Manual review" if manual_if_present else "Not applicable"

    return [
        {
            "category": "SQL injection",
            "status": category_status(["R004"]),
            "reason": "Checked only when database or query code is present.",
        },
        {
            "category": "XSS and browser injection",
            "status": category_status(["R005", "R045"], dynamic_hit=has_dynamic_signal("console", "stack trace", "source map", "frontend env")),
            "reason": "Static sink checks run first; sandbox adds browser-visible leak checks when runtime testing is enabled.",
        },
        {
            "category": "CSRF on state-changing session routes",
            "status": category_status(["R027"]),
            "reason": "Only applicable when cookie or session-backed write routes are detected.",
        },
        {
            "category": "Authentication and admin exposure",
            "status": category_status(["R028", "R029", "R037", "R050"], dynamic_hit=has_dynamic_signal("admin", "login", "unauthenticated")),
            "reason": "Static auth checks run first; sandbox validates public/admin route behavior without real credentials.",
        },
        {
            "category": "CORS and security headers",
            "status": category_status(["R006", "R021"], dynamic_hit=has_dynamic_signal("cors", "header", "cookie")),
            "reason": "Header and CORS posture can be verified both from code and from a safe localhost runtime response.",
        },
        {
            "category": "Secrets and frontend exposure",
            "status": category_status(["R001", "R002", "R003", "R025", "R026", "R031", "R032"], dynamic_hit=has_dynamic_signal("secret", "token", "env", "api key")),
            "reason": "Committed secret checks are static; sandbox only looks for browser-visible leaks in sanitized output.",
        },
        {
            "category": "Unsafe file access and uploads",
            "status": category_status(["R024", "R047"]),
            "reason": "Only checked when upload handlers or file path operations exist in the project.",
        },
        {
            "category": "SSRF and outbound fetch abuse",
            "status": category_status(["R048"]),
            "reason": "Safe static checks look for risky fetch patterns without executing outbound traffic.",
        },
        {
            "category": "Supply chain and build scripts",
            "status": category_status(["R017", "R043", "R044"]),
            "reason": "Package lifecycle scripts and suspicious installer behavior are reviewed deterministically.",
        },
        {
            "category": "Rate limits and safe DDoS signals",
            "status": category_status(["R016"], manual_if_present=True),
            "reason": "InfraRed AI does not simulate load; it only checks safe signals like rate limiting, expensive routes, and upload controls.",
        },
        {
            "category": "Malware, phishing, ransomware, keylogging",
            "status": "Manual review",
            "reason": "These classes are not actively simulated in the MVP and require code review beyond safe local checks.",
        },
    ]


def build_fallback_report(stack: dict, rules: dict, agent_outputs: list[dict], dynamic_result: Optional[dict] = None) -> dict:
    score = compute_risk_score(rules["summary"])
    ai_risks = _collect_ai_risks(agent_outputs)
    dynamic_findings = dynamic_result.get("findings", []) if isinstance(dynamic_result, dict) and isinstance(dynamic_result.get("findings"), list) else []
    incomplete_agents = _incomplete_agent_count(agent_outputs)
    score -= incomplete_agents * 8
    for risk in ai_risks:
        severity = str(risk.get("severity", "")).lower()
        if severity == "critical":
            score -= 25
        elif severity == "high":
            score -= 15
        elif severity == "medium":
            score -= 8
        elif severity == "low":
            score -= 3
    for risk in dynamic_findings:
        severity = str(risk.get("severity", "")).lower()
        if severity == "critical":
            score -= 25
        elif severity == "high":
            score -= 15
        elif severity == "medium":
            score -= 8
        elif severity == "low":
            score -= 3
    if _dynamic_incomplete(dynamic_result):
        score -= 12
        confidence_cap = dynamic_result.get("confidence_cap") if isinstance(dynamic_result, dict) else 69
        if not isinstance(confidence_cap, int):
            confidence_cap = 69
        score = min(score, confidence_cap)
    score = max(0, min(100, score))
    decision = fallback_decision(rules["summary"], agent_outputs)
    if any(str(risk.get("severity", "")).lower() in {"critical", "high"} for risk in dynamic_findings):
        decision = "BLOCK"
    elif _dynamic_incomplete(dynamic_result):
        decision = "REVIEW" if _decision_rank(decision) < _decision_rank("REVIEW") else decision
    elif any(str(risk.get("severity", "")).lower() == "medium" for risk in dynamic_findings):
        decision = "REVIEW" if _decision_rank(decision) < _decision_rank("REVIEW") else decision
    elif any(str(risk.get("severity", "")).lower() == "low" for risk in dynamic_findings) and decision == "PASS":
        decision = "GO_WITH_CAUTION"
    findings = [item for item in rules["results"] if item["status"] in {"fail", "review"}]
    grouped = {
        "critical": [item for item in findings if item["severity"] == "critical"][:6],
        "high": [item for item in findings if item["severity"] == "high"][:8],
        "medium": [item for item in findings if item["severity"] == "medium"][:8],
        "low": [item for item in findings if item["severity"] == "low"][:6],
    }
    top_risks = [_rule_to_top_risk(item) for item in sorted(findings, key=lambda item: _severity_rank(item["severity"]), reverse=True)[:4]]
    top_risks.extend(_ai_risk_to_top_risk(item) for item in sorted(ai_risks, key=lambda item: _severity_rank(item.get("severity", "")), reverse=True)[:4])
    top_risks.extend(_dynamic_risk_to_top_risk(item) for item in sorted(dynamic_findings, key=lambda item: _severity_rank(item.get("severity", "")), reverse=True)[:4])
    top_risks = top_risks[:6]
    agent_cards = [_agent_to_card(agent) for agent in agent_outputs if isinstance(agent, dict)]
    safe_areas = _build_safe_areas(agent_outputs)
    what_to_fix_first = _build_fix_priorities(findings)
    for index, finding in enumerate(sorted(dynamic_findings, key=lambda item: _severity_rank(item.get("severity", "")), reverse=True)[:3], start=len(what_to_fix_first) + 1):
        what_to_fix_first.append(
            {
                "priority": index,
                "fix": finding.get("fix", "Harden the affected runtime behavior."),
                "why_first": finding.get("summary", "Runtime sandbox testing found a deployment risk."),
                "files": [finding.get("path")] if finding.get("path") else [],
                "estimated_effort": "small" if finding.get("severity") in {"low", "medium"} else "medium",
            }
        )
    what_to_fix_first = what_to_fix_first[:5]
    attack_chain = _build_attack_chain(findings, agent_outputs)
    ai_completed = len(agent_cards)
    contextual_warning = ""
    if rules["summary"]["failed"] == 0 and rules["summary"]["review"] == 0 and ai_risks:
        contextual_warning = "Deterministic checks passed, but AI contextual review found risks."
    elif rules["summary"]["failed"] == 0 and rules["summary"]["review"] == 0 and incomplete_agents > 0:
        contextual_warning = "Deterministic checks passed, but AI review was incomplete. Deployment requires review."
    elif not findings and dynamic_findings:
        contextual_warning = "Deterministic checks passed, but dynamic sandbox testing found runtime exposure."
    elif _dynamic_incomplete(dynamic_result):
        contextual_warning = "Dynamic sandbox testing was enabled but incomplete. Deployment confidence is reduced."

    combined_severity = {
        "critical": rules["summary"]["critical"] + sum(1 for item in dynamic_findings if item.get("severity") == "critical"),
        "high": rules["summary"]["high"] + sum(1 for item in dynamic_findings if item.get("severity") == "high"),
        "medium": rules["summary"]["medium"] + sum(1 for item in dynamic_findings if item.get("severity") == "medium"),
        "low": rules["summary"]["low"] + sum(1 for item in dynamic_findings if item.get("severity") == "low"),
    }

    executive_summary = {
        "plain_english": "InfraRed AI reviewed the project with deterministic security tests first, then used masked-context AI agents to look for deeper deployment risks.",
        "why_this_decision": contextual_warning or ("Critical or high-confidence findings can block deployment, while medium-confidence items require review before launch." if decision in {"BLOCK", "REVIEW"} else ("No deployment-blocking issues were found, but low-impact issues or assumptions remain." if decision == "GO_WITH_CAUTION" else "No deployment-blocking issue was confirmed from the available evidence.")),
        "business_risk": "The current issues can increase breach risk, investor diligence friction, and pre-launch operational risk." if findings or ai_risks or incomplete_agents or dynamic_findings or _dynamic_incomplete(dynamic_result) else "No major business risk was identified from the uploaded evidence.",
        "recommended_next_step": "Fix the top-priority findings, rerun the scan, and only then move toward deployment." if decision in {"BLOCK", "REVIEW"} else ("Deploy only if the remaining low-impact issues are acceptable for the current demo or staging environment." if decision == "GO_WITH_CAUTION" else "Review the assumptions, run normal QA, and keep the secure defaults in place."),
    }
    audit_process = [
        {"step": "Project intake", "what_happened": "The uploaded ZIP was filtered to security-relevant files."},
        {"step": "Secret masking", "what_happened": "Secrets were masked before rule checks and AI review."},
        {"step": "Rule engine", "what_happened": "50 deterministic checks looked for known deployment risks."},
        {"step": "AI security board", "what_happened": "Parallel agents reviewed the sanitized evidence for contextual risks."},
        {"step": "Dynamic sandbox testing", "what_happened": dynamic_result.get("summary", "Dynamic sandbox testing was not enabled.") if isinstance(dynamic_result, dict) and dynamic_result.get("enabled") else "Dynamic sandbox testing was not enabled."},
        {"step": "Final reporter", "what_happened": "The final decision combined rule findings and agent outputs."},
    ]
    return {
        "product": "InfraRed AI",
        "detected_stack": stack["label"],
        "risk_score": score,
        "confidence_score": score,
        "decision": decision,
        "executive_summary": executive_summary,
        "audit_process": audit_process,
        "passed_tests_count": rules["summary"]["passed"],
        "failed_tests_count": rules["summary"]["failed"],
        "review_tests_count": rules["summary"]["review"],
        "severity_counts": combined_severity,
        "critical_findings": grouped["critical"],
        "high_findings": grouped["high"],
        "medium_findings": grouped["medium"],
        "low_findings": grouped["low"],
        "top_risks": top_risks,
        "safe_areas": safe_areas,
        "agent_cards": agent_cards,
        "attack_chain": attack_chain,
        "business_impact": executive_summary["business_risk"],
        "what_to_fix_first": what_to_fix_first,
        "exact_fixes": [item["fix"] for item in what_to_fix_first],
        "ai_contextual_risks": ai_risks,
        "agents_completed_count": ai_completed,
        "agents_expected_count": 5,
        "incomplete_agent_count": incomplete_agents,
        "score_band": get_score_band(score),
        "confidence_status": get_score_band(score),
        "scan_confidence": _scan_confidence_label(dynamic_result, incomplete_agents),
        "risk_level": get_risk_level(decision, combined_severity, ai_risks + dynamic_findings),
        "attack_coverage_matrix": _attack_coverage_matrix(rules, dynamic_result),
        "rules_not_used_count": rules["summary"].get("not_applicable", 0),
        "dynamic_testing": dynamic_result or {"enabled": False, "status": "not_enabled", "summary": "Dynamic sandbox testing was not enabled.", "runtime_agents": [], "evidence_cards": [], "findings": [], "checks": []},
    }


def normalize_report(reporter_output: Optional[dict], fallback_report: dict) -> dict:
    if not isinstance(reporter_output, dict):
        return fallback_report

    normalized = dict(fallback_report)
    normalized.update(reporter_output)

    if not isinstance(normalized.get("executive_summary"), dict):
        text = str(normalized.get("executive_summary") or fallback_report["executive_summary"]["plain_english"])
        normalized["executive_summary"] = dict(fallback_report["executive_summary"])
        normalized["executive_summary"]["plain_english"] = text
    if not isinstance(normalized.get("audit_process"), list):
        normalized["audit_process"] = fallback_report["audit_process"]
    if not isinstance(normalized.get("top_risks"), list):
        normalized["top_risks"] = fallback_report["top_risks"]
    if not isinstance(normalized.get("safe_areas"), list):
        normalized["safe_areas"] = fallback_report["safe_areas"]
    if not isinstance(normalized.get("what_to_fix_first"), list):
        normalized["what_to_fix_first"] = fallback_report["what_to_fix_first"]
    if not isinstance(normalized.get("exact_fixes"), list):
        normalized["exact_fixes"] = fallback_report["exact_fixes"]
    if not isinstance(normalized.get("agent_cards"), list) or not normalized["agent_cards"]:
        normalized["agent_cards"] = fallback_report["agent_cards"]

    attack_chain = normalized.get("attack_chain")
    if isinstance(attack_chain, list):
        normalized["attack_chain"] = {
            "title": "Most likely breach path",
            "plain_english_summary": "The findings suggest a possible breach path, but the older report format did not provide structured steps.",
            "steps": [{"label": f"Step {index + 1}", "description": str(step), "related_finding": ""} for index, step in enumerate(attack_chain[:5])],
        }
    elif not isinstance(attack_chain, dict):
        normalized["attack_chain"] = fallback_report["attack_chain"]

    reporter_severity = normalized.get("severity_counts")
    if not isinstance(reporter_severity, dict):
        normalized["severity_counts"] = fallback_report["severity_counts"]
    else:
        merged = dict(fallback_report["severity_counts"])
        merged.update(reporter_severity)
        normalized["severity_counts"] = merged

    if _decision_rank(normalized.get("decision", "REVIEW")) < _decision_rank(fallback_report.get("decision", "REVIEW")):
        normalized["decision"] = fallback_report["decision"]

    return normalized


def report_has_required_shape(report: Optional[dict]) -> bool:
    if not isinstance(report, dict):
        return False
    required_keys = {
        "product",
        "detected_stack",
        "risk_score",
        "decision",
        "executive_summary",
        "passed_tests_count",
        "failed_tests_count",
        "review_tests_count",
        "severity_counts",
        "safe_areas",
        "agent_cards",
        "attack_chain",
        "what_to_fix_first",
    }
    if not required_keys.issubset(report.keys()):
        return False
    if not isinstance(report.get("executive_summary"), dict):
        return False
    severity_counts = report.get("severity_counts")
    if not isinstance(severity_counts, dict):
        return False
    return {"critical", "high", "medium", "low"}.issubset(severity_counts.keys())
