from __future__ import annotations


AGENT_NAMES = [
    "Infra Auditor Agent",
    "Database Auditor Agent",
    "AppSec Agent",
    "Secrets/Supply Chain Agent",
    "Red-Team Chain Agent",
]


def build_demo_agents(context: dict) -> list[dict]:
    findings = context["failed_findings"][:5]
    outputs = []
    for name in AGENT_NAMES:
        risks = []
        if findings:
            source = findings[min(len(outputs), len(findings) - 1)]
            risks.append(
                {
                    "title": source["title"],
                    "severity": source["severity"],
                    "evidence_used": source["evidence"],
                    "why_rule_engine_missed_it": "The rule engine flags the direct pattern, but cross-file business impact still needs context.",
                    "business_impact": "An attacker or reviewer could connect this issue to a larger production failure path.",
                    "fix": source["fix"],
                }
            )
        outputs.append(
            {
                "agent": name,
                "status": "RISK_FOUND" if risks else "SAFE",
                "summary": "Contextual risk found." if risks else "SAFE",
                "new_contextual_risks": risks,
                "safe_areas": [
                    "Sanitized snippets were reviewed.",
                    "No additional raw secrets were exposed to the agent context.",
                    "Assumption: unavailable files were not present in the uploaded project.",
                ],
                "assumptions": ["Only masked, compressed context was provided to this agent."],
            }
        )
    return outputs
