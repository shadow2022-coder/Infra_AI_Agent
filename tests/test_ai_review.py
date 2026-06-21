import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from app import make_safe_report_base_name
from core.agent_runner import normalize_agent_output
from core.repair_agent import run_deterministic_repair, should_attempt_repair
from core.report_renderer import render_fix_brief_markdown, render_report_html
from core.risk_scoring import build_fallback_report
from core.runtime_evidence import discover_runtime_routes
from core.rule_engine import run_rules
from core.secret_masker import mask_text
from core.zip_loader import extract_zip_bytes


def _rules_all_pass():
    results = []
    for index in range(1, 51):
        results.append(
            {
                "id": f"R{index:03d}",
                "title": f"Rule {index}",
                "severity": "medium",
                "status": "pass",
                "file": "N/A",
                "evidence": "No deterministic issue detected.",
                "why_it_matters": "N/A",
                "fix": "N/A",
            }
        )
    return {"results": results, "summary": {"passed": 50, "failed": 0, "review": 0, "not_applicable": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}


class AIReviewTests(unittest.TestCase):
    def test_secret_masker_masks_emails_tokens_cookies_and_frontend_secrets(self):
        text = (
            "harsha@example.com\n"
            "Authorization: Bearer abc123supersecrettoken\n"
            "Cookie: session=abc123; theme=dark\n"
            "Set-Cookie: refresh_token=xyz987; HttpOnly; Secure\n"
            "api_key=abc123456789\n"
            "NEXT_PUBLIC_SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        )
        masked = mask_text(text)
        self.assertIn("[EMAIL_MASKED]", masked)
        self.assertIn("Authorization: Bearer [TOKEN_MASKED]", masked)
        self.assertIn("Cookie: session=[COOKIE_MASKED]; theme=[COOKIE_MASKED]", masked)
        self.assertIn("Set-Cookie: refresh_token=[COOKIE_MASKED]; HttpOnly; Secure", masked)
        self.assertIn("api_key=[SECRET_MASKED]", masked)
        self.assertIn("NEXT_PUBLIC_SUPABASE_KEY=[SECRET_MASKED]", masked)
        self.assertNotIn("harsha@example.com", masked)
        self.assertNotIn("abc123supersecrettoken", masked)

    def test_filename_safety(self):
        self.assertEqual(make_safe_report_base_name("My Cool App.zip"), "My_Cool_App")
        self.assertEqual(make_safe_report_base_name("../../secret.zip"), "secret")

    def test_docker_rule_can_be_not_applicable(self):
        scan = {"raw_contents": {"app/package.json": "{}"}}
        result = run_rules(scan)
        docker_rule = next(item for item in result["results"] if item["id"] == "R012")
        self.assertEqual(docker_rule["status"], "not_applicable")

    def test_rules_pass_but_ai_high_risk_is_not_pass(self):
        rules = _rules_all_pass()
        agents = [
            {
                "agent": "AppSec Agent",
                "status": "RISK_FOUND",
                "summary": "High contextual risk found.",
                "new_contextual_risks": [
                    {
                        "title": "Missing ownership check in destructive route",
                        "severity": "high",
                        "evidence_used": "Delete route trusts caller context too loosely.",
                        "why_rule_engine_missed_it": "Business logic issue required contextual review.",
                        "business_impact": "Unauthorized modification may occur.",
                        "fix": "Add server-side ownership verification.",
                    }
                ],
                "safe_areas": [],
                "assumptions": [],
                "output_valid": True,
            }
        ] + [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents)
        self.assertNotEqual(report["decision"], "PASS")
        self.assertTrue(report["ai_contextual_risks"])

    def test_rules_pass_but_ai_low_risk_is_go_with_caution(self):
        rules = _rules_all_pass()
        agents = [
            {
                "agent": "AppSec Agent",
                "status": "RISK_FOUND",
                "summary": "Low contextual risk found.",
                "new_contextual_risks": [
                    {
                        "title": "Verbose error message reveals internals",
                        "severity": "low",
                        "evidence_used": "Stack traces are visible in one edge path.",
                        "why_rule_engine_missed_it": "Contextual issue across code flow.",
                        "business_impact": "Small information disclosure risk.",
                        "fix": "Return a generic error for external callers.",
                    }
                ],
                "safe_areas": [],
                "assumptions": [],
                "output_valid": True,
            }
        ] + [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents)
        self.assertEqual(report["decision"], "GO_WITH_CAUTION")

    def test_rules_pass_but_malformed_agent_forces_review(self):
        rules = _rules_all_pass()
        malformed = normalize_agent_output("", "AppSec Agent")
        agents = [malformed] + [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents)
        self.assertEqual(report["decision"], "REVIEW")
        self.assertEqual(report["incomplete_agent_count"], 1)

    def test_rules_pass_and_all_agents_safe_can_pass(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents)
        self.assertEqual(report["decision"], "PASS")

    def test_string_risk_is_normalized_without_crash(self):
        normalized = normalize_agent_output(
            {
                "status": "REVIEW",
                "summary": "Review recommended",
                "new_contextual_risks": ["Missing ownership check in delete route"],
                "safe_areas": [],
                "assumptions": [],
            },
            "AppSec Agent",
        )
        self.assertTrue(normalized["new_contextual_risks"])
        self.assertIsInstance(normalized["new_contextual_risks"][0], dict)

    def test_runtime_route_discovery_uses_project_hints(self):
        routes = discover_runtime_routes(
            {
                "README.md": "Login at /login and admin console at /admin. Health route available.",
                "app/api/health/route.ts": "export async function GET() {}",
            }
        )
        self.assertIn("/", routes)
        self.assertIn("/login", routes)
        self.assertIn("/admin", routes)
        self.assertIn("/api/health", routes)

    def test_markdown_report_includes_sandbox_proof_metadata(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents, dynamic_result={"enabled": True, "status": "completed", "summary": "Dynamic proof complete.", "screenshots": [{"file_name": "homepage.png", "title": "Homepage screenshot", "route": "/", "status_code": 200, "captured_at": "2026-06-20T00:00:01Z"}], "checks": [{"title": "Homepage reachable", "path": "/", "status": "pass", "severity": "low", "evidence": "200"}], "proof_metadata": {"tested_url": "http://127.0.0.1:43210", "timestamp": "2026-06-20T00:00:00Z", "docker_image_name": "infrared-sandbox-test", "container_id_short": "abc123def456", "routes_tested": ["/", "/login"], "screenshot_count": 1, "cleanup_status": "Sandbox destroyed", "readiness_note": "Readiness confirmed via /api/health with status 200."}, "cleanup_status": "Sandbox destroyed", "runtime_agents": [], "evidence_cards": [], "findings": [], "timeline": []})
        markdown = render_fix_brief_markdown(report, rules["results"], agents, "Test Stack")
        self.assertIn("Sandbox Proof / Runtime Evidence", markdown)
        self.assertIn("http://127.0.0.1:43210", markdown)
        self.assertIn("homepage.png", markdown)
        self.assertIn("status=200", markdown)

    def test_report_includes_attack_coverage_matrix_and_scan_confidence(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report(
            {"label": "Test Stack"},
            rules,
            agents,
            dynamic_result={"enabled": True, "attempted": True, "mode": "SafeTestAgents", "status": "skipped", "reason": "docker_unavailable", "summary": "Dynamic sandbox testing was not completed because Docker was unavailable.", "runtime_agents": [], "evidence_cards": [], "findings": [], "checks": []},
        )
        self.assertEqual(report["scan_confidence"], "Low")
        self.assertTrue(report["attack_coverage_matrix"])
        self.assertIn("Attack Coverage Matrix", render_fix_brief_markdown(report, rules["results"], agents, "Test Stack"))

    def test_markdown_report_hides_fake_sandbox_proof_when_not_completed(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents, dynamic_result={"enabled": True, "status": "unsupported", "reason": "unsupported_startup", "summary": "Dynamic Sandbox Testing was skipped because no safe startup strategy was detected. Add a Dockerfile and README run command to enable sandbox testing.", "runtime_agents": [], "evidence_cards": [], "findings": [], "checks": []})
        markdown = render_fix_brief_markdown(report, rules["results"], agents, "Test Stack")
        self.assertNotIn("Tested URL: N/A", markdown)
        self.assertNotIn("Screenshot count: 0", markdown)

    def test_markdown_report_adds_sandbox_guidance_for_safetestagents(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents, dynamic_result={"enabled": True, "attempted": True, "mode": "SafeTestAgents", "status": "skipped", "reason": "docker_unavailable", "summary": "Dynamic sandbox testing was not completed because Docker was unavailable.", "runtime_agents": [], "evidence_cards": [], "findings": [], "checks": []})
        markdown = render_fix_brief_markdown(report, rules["results"], agents, "Test Stack")
        self.assertIn("How to Get Sandbox Testing Done", markdown)
        self.assertIn("docker info", markdown)

    def test_markdown_report_demo_fallback_disables_sandbox(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report({"label": "Test Stack"}, rules, agents, dynamic_result={"enabled": False, "attempted": False, "mode": "Demo Fallback", "status": "not_enabled", "reason": "sandbox_disabled_in_demo_fallback", "summary": "Sandbox testing is disabled in Demo Fallback mode. Use SafeTestAgents for runtime sandbox testing.", "runtime_agents": [], "evidence_cards": [], "findings": [], "checks": []})
        markdown = render_fix_brief_markdown(report, rules["results"], agents, "Test Stack")
        self.assertIn("Sandbox testing is disabled in Demo Fallback mode", markdown)
        self.assertNotIn("Sandbox Proof / Runtime Evidence", markdown)

    def test_markdown_report_includes_repair_changes(self):
        rules = _rules_all_pass()
        agents = [
            {"agent": name, "status": "SAFE", "summary": "SAFE", "new_contextual_risks": [], "safe_areas": [], "assumptions": [], "output_valid": True}
            for name in ["Infra Auditor Agent", "Database Auditor Agent", "AppSec Agent", "Secrets/Supply Chain Agent", "Red-Team Chain Agent"]
        ]
        report = build_fallback_report(
            {"label": "Test Stack"},
            rules,
            agents,
            dynamic_result={
                "enabled": True,
                "attempted": True,
                "mode": "SafeTestAgents",
                "status": "completed_after_repair",
                "summary": "Sandbox testing initially failed, but the Repair Agent patched a temporary sandbox copy and completed runtime testing.",
                "repair_attempted": True,
                "repair_status": "succeeded",
                "original_failure": {"message": "No safe detected startup strategy was available for this stack."},
                "repair_changes": [
                    {
                        "file": "Dockerfile",
                        "change_type": "created",
                        "reason": "Needed safe Docker startup for sandbox testing",
                        "summary": "Added Node Dockerfile",
                        "security_impact": "No production security issue was fixed; change only enabled runtime testing",
                    }
                ],
                "screenshots": [{"file_name": "homepage.png", "title": "Homepage screenshot", "route": "/", "status_code": 200, "captured_at": "2026-06-20T00:00:01Z"}],
                "checks": [],
                "findings": [],
                "runtime_agents": [],
                "proof_metadata": {"tested_url": "http://127.0.0.1:43210", "timestamp": "2026-06-20T00:00:00Z", "docker_image_name": "infrared-sandbox-test", "container_id_short": "abc123def456", "routes_tested": ["/"], "screenshot_count": 1, "cleanup_status": "Sandbox destroyed"},
                "timeline": [],
            },
        )
        markdown = render_fix_brief_markdown(report, rules["results"], agents, "Test Stack")
        self.assertIn("Changes Made to Enable Sandbox Testing", markdown)
        self.assertIn("Dockerfile", markdown)

    def test_should_attempt_repair_skips_docker_unavailable(self):
        decision = should_attempt_repair({"reason": "docker_unavailable"}, {"label": "Docker + Node.js"}, ["package.json", "server.js"])
        self.assertFalse(decision["attempt"])

    def test_run_deterministic_repair_adds_startup_files_to_temp_copy(self):
        with TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "package.json").write_text('{"name":"demo","scripts":{}}', encoding="utf-8")
            (root / "server.js").write_text("const http = require('http');\nserver.listen(3000, '127.0.0.1');\n", encoding="utf-8")
            result = run_deterministic_repair(root, {"reason": "unsupported_startup"}, {"label": "Node.js"})
            self.assertTrue(result["attempted"])
            self.assertTrue(result["changes"])
            self.assertTrue((root / "Dockerfile").exists())
            self.assertIn('"start": "node server.js"', (root / "package.json").read_text(encoding="utf-8"))
            self.assertIn("0.0.0.0", (root / "server.js").read_text(encoding="utf-8"))

    def test_run_deterministic_repair_adds_streamlit_dockerfile(self):
        with TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "requirements.txt").write_text("streamlit==1.46.1\nrequests==2.32.4\n", encoding="utf-8")
            (root / "app.py").write_text("import streamlit as st\nst.title('InfraRed AI')\n", encoding="utf-8")
            result = run_deterministic_repair(root, {"reason": "unsupported_startup"}, {"label": "Python + Streamlit"})
            self.assertTrue(result["changes"])
            dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
            self.assertIn("streamlit", dockerfile)
            self.assertIn("8501", dockerfile)

    def test_render_report_html_escapes_script_breakers_from_runtime_content(self):
        html = render_report_html(
            Path("templates/report_template.html"),
            {
                "project_name": "demo",
                "dynamic_testing": {
                    "status": "completed",
                    "enabled": True,
                    "summary": "</script><div>broken</div>",
                    "screenshots": [],
                    "checks": [],
                    "findings": [],
                    "runtime_agents": [],
                    "proof_metadata": {},
                    "timeline": [],
                },
            },
            [],
        )
        self.assertIn("\\u003c/script\\u003e", html)
        self.assertNotIn("</script><div>broken</div>", html)

    def test_zip_loader_flattens_shared_wrapper_path(self):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("demo_inputs/t1/package.json", '{"name":"t1"}')
            zf.writestr("demo_inputs/t1/Dockerfile", "FROM node:20")
        extracted = extract_zip_bytes(buf.getvalue(), "t1.zip")
        self.assertTrue((extracted["project_root"] / "package.json").exists())
        self.assertTrue((extracted["project_root"] / "Dockerfile").exists())


if __name__ == "__main__":
    unittest.main()
