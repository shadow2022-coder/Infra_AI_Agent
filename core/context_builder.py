from __future__ import annotations

import json


def build_context(scan: dict, stack: dict, rules: dict, masked_contents: dict[str, str]) -> dict:
    failed = [item for item in rules["results"] if item["status"] == "fail"][:25]
    review = [item for item in rules["results"] if item["status"] == "review"][:25]
    safe_categories = [item["title"] for item in rules["results"] if item["status"] == "pass"][:10]
    useful_files = scan["useful_files"][:40]

    security_sensitive_files = [
        path for path in useful_files
        if any(token in path.lower() for token in ("api", "route", "auth", "session", "db", "database", "supabase", "stripe", "payment", "terraform", "docker", "k8s", "kubernetes", "storage", "bucket", "admin", "middleware"))
    ][:20]
    route_inventory = [path for path in useful_files if any(token in path.lower() for token in ("/api/", "route.", "routes/"))][:20]
    auth_related_files = [path for path in useful_files if any(token in path.lower() for token in ("auth", "session", "middleware", "login", "admin"))][:12]
    database_related_files = [path for path in useful_files if any(token in path.lower() for token in ("db", "database", "supabase", "prisma", "schema", "migration"))][:12]
    payment_related_files = [path for path in useful_files if any(token in path.lower() for token in ("stripe", "payment", "billing", "subscription", "webhook"))][:12]
    infra_related_files = [path for path in useful_files if any(token in path.lower() for token in ("docker", "terraform", "k8s", "kubernetes", "vercel", ".github/workflows"))][:12]
    storage_related_files = [path for path in useful_files if any(token in path.lower() for token in ("storage", "bucket", "upload", "cdn", "s3"))][:12]

    snippets = []
    preferred_snippets = []
    seen = set()
    for collection in (security_sensitive_files, auth_related_files, database_related_files, payment_related_files, infra_related_files, storage_related_files, route_inventory, useful_files):
        for path in collection:
            if path not in seen:
                seen.add(path)
                preferred_snippets.append(path)
    for path in preferred_snippets[:40]:
        content = masked_contents.get(path, "")
        if not content:
            continue
        snippet = content[:1200]
        snippets.append({"file": path, "snippet": snippet})
        if len(snippets) >= 12:
            break

    context = {
        "detected_stack": stack["label"],
        "useful_file_inventory": useful_files,
        "security_sensitive_files": security_sensitive_files,
        "rule_summary": rules["summary"],
        "failed_findings": failed,
        "review_findings": review,
        "safe_passed_categories": safe_categories,
        "selected_masked_snippets": snippets,
        "route_inventory": route_inventory,
        "auth_related_files": auth_related_files,
        "database_related_files": database_related_files,
        "payment_related_files": payment_related_files,
        "infra_related_files": infra_related_files,
        "storage_related_files": storage_related_files,
    }

    serialized = json.dumps(context)
    if len(serialized) > 35000:
        while len(serialized) > 35000 and context["selected_masked_snippets"]:
            context["selected_masked_snippets"].pop()
            serialized = json.dumps(context)
    return context
