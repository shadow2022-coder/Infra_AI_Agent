from __future__ import annotations

import json


def detect_stack(useful_files: list[str], raw_contents: dict[str, str]) -> dict:
    badges = set()
    lower_files = {path.lower() for path in useful_files}
    package_json = raw_contents.get("package.json")

    dependencies = {}
    if package_json:
        try:
            pkg = json.loads(package_json)
            dependencies.update(pkg.get("dependencies", {}))
            dependencies.update(pkg.get("devDependencies", {}))
        except json.JSONDecodeError:
            pass

    dep_names = set(dependencies)
    if "next" in dep_names or any("/app/" in path for path in lower_files):
        badges.add("Next.js")
    if "react" in dep_names:
        badges.add("React")
    if "@supabase/supabase-js" in dep_names or any("supabase/" in path for path in lower_files):
        badges.add("Supabase")
    if "stripe" in dep_names or any("stripe" in path for path in lower_files):
        badges.add("Stripe")
    if any("vercel.json" in path for path in lower_files):
        badges.add("Vercel")
    if "firebase" in dep_names or "@firebase/app" in dep_names:
        badges.add("Firebase")
    if "express" in dep_names:
        badges.add("Node/Express")
    if any(path.endswith(".py") for path in lower_files):
        badges.add("Python")
    if "fastapi" in dep_names:
        badges.add("FastAPI")
    if any("dockerfile" == path.split("/")[-1] for path in lower_files) or "docker-compose.yml" in lower_files:
        badges.add("Docker")
    if any(path.endswith(".tf") for path in lower_files):
        badges.add("Terraform")
    if any("k8s" in path or "kubernetes" in path for path in lower_files):
        badges.add("Kubernetes")
    if any(path.endswith("schema.prisma") for path in lower_files):
        badges.add("Prisma")
    if any(path.startswith(".github/workflows/") for path in lower_files):
        badges.add("GitHub Actions")
    if any("postgres" in text.lower() or "postgresql" in text.lower() for text in raw_contents.values()):
        badges.add("PostgreSQL")

    combo = " + ".join(sorted(badges)) if badges else "Unknown stack"
    return {"badges": sorted(badges), "label": combo}
