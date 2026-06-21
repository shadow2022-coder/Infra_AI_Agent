from __future__ import annotations

from pathlib import Path

IGNORED_DIRS = {
    "node_modules",
    ".git",
    "dist",
    "build",
    ".next",
    ".turbo",
    "coverage",
    ".cache",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
}

IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".mp4",
    ".mov",
    ".avi",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".mp3",
    ".wav",
}

USEFUL_NAMES = {
    "package.json",
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
    "Dockerfile",
    "docker-compose.yml",
    "vercel.json",
    ".env",
    ".env.example",
    ".env.local",
    "schema.sql",
}

USEFUL_PARTS = {
    "supabase",
    "prisma",
    "terraform",
    ".github/workflows",
    "middleware",
    "auth",
    "session",
    "stripe",
    "payment",
    "storage",
    "rbac",
    "role",
    "policy",
    "route",
    "api",
    "k8s",
    "kubernetes",
}

TEXT_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".md",
    ".sql",
    ".prisma",
    ".tf",
    ".txt",
    ".sh",
    ".ini",
}

MAX_FILE_BYTES = 220_000
MAX_LOCK_BYTES = 140_000


def _is_binary(file_path: Path) -> bool:
    try:
        with file_path.open("rb") as handle:
            chunk = handle.read(1024)
    except OSError:
        return True
    return b"\x00" in chunk


def _is_minified(name: str, content: str) -> bool:
    return (".min." in name) or (len(content) > 3000 and "\n" not in content[:2500])


def _is_useful(rel_path: str, file_path: Path) -> bool:
    name = file_path.name
    lower = rel_path.lower()
    if name in USEFUL_NAMES:
        return True
    if any(part in lower for part in USEFUL_PARTS):
        return True
    return file_path.suffix.lower() in {".py", ".ts", ".tsx", ".js", ".jsx", ".sql", ".prisma", ".tf"}


def scan_project(project_root: Path) -> dict:
    all_files = []
    useful_files = []
    ignored = []
    raw_contents = {}

    for file_path in sorted(project_root.rglob("*")):
        if not file_path.is_file():
            continue

        rel_path = file_path.relative_to(project_root).as_posix()
        all_files.append(rel_path)
        parts = set(file_path.parts)
        if parts & IGNORED_DIRS:
            ignored.append({"path": rel_path, "reason": "ignored_directory"})
            continue

        suffix = file_path.suffix.lower()
        if suffix in IGNORED_EXTENSIONS:
            ignored.append({"path": rel_path, "reason": "binary_or_media"})
            continue

        size = file_path.stat().st_size
        if file_path.name.endswith("lock.json") and size > MAX_LOCK_BYTES:
            ignored.append({"path": rel_path, "reason": "large_lock_file"})
            continue
        if size > MAX_FILE_BYTES:
            ignored.append({"path": rel_path, "reason": "large_generated_file"})
            continue
        if _is_binary(file_path):
            ignored.append({"path": rel_path, "reason": "binary_file"})
            continue

        if suffix not in TEXT_EXTENSIONS and file_path.name not in USEFUL_NAMES:
            ignored.append({"path": rel_path, "reason": "not_security_relevant"})
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        if _is_minified(rel_path, content):
            ignored.append({"path": rel_path, "reason": "minified_bundle"})
            continue

        raw_contents[rel_path] = content
        if _is_useful(rel_path, file_path):
            useful_files.append(rel_path)

    return {
        "project_root": project_root,
        "all_files": all_files,
        "useful_files": useful_files[:80],
        "ignored_files": ignored,
        "raw_contents": raw_contents,
        "scanned_file_count": len(raw_contents),
    }
