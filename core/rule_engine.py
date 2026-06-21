from __future__ import annotations

import json
import re
from collections import Counter
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from core.secret_masker import mask_text

RULES = [
    ("R001", "Exposed secrets detected", "critical"),
    ("R002", ".env file present in project", "high"),
    ("R003", "Weak secret detected", "high"),
    ("R004", "SQL injection pattern", "critical"),
    ("R005", "XSS pattern", "high"),
    ("R006", "CORS wildcard enabled", "high"),
    ("R007", "Public database exposure", "critical"),
    ("R008", "Missing Supabase RLS", "critical"),
    ("R009", "Plaintext password field", "high"),
    ("R010", "Wildcard IAM rule", "critical"),
    ("R011", "Public storage bucket", "high"),
    ("R012", "Docker container runs as root", "medium"),
    ("R013", "Docker privileged mode", "high"),
    ("R014", "Kubernetes privileged container", "high"),
    ("R015", "Weak auth/session settings", "high"),
    ("R016", "Missing rate limiting", "medium"),
    ("R017", "Dangerous dependency script", "medium"),
    ("R018", "Unsafe GitHub Actions workflow", "medium"),
    ("R019", "Debug mode enabled", "medium"),
    ("R020", "Insecure cookies", "medium"),
    ("R021", "Missing security headers", "medium"),
    ("R022", "Open redirect pattern", "medium"),
    ("R023", "Hardcoded admin credentials", "critical"),
    ("R024", "Unsafe file upload handling", "medium"),
    ("R025", "Public service role usage", "critical"),
    ("R026", "Client-side secret usage", "critical"),
    ("R027", "Missing CSRF protection", "medium"),
    ("R028", "Overly permissive API routes", "high"),
    ("R029", "Missing authorization checks", "high"),
    ("R030", "Stripe webhook verification missing", "high"),
    ("R031", "Stripe secret in frontend", "critical"),
    ("R032", "Database URL exposed", "critical"),
    ("R033", "JWT none or weak algorithm", "high"),
    ("R034", "Long-lived tokens", "medium"),
    ("R035", "Sensitive data logged", "medium"),
    ("R036", "GraphQL introspection exposure", "low"),
    ("R037", "Admin route without middleware", "high"),
    ("R038", "S3/public bucket-style config", "high"),
    ("R039", "Firebase permissive rules", "high"),
    ("R040", "Terraform public access", "high"),
    ("R041", "Kubernetes LoadBalancer exposure", "medium"),
    ("R042", "Docker ADD remote URL", "medium"),
    ("R043", "npm install script risk", "medium"),
    ("R044", "Suspicious postinstall script", "medium"),
    ("R045", "eval/new Function usage", "high"),
    ("R046", "Dangerous shell execution", "high"),
    ("R047", "Path traversal pattern", "high"),
    ("R048", "SSRF-prone fetch pattern", "medium"),
    ("R049", "Missing tenant isolation hints", "medium"),
    ("R050", "Unprotected cron/webhook route", "high"),
]

AUTH_CHECK_TOKENS = (
    "session",
    "getserversession",
    "auth(",
    "requireauth",
    "verifytoken",
    "middleware",
    "authorization",
    "bearer",
    "jwt.verify",
    "supabase.auth.getuser",
    "getuser(",
    "clerk",
    "currentuser",
    "withauth",
    "isauthenticated",
    "requireuser",
)
OWNERSHIP_TOKENS = ("user.id", "session.user.id", "ownerid", "tenantid", "organizationid", "accountid", "role", "isadmin", "policy")
USER_INPUT_TOKENS = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.args",
    "request.form",
    "searchparams.get",
    "params.",
    "body.",
    "formdata",
    "input",
    "userinput",
    "process.argv",
)
DANGEROUS_SINK_TOKENS = ("exec(", "execsync(", "spawn(", "spawnsync(", "system(", "subprocess.call(", "subprocess.run(", "os.system(", "child_process.exec", "child_process.spawn")
DANGEROUS_SCRIPT_TOKENS = (
    "curl",
    "wget",
    "bash",
    " sh ",
    "sh -c",
    "eval",
    "node -e",
    "python -c",
    "ruby -e",
    "perl -e",
    "powershell",
    "invoke-webrequest",
    "http://",
    "https://",
    "chmod +x",
    "base64 -d",
    "nc ",
    "netcat",
)
SECRET_NAME_HINTS = (
    "secret",
    "token",
    "api_key",
    "apikey",
    "service_role",
    "anon_key",
    "database_url",
    "db_url",
    "private_key",
    "access_key",
    "password",
    "jwt",
    "stripe",
    "openai",
)
PLACEHOLDER_HINTS = (
    "placeholder",
    "your_",
    "your-",
    "yourkey",
    "your key",
    "example",
    "sample",
    "demo",
    "fake",
    "test",
    "changeme",
    "replace_me",
    "replace-me",
    "<api_key>",
    "<token>",
    "<secret>",
    "xxx",
)


def iter_files(scan: dict, extensions: Optional[Iterable[str]] = None, names: Optional[Iterable[str]] = None, path_contains: Optional[Iterable[str]] = None) -> Iterator[dict]:
    extensions_set = {item.lower() for item in (extensions or [])}
    names_set = {item.lower() for item in (names or [])}
    path_parts = [item.lower() for item in (path_contains or [])]
    for path, text in scan["raw_contents"].items():
        lower_path = path.lower()
        name = path.rsplit("/", 1)[-1].lower()
        if extensions_set and not any(lower_path.endswith(ext) for ext in extensions_set):
            continue
        if names_set and name not in names_set:
            continue
        if path_parts and not any(part in lower_path for part in path_parts):
            continue
        yield {"path": path, "text": text}


def get_file_text(file_obj_or_dict: dict) -> str:
    return file_obj_or_dict["text"]


def get_file_path(file_obj_or_dict: dict) -> str:
    return file_obj_or_dict["path"]


def has_any(text: str, needles: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def regex_search(pattern: str, text: str, flags: int = re.I | re.M):
    return re.search(pattern, text, flags)


def compact_evidence(text: str, max_len: int = 220) -> str:
    squashed = re.sub(r"\s+", " ", text.strip())
    return squashed[:max_len]


def mask_evidence(text: str) -> str:
    return compact_evidence(mask_text(text))


def strip_comments_for_detection(text: str) -> str:
    without_block = re.sub(r"/\*[\s\S]*?\*/", " ", text)
    without_line = re.sub(r"(^|\s)//.*?$", " ", without_block, flags=re.M)
    without_hash = re.sub(r"^\s*#.*?$", " ", without_line, flags=re.M)
    return without_hash


def is_placeholder_secret(value: str) -> bool:
    lowered = value.strip().strip("\"'").lower()
    if not lowered:
        return True
    if any(hint in lowered for hint in PLACEHOLDER_HINTS):
        return True
    if lowered in {"true", "false", "null", "none"}:
        return True
    return bool(re.fullmatch(r"[x\*_\-]{4,}", lowered))


def is_probably_secret(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    lowered = stripped.lower()
    if is_placeholder_secret(stripped):
        return False
    patterns = (
        r"sk_(live|test)_[a-z0-9]{8,}",
        r"sk-[a-z0-9]{20,}",
        r"rk-[a-z0-9_-]{16,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{20,}",
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        r"(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://",
    )
    if any(regex_search(pattern, stripped, re.I) for pattern in patterns):
        return True
    if len(stripped) >= 20 and re.search(r"[A-Za-z]", stripped) and re.search(r"\d", stripped):
        return True
    return any(token in lowered for token in ("service_role", "jwt_secret", "stripe_secret", "database_url"))


def is_route_file(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(("/route.ts", "/route.js", "/route.py")) or "/api/" in lowered or "routes/" in lowered or "webhook" in lowered


def has_auth_check(text: str) -> bool:
    return has_any(strip_comments_for_detection(text), AUTH_CHECK_TOKENS)


def has_user_input_source(text: str) -> bool:
    return has_any(strip_comments_for_detection(text), USER_INPUT_TOKENS)


def has_dangerous_sink(text: str) -> bool:
    return has_any(strip_comments_for_detection(text), DANGEROUS_SINK_TOKENS)


def _parse_json(text: str) -> Optional[dict]:
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _iter_env_pairs(text: str) -> Iterator[Tuple[str, str]]:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        yield key.strip(), value.strip()


def _find_real_secret(file_obj: dict) -> Optional[str]:
    for key, value in _iter_env_pairs(get_file_text(file_obj)):
        if any(hint in key.lower() for hint in SECRET_NAME_HINTS) and is_probably_secret(value):
            return f"{key}={value}"
    text = get_file_text(file_obj)
    for pattern in (
        r"sk_(?:live|test)_[A-Za-z0-9]+",
        r"sk-[A-Za-z0-9]{20,}",
        r"rk-[A-Za-z0-9_-]{16,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{20,}",
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s\"']+",
    ):
        match = regex_search(pattern, text)
        if match and is_probably_secret(match.group(0)):
            return match.group(0)
    return None


def _issue(status: str, file_path: str, evidence: str) -> Tuple[str, str, str]:
    return status, file_path, mask_evidence(evidence)


def _scan_has(scan: dict, *, path_tokens: Iterable[str] = (), extensions: Iterable[str] = (), names: Iterable[str] = ()) -> bool:
    tokens = [item.lower() for item in path_tokens]
    exts = [item.lower() for item in extensions]
    file_names = [item.lower() for item in names]
    for path in scan["raw_contents"]:
        lower = path.lower()
        name = lower.rsplit("/", 1)[-1]
        if tokens and any(token in lower for token in tokens):
            return True
        if exts and any(lower.endswith(ext) for ext in exts):
            return True
        if file_names and name in file_names:
            return True
    return False


def _weak_secret_value(value: str) -> bool:
    lowered = value.strip().strip("\"'").lower()
    return lowered in {"dev", "development", "changeme", "password", "admin", "admin123", "123456", "secret", "test", "jwtsecret", "default"}


def _script_is_dangerous(script: str) -> bool:
    lowered = f" {script.lower()} "
    return any(token in lowered for token in DANGEROUS_SCRIPT_TOKENS)


def _is_client_file(path: str, text: str) -> bool:
    lowered = path.lower()
    return lowered.endswith((".tsx", ".jsx", ".ts", ".js")) and (
        any(part in lowered for part in ("app/", "pages/", "components/", "src/components/", "public/"))
        or "\"use client\"" in text
        or "'use client'" in text
    )


def _sensitive_route(path: str, text: str) -> bool:
    lowered = f"{path.lower()} {text.lower()}"
    return any(token in lowered for token in ("login", "signup", "auth", "password", "otp", "payment", "checkout", "api key", "apikey", "webhook"))


def _has_rate_limit(text: str) -> bool:
    return has_any(text, ("ratelimit", "rate limit", "upstash/ratelimit", "express-rate-limit", "slowapi", "limiter", "throttle"))


def _has_security_headers(text: str) -> bool:
    return has_any(text, ("content-security-policy", "x-frame-options", "strict-transport-security", "helmet(", "frame-ancestors", "x-content-type-options"))


def _docker_final_stage_status(text: str) -> Optional[Tuple[str, str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    from_indexes = [index for index, line in enumerate(lines) if line.lower().startswith("from ")]
    if not from_indexes:
        return None
    final_lines = lines[from_indexes[-1] + 1 :]
    users = [line.split(None, 1)[1].strip() for line in final_lines if line.lower().startswith("user ")]
    if not users:
        return "fail", "Final Docker stage has no USER directive."
    final_user = users[-1].strip("\"'")
    if final_user.lower() == "root":
        return "fail", "Final Docker stage explicitly sets USER root."
    if regex_search(r"^\d+$", final_user) and final_user != "0":
        return None
    if final_user and final_user not in {"0", "${ROOT_USER}"}:
        return None
    return "review", f"Unable to confirm whether USER {final_user or 'unknown'} is non-root."


def _route_has_write_handler(text: str) -> bool:
    return has_any(text, ("post(", "put(", "patch(", "delete(", "export async function post", "export async function put", "export async function patch", "export async function delete", "app.post(", "router.post(", "@app.post(", "@router.post("))


def _route_has_public_get_only(text: str) -> bool:
    lowered = strip_comments_for_detection(text).lower()
    return has_any(lowered, ("get(", "export async function get", "app.get(", "router.get(", "@app.get(", "@router.get(")) and not _route_has_write_handler(lowered)


def _request_ids_without_ownership(text: str) -> bool:
    lowered = strip_comments_for_detection(text).lower()
    return has_any(lowered, ("req.params", "req.body", "searchparams.get", "params.", "body.", "request.args", "request.form")) and not has_any(lowered, OWNERSHIP_TOKENS)


def _check_r001(scan: dict):
    for file_obj in iter_files(scan):
        secret = _find_real_secret(file_obj)
        if secret:
            return _issue("fail", get_file_path(file_obj), secret)
    return None


def _check_r002(scan: dict):
    for file_obj in iter_files(scan, path_contains=(".env",)):
        path = get_file_path(file_obj).lower()
        has_secret = False
        sample_value = None
        for key, value in _iter_env_pairs(get_file_text(file_obj)):
            if any(hint in key.lower() for hint in SECRET_NAME_HINTS) and is_probably_secret(value):
                has_secret = True
                sample_value = f"{key}={value}"
                break
        if not has_secret:
            continue
        if any(path.endswith(suffix) for suffix in (".env.example", ".env.sample", ".env.template")):
            return _issue("review", get_file_path(file_obj), sample_value or "Example environment file contains realistic secret-like values.")
        return _issue("fail", get_file_path(file_obj), sample_value or "Environment file contains real secret-like values.")
    return None


def _check_r003(scan: dict):
    for file_obj in iter_files(scan):
        for key, value in _iter_env_pairs(get_file_text(file_obj)):
            if any(token in key.lower() for token in ("secret", "password", "token", "jwt")) and _weak_secret_value(value):
                return _issue("fail", get_file_path(file_obj), f"{key}={value}")
    return None


def _check_r004(scan: dict):
    dynamic_sql = (
        r"(select|insert|update|delete)[^;\n]{0,200}(\+|\$\{|f\"|f'|format\()",
        r"db\.query\([^)]*(\+|\$\{)",
        r"execute\([^)]*(\+|\$\{)",
    )
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".py")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_user_input_source(text):
            continue
        if any(regex_search(pattern, text) for pattern in dynamic_sql):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r005(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".vue")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("dangerouslysetinnerhtml", "innerhtml", "insertadjacenthtml", "v-html")):
            continue
        if has_any(text, ("dompurify", "sanitizehtml", "escapehtml", " he.", "xss")):
            continue
        if has_user_input_source(text):
            return _issue("fail", get_file_path(file_obj), text)
        return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r006(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("access-control-allow-origin", "origin: \"*\"", "origin: '*'", "\"value\": \"*\"")):
            continue
        if has_any(text, ("credentials: true", "allow-credentials", "app.use('/api", "source\": \"/api", "cors(")):
            return _issue("fail", get_file_path(file_obj), text)
        return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r007(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if regex_search(r"(5432|3306|27017).*(0\.0\.0\.0/0)", text) or has_any(text, ("publicly_accessible = true", "db_public = true", "allow public database")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r008(scan: dict):
    for file_obj in iter_files(scan, extensions=(".sql",), path_contains=("supabase/migrations",)):
        text = strip_comments_for_detection(get_file_text(file_obj))
        table_match = regex_search(r"create table\s+(?:public\.)?(\w+)", text)
        if not table_match:
            continue
        table_name = table_match.group(1).lower()
        if table_name not in {"users", "customers", "payments", "orders", "profiles", "accounts", "invoices", "transactions", "subscriptions"}:
            continue
        if f"alter table {table_name} enable row level security" in text.lower() or "create policy" in text.lower():
            continue
        return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r009(scan: dict):
    for file_obj in iter_files(scan, extensions=(".prisma", ".sql", ".py", ".ts", ".tsx", ".js", ".jsx")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if regex_search(r"\bpassword\b\s+(text|string|varchar)", text) or regex_search(r"\bpassword\s*:\s*string\b", text):
            if "hash" not in text.lower():
                return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r010(scan: dict):
    for file_obj in iter_files(scan, extensions=(".tf", ".json", ".yaml", ".yml")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("iam", "policy", "principal", "action", "resource")):
            continue
        if regex_search(r"action\s*[:=]\s*['\"]?\*['\"]?", text) or regex_search(r"resource\s*[:=]\s*['\"]?\*['\"]?", text) or regex_search(r"principal\s*[:=]\s*['\"]?\*['\"]?", text):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r011(scan: dict):
    for file_obj in iter_files(scan, path_contains=("storage", "bucket", "supabase")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("public = true", "public: true", "public-read", "acl = \"public-read\"")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r012(scan: dict):
    for file_obj in iter_files(scan, names=("dockerfile",), path_contains=("dockerfile",)):
        status = _docker_final_stage_status(get_file_text(file_obj))
        if status:
            level, evidence = status
            return _issue(level, get_file_path(file_obj), evidence)
    return None


def _check_r013(scan: dict):
    for file_obj in iter_files(scan, names=("docker-compose.yml", "docker-compose.yaml"), extensions=(".yml", ".yaml")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "privileged: true" in text.lower():
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r014(scan: dict):
    for file_obj in iter_files(scan, extensions=(".yml", ".yaml"), path_contains=("k8s", "kubernetes", "deployment")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "privileged: true" in text.lower():
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r015(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("secure: false", "httponly: false", "samesite: \"none\"", "samesite: 'none'", "sameSite: \"none\"", "sameSite: 'none'")):
            return _issue("fail", get_file_path(file_obj), text)
        for key, value in _iter_env_pairs(text):
            if any(token in key.lower() for token in ("jwt_secret", "session_secret")) and _weak_secret_value(value):
                return _issue("fail", get_file_path(file_obj), f"{key}={value}")
    return None


def _check_r016(scan: dict):
    all_text = "\n".join(scan["raw_contents"].values())
    if _has_rate_limit(all_text):
        return None
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if is_route_file(get_file_path(file_obj)) and _sensitive_route(get_file_path(file_obj), text):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r017(scan: dict):
    for file_obj in iter_files(scan, names=("package.json",)):
        data = _parse_json(get_file_text(file_obj))
        if not data:
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for key in ("install", "prepare"):
            script = scripts.get(key)
            if isinstance(script, str) and _script_is_dangerous(script):
                return _issue("fail", get_file_path(file_obj), f"{key}: {script}")
    return None


def _check_r018(scan: dict):
    for file_obj in iter_files(scan, path_contains=(".github/workflows",), extensions=(".yml", ".yaml")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("pull_request_target", "secrets: inherit", "workflow_run")):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r019(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("debug=true", "debug = true", "fastapi(debug=true)", "node_env=development", "flask_env=development")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r020(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("secure: false", "httponly: false", "httpOnly: false")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r021(scan: dict):
    all_text = "\n".join(scan["raw_contents"].values())
    if _has_security_headers(all_text):
        return None
    if any(badge in all_text.lower() for badge in ("next", "express", "react")) or any(is_route_file(path) for path in scan["raw_contents"]):
        return _issue("review", "N/A", "No security header middleware or header config was detected.")
    return None


def _check_r022(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".py")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("redirect(", "res.redirect(", "window.location")) and has_user_input_source(text) and not has_any(text, ("allowlist", "whitelist", "new url(", "startsWith('/')")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r023(scan: dict):
    for file_obj in iter_files(scan):
        text = get_file_text(file_obj)
        if has_any(text, ("admin@example.com", "admin123", "root:root")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r024(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("multer", "upload", "formdata", "createReadStream", "file =")):
            continue
        if not has_any(text, ("mimetype", "content-type", "filesize", "size limit", "basename", "sanitize", "allowlist")):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r025(scan: dict):
    for file_obj in iter_files(scan):
        text = get_file_text(file_obj)
        if "service_role" not in text.lower():
            continue
        return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r026(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx")):
        path = get_file_path(file_obj)
        text = get_file_text(file_obj)
        if not _is_client_file(path, text):
            continue
        if has_any(text, ("service_role", "stripe_secret", "openai_api_key", "database_url")) or regex_search(r"NEXT_PUBLIC_[A-Z0-9_]*(SECRET|TOKEN|SERVICE_ROLE|DATABASE_URL)", text):
            return _issue("fail", path, text)
    return None


def _check_r027(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj)
        text = strip_comments_for_detection(get_file_text(file_obj))
        if is_route_file(path) and _route_has_write_handler(text) and has_any(text, ("cookie", "session")) and not has_any(text, ("csrf", "origin check", "same-origin", "double submit")):
            return _issue("review", path, text)
    return None


def _check_r028(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj)
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not is_route_file(path):
            continue
        if not (_route_has_write_handler(text) or (_route_has_public_get_only(text) and _sensitive_route(path, text))):
            continue
        if has_auth_check(text):
            continue
        if _route_has_public_get_only(text) and not _sensitive_route(path, text):
            continue
        return _issue("fail", path, text)
    return None


def _check_r029(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj)
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not is_route_file(path):
            continue
        if not _request_ids_without_ownership(text):
            continue
        if has_auth_check(text):
            return _issue("review", path, text)
        if has_any(f"{path} {text}", ("user", "account", "order", "payment", "invoice", "subscription", "admin")):
            return _issue("fail", path, text)
    return None


def _check_r030(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj).lower()
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "webhook" in path or "stripe" in path or has_any(text, ("stripe", "webhook")):
            if has_any(text, ("constructevent", "verifysignature", "svix.verify", "crypto.createhmac")):
                continue
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r031(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx")):
        path = get_file_path(file_obj)
        text = get_file_text(file_obj)
        if _is_client_file(path, text) and has_any(text, ("sk_live_", "sk_test_", "STRIPE_SECRET_KEY", "process.env.STRIPE_SECRET")):
            return _issue("fail", path, text)
    return None


def _check_r032(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj)
        text = get_file_text(file_obj)
        if regex_search(r"(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s\"']+", text):
            return _issue("fail", path, text)
    return None


def _check_r033(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("algorithm: \"none\"", "algorithm: 'none'", "alg: \"none\"", "alg: 'none'", "algorithms: [\"none\"]", "algorithms: ['none']")):
            return _issue("fail", get_file_path(file_obj), text)
        if "jwt.decode(" in text.lower() and has_any(text, ("auth", "login", "session", "bearer")):
            return _issue("review", get_file_path(file_obj), text)
        if "ignoreexpiration: true" in text.lower():
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r034(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if regex_search(r"expiresin\s*:\s*['\"](?:9\d|[1-9]\d{2,})d['\"]", text) or regex_search(r"maxage\s*:\s*(?:3[1-9]\d{5}|[4-9]\d{6,})", text):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r035(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("console.log(", "logger.", "print(")) and has_any(text, ("password", "token", "secret", "authorization", "req.body", "body.password")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r036(scan: dict):
    for file_obj in iter_files(scan):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("introspection: true", "graphiql: true", "playground: true")):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r037(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj)
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "admin" in path.lower() and is_route_file(path) and not has_auth_check(text):
            return _issue("fail", path, text)
    return None


def _check_r038(scan: dict):
    return _check_r011(scan)


def _check_r039(scan: dict):
    for file_obj in iter_files(scan, path_contains=("firebase",), extensions=(".rules", ".txt", ".js")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "allow read, write: if true" in text.lower():
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r040(scan: dict):
    for file_obj in iter_files(scan, extensions=(".tf",)):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("0.0.0.0/0", "public-read", "publicly_accessible = true")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r041(scan: dict):
    for file_obj in iter_files(scan, extensions=(".yml", ".yaml"), path_contains=("k8s", "kubernetes", "service")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "type: loadbalancer" in text.lower():
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r042(scan: dict):
    for file_obj in iter_files(scan, names=("dockerfile",), path_contains=("dockerfile",)):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if regex_search(r"^\s*ADD\s+https?://", text, re.I | re.M):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r043(scan: dict):
    for file_obj in iter_files(scan, names=("package.json",)):
        data = _parse_json(get_file_text(file_obj))
        if not data:
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for key in ("install", "prepare", "preinstall", "postinstall"):
            script = scripts.get(key)
            if isinstance(script, str) and _script_is_dangerous(script):
                return _issue("fail", get_file_path(file_obj), f"{key}: {script}")
    return None


def _check_r044(scan: dict):
    for file_obj in iter_files(scan, names=("package.json",)):
        data = _parse_json(get_file_text(file_obj))
        if not data:
            continue
        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            continue
        for key in ("postinstall", "preinstall"):
            script = scripts.get(key)
            if isinstance(script, str) and _script_is_dangerous(script):
                return _issue("fail", get_file_path(file_obj), f"{key}: {script}")
    return None


def _check_r045(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if has_any(text, ("eval(", "new function(")):
            return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r046(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".py")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_dangerous_sink(text):
            continue
        if has_user_input_source(text):
            return _issue("fail", get_file_path(file_obj), text)
        if regex_search(r"(exec|spawn|system|subprocess\.run|subprocess\.call|os\.system)\([^)]*(\+|\$\{|format\(|f\"|f')", text):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r047(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".py")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("path.join", "path.resolve", "readfile", "readfilesync", "createreadstream", "writefile", "writefilesync", "sendfile", "open(", "fs.")):
            continue
        if has_user_input_source(text) and has_any(text, ("filename", "fileName", "pathparam", "req.query", "req.params", "request.args", "searchparams.get", "body.")):
            if not has_any(text, ("path.basename", "normalize", "sanitize", "safejoin", "zod", "joi(", "joi.", "allowlist", "whitelist")):
                return _issue("fail", get_file_path(file_obj), text)
    return None


def _check_r048(scan: dict):
    for file_obj in iter_files(scan, extensions=(".js", ".jsx", ".ts", ".tsx", ".py")):
        text = strip_comments_for_detection(get_file_text(file_obj))
        if not has_any(text, ("fetch(", "axios.get(", "axios.post(", "requests.get(", "requests.post(", "httpx.get(", "httpx.post(")):
            continue
        if has_user_input_source(text) and not has_any(text, ("allowlist", "whitelist", "hostname", "urlparse", "new url(", "startswith(\"https://api.")):
            return _issue("review", get_file_path(file_obj), text)
    return None


def _check_r049(scan: dict):
    all_text = "\n".join(scan["raw_contents"].values()).lower()
    if any(token in all_text for token in ("organization", "workspace", "tenant", "team")) and not any(token in all_text for token in ("tenantid", "organizationid", "workspaceid", "accountid", "ownerid")):
        return _issue("review", "N/A", "Multi-tenant concepts were detected without clear tenant isolation fields.")
    return None


def _check_r050(scan: dict):
    for file_obj in iter_files(scan):
        path = get_file_path(file_obj).lower()
        text = strip_comments_for_detection(get_file_text(file_obj))
        if "cron" in path or "webhook" in path:
            if has_any(text, ("authorization", "bearer", "signature", "verify", "constructevent", "svix.verify", "crypto.createhmac")):
                continue
            return _issue("fail", get_file_path(file_obj), text)
    return None


CHECKS = {
    "R001": _check_r001,
    "R002": _check_r002,
    "R003": _check_r003,
    "R004": _check_r004,
    "R005": _check_r005,
    "R006": _check_r006,
    "R007": _check_r007,
    "R008": _check_r008,
    "R009": _check_r009,
    "R010": _check_r010,
    "R011": _check_r011,
    "R012": _check_r012,
    "R013": _check_r013,
    "R014": _check_r014,
    "R015": _check_r015,
    "R016": _check_r016,
    "R017": _check_r017,
    "R018": _check_r018,
    "R019": _check_r019,
    "R020": _check_r020,
    "R021": _check_r021,
    "R022": _check_r022,
    "R023": _check_r023,
    "R024": _check_r024,
    "R025": _check_r025,
    "R026": _check_r026,
    "R027": _check_r027,
    "R028": _check_r028,
    "R029": _check_r029,
    "R030": _check_r030,
    "R031": _check_r031,
    "R032": _check_r032,
    "R033": _check_r033,
    "R034": _check_r034,
    "R035": _check_r035,
    "R036": _check_r036,
    "R037": _check_r037,
    "R038": _check_r038,
    "R039": _check_r039,
    "R040": _check_r040,
    "R041": _check_r041,
    "R042": _check_r042,
    "R043": _check_r043,
    "R044": _check_r044,
    "R045": _check_r045,
    "R046": _check_r046,
    "R047": _check_r047,
    "R048": _check_r048,
    "R049": _check_r049,
    "R050": _check_r050,
}

APPLICABILITY = {
    "R008": (lambda scan: _scan_has(scan, path_tokens=("supabase/migrations",), extensions=(".sql",)), "No Supabase migration files found, so the RLS check was not used."),
    "R010": (lambda scan: _scan_has(scan, path_tokens=("iam", "policy"), extensions=(".tf", ".json", ".yaml", ".yml")), "No IAM or policy configuration was found, so the wildcard IAM check was not used."),
    "R011": (lambda scan: _scan_has(scan, path_tokens=("storage", "bucket", "s3", "supabase")), "No object storage configuration was found, so the bucket exposure check was not used."),
    "R012": (lambda scan: _scan_has(scan, names=("dockerfile",), path_tokens=("dockerfile",)), "No Dockerfile found, so the Docker runtime user check was not used."),
    "R013": (lambda scan: _scan_has(scan, names=("docker-compose.yml", "docker-compose.yaml")), "No docker-compose file found, so the Docker privileged mode check was not used."),
    "R014": (lambda scan: _scan_has(scan, path_tokens=("k8s", "kubernetes"), extensions=(".yml", ".yaml")), "No Kubernetes manifests found, so the privileged container check was not used."),
    "R016": (lambda scan: any(is_route_file(path) and _sensitive_route(path, text) for path, text in scan["raw_contents"].items()), "No sensitive auth, payment, upload, or webhook route was found, so the rate-limit check was not used."),
    "R018": (lambda scan: _scan_has(scan, path_tokens=(".github/workflows",), extensions=(".yml", ".yaml")), "No GitHub Actions workflow was found, so the CI/CD workflow check was not used."),
    "R027": (lambda scan: any(is_route_file(path) and _route_has_write_handler(text) and has_any(text, ("cookie", "session")) for path, text in scan["raw_contents"].items()), "No state-changing session/cookie route was found, so the CSRF check was not used."),
    "R030": (lambda scan: any("webhook" in path.lower() or "stripe" in path.lower() or has_any(text, ("stripe", "webhook")) for path, text in scan["raw_contents"].items()), "No payment or webhook route was found, so the webhook verification check was not used."),
    "R031": (lambda scan: any(_is_client_file(path, text) for path, text in scan["raw_contents"].items()), "No client-side code was found, so the frontend Stripe secret check was not used."),
    "R033": (lambda scan: any(has_any(text, ("jwt", "token", "session")) for text in scan["raw_contents"].values()), "No JWT or token-handling code was found, so the JWT algorithm check was not used."),
    "R036": (lambda scan: any("graphql" in path.lower() or "graphql" in text.lower() for path, text in scan["raw_contents"].items()), "No GraphQL surface was found, so the introspection check was not used."),
    "R039": (lambda scan: _scan_has(scan, path_tokens=("firebase",), names=("firebase.rules",)), "No Firebase rules were found, so the Firebase permissive-rules check was not used."),
    "R040": (lambda scan: _scan_has(scan, extensions=(".tf",)), "No Terraform files were found, so the Terraform public-access check was not used."),
    "R041": (lambda scan: _scan_has(scan, path_tokens=("k8s", "kubernetes"), extensions=(".yml", ".yaml")), "No Kubernetes service manifests were found, so the LoadBalancer exposure check was not used."),
    "R042": (lambda scan: _scan_has(scan, names=("dockerfile",), path_tokens=("dockerfile",)), "No Dockerfile found, so the remote ADD check was not used."),
}

WHY_BY_SEVERITY = {
    "critical": "This can directly expose customer data or create an immediate deployment blocker.",
    "high": "This materially raises breach likelihood or investor-facing deployment risk.",
    "medium": "This weakens baseline security posture and should be fixed before production growth.",
    "low": "This is a smaller hardening gap worth tracking.",
    "info": "This is informational and should be reviewed in context.",
}
FIX_BY_RULE = {
    "R002": "Keep real secrets only in deployment-managed secret stores. Commit placeholder-only `.env.example` files.",
    "R004": "Use parameterized queries or ORM filters instead of concatenating user input into SQL.",
    "R005": "Sanitize untrusted HTML with a vetted sanitizer or avoid raw HTML sinks entirely.",
    "R008": "Enable Supabase Row Level Security and add explicit least-privilege policies for sensitive tables.",
    "R012": "Create a non-root runtime user in the final Docker stage and switch to it before app start.",
    "R016": "Add route-level rate limiting to sensitive auth, payment, and webhook endpoints.",
    "R025": "Move service-role access to a trusted server path and never expose it to client bundles or committed app files.",
    "R028": "Require authentication and authorization for sensitive route handlers before processing the request.",
    "R030": "Verify webhook signatures before accepting the event payload.",
    "R043": "Keep lifecycle scripts deterministic and local; remove download-and-execute behavior from package scripts.",
    "R046": "Avoid shelling out with user-controlled input. Use strict allowlists or direct library APIs instead.",
    "R047": "Resolve file paths against an allowlisted base path and sanitize untrusted filenames before file access.",
}


def _result(rule_id: str, title: str, severity: str, status: str, file_path: str, evidence: str, why: str, fix: str) -> dict:
    return {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "status": status,
        "file": file_path,
        "evidence": evidence,
        "why_it_matters": why,
        "fix": fix,
        "reason": why,
        "files": [] if file_path == "N/A" else [file_path],
    }


def run_rules(scan: dict) -> dict:
    results: List[dict] = []
    for rule_id, title, severity in RULES:
        check = CHECKS[rule_id](scan)
        if check is None:
            applicable = True
            applicability_reason = ""
            if rule_id in APPLICABILITY:
                applicable, applicability_reason = APPLICABILITY[rule_id][0](scan), APPLICABILITY[rule_id][1]
            if applicable:
                status = "pass"
                file_path = "N/A"
                evidence = "No deterministic issue detected."
            else:
                status = "not_applicable"
                file_path = "N/A"
                evidence = ""
        else:
            status, file_path, evidence = check
        results.append(
            _result(
                rule_id,
                title,
                "info" if status == "not_applicable" else severity,
                status,
                file_path,
                evidence,
                applicability_reason if status == "not_applicable" else WHY_BY_SEVERITY[severity],
                FIX_BY_RULE.get(rule_id, "Harden the affected code/config, remove unsafe patterns, and add explicit security controls."),
            )
        )

    severity_counter = Counter(item["severity"] for item in results if item["status"] != "pass")
    status_counter = Counter(item["status"] for item in results)
    return {
        "results": results,
        "summary": {
            "passed": status_counter.get("pass", 0),
            "failed": status_counter.get("fail", 0),
            "review": status_counter.get("review", 0),
            "not_applicable": status_counter.get("not_applicable", 0),
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
        },
    }
