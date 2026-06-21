from __future__ import annotations

import re

MASK = "[MASKED]"
EMAIL_MASK = "[EMAIL_MASKED]"
TOKEN_MASK = "[TOKEN_MASKED]"
COOKIE_MASK = "[COOKIE_MASKED]"
SECRET_MASK = "[SECRET_MASKED]"

DIRECT_PATTERNS = [
    re.compile(r"sk_(live|test)_[A-Za-z0-9]+"),
    re.compile(r"rk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"(postgres(?:ql)?://[^\s\"']+)"),
    re.compile(r"(mysql://[^\s\"']+)"),
    re.compile(r"(mongodb(\+srv)?://[^\s\"']+)"),
]

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
AUTH_BEARER_PATTERN = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)([^\s,;]+)")
COOKIE_HEADER_PATTERN = re.compile(r"(?im)^(Cookie|Set-Cookie)\s*:\s*([^\n\r]+)$")
COOKIE_KV_PATTERN = re.compile(r"([A-Za-z0-9_.\-]+)=([^;\s]+)")
TOKEN_FIELD_PATTERN = re.compile(
    r"(?i)\b(session|sessionid|session_token|token|access_token|refresh_token|id_token|jwt|jwt_token)\b\s*([:=])\s*([\"']?)([^\s\"';,]{6,})"
)
SECRET_FIELD_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|apikey|service_role|anon_key|database_url|connection_string|webhook|next_public_[a-z0-9_]*|vite_[a-z0-9_]*)\b\s*([:=])\s*([\"']?)([^\s\"';,]{6,})"
)


def _looks_secret_like(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    lowered = stripped.lower()
    if len(stripped) < 8:
        return False
    if any(marker in lowered for marker in ("sk_live_", "sk_test_", "service_role", "database_url", "connection_string", "bearer ", "eyj")):
        return True
    return len(stripped) >= 12 and bool(re.search(r"[A-Za-z]", stripped)) and (
        bool(re.search(r"\d", stripped)) or bool(re.search(r"[_\-]", stripped))
    )


def _mask_cookie_header(match: re.Match) -> str:
    header_name = match.group(1)
    header_value = match.group(2)

    def replace_cookie(pair: re.Match) -> str:
        key = pair.group(1)
        value = pair.group(2)
        if key.lower() in {"path", "expires", "max-age", "domain", "samesite"}:
            return pair.group(0)
        if key.lower() == "secure" or key.lower() == "httponly":
            return pair.group(0)
        if value and len(value) >= 1:
            return f"{key}={COOKIE_MASK}"
        return pair.group(0)

    return f"{header_name}: {COOKIE_KV_PATTERN.sub(replace_cookie, header_value)}"


def _mask_token_field(match: re.Match) -> str:
    key = match.group(1)
    separator = match.group(2)
    quote = match.group(3) or ""
    return f"{key}{separator}{quote}{TOKEN_MASK}{quote}"


def _mask_secret_field(match: re.Match) -> str:
    key = match.group(1)
    separator = match.group(2)
    quote = match.group(3) or ""
    value = match.group(4)
    if key.lower().startswith("next_public_") or key.lower().startswith("vite_"):
        if not _looks_secret_like(value):
            return match.group(0)
    return f"{key}{separator}{quote}{SECRET_MASK}{quote}"


def mask_text(text: str) -> str:
    masked = text
    masked = EMAIL_PATTERN.sub(EMAIL_MASK, masked)
    masked = AUTH_BEARER_PATTERN.sub(lambda m: f"{m.group(1)}{TOKEN_MASK}", masked)
    for pattern in DIRECT_PATTERNS:
        masked = pattern.sub(SECRET_MASK, masked)
    masked = TOKEN_FIELD_PATTERN.sub(_mask_token_field, masked)
    masked = SECRET_FIELD_PATTERN.sub(_mask_secret_field, masked)
    masked = COOKIE_HEADER_PATTERN.sub(_mask_cookie_header, masked)
    return masked


def mask_json_payload(value):
    if isinstance(value, dict):
        return {key: mask_json_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_json_payload(item) for item in value]
    if isinstance(value, str):
        return mask_text(value)
    return value


def summarize_masking(raw_contents: dict[str, str]) -> dict:
    masked_files = {}
    masked_hits = 0
    for path, content in raw_contents.items():
        masked = mask_text(content)
        if masked != content:
            masked_hits += 1
        masked_files[path] = masked
    return {
        "masked_contents": masked_files,
        "masked_file_count": masked_hits,
        "masking_active": True,
    }
