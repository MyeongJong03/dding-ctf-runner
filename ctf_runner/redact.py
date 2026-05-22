from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTION = "[REDACTED]"

_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}")
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_HEADER_RE = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*:\s*).*$"
)
_SECRET_ASSIGN_KEY = (
    r"session(?:id)?[\w.-]*|csrf(?:token)?[\w.-]*|token[\w.-]*|auth[\w.-]*|"
    r"password[\w.-]*|passwd[\w.-]*|secret[\w.-]*|api[_-]?key[\w.-]*|jwt[\w.-]*|flag"
)
_KV_SECRET_RE = re.compile(rf"(?i)\b({_SECRET_ASSIGN_KEY})\s*=\s*[^;\s&]+")
_ASSIGN_SECRET_RE = re.compile(rf"(?i)\b({_SECRET_ASSIGN_KEY})\s*[:=]\s*['\"]?[^'\"\s,}}]+")
_QUERY_SECRET_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "code",
    "cookie",
    "csrf",
    "flag",
    "jwt",
    "key",
    "password",
    "secret",
    "session",
    "sessionid",
    "token",
}


def _redact_url_query(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.query:
        return raw
    query = []
    changed = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _QUERY_SECRET_KEYS or any(marker in key.lower() for marker in ("token", "secret", "cookie")):
            query.append((key, REDACTION))
            changed = True
        else:
            query.append((key, value))
    if not changed:
        return raw
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def redact_text(text: str) -> str:
    """Redact common CTF secrets from display/log text."""
    if text is None:
        return ""
    redacted = str(text)
    redacted = _URL_RE.sub(_redact_url_query, redacted)
    redacted = _HEADER_RE.sub(lambda m: f"{m.group(1)}{REDACTION}", redacted)
    redacted = _BEARER_RE.sub(f"Bearer {REDACTION}", redacted)
    redacted = _JWT_RE.sub(REDACTION, redacted)
    redacted = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTION}", redacted)
    redacted = _ASSIGN_SECRET_RE.sub(lambda m: f"{m.group(1)}={REDACTION}", redacted)
    redacted = _FLAG_RE.sub(REDACTION, redacted)
    return redacted
