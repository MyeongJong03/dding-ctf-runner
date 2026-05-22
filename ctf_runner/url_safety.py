from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from .redact import redact_text


_PUBLIC_URL_RE = re.compile(
    r"(?:(?:https?|tcp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|[A-Za-z0-9.-]+\.trycloudflare\.com[^\s\"'<>]*)"
)


def strip_public_url_query(url: str) -> str:
    value = redact_text(str(url or "").strip())
    if not value:
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value.split("?", 1)[0].split("#", 1)[0]
    if not parts.scheme and not parts.netloc:
        return value.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def redacted_public_url(url: str) -> str:
    stripped = strip_public_url_query(url)
    if not stripped:
        return ""
    try:
        parts = urlsplit(stripped)
    except ValueError:
        return "[REDACTED_PUBLIC_URL]"
    scheme = parts.scheme or "public"
    host = parts.hostname or ""
    port = _safe_port(parts)
    if not host:
        return f"{scheme}://[REDACTED_PUBLIC_URL]"
    if host.endswith(".trycloudflare.com"):
        host_summary = "<redacted>.trycloudflare.com"
    elif host == "bore.pub" or host.endswith(".bore.pub"):
        host_summary = host
    else:
        host_summary = "<redacted-host>"
    port_part = f":{port}" if port else ""
    return f"{scheme}://{host_summary}{port_part}"


def public_url_display(url: str, *, show_public_url: bool = False) -> str:
    if not url:
        return ""
    if show_public_url:
        return strip_public_url_query(url)
    return redacted_public_url(url)


def public_url_fields(url: str, *, show_public_url: bool = False) -> dict[str, object]:
    return {
        "public_url_available": bool(str(url or "").strip()),
        "public_url_redacted": redacted_public_url(url),
        "public_url_display": public_url_display(url, show_public_url=show_public_url),
    }


def redact_public_urls(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return redacted_public_url(match.group(0))

    return _PUBLIC_URL_RE.sub(replace, redact_text(str(text or "")))


def _safe_port(parts) -> int | None:
    try:
        return parts.port
    except ValueError:
        return None
