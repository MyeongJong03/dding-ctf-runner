from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .redact import redact_text


PLACEHOLDERS = {
    "callback_token": "{TOKEN_PLACEHOLDER}",
    "probe": "{PROBE_ID}",
}


def generate_callback_payloads(callback_url: str) -> dict[str, Any]:
    base = _safe_callback_base(callback_url)
    hit_url = f"{base}/hit/{PLACEHOLDERS['callback_token']}"
    collect_url = f"{base}/collect"
    ping_url = f"{base}/ping?probe={PLACEHOLDERS['probe']}"
    snippets = {
        "plain_url": hit_url,
        "img_src": f'<img src="{hit_url}" alt="">',
        "script_src": f'<script src="{collect_url}"></script>',
        "fetch": (
            f'fetch("{collect_url}", '
            f'{{method: "POST", mode: "no-cors", credentials: "omit", body: "probe={PLACEHOLDERS["probe"]}"}})'
        ),
        "css_url": f'background-image: url("{hit_url}");',
        "ssrf_url": ping_url,
    }
    return {
        "status": "ok",
        "callback_url": base,
        "placeholders": dict(PLACEHOLDERS),
        "snippets": snippets,
        "policy": {
            "target_required": False,
            "contains_credentials": False,
            "note": "Helper snippets only; do not add cookies, tokens, auth headers, browser storage, or target-specific exploit logic.",
        },
    }


def _safe_callback_base(callback_url: str) -> str:
    raw = redact_text(str(callback_url or "").strip())
    if not raw:
        raise ValueError("--callback-url is required")
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("callback URL must be http(s)")
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))
