from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import get_paths
from .redact import redact_text


_SENSITIVE_KEYS = {"flag", "token", "cookie", "authorization", "password", "secret", "api_key", "auth"}


def _redact_details(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if any(marker in str(key).lower() for marker in _SENSITIVE_KEYS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = _redact_details(item)
        return redacted
    if isinstance(value, list):
        return [_redact_details(item) for item in value]
    return value


def write_event(
    event_type: str,
    status: str,
    details: Any | None = None,
    *,
    worker_id: str | None = None,
    challenge_id: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "worker_id": worker_id,
        "challenge_id": challenge_id,
        "event_type": event_type,
        "status": status,
        "details_redacted": _redact_details(details or {}),
    }
    out_path = Path(path).expanduser() if path else get_paths().telemetry_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, sort_keys=True) + "\n")
    return event
