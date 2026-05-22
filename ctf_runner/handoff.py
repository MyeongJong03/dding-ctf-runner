from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .redact import redact_text
from .solve_result import public_solver_result
from .state import utc_now


def write_handoff(run_dir: str | Path, challenge_id: str, result: dict[str, Any], reason: str) -> dict[str, Any]:
    """Append a compact, raw-flag-free handoff record."""
    safe = public_solver_result(result)
    record = {
        "timestamp": utc_now(),
        "challenge_id": str(challenge_id),
        "status": safe.get("status", "stalled"),
        "reason": redact_text(reason),
        "facts": safe.get("facts", []),
        "attempts": safe.get("attempts", []),
        "next_ideas": safe.get("next_ideas", []),
        "flag_hashes": [item["flag_hash"] for item in safe.get("flag_candidates", []) if item.get("flag_hash")],
    }
    path = Path(run_dir).expanduser() / "handoff.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read_handoffs(run_dir: str | Path, challenge_id: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    path = Path(run_dir).expanduser() / "handoff.jsonl"
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if challenge_id and str(item.get("challenge_id")) != str(challenge_id):
            continue
        rows.append(item)
    return rows[-limit:]
