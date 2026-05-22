from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .redact import redact_text


MAX_PROMPT_BYTES = 20 * 1024
MAX_BRIEF_BYTES = 14 * 1024
MAX_SELECTED_FILES = 6
MAX_SELECTED_FILE_BYTES = 4 * 1024
MAX_SELECTED_FILE_SIZE = 32 * 1024
SENSITIVE_PATH_MARKERS = ("auth", "cookie", "token", "password", "passwd", "secret", "storage_state", "history")
SENSITIVE_KEY_MARKERS = ("auth", "cookie", "token", "password", "passwd", "secret", "api_key", "apikey", "session")
PROMPT_ASSIGN_SECRET_KEYS = (
    "session",
    "sessionid",
    "csrf",
    "csrf_token",
    "token",
    "auth",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "jwt",
    "cookie",
    "private_key",
)


def build_solve_prompt(
    challenge: dict[str, Any],
    brief_path: str | Path,
    selected_files: list[str | Path] | None = None,
    mode: str = "competition",
) -> str:
    """Build a compact, redacted prompt for one solver attempt."""
    brief = _read_bounded_text(Path(brief_path), MAX_BRIEF_BYTES)
    metadata = _challenge_metadata(challenge)
    selected = _selected_file_sections(selected_files or [])
    docker_section = _docker_pool_section(metadata)

    sections = [
        "You are a CTF competition worker running inside dding-ctf-runner.",
        "",
        "Operational rules:",
        "- Solve from local artifacts and local commands only unless the operator explicitly provides a live gate.",
        "- Use ctfctl for runner state, ingest, platform, and submit planning commands.",
        "- Use the challenge_dir and Top Interesting Files in brief.md to inspect non-sensitive local challenge files.",
        "- Do not read, print, persist, or summarize raw cookies, tokens, auth files, browser storage, private keys, passwords, or shell history.",
        "- Keep exploit transcripts compact. Do not create public writeups.",
        "- Do not invent flags. Only emit FLAG_CANDIDATE if directly observed or derived from local evidence.",
        "- When using local file evidence, include EVIDENCE_SOURCE path and DERIVATION steps.",
        "- For simple encodings, actually decode them using shell/Python before the final answer.",
        "- If a flag-like decoy exists, mark it as REJECTED_CANDIDATE with a reason.",
        "- If stuck, provide compact facts, attempted paths, and next ideas.",
        "",
        "Required final block:",
        "STATUS: solved|stalled",
        "CONFIDENCE: high|medium|low",
        "EVIDENCE_SOURCE: <local path or none>",
        "DERIVATION: <commands/decoding/extraction steps, redacted>",
        "FLAG_CANDIDATE: <flag>  # only when directly observed or derived",
        "REJECTED_CANDIDATES:",
        "- <candidate preview or hash> reason=<why rejected>",
        "NEXT_IDEAS:",
        "- <next action for another worker>",
        "",
        f"Mode: {redact_text(mode)}",
        "",
        "Challenge metadata:",
        _redacted_json(metadata),
        "",
    ]
    if docker_section:
        sections.extend(["Docker pool:", docker_section, ""])
    sections.extend(["brief.md:", brief])
    if selected:
        sections.extend(["", "Selected local file evidence:", *selected])

    prompt = _redact_prompt_text("\n".join(sections).rstrip() + "\n")
    if len(prompt.encode("utf-8")) <= MAX_PROMPT_BYTES:
        return prompt

    compact_sections = sections[: sections.index("brief.md:") + 1]
    compact_sections.append(_truncate_to_bytes(brief, _brief_budget(compact_sections)))
    prompt = _redact_prompt_text("\n".join(compact_sections).rstrip() + "\n")
    if len(prompt.encode("utf-8")) <= MAX_PROMPT_BYTES:
        return prompt
    return _truncate_to_bytes(prompt, MAX_PROMPT_BYTES)


def select_prompt_files(
    challenge: dict[str, Any],
    brief_path: str | Path,
    *,
    max_files: int = MAX_SELECTED_FILES,
) -> list[Path]:
    """Select a bounded set of local text/source files for solver context."""
    metadata = _metadata_dict(challenge.get("metadata"))
    brief = Path(brief_path).expanduser()
    challenge_dir = _expand_display_path(str(metadata.get("challenge_dir") or brief.parent))
    manifest_path = _expand_display_path(str(metadata.get("manifest_path") or (challenge_dir / "manifest" / "manifest.json")))
    scan_path = _expand_display_path(str(metadata.get("scan_path") or (challenge_dir / "manifest" / "scan.json")))
    manifest = _read_json_dict(manifest_path)
    scan = _read_json_dict(scan_path)
    root = _expand_display_path(str(manifest.get("root_dir") or challenge_dir))

    selected: list[Path] = []
    seen: set[Path] = set()

    def add_candidate(rel_or_path: Any, entry: dict[str, Any] | None = None) -> None:
        if len(selected) >= max_files:
            return
        raw = str(rel_or_path or "").strip()
        if not raw:
            return
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = root / raw
        try:
            path = path.resolve()
        except OSError:
            return
        if path in seen or not _prompt_file_allowed(path, entry):
            return
        seen.add(path)
        selected.append(path)

    interesting = scan.get("interesting_files") if isinstance(scan.get("interesting_files"), list) else []
    by_path = {str(item.get("path") or ""): item for item in manifest.get("files") or [] if isinstance(item, dict)}
    for item in interesting:
        if isinstance(item, dict):
            rel = item.get("path")
            add_candidate(rel, by_path.get(str(rel or ""), item))

    files = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
    files.sort(key=lambda item: (-int(item.get("interesting_score") or item.get("score") or 0), str(item.get("path") or "")))
    for item in files:
        add_candidate(item.get("path"), item)

    if len(selected) < max_files:
        raw_dir = _expand_display_path(str(metadata.get("raw_dir") or (challenge_dir / "raw")))
        for path in sorted(raw_dir.glob("*")) if raw_dir.exists() else []:
            add_candidate(path)
            if len(selected) >= max_files:
                break
    return selected


def _challenge_metadata(challenge: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "id": challenge.get("id") or challenge.get("challenge_id"),
        "contest_id": challenge.get("contest_id"),
        "name": challenge.get("name"),
        "category": challenge.get("category"),
        "points": challenge.get("points"),
        "solves": challenge.get("solves"),
        "status": challenge.get("status"),
        "source": challenge.get("source"),
        "priority": challenge.get("priority"),
    }
    metadata = challenge.get("metadata")
    if isinstance(metadata, str) and metadata.strip():
        try:
            fields["metadata"] = json.loads(metadata)
        except json.JSONDecodeError:
            fields["metadata"] = redact_text(metadata)
    elif isinstance(metadata, dict):
        fields["metadata"] = metadata
    return {key: value for key, value in fields.items() if value not in (None, "", {})}


def _docker_pool_section(metadata: dict[str, Any]) -> str:
    hint = metadata.get("metadata", {}).get("docker_pool_hint") if isinstance(metadata.get("metadata"), dict) else None
    if not isinstance(hint, dict) or not hint.get("available"):
        return ""
    command = redact_text(str(hint.get("safe_command") or "ctfctl docker pool-exec --contest-id <contest> --worker-id <worker> --command '<local command>' --json"))
    workspace = redact_text(str(hint.get("workspace") or ""))
    container = redact_text(str(hint.get("container_name") or ""))
    return "\n".join(
        [
            "- Docker pool available via `ctfctl docker pool-exec` for local pwn/rev tooling.",
            f"- Container: {container}",
            f"- Workspace: {workspace}",
            f"- Command: {command}",
            "- Do not pass secrets through Docker env, command args, logs, or copied files.",
        ]
    )


def _read_bounded_text(path: Path, byte_limit: int, *, preserve_flag_like: bool = False) -> str:
    try:
        data = path.expanduser().read_bytes()
    except FileNotFoundError:
        return "[brief missing]\n"
    text = data[:byte_limit].decode("utf-8", errors="replace")
    if len(data) > byte_limit:
        text = text.rstrip() + "\n\n[brief truncated to prompt budget]\n"
    return _redact_prompt_file_text(text) if preserve_flag_like else redact_text(text)


def _selected_file_sections(paths: list[str | Path]) -> list[str]:
    sections: list[str] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        display = redact_text(str(path))
        lowered = str(path).lower()
        if any(marker in lowered for marker in SENSITIVE_PATH_MARKERS):
            sections.append(f"## {display}\n[content skipped: sensitive path marker]\n")
            continue
        if not path.exists() or not path.is_file() or path.is_symlink():
            sections.append(f"## {display}\n[content unavailable]\n")
            continue
        sections.append(f"## {display}\n{_read_bounded_text(path, MAX_SELECTED_FILE_BYTES, preserve_flag_like=True)}")
    return sections


def _redacted_json(data: Any) -> str:
    return redact_text(json.dumps(_scrub_sensitive_keys(data), indent=2, sort_keys=True, default=str))


def _scrub_sensitive_keys(value: Any) -> Any:
    if isinstance(value, dict):
        scrubbed: dict[str, Any] = {}
        for key, item in value.items():
            if any(marker in str(key).lower() for marker in SENSITIVE_KEY_MARKERS):
                scrubbed[str(key)] = "[REDACTED]"
            else:
                scrubbed[str(key)] = _scrub_sensitive_keys(item)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_sensitive_keys(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _truncate_to_bytes(text: str, byte_limit: int) -> str:
    suffix = "\n[truncated to prompt budget]\n"
    suffix_bytes = suffix.encode("utf-8")
    budget = max(0, byte_limit - len(suffix_bytes))
    data = text.encode("utf-8")[:budget]
    return _redact_prompt_text(data.decode("utf-8", errors="ignore").rstrip() + suffix)


def _brief_budget(prefix_sections: list[str]) -> int:
    prefix = "\n".join(prefix_sections).encode("utf-8")
    return max(1024, MAX_PROMPT_BYTES - len(prefix) - 512)


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _read_json_dict(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _expand_display_path(value: str) -> Path:
    text = str(value or "")
    if text == "~":
        return Path.home()
    if text.startswith("~/"):
        return Path.home() / text[2:]
    return Path(text).expanduser()


def _prompt_file_allowed(path: Path, entry: dict[str, Any] | None = None) -> bool:
    lowered = str(path).lower()
    if any(marker in lowered for marker in SENSITIVE_PATH_MARKERS):
        return False
    if path.name == "brief.md" or "/manifest/" in path.as_posix():
        return False
    if not path.exists() or not path.is_file() or path.is_symlink():
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size > MAX_SELECTED_FILE_SIZE:
        return False
    if entry:
        if entry.get("is_large"):
            return False
        if entry.get("readable_text") is False:
            return False
        category = str(entry.get("category") or "").lower()
        detected = str(entry.get("detected_type") or "").lower()
        if category and category not in {"text", "source", "config", "document", "unknown"} and "text" not in detected:
            return False
    return True


def _redact_prompt_text(text: str) -> str:
    return "\n".join(_redact_prompt_line(line) for line in str(text or "").splitlines())


def _redact_prompt_file_text(text: str) -> str:
    return _redact_prompt_text(text)


def _redact_prompt_line(line: str) -> str:
    lowered = line.lower()
    if any(header in lowered for header in ("authorization:", "cookie:", "set-cookie:", "x-api-key:", "x-auth-token:", "x-csrf-token:")):
        return line.split(":", 1)[0] + ": [REDACTED]"
    stripped = line
    for key in PROMPT_ASSIGN_SECRET_KEYS:
        stripped = _redact_assignment_key(stripped, key)
    return stripped


def _redact_assignment_key(line: str, key: str) -> str:
    import re

    pattern = re.compile(rf"(?i)\b({re.escape(key)})[\w.-]*\s*([:=])\s*['\"]?[^'\"\s,}}]+")
    return pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", line)
