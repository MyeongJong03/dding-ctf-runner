from __future__ import annotations

import json
import re
from typing import Any

from .redact import redact_text
from .submit import classify_flag_confidence, detect_flag_candidates, hash_flag, redact_flag


VALID_STATUSES = {"solved", "stalled", "needs_more_info", "error"}
VALID_SOURCES = {"exploit_output", "file_read", "local_attachment", "manual", "solver_output", "unknown"}
VALID_CONFIDENCES = {"high", "medium", "low"}


def parse_solver_output(text: str) -> dict[str, Any]:
    """Parse a worker solver transcript while keeping raw candidates isolated."""
    raw_text = normalize_solver_output(text or "")
    lines = raw_text.splitlines()
    payloads = _json_payloads(raw_text) + _markdown_table_payloads(raw_text)
    explicit_status = _parse_status(lines) or _json_status(payloads)
    confidence = _parse_confidence(lines, payloads)
    evidence_source = _parse_evidence_source(lines, payloads)
    derivation = _parse_derivation(lines, payloads)
    source = _parse_source(lines, raw_text, payloads, evidence_source=evidence_source)
    local_verified = (
        _parse_bool_field(lines, "LOCAL_VERIFIED")
        or _json_bool(payloads, "local_verified")
        or _verified_by_context(raw_text)
        or bool(evidence_source and derivation)
    )
    fake_like_context = _parse_bool_field(lines, "FAKE_LIKE") or _json_bool(payloads, "fake_like")
    evidence = evidence_source or _parse_evidence(lines, payloads)
    summary = _parse_summary(lines, raw_text, payloads)
    sections = _parse_sections(lines, payloads)
    rejected_candidates = _rejected_candidate_objects(_find_rejected_candidates(raw_text, payloads))
    rejected_values = {item["candidate"] for item in rejected_candidates}
    candidates = _candidate_objects(
        [candidate for candidate in _find_candidates(raw_text, payloads) if candidate not in rejected_values],
        source,
        local_verified,
        fake_like_context,
        confidence=confidence,
        evidence_source=evidence_source,
        derivation=derivation,
        summary=summary,
    )
    status = explicit_status or ("solved" if candidates else "stalled")
    confidence_context = {
        "source": source,
        "local_verified": local_verified,
        "fake_like": bool(fake_like_context or any(item["fake_like"] for item in candidates)),
        "evidence": evidence,
        "evidence_source": evidence_source,
        "derivation": derivation,
        "confidence": confidence,
        "rejected_candidate_count": len(rejected_candidates),
    }
    return {
        "status": status,
        "flag_candidates": candidates,
        "rejected_candidates": rejected_candidates,
        "summary": summary,
        "facts": sections["facts"],
        "attempts": sections["attempts"],
        "next_ideas": sections["next_ideas"],
        "confidence_context": confidence_context,
    }


def normalize_solver_output(text: str) -> str:
    """Remove known Codex/wrapper framing while preserving solver content."""
    stripped = _strip_leading_wrapper_json(str(text or ""))
    lines: list[str] = []
    for line in stripped.splitlines():
        if _is_prompt_echo_start(line):
            break
        if _is_noise_line(line):
            continue
        if line.strip().startswith("```"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def public_solver_result(result: dict[str, Any]) -> dict[str, Any]:
    """Return a display/state-safe view of a parsed solver result."""
    public_candidates = []
    for item in result.get("flag_candidates") or []:
        public_candidates.append(
            {
                "candidate_preview": item.get("candidate_preview"),
                "flag_hash": item.get("flag_hash"),
                "confidence": item.get("confidence"),
                "source": item.get("source"),
                "local_verified": bool(item.get("local_verified")),
                "fake_like": bool(item.get("fake_like")),
            }
        )
    return {
        "status": result.get("status", "error"),
        "flag_candidates": public_candidates,
        "rejected_candidates": [
            {
                "candidate_preview": item.get("candidate_preview"),
                "flag_hash": item.get("flag_hash"),
                "reason": redact_text(str(item.get("reason") or "")),
            }
            for item in result.get("rejected_candidates") or []
        ],
        "summary": redact_text(str(result.get("summary") or "")),
        "facts": _redacted_list(result.get("facts") or []),
        "attempts": _redacted_list(result.get("attempts") or []),
        "next_ideas": _redacted_list(result.get("next_ideas") or []),
        "confidence_context": {
            "source": _safe_source((result.get("confidence_context") or {}).get("source")),
            "local_verified": bool((result.get("confidence_context") or {}).get("local_verified")),
            "fake_like": bool((result.get("confidence_context") or {}).get("fake_like")),
            "evidence": redact_text(str((result.get("confidence_context") or {}).get("evidence") or "")),
            "evidence_source": redact_text(str((result.get("confidence_context") or {}).get("evidence_source") or "")),
            "derivation": redact_text(str((result.get("confidence_context") or {}).get("derivation") or "")),
            "confidence": _safe_confidence((result.get("confidence_context") or {}).get("confidence")),
            "rejected_candidate_count": int((result.get("confidence_context") or {}).get("rejected_candidate_count") or 0),
        },
    }


def candidate_submit_context(result: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    context = result.get("confidence_context") or {}
    return {
        "source": candidate.get("source") or context.get("source") or "unknown",
        "summary": result.get("summary") or "",
        "local_verified": bool(candidate.get("local_verified") or context.get("local_verified")),
        "fake_like": bool(candidate.get("fake_like") or context.get("fake_like")),
        "evidence": context.get("evidence") or "",
        "evidence_source": context.get("evidence_source") or context.get("evidence") or "",
        "derivation": context.get("derivation") or "",
        "confidence": context.get("confidence") or candidate.get("confidence") or "",
    }


def _parse_status(lines: list[str]) -> str | None:
    for line in lines:
        match = re.match(r"^\s*STATUS\s*:\s*([A-Za-z_]+)", line, flags=re.IGNORECASE)
        if match:
            value = match.group(1).lower()
            return value if value in VALID_STATUSES else "error"
    return None


def _parse_source(
    lines: list[str],
    text: str,
    payloads: list[dict[str, Any]] | None = None,
    *,
    evidence_source: str = "",
) -> str:
    for line in lines:
        match = re.match(r"^\s*SOURCE\s*:\s*([A-Za-z_]+)", line, flags=re.IGNORECASE)
        if match:
            return _safe_source(match.group(1))
    for payload in payloads or []:
        for key in ("source", "candidate_source", "provenance"):
            if key in payload:
                source = _safe_source(payload.get(key))
                if source != "unknown":
                    return source
    lowered = text.lower()
    if "exploit output" in lowered or "exploit_output" in lowered:
        return "exploit_output"
    if "file_read" in lowered or "file read" in lowered or "read from file" in lowered:
        return "file_read"
    if "local_attachment" in lowered or "local attachment" in lowered:
        return "local_attachment"
    if "from the file" in lowered or "in the file" in lowered or "note.txt" in lowered:
        return "file_read"
    if "solver_output" in lowered or "solver output" in lowered:
        return "solver_output"
    if "manual" in lowered:
        return "manual"
    if evidence_source:
        return "file_read"
    return "unknown"


def _safe_source(value: Any) -> str:
    source = str(value or "").strip().lower()
    return source if source in VALID_SOURCES else "unknown"


def _safe_confidence(value: Any) -> str:
    confidence = str(value or "").strip().lower()
    return confidence if confidence in VALID_CONFIDENCES else ""


def _parse_bool_field(lines: list[str], field: str) -> bool:
    pattern = re.compile(rf"^\s*{re.escape(field)}\s*:\s*(true|false|yes|no|1|0)", flags=re.IGNORECASE)
    for line in lines:
        match = pattern.match(line)
        if match:
            return match.group(1).lower() in {"true", "yes", "1"}
    return False


def _parse_evidence(lines: list[str], payloads: list[dict[str, Any]] | None = None) -> str:
    for line in lines:
        match = re.match(r"^\s*EVIDENCE\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if match:
            return redact_text(match.group(1).strip())[:500]
    for payload in payloads or []:
        value = payload.get("evidence")
        if isinstance(value, str) and value.strip():
            return redact_text(value.strip())[:500]
    return ""


def _parse_confidence(lines: list[str], payloads: list[dict[str, Any]] | None = None) -> str:
    for line in lines:
        match = re.match(r"^\s*CONFIDENCE\s*:\s*(high|medium|low)\b", line, flags=re.IGNORECASE)
        if match:
            return match.group(1).lower()
    for payload in payloads or []:
        for key in ("confidence", "CONFIDENCE"):
            value = _safe_confidence(payload.get(key))
            if value:
                return value
    return ""


def _parse_evidence_source(lines: list[str], payloads: list[dict[str, Any]] | None = None) -> str:
    for line in lines:
        match = re.match(r"^\s*(EVIDENCE_SOURCE|EVIDENCE PATH|SOURCE_PATH)\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if match:
            value = match.group(2).strip()
            return "" if value.lower() in {"none", "n/a", "na"} else redact_text(value)[:500]
    for payload in payloads or []:
        for key in ("evidence_source", "evidence_path", "source_path", "EVIDENCE_SOURCE"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip() and value.strip().lower() not in {"none", "n/a", "na"}:
                return redact_text(value.strip())[:500]
    return ""


def _parse_derivation(lines: list[str], payloads: list[dict[str, Any]] | None = None) -> str:
    for index, line in enumerate(lines):
        match = re.match(r"^\s*DERIVATION\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if value:
            return redact_text(value)[:1000]
        gathered: list[str] = []
        for next_line in lines[index + 1 :]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if _is_schema_header(next_line):
                break
            gathered.append(stripped.lstrip("-* ").strip())
            if len(" ".join(gathered)) > 1000:
                break
        return redact_text("; ".join(gathered))[:1000]
    for payload in payloads or []:
        for key in ("derivation", "DERIVATION", "steps", "explanation"):
            value = payload.get(key)
            if isinstance(value, list):
                joined = "; ".join(str(item) for item in value if str(item).strip())
                if joined:
                    return redact_text(joined)[:1000]
            if isinstance(value, str) and value.strip():
                return redact_text(value.strip())[:1000]
    return ""


def _json_bool(payloads: list[dict[str, Any]], field: str) -> bool:
    variants = {field, field.upper(), field.lower(), field.replace("_", "-")}
    for payload in payloads:
        for key in variants:
            if key in payload:
                value = payload.get(key)
                if isinstance(value, bool):
                    return value
                if isinstance(value, (int, float)):
                    return bool(value)
                if isinstance(value, str):
                    return value.strip().lower() in {"true", "yes", "1"}
    return False


def _verified_by_context(text: str) -> bool:
    lowered = text.lower()
    return any(
        marker in lowered
        for marker in (
            "local_verified: true",
            "locally verified",
            "verified locally",
            "read from file",
            "from the file",
            "note.txt",
        )
    )


def _contains_fake_context(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in ("decoy", "fake flag", "sample flag", "placeholder flag"))


def _parse_summary(lines: list[str], text: str, payloads: list[dict[str, Any]] | None = None) -> str:
    for line in lines:
        match = re.match(r"^\s*SUMMARY\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if match:
            return redact_text(match.group(1).strip())
    for payload in payloads or []:
        for key in ("summary", "message", "result"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return redact_text(value.strip())
    first_content = next((line.strip() for line in lines if line.strip()), "")
    return redact_text(first_content or ("solver produced no summary" if not text else "solver output parsed"))


def _parse_sections(lines: list[str], payloads: list[dict[str, Any]] | None = None) -> dict[str, list[str]]:
    sections = {"facts": [], "attempts": [], "next_ideas": []}
    current: str | None = None
    headers = {
        "FACTS": "facts",
        "ATTEMPTS": "attempts",
        "TRIED": "attempts",
        "NEXT_IDEAS": "next_ideas",
        "NEXT IDEAS": "next_ideas",
        "NEXT": "next_ideas",
    }
    for line in lines:
        stripped = line.strip()
        header = stripped.rstrip(":").upper()
        if header in headers:
            current = headers[header]
            continue
        if _is_schema_header(line):
            current = None
            continue
        if _is_prompt_echo_start(line):
            break
        if current and stripped:
            sections[current].append(redact_text(stripped.lstrip("-* ").strip()))
    for payload in payloads or []:
        for key, section in (("facts", "facts"), ("attempts", "attempts"), ("tried", "attempts"), ("next_ideas", "next_ideas"), ("next", "next_ideas")):
            value = payload.get(key)
            if isinstance(value, list):
                sections[section].extend(redact_text(str(item)) for item in value if str(item).strip())
            elif isinstance(value, str) and value.strip():
                sections[section].append(redact_text(value.strip()))
    return sections


def _find_candidates(text: str, payloads: list[dict[str, Any]] | None = None) -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(FLAG_CANDIDATE|FLAG|CANDIDATE)\s*:\s*(.+?)\s*$", line, flags=re.IGNORECASE)
        if match:
            for candidate in detect_flag_candidates(match.group(2)):
                if candidate not in seen:
                    seen.add(candidate)
                    candidates.append(candidate)
    for payload in payloads or []:
        for value in _json_candidate_values(payload):
            for candidate in detect_flag_candidates(value):
                if candidate not in seen:
                    seen.add(candidate)
                    candidates.append(candidate)
    for candidate in detect_flag_candidates(text):
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _find_rejected_candidates(text: str, payloads: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    lines = text.splitlines()
    in_section = False
    for line in lines:
        if re.match(r"^\s*REJECTED_CANDIDATES?\s*:?\s*$", line, flags=re.IGNORECASE):
            in_section = True
            continue
        match = re.match(r"^\s*REJECTED_CANDIDATE\s*:\s*(.+?)\s*$", line, flags=re.IGNORECASE)
        if match:
            _append_rejected(rejected, seen, match.group(1), "")
            continue
        if in_section:
            if _is_schema_header(line):
                in_section = False
                continue
            if line.strip():
                _append_rejected(rejected, seen, line, line)
    for payload in payloads or []:
        for item in _json_rejected_values(payload):
            _append_rejected(rejected, seen, item.get("candidate", ""), item.get("reason", ""))
    return rejected


def _append_rejected(rejected: list[dict[str, str]], seen: set[str], text: str, reason: str) -> None:
    candidates = detect_flag_candidates(text)
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        clean_reason = re.sub(re.escape(candidate), "", str(reason or ""), flags=re.IGNORECASE).strip(" -|:;")
        rejected.append({"candidate": candidate, "reason": redact_text(clean_reason or "rejected by solver")})


def _rejected_candidate_objects(items: list[dict[str, str]]) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for item in items:
        candidate = item.get("candidate") or ""
        if not candidate:
            continue
        objects.append(
            {
                "candidate": candidate,
                "candidate_preview": redact_flag(candidate),
                "flag_hash": hash_flag(candidate),
                "reason": redact_text(item.get("reason") or "rejected by solver"),
            }
        )
    return objects


def _candidate_objects(
    candidates: list[str],
    source: str,
    local_verified: bool,
    fake_like_context: bool,
    *,
    confidence: str,
    evidence_source: str,
    derivation: str,
    summary: str,
) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for candidate in candidates:
        classification = classify_flag_confidence(
            candidate,
            context={
                "source": source,
                "local_verified": local_verified,
                "evidence_source": evidence_source,
                "evidence": evidence_source,
                "derivation": derivation,
                "confidence": confidence,
                "summary": summary,
            },
        )
        fake_like = bool(fake_like_context or classification.get("fake_likely"))
        objects.append(
            {
                "candidate": candidate,
                "candidate_preview": redact_flag(candidate),
                "flag_hash": hash_flag(candidate),
                "confidence": classification.get("confidence"),
                "source": source,
                "local_verified": local_verified,
                "fake_like": fake_like,
            }
        )
    return objects


def _redacted_list(items: list[Any]) -> list[str]:
    return [redact_text(str(item)) for item in items]


def _json_status(payloads: list[dict[str, Any]]) -> str | None:
    for payload in payloads:
        value = str(payload.get("status") or "").strip().lower()
        if value:
            return value if value in VALID_STATUSES else "error"
    return None


def _json_payloads(text: str) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    seen: set[str] = set()
    candidates = [text]
    candidates.extend(match.group(1) for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.I | re.S))
    decoder = json.JSONDecoder()
    for candidate in candidates:
        for match in re.finditer(r"\{", candidate):
            try:
                value, end = decoder.raw_decode(candidate[match.start() :])
            except json.JSONDecodeError:
                continue
            if not isinstance(value, dict):
                continue
            raw = candidate[match.start() : match.start() + end]
            if raw in seen:
                continue
            seen.add(raw)
            payloads.append(value)
    return payloads


def _markdown_table_payloads(text: str) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if "|" not in line or index + 1 >= len(lines) or not _looks_like_table_separator(lines[index + 1]):
            index += 1
            continue
        headers = [_normalize_key(cell) for cell in _split_table_row(line)]
        rows: list[list[str]] = []
        index += 2
        while index < len(lines) and "|" in lines[index]:
            rows.append(_split_table_row(lines[index]))
            index += 1
        if not headers or not rows:
            continue
        if len(headers) >= 2 and headers[0] in {"field", "key", "name"} and headers[1] in {"value", "val"}:
            payload: dict[str, Any] = {}
            for row in rows:
                if len(row) >= 2:
                    payload[_normalize_key(row[0])] = row[1].strip()
            if payload:
                payloads.append(payload)
            continue
        payload = {}
        rejected: list[dict[str, str]] = []
        for row in rows:
            row_map = {headers[pos]: row[pos].strip() for pos in range(min(len(headers), len(row)))}
            status = str(row_map.get("status") or row_map.get("decision") or "").lower()
            candidate = row_map.get("candidate") or row_map.get("flag_candidate") or row_map.get("flag")
            if candidate and ("reject" in status or "decoy" in status):
                rejected.append({"candidate": candidate, "reason": row_map.get("reason") or status})
            for key, value in row_map.items():
                if key in {"status", "confidence", "evidence_source", "derivation", "flag_candidate", "flag", "candidate"} and value:
                    payload.setdefault(key, value)
        if rejected:
            payload["rejected_candidates"] = rejected
        if payload:
            payloads.append(payload)
    return payloads


def _looks_like_table_separator(line: str) -> bool:
    cells = _split_table_row(line)
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell.strip()) for cell in cells)


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _json_candidate_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in {"rejected", "rejected_candidate", "rejected_candidates", "decoy", "decoys", "false_positive", "false_positives"}:
                continue
            if lowered in {"flag", "candidate", "flag_candidate", "flag_candidates", "candidate_flag"}:
                values.extend(_json_candidate_values(item))
            elif isinstance(item, (dict, list)):
                values.extend(_json_candidate_values(item))
            elif isinstance(item, str) and detect_flag_candidates(item):
                values.append(item)
    elif isinstance(value, list):
        for item in value:
            values.extend(_json_candidate_values(item))
    elif isinstance(value, str):
        values.append(value)
    return values


def _json_rejected_values(value: Any) -> list[dict[str, str]]:
    values: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in {"rejected", "rejected_candidate", "rejected_candidates", "decoy", "decoys", "false_positive", "false_positives"}:
                if isinstance(item, list):
                    for entry in item:
                        if isinstance(entry, dict):
                            candidate = str(entry.get("candidate") or entry.get("flag") or entry.get("flag_candidate") or "")
                            reason = str(entry.get("reason") or entry.get("status") or "rejected by solver")
                            values.append({"candidate": candidate, "reason": reason})
                        else:
                            values.append({"candidate": str(entry), "reason": "rejected by solver"})
                elif isinstance(item, dict):
                    candidate = str(item.get("candidate") or item.get("flag") or item.get("flag_candidate") or "")
                    reason = str(item.get("reason") or item.get("status") or "rejected by solver")
                    values.append({"candidate": candidate, "reason": reason})
                else:
                    values.append({"candidate": str(item), "reason": "rejected by solver"})
            elif isinstance(item, (dict, list)):
                values.extend(_json_rejected_values(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(_json_rejected_values(item))
    elif isinstance(value, str):
        values.append({"candidate": value, "reason": "rejected by solver"})
    return values


def _strip_leading_wrapper_json(text: str) -> str:
    remaining = text.lstrip()
    decoder = json.JSONDecoder()
    while remaining.startswith("{"):
        try:
            value, end = decoder.raw_decode(remaining)
        except json.JSONDecodeError:
            break
        if not isinstance(value, dict) or not _looks_like_wrapper_json(value):
            break
        remaining = remaining[end:].lstrip()
    return remaining


def _looks_like_wrapper_json(value: dict[str, Any]) -> bool:
    keys = {str(key) for key in value}
    strong_wrapper_keys = {
        "argv",
        "codex_binary",
        "command",
        "repo_root",
        "validation",
        "worker_home",
        "worker_id",
    }
    weak_wrapper_keys = {"add_dirs", "danger_mode", "dry_run", "mode", "sandbox_mode"}
    has_candidate_key = any(key.lower() in {"flag", "flag_candidate", "candidate", "flag_candidates"} for key in keys)
    return not has_candidate_key and (
        bool(keys & strong_wrapper_keys) or ("mode" in keys and bool(keys & (weak_wrapper_keys - {"mode"})))
    )


def _is_noise_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    patterns = (
        r"^\[warn\]\s+competition worker uses model=",
        r"^OpenAI Codex\b",
        r"^codex-cli\b",
        r"^-{3,}$",
        r"^workdir:\s+",
        r"^model:\s+",
        r"^provider:\s+",
        r"^approval:\s+",
        r"^sandbox:\s+",
        r"^reasoning effort:\s+",
        r"^tokens used:\s+",
        r"^token usage:\s+",
        r"^usage:\s+",
        r"^dry-run command:\s+",
        r"^dry-run:\s+codex was not executed$",
        r"^Reading additional input from stdin",
        r"^reasoning summaries:",
        r"^session id:",
        r"^(user|assistant|codex)$",
    )
    return any(re.match(pattern, stripped, flags=re.IGNORECASE) for pattern in patterns)


def _is_schema_header(line: str) -> bool:
    return bool(
        re.match(
            r"^\s*(STATUS|SUMMARY|SOURCE|CONFIDENCE|LOCAL_VERIFIED|FAKE_LIKE|EVIDENCE|EVIDENCE_SOURCE|DERIVATION|FLAG_CANDIDATE|REJECTED_CANDIDATES?|FACTS|ATTEMPTS|NEXT_IDEAS|NEXT IDEAS)\s*:",
            line,
            re.I,
        )
    )


def _is_prompt_echo_start(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("You are a CTF competition worker running inside dding-ctf-runner.")
