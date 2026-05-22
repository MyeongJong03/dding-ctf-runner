from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .auth import _parse_minimal_yaml
from .redact import redact_text


FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}")
COMMON_PREFIXES = {"DH", "FLAG", "CTF", "DING", "SEKAI", "HTB", "DUCTF", "PICOCTF", "PCTF", "TJCTF"}
HIGH_CONFIDENCE_SOURCES = {
    "exploit_output",
    "platform_accepted",
    "platform_accepted_path",
    "known_flag_source",
    "solver_output",
    "verified_solver",
}
HIGH_CONFIDENCE_MARKERS = (
    "accepted",
    "correct",
    "verified",
    "solved",
    "exploit output",
    "known flag source",
    "platform accepted",
)
UNCERTAIN_MARKERS = ("maybe", "candidate", "partial", "guess", "uncertain", "untested")
FAKE_TOKEN_MARKERS = {"fake", "test", "example", "dummy", "sample", "readme", "todo"}
FAKE_SUBSTRING_MARKERS = (
    "not_the_flag",
    "not-the-flag",
    "submit_guard",
    "placeholder",
    "changeme",
    "replace_me",
    "replace-me",
    "lorem",
    "flag_here",
    "your_flag",
)
DUPLICATE_STATUSES = {"submitted", "accepted", "rejected", "rate_limited", "wrong", "incorrect"}
WRONG_STATUSES = {"wrong", "incorrect", "rejected"}


def hash_flag(candidate: str) -> str:
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def flag_hash(candidate: str) -> str:
    """Backward-compatible alias for older tests and callers."""
    return hash_flag(candidate)


def redact_flag(candidate: str) -> str:
    value = str(candidate or "")
    if not value:
        return "[redacted-empty]"
    prefix = value.split("{", 1)[0] if "{" in value else ""
    if prefix and len(prefix) <= 32 and FLAG_RE.fullmatch(value):
        return f"{prefix}" + "{...}" + f" len={len(value)}"
    return f"[redacted len={len(value)}]"


def _compile_flag_regex(flag_regex: str | None) -> re.Pattern[str]:
    if not flag_regex:
        return FLAG_RE
    return re.compile(flag_regex)


def detect_flag_candidates(text: str, flag_regex: str | None = None) -> list[str]:
    pattern = _compile_flag_regex(flag_regex)
    seen: set[str] = set()
    candidates: list[str] = []
    for match in pattern.finditer(text or ""):
        value = match.group(0)
        if value not in seen:
            seen.add(value)
            candidates.append(value)
    return candidates


def _policy_flag_regex(policy: Mapping[str, Any] | None) -> str | None:
    if not policy:
        return None
    value = policy.get("flag_regex")
    return str(value) if value else None


def _context_text(context: Any) -> str:
    if context is None:
        return ""
    if isinstance(context, Mapping):
        values: list[str] = []
        for key in ("source", "path", "status", "message", "summary", "text", "evidence", "evidence_source", "derivation", "confidence"):
            value = context.get(key)
            if value is not None:
                values.append(str(value))
        return " ".join(values)
    return str(context)


def _context_source(context: Any) -> str:
    if isinstance(context, Mapping):
        return str(context.get("source") or "").strip().lower()
    return ""


def _context_local_verified(context: Any) -> bool:
    if isinstance(context, Mapping):
        value = context.get("local_verified")
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1"}
        if _context_evidence_source_present(context) and _context_derivation_present(context):
            return True
    return False


def _context_evidence_source_present(context: Any) -> bool:
    if not isinstance(context, Mapping):
        return False
    for key in ("evidence_source", "evidence", "path"):
        value = str(context.get(key) or "").strip().lower()
        if value and value not in {"none", "n/a", "na", "unknown"}:
            return True
    return False


def _context_derivation_present(context: Any) -> bool:
    if not isinstance(context, Mapping):
        return False
    value = context.get("derivation")
    if isinstance(value, list):
        return any(str(item).strip() for item in value)
    return bool(str(value or "").strip())


def _matches_regex(candidate: str, flag_regex: str | None) -> bool:
    try:
        return bool(_compile_flag_regex(flag_regex).fullmatch(candidate or ""))
    except re.error:
        return False


def _fake_reasons(candidate: str, context: Any) -> list[str]:
    candidate_l = str(candidate or "").lower()
    context_l = _context_text(context).lower()
    inner = candidate_l.split("{", 1)[1].rstrip("}") if "{" in candidate_l else candidate_l
    tokens = {token for token in re.split(r"[^a-z0-9]+", inner) if token}
    reasons = []
    if isinstance(context, Mapping) and bool(context.get("fake_like")):
        reasons.append("solver_marked_fake_like")
    if tokens & FAKE_TOKEN_MARKERS or any(marker in candidate_l for marker in FAKE_SUBSTRING_MARKERS):
        reasons.append("candidate_contains_fake_marker")
    if any(marker in context_l for marker in ("readme", "example", "placeholder", "test fixture", "sample flag")):
        reasons.append("context_is_example_like")
    if re.fullmatch(r"[A-Za-z0-9_]{2,32}\{(?:x+|a+|0+|1+|flag|test|dummy|example)\}", candidate_l):
        reasons.append("common_bait_pattern")
    return reasons


def classify_flag_confidence(
    candidate: str,
    context: Any | None = None,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    policy = policy or {}
    configured_regex = _policy_flag_regex(policy)
    default_match = _matches_regex(candidate, None)
    configured_match = _matches_regex(candidate, configured_regex)
    digest = hash_flag(candidate)
    fake_reasons = _fake_reasons(candidate, context)
    result: dict[str, Any] = {
        "candidate_preview": redact_flag(candidate),
        "flag_hash": digest,
        "confidence": "none",
        "matches_flag_regex": configured_match,
        "matches_default_regex": default_match,
        "fake_likely": bool(fake_reasons),
        "reasons": [],
    }
    if not configured_match:
        result["reasons"].append("not_flag_like")
        return result
    if fake_reasons:
        result["confidence"] = "low"
        result["reasons"].extend(fake_reasons)
        return result

    source = _context_source(context)
    context_l = _context_text(context).lower()
    evidence_present = _context_evidence_source_present(context)
    derivation_present = _context_derivation_present(context)
    explicit_confidence = str(context.get("confidence") or "").strip().lower() if isinstance(context, Mapping) else ""
    if (
        (source in HIGH_CONFIDENCE_SOURCES)
        or (source in {"file_read", "local_attachment", "solver_output", "exploit_output"} and _context_local_verified(context))
        or (evidence_present and (derivation_present or explicit_confidence == "high"))
        or any(marker in context_l for marker in HIGH_CONFIDENCE_MARKERS)
    ):
        result["confidence"] = "high"
        result["reasons"].append("verified_source")
        return result

    prefix = candidate.split("{", 1)[0].upper() if "{" in candidate else ""
    if prefix in COMMON_PREFIXES and bool(policy.get("trust_common_prefix_without_context", False)):
        result["confidence"] = "high"
        result["reasons"].append("trusted_common_prefix")
        return result

    if any(marker in context_l for marker in UNCERTAIN_MARKERS):
        result["confidence"] = "medium"
        result["reasons"].append("uncertain_context")
        return result

    result["confidence"] = "medium"
    result["reasons"].append("flag_like_uncertain_context")
    return result


def load_submit_policy(path: str | Path | None = None) -> dict[str, Any]:
    default = {
        "auto_submit_default": True,
        "require_high_confidence": True,
        "max_wrong_per_challenge": 2,
        "cooldown_seconds": 30,
        "duplicate_detection": "sha256",
        "submit_requires_live": True,
        "submit_requires_confirm_or_policy": True,
        "allow_medium_confidence_when_no_limit": False,
        "reject_fake_like": True,
    }
    if not path:
        return default
    config_path = Path(path).expanduser()
    if not config_path.exists():
        return default
    loaded = _parse_minimal_yaml(config_path)
    default.update(loaded)
    return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _submitted_at_epoch(item: Mapping[str, Any]) -> float:
    for key in ("submitted_at_epoch", "created_at_epoch"):
        value = item.get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                pass
    value = item.get("submitted_at") or item.get("created_at")
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _decision(
    allowed: bool,
    reason: str,
    classification: Mapping[str, Any],
    *,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "allowed": allowed,
        "reason": reason,
        "confidence": classification.get("confidence"),
        "fake_likely": bool(classification.get("fake_likely")),
        "flag_hash": classification.get("flag_hash"),
        "candidate_preview": classification.get("candidate_preview"),
        "classification": dict(classification),
    }
    if extra:
        payload.update(extra)
    return payload


def should_submit(
    candidate: str,
    policy: Mapping[str, Any] | None = None,
    previous_submissions: list[dict[str, Any]] | None = None,
    challenge_state: Mapping[str, Any] | None = None,
    *,
    context: Any | None = None,
) -> dict[str, Any]:
    policy = policy or load_submit_policy()
    previous_submissions = previous_submissions or []
    challenge_state = challenge_state or {}
    classification = classify_flag_confidence(candidate, context=context, policy=policy)
    digest = str(classification["flag_hash"])

    if challenge_state.get("solved") or str(challenge_state.get("status") or "").lower() == "solved":
        return _decision(False, "already_solved", classification)
    if not policy.get("auto_submit_default", False):
        return _decision(False, "auto_submit_disabled", classification)
    if classification["confidence"] == "none":
        return _decision(False, "not_flag_like", classification)
    if policy.get("reject_fake_like", True) and classification.get("fake_likely"):
        return _decision(False, "fake_likely", classification)

    duplicate_statuses = DUPLICATE_STATUSES
    if str(policy.get("duplicate_detection") or "").lower() == "sha256":
        for item in previous_submissions:
            status = str(item.get("status") or "").lower()
            if item.get("flag_hash") == digest and status in duplicate_statuses:
                return _decision(False, "duplicate", classification)

    wrong = [item for item in previous_submissions if str(item.get("status") or "").lower() in WRONG_STATUSES]
    max_wrong = _coerce_int(policy.get("max_wrong_per_challenge"), 2)
    if max_wrong >= 0 and len(wrong) >= max_wrong:
        return _decision(False, "wrong_submission_limit", classification, extra={"wrong_count": len(wrong)})

    cooldown = _coerce_int(policy.get("cooldown_seconds"), 0)
    if cooldown > 0 and wrong:
        latest = max(_submitted_at_epoch(item) for item in wrong)
        remaining = int(max(0, cooldown - (time.time() - latest))) if latest else 0
        if remaining > 0:
            return _decision(
                False,
                "cooldown_active",
                classification,
                extra={"cooldown_remaining_seconds": remaining, "wrong_count": len(wrong)},
            )

    confidence = str(classification.get("confidence") or "")
    if policy.get("require_high_confidence", True) and confidence != "high":
        return _decision(False, "confidence_too_low", classification)
    if (
        confidence == "medium"
        and max_wrong < 0
        and not bool(policy.get("allow_medium_confidence_when_no_limit", False))
    ):
        return _decision(False, "medium_confidence_without_limit_disabled", classification)
    return _decision(True, "ok", classification, extra={"wrong_count": len(wrong)})


def submission_public_payload(candidate: str, context: Any | None = None, policy: Mapping[str, Any] | None = None) -> dict[str, Any]:
    classification = classify_flag_confidence(candidate, context=context, policy=policy)
    return {
        "candidate_preview": classification["candidate_preview"],
        "flag_hash": classification["flag_hash"],
        "confidence": classification["confidence"],
        "fake_likely": classification["fake_likely"],
        "reasons": classification["reasons"],
    }


def record_submission_attempt(
    *,
    challenge_id: str,
    candidate: str | None = None,
    flag_hash_value: str | None = None,
    status: str,
    confidence: str | None = None,
    result_summary: str | Mapping[str, Any] | None = None,
    worker_id: str | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    if not flag_hash_value:
        if candidate is None:
            raise ValueError("candidate or flag_hash_value is required")
        flag_hash_value = hash_flag(candidate)
    if isinstance(result_summary, Mapping):
        summary = redact_text(json.dumps(dict(result_summary), sort_keys=True))
    else:
        summary = redact_text(str(result_summary or ""))
    from .state import record_submission_attempt as state_record_submission_attempt

    return state_record_submission_attempt(
        challenge_id=challenge_id,
        flag_hash=flag_hash_value,
        status=status,
        confidence=confidence,
        result_summary_redacted=summary,
        worker_id=worker_id,
        db_path=db_path,
    )
