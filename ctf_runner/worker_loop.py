from __future__ import annotations

import json
import hashlib
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .contest_control import contest_guard_flags, profile_path_from_control
from .docker_pool import container_name as docker_container_name
from .docker_pool import default_workspace as docker_default_workspace
from .handoff import write_handoff
from .paths import get_paths, repo_root
from .platform_base import action_to_dict
from .platform_ctfd import load_platform_adapter
from .postsolve import generate_postsolve
from .redact import redact_text
from .run_mode import check_action_allowed, resolve_run_mode, target_kind_for_challenge
from .solve_prompt import build_solve_prompt, select_prompt_files
from .solve_result import candidate_submit_context, normalize_solver_output, parse_solver_output, public_solver_result
from .state import (
    claim_next_challenge,
    get_challenge,
    get_challenge_state,
    heartbeat_claim,
    init_db,
    list_submissions,
    record_event,
    update_challenge_solved,
    update_challenge_status,
)
from .submit import load_submit_policy, record_submission_attempt, should_submit
from .telemetry import write_event as write_telemetry


MOCK_SOLVED_MARKER = "DDING_MOCK_SOLVER_SOLVED"
MOCK_STALLED_MARKER = "DDING_MOCK_SOLVER_STALLED"
MOCK_DECOY_THEN_SOLVED_MARKER = "DDING_MOCK_SOLVER_DECOY_THEN_SOLVED"


def run_worker_once(
    worker_id: str,
    mode: str = "dry-run",
    solver: str = "mock",
    live_submit: bool = False,
    *,
    allow_codex_call: bool = False,
    confirm_submit: bool = False,
    platform_config: str | Path | None = None,
    db_path: str | Path | None = None,
    contests_root: str | Path | None = None,
    state_root: str | Path | None = None,
    telemetry_path: str | Path | None = None,
    submit_policy_path: str | Path | None = None,
    run_mode: str | None = None,
    allow_real_solve_dry_run: bool = False,
    confirm_competition: bool = False,
    contest_id: str | None = None,
    postsolve: bool | None = None,
    stale_after_sec: int | float | None = 900,
) -> dict[str, Any]:
    if mode not in {"dry-run", "competition"}:
        raise ValueError("mode must be dry-run or competition")
    if solver not in {"mock", "codex"}:
        raise ValueError("solver must be mock or codex")
    effective_run_mode = resolve_run_mode(run_mode)

    init_db(db_path)
    paths = get_paths()
    run_root = Path(state_root).expanduser() if state_root else paths.state_root
    handoff_dir = run_root / "handoffs"
    telemetry_event_count = 0

    def emit(
        event_type: str,
        status: str,
        details: Any | None = None,
        *,
        challenge_id: str | None = None,
    ) -> None:
        nonlocal telemetry_event_count
        telemetry_event_count += 1
        _event(
            event_type,
            status,
            details,
            worker_id=worker_id,
            challenge_id=challenge_id,
            db_path=db_path,
            telemetry_path=telemetry_path,
        )

    challenge = claim_next_challenge(worker_id, db_path, stale_after_sec=stale_after_sec)
    if challenge is None:
        emit("worker_idle", "empty", {})
        return {
            "status": "empty",
            "worker_id": worker_id,
            "solver": solver,
            "solver_backend": solver,
            "flag_candidate_count": 0,
            "submit_plan_status": "none",
            "state_after": "empty",
            "telemetry_event_count": telemetry_event_count,
            "handoff_written": False,
        }

    challenge_id = str(challenge["id"])
    effective_contest_id = _challenge_contest_id(challenge, override=contest_id)
    contest_flags = contest_guard_flags(effective_contest_id, state_root=state_root)
    handoff_written = False
    emit("worker_claimed", "ok", {"challenge": _public_challenge(challenge)}, challenge_id=challenge_id)
    try:
        target_kind = target_kind_for_challenge(challenge)
        solve_decision = check_action_allowed(
            effective_run_mode,
            "real_challenge_solve",
            target_kind,
            flags={
                "allow_real_solve_dry_run": allow_real_solve_dry_run,
                "confirm_competition": confirm_competition,
                **contest_flags,
            },
        )
        if not solve_decision.allowed:
            decision_payload = solve_decision.to_dict()
            update_challenge_status(
                challenge_id,
                "blocked_by_mode",
                worker_id=worker_id,
                details={
                    "run_mode": effective_run_mode,
                    "target_kind": target_kind,
                    "contest_id": effective_contest_id,
                    "decision": decision_payload,
                },
                db_path=db_path,
            )
            emit(
                "worker_blocked_by_mode",
                "blocked",
                {
                    "run_mode": effective_run_mode,
                    "target_kind": target_kind,
                    "contest_id": effective_contest_id,
                    "decision": decision_payload,
                },
                challenge_id=challenge_id,
            )
            return {
                "status": "blocked_by_mode",
                "worker_id": worker_id,
                "challenge_id": challenge_id,
                "solver": solver,
                "solver_backend": solver,
                "mode": mode,
                "run_mode": effective_run_mode,
                "target_kind": target_kind,
                "contest_id": effective_contest_id,
                "contest_armed": bool(contest_flags.get("contest_armed")),
                "mode_decision": decision_payload,
                "reason": solve_decision.reason,
                "live_submit_called": False,
                "flag_candidate_count": 0,
                "submit_plan_status": "none",
                "state_after": "blocked_by_mode",
                "telemetry_event_count": telemetry_event_count,
                "handoff_written": False,
            }
        effective_platform_config = platform_config or profile_path_from_control(effective_contest_id, state_root=state_root)
        platform = load_platform_adapter(effective_platform_config) if effective_platform_config else None
        effective_contests_root = contests_root or (platform.downloads_root if platform else None)
        update_challenge_status(challenge_id, "solving", worker_id=worker_id, db_path=db_path)
        heartbeat_claim(worker_id, challenge_id, db_path)
        brief_path = locate_or_generate_brief(challenge, contests_root=effective_contests_root, state_root=run_root)
        prompt_mode = "competition" if effective_run_mode == "competition" else mode
        prompt_challenge = _with_docker_pool_hint(challenge, contest_id=effective_contest_id, worker_id=worker_id)
        selected_files = select_prompt_files(prompt_challenge, brief_path)
        prompt = build_solve_prompt(prompt_challenge, brief_path, selected_files=selected_files, mode=prompt_mode)
        emit(
            "solve_prompt_built",
            "ok",
            {
                "prompt_bytes": len(prompt.encode("utf-8")),
                "brief_path": _display_path(brief_path),
                "selected_file_count": len(selected_files),
                "selected_files": [_display_path(path) for path in selected_files],
            },
            challenge_id=challenge_id,
        )
        emit("solver_started", solver, {"solver": solver}, challenge_id=challenge_id)
        output = _run_solver(worker_id, solver, prompt, brief_path, allow_codex_call=allow_codex_call)
        heartbeat_claim(worker_id, challenge_id, db_path)
        result = parse_solver_output(output)
        public_result = public_solver_result(result)
        parse_status = "ok" if public_result.get("status") != "error" else "error"
        rejected_count = len(public_result.get("rejected_candidates") or [])
        evidence_context = public_result.get("confidence_context") or {}
        evidence_source_present = bool(evidence_context.get("evidence_source") or evidence_context.get("evidence"))
        emit(
            "solver_completed",
            public_result["status"],
            {"summary": public_result["summary"], "candidate_count": len(public_result["flag_candidates"])},
            challenge_id=challenge_id,
        )
        if result["flag_candidates"]:
            emit(
                "flag_candidate_detected",
                "hash_only",
                {"candidate_hashes": [item["flag_hash"] for item in public_result["flag_candidates"]]},
                challenge_id=challenge_id,
            )
        submit_decision = check_action_allowed(
            effective_run_mode,
            "live_submit",
            target_kind,
            flags={"confirm_submit": confirm_submit, "confirm_competition": confirm_competition, **contest_flags},
            policy=getattr(platform, "policy", {}) if platform else {},
        )
        effective_live_submit = bool(live_submit and submit_decision.allowed)
        if live_submit and not submit_decision.allowed:
            emit(
                "live_submit_blocked_by_mode",
                "blocked",
                {"run_mode": effective_run_mode, "target_kind": target_kind, "decision": submit_decision.to_dict()},
                challenge_id=challenge_id,
            )
        plans = _plan_submissions(
            challenge_id,
            result,
            worker_id=worker_id,
            live_submit=effective_live_submit,
            confirm_submit=confirm_submit,
            platform=platform,
            challenge=challenge,
            db_path=db_path,
            submit_policy_path=submit_policy_path,
        )
        final_status = _final_status(result, plans)
        postsolve_summary: dict[str, Any] | None = None
        failure_reason = ""
        if final_status == "submit_planned":
            emit(
                "submit_planned",
                "planned",
                {"plans": plans, "live_submit_called": False},
                challenge_id=challenge_id,
            )
        elif final_status == "solved":
            accepted_plan = next((plan for plan in plans if plan.get("status") == "accepted"), {})
            update_challenge_solved(
                challenge_id,
                worker_id=worker_id,
                db_path=db_path,
            )
            if _should_generate_postsolve(
                postsolve,
                target_kind=target_kind,
                run_mode=effective_run_mode,
                contest_flags=contest_flags,
            ):
                postsolve_summary = generate_postsolve(
                    effective_contest_id or str(challenge.get("contest_id") or "manual"),
                    challenge_id,
                    state={**challenge, "status": "solved"},
                    result={
                        "status": "solved",
                        "solver_result": public_result,
                        "submit_plans": plans,
                        "worker_id": worker_id,
                        "run_mode": effective_run_mode,
                        "target_kind": target_kind,
                    },
                    output_dir=_challenge_output_dir(challenge, effective_contests_root),
                    require_solved=False,
                )
            else:
                postsolve_summary = {"status": "skipped", "reason": "postsolve_not_enabled"}
            emit(
                "challenge_solved",
                "accepted",
                {
                    "flag_hash": accepted_plan.get("flag_hash"),
                    "postsolve_summary": postsolve_summary,
                    "live_submit_called": bool(accepted_plan.get("live_submit_called")),
                },
                challenge_id=challenge_id,
            )
        elif final_status == "error":
            failure_reason = "solver_error"
            write_handoff(handoff_dir, challenge_id, result, "solver error")
            handoff_written = True
            emit(
                "challenge_error",
                "error",
                {"reason": "solver error"},
                challenge_id=challenge_id,
            )
        elif final_status == "stalled":
            failure_reason = "no_acceptable_submit_plan" if plans else "no_flag_candidate"
            write_handoff(handoff_dir, challenge_id, result, "no acceptable submit plan" if plans else "no flag candidate")
            handoff_written = True
            emit(
                "challenge_stalled",
                "stalled",
                {"reason": "no acceptable submit plan" if plans else "no flag candidate"},
                challenge_id=challenge_id,
            )
        if final_status != "solved":
            update_challenge_status(challenge_id, final_status, worker_id=worker_id, db_path=db_path)
        state_after = str(get_challenge_state(challenge_id, db_path).get("status") or final_status)
        return {
            "status": final_status,
            "worker_id": worker_id,
            "challenge_id": challenge_id,
            "solver": solver,
            "solver_backend": solver,
            "mode": mode,
            "run_mode": effective_run_mode,
            "target_kind": target_kind,
            "contest_id": effective_contest_id,
            "contest_armed": bool(contest_flags.get("contest_armed")),
            "live_submit_called": any(bool(plan.get("live_submit_called")) for plan in plans),
            "live_submit_mode_decision": submit_decision.to_dict(),
            "flag_candidate_count": len(public_result["flag_candidates"]),
            "candidate_count": len(public_result["flag_candidates"]),
            "rejected_candidate_count": rejected_count,
            "solver_output_status": public_result.get("status"),
            "parse_status": parse_status,
            "evidence_source_present": evidence_source_present,
            "failure_reason": failure_reason,
            "submit_plan_status": _submit_plan_status(plans),
            "state_after": state_after,
            "telemetry_event_count": telemetry_event_count,
            "handoff_written": handoff_written,
            "solver_result": public_result,
            "submit_plans": plans,
            "postsolve_summary": postsolve_summary,
        }
    except Exception as exc:  # noqa: BLE001 - worker loop must leave compact state.
        parsed = parse_solver_output(f"STATUS: error\nSUMMARY: {type(exc).__name__}: {redact_text(str(exc))}\n")
        write_handoff(handoff_dir, challenge_id, parsed, "worker_error")
        handoff_written = True
        update_challenge_status(challenge_id, "error", worker_id=worker_id, db_path=db_path)
        emit(
            "worker_error",
            "error",
            {"error": f"{type(exc).__name__}: {redact_text(str(exc))}"},
            challenge_id=challenge_id,
        )
        return {
            "status": "error",
            "worker_id": worker_id,
            "challenge_id": challenge_id,
            "solver": solver,
            "solver_backend": solver,
            "flag_candidate_count": 0,
            "submit_plan_status": "none",
            "state_after": "error",
            "telemetry_event_count": telemetry_event_count,
            "handoff_written": handoff_written,
            "error": redact_text(str(exc)),
        }


def run_worker_forever(
    worker_id: str,
    mode: str = "dry-run",
    solver: str = "mock",
    *,
    max_iterations: int | None = None,
    sleep_seconds: float = 2.0,
    stop_when_empty: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    iterations = 0
    empty_count = 0
    results: list[dict[str, Any]] = []
    limit = None if max_iterations in (None, 0) else max(0, int(max_iterations))
    while limit is None or iterations < limit:
        result = run_worker_once(worker_id, mode=mode, solver=solver, **kwargs)
        results.append(result)
        iterations += 1
        if result.get("status") == "empty":
            empty_count += 1
            if stop_when_empty:
                break
            if sleep_seconds:
                time.sleep(sleep_seconds)
            continue
        if limit is None and sleep_seconds:
            time.sleep(sleep_seconds)
    return {"status": "ok", "iterations": iterations, "empty_count": empty_count, "results": results}


def locate_or_generate_brief(
    challenge: dict[str, Any],
    *,
    contests_root: str | Path | None = None,
    state_root: str | Path | None = None,
) -> Path:
    challenge_id = str(challenge.get("id") or challenge.get("challenge_id") or "")
    metadata = _metadata_dict(challenge.get("metadata"))
    root = Path(contests_root).expanduser() if contests_root else get_paths().contests_root
    candidates: list[Path] = []
    for key in ("brief_path",):
        if metadata.get(key):
            candidates.append(_expand_display_path(str(metadata[key])))
    if metadata.get("challenge_dir"):
        candidates.append(_expand_display_path(str(metadata["challenge_dir"])) / "brief.md")
    contest_id = str(challenge.get("contest_id") or metadata.get("contest_id") or "manual")
    if challenge_id:
        candidates.append(root / _safe_slug(contest_id) / _safe_slug(challenge_id) / "brief.md")
        candidates.append(root / "manual" / _safe_slug(challenge_id) / "brief.md")
    for candidate in candidates:
        if candidate.name == "brief.md" and candidate.exists() and candidate.is_file():
            return candidate

    run_root = Path(state_root).expanduser() if state_root else get_paths().state_root
    generated = run_root / "generated-briefs" / _safe_slug(challenge_id or "unknown") / "brief.md"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(_minimal_brief(challenge, metadata), encoding="utf-8")
    return generated


def build_prompt_for_challenge(
    challenge_id: str,
    *,
    db_path: str | Path | None = None,
    contests_root: str | Path | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    challenge = get_challenge(challenge_id, db_path)
    if challenge is None:
        challenge = {"id": challenge_id, "name": challenge_id, "status": "unknown", "metadata": "{}"}
    brief_path = locate_or_generate_brief(challenge, contests_root=contests_root, state_root=state_root)
    selected_files = select_prompt_files(challenge, brief_path)
    prompt = build_solve_prompt(challenge, brief_path, selected_files=selected_files)
    return {
        "status": "ok",
        "challenge_id": challenge_id,
        "brief_path": _display_path(brief_path),
        "selected_file_count": len(selected_files),
        "prompt_bytes": len(prompt.encode("utf-8")),
        "prompt": prompt,
    }


def _run_solver(worker_id: str, solver: str, prompt: str, brief_path: Path, *, allow_codex_call: bool) -> str:
    if solver == "mock":
        return _run_mock_solver(prompt)
    if not allow_codex_call:
        return "STATUS: error\nSUMMARY: codex solver call blocked; pass --allow-codex-call for one explicit call\nSOURCE: unknown\nLOCAL_VERIFIED: false\nFAKE_LIKE: false\nNEXT_IDEAS:\n- Re-run with mock or explicit Codex call approval.\n"
    return _run_codex_solver(worker_id, prompt)


def _run_codex_solver(worker_id: str, prompt: str) -> str:
    script = repo_root() / "scripts" / "run-codex-worker.sh"
    try:
        completed = subprocess.run(
            [str(script), "--run", worker_id, "exec", prompt],
            cwd=repo_root(),
            text=True,
            capture_output=True,
            check=False,
            timeout=900,
        )
    except subprocess.TimeoutExpired as exc:
        partial = "\n".join(part for part in (exc.stdout, exc.stderr) if isinstance(part, str))
        return _solver_error_output("codex exec timed out", partial)
    except OSError as exc:
        return _solver_error_output(f"codex exec launch failed: {type(exc).__name__}", str(exc))
    combined = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    cleaned = normalize_solver_output(combined)
    if completed.returncode != 0:
        return _solver_error_output(f"codex exec returned {completed.returncode}", cleaned)
    if not cleaned.strip():
        return _solver_error_output("codex exec produced empty output", combined)
    return cleaned


def _with_docker_pool_hint(challenge: dict[str, Any], *, contest_id: str, worker_id: str) -> dict[str, Any]:
    if not _is_pwn_rev_category(challenge):
        return challenge
    contest_id = contest_id or str(challenge.get("contest_id") or "manual")
    metadata = _metadata_dict(challenge.get("metadata"))
    if metadata.get("docker_pool_hint"):
        return challenge
    hint = {
        "available": True,
        "contest_id": contest_id,
        "worker_id": worker_id,
        "container_name": docker_container_name(contest_id, worker_id),
        "workspace": _display_path(docker_default_workspace(contest_id, worker_id)),
        "safe_command": f"ctfctl docker pool-exec --contest-id {contest_id} --worker-id {worker_id} --command '<local command>' --json",
        "rules": [
            "Use the pool only for local pwn/rev tooling and local challenge artifacts.",
            "Do not pass cookies, tokens, auth headers, passwords, private keys, or flags as Docker env or command args.",
        ],
    }
    metadata["docker_pool_hint"] = hint
    updated = dict(challenge)
    updated["metadata"] = json.dumps(metadata, sort_keys=True)
    return updated


def _is_pwn_rev_category(challenge: dict[str, Any]) -> bool:
    category = str(challenge.get("category") or "").strip().lower()
    return category in {"pwn", "rev", "reverse", "reversing", "reverse engineering", "binary", "pwn/rev"} or "pwn" in category or "rev" in category


def _solver_error_output(summary: str, transcript: str = "") -> str:
    lines = [
        "STATUS: error",
        f"SUMMARY: {redact_text(summary)}",
        "SOURCE: unknown",
        "LOCAL_VERIFIED: false",
        "FAKE_LIKE: false",
    ]
    if transcript.strip():
        lines.extend(["ATTEMPTS:", f"- {redact_text(transcript[-1000:])}"])
    return "\n".join(lines).rstrip() + "\n"


def _run_mock_solver(prompt: str) -> str:
    if MOCK_DECOY_THEN_SOLVED_MARKER in prompt:
        decoy = "FLAG" + "{" + "example_dummy_flag" + "}"
        candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
        return "\n".join(
            [
                "STATUS: solved",
                "SUMMARY: mock solver found one fake-like candidate and one verified candidate",
                "SOURCE: exploit_output",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {decoy}",
                f"FLAG_CANDIDATE: {candidate}",
                "FACTS:",
                "- brief contained the mock duplicate/decoy marker",
                "ATTEMPTS:",
                "- mock backend emitted deterministic decoy and real candidates",
                "NEXT_IDEAS:",
                "- Submit only the verified non-fake-like candidate through guarded ctfctl planning.",
                "",
            ]
        )
    if MOCK_SOLVED_MARKER in prompt:
        candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
        return "\n".join(
            [
                "STATUS: solved",
                "SUMMARY: mock solver found a locally verified candidate",
                "SOURCE: exploit_output",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {candidate}",
                "FACTS:",
                "- brief contained the mock solved marker",
                "ATTEMPTS:",
                "- mock backend generated deterministic solver output",
                "NEXT_IDEAS:",
                "- Submit only through guarded ctfctl planning.",
                "",
            ]
        )
    if MOCK_STALLED_MARKER in prompt:
        return "\n".join(
            [
                "STATUS: stalled",
                "SUMMARY: mock solver intentionally stalled",
                "SOURCE: unknown",
                "LOCAL_VERIFIED: false",
                "FAKE_LIKE: false",
                "FACTS:",
                "- brief contained the mock stalled marker",
                "ATTEMPTS:",
                "- mock backend did not produce a candidate",
                "NEXT_IDEAS:",
                "- Inspect the top interesting files from brief.md.",
                "",
            ]
        )
    return "\n".join(
        [
            "STATUS: stalled",
            "SUMMARY: mock solver found no marker",
            "SOURCE: unknown",
            "LOCAL_VERIFIED: false",
            "FAKE_LIKE: false",
            "FACTS:",
            "- no mock solve marker was present",
            "ATTEMPTS:",
            "- mock backend completed without external calls",
            "NEXT_IDEAS:",
            "- Add local evidence or run a real Codex attempt with explicit approval.",
            "",
        ]
    )


def _plan_submissions(
    challenge_id: str,
    result: dict[str, Any],
    *,
    worker_id: str,
    live_submit: bool,
    confirm_submit: bool,
    platform: Any | None,
    challenge: dict[str, Any],
    db_path: str | Path | None,
    submit_policy_path: str | Path | None,
) -> list[dict[str, Any]]:
    policy = load_submit_policy(submit_policy_path)
    previous = list_submissions(challenge_id, db_path)
    challenge_state = get_challenge_state(challenge_id, db_path)
    plans: list[dict[str, Any]] = []
    for candidate in result.get("flag_candidates") or []:
        submit_context = candidate_submit_context(result, candidate)
        submit_context.update(_submission_evidence_context(challenge, platform))
        decision = should_submit(
            candidate["candidate"],
            policy,
            previous_submissions=previous,
            challenge_state=challenge_state,
            context=submit_context,
        )
        record_status = "planned" if decision["allowed"] else "blocked"
        live_submit_called = False
        platform_action: dict[str, Any] | None = None
        result_summary: dict[str, Any] = {
            "reason": decision["reason"],
            "candidate_preview": decision.get("candidate_preview"),
            "live_submit_requested": live_submit,
            "live_submit_called": False,
            "phase": "phase6_worker_loop",
            "source": submit_context.get("source"),
            "local_verified": bool(submit_context.get("local_verified")),
            "platform": submit_context.get("platform"),
            "evidence": submit_context.get("evidence"),
            "evidence_source": submit_context.get("evidence_source"),
            "derivation_present": bool(submit_context.get("derivation")),
        }
        if live_submit and decision["allowed"]:
            live_ready_reason = _live_submit_ready_reason(platform=platform, confirm_submit=confirm_submit)
            if live_ready_reason == "ok":
                action = platform.submit_flag(challenge_id, candidate["candidate"], live=True, confirm=True)
                platform_action = action_to_dict(action)
                live_submit_called = bool(action.network)
                record_status = action.status if action.status in {"accepted", "rejected", "rate_limited", "planned"} else "blocked"
                result_summary.update(
                    {
                        "reason": action.status,
                        "live_submit_called": live_submit_called,
                        "platform_action_status": action.status,
                        "result_summary_redacted": action.details.get("result_summary_redacted"),
                    }
                )
            else:
                record_status = "planned"
                result_summary["live_submit_blocked_reason"] = live_ready_reason
        record = record_submission_attempt(
            challenge_id=challenge_id,
            candidate=candidate["candidate"],
            status=record_status,
            confidence=str(decision.get("confidence") or ""),
            result_summary=result_summary,
            worker_id=worker_id,
            db_path=db_path,
        )
        previous.append(
            {
                "challenge_id": challenge_id,
                "flag_hash": record.get("flag_hash") or decision.get("flag_hash"),
                "status": record.get("status") or record_status,
                "submitted_at": record.get("submitted_at"),
            }
        )
        plan = {
            "status": record_status,
            "allowed": bool(decision["allowed"]),
            "reason": decision["reason"],
            "confidence": decision.get("confidence"),
            "candidate_preview": decision.get("candidate_preview"),
            "flag_hash": decision.get("flag_hash"),
            "fake_likely": bool(decision.get("fake_likely")),
            "source": submit_context.get("source"),
            "local_verified": bool(submit_context.get("local_verified")),
            "platform": submit_context.get("platform"),
            "evidence": redact_text(str(submit_context.get("evidence") or "")),
            "evidence_source": redact_text(str(submit_context.get("evidence_source") or "")),
            "derivation_present": bool(submit_context.get("derivation")),
            "live_submit_requested": live_submit,
            "confirm_submit_requested": confirm_submit,
            "live_submit_called": live_submit_called,
            "result_summary_redacted": redact_text(json.dumps(result_summary, sort_keys=True)),
            "record": {
                "status": record.get("status"),
                "flag_hash": record.get("flag_hash"),
                "unchanged": record.get("unchanged", False),
            },
        }
        if platform_action:
            plan["platform_action"] = platform_action
        plans.append(plan)
    return plans


def _final_status(result: dict[str, Any], plans: list[dict[str, Any]]) -> str:
    if str(result.get("status")) == "error":
        return "error"
    if any(plan.get("status") == "accepted" for plan in plans):
        return "solved"
    if any(plan.get("status") == "planned" for plan in plans):
        return "submit_planned"
    return "stalled"


def _submit_plan_status(plans: list[dict[str, Any]]) -> str:
    if any(plan.get("status") == "accepted" for plan in plans):
        return "accepted"
    if any(plan.get("status") == "rejected" for plan in plans):
        return "rejected"
    if any(plan.get("status") == "rate_limited" for plan in plans):
        return "rate_limited"
    if any(plan.get("status") == "planned" for plan in plans):
        return "planned"
    if plans:
        return "blocked"
    return "none"


def _live_submit_ready_reason(*, platform: Any | None, confirm_submit: bool) -> str:
    if platform is None:
        return "missing_platform_config"
    if not confirm_submit:
        return "live_submit_requires_confirm"
    base_url = str(getattr(platform, "base_url", "") or "")
    if not _is_loopback_url(base_url) and not bool(getattr(platform, "policy", {}).get("allow_worker_nonlocal_submission")):
        return "worker_live_submit_requires_loopback_platform"
    return "ok"


def _is_loopback_url(value: str) -> bool:
    try:
        from urllib.parse import urlsplit

        host = urlsplit(value).hostname
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


def _submission_evidence_context(challenge: dict[str, Any], platform: Any | None) -> dict[str, Any]:
    metadata = _metadata_dict(challenge.get("metadata"))
    evidence = metadata.get("evidence") or _evidence_from_metadata(metadata)
    platform_name = getattr(platform, "platform_name", None) if platform else metadata.get("platform")
    context: dict[str, Any] = {
        "platform": platform_name,
        "evidence": evidence,
    }
    if platform_name == "fake_ctfd":
        context["fake_like"] = False
    return context


def _evidence_from_metadata(metadata: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("brief_path", "manifest_path"):
        raw = metadata.get(key)
        if not raw:
            continue
        path = _expand_display_path(str(raw))
        digest = _sha256_file(path)
        if digest:
            parts.append(f"{key}={_display_path(path)} sha256={digest}")
        else:
            parts.append(f"{key}={_display_path(path)}")
    return "; ".join(parts)


def _sha256_file(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _challenge_output_dir(challenge: dict[str, Any], contests_root: str | Path | None) -> Path:
    metadata = _metadata_dict(challenge.get("metadata"))
    if metadata.get("challenge_dir"):
        return _expand_display_path(str(metadata["challenge_dir"]))
    root = Path(contests_root).expanduser() if contests_root else get_paths().contests_root
    contest_id = str(challenge.get("contest_id") or metadata.get("contest_id") or "manual")
    challenge_id = str(challenge.get("id") or challenge.get("challenge_id") or "unknown")
    return root / _safe_slug(contest_id) / _safe_slug(challenge_id)


def _event(
    event_type: str,
    status: str,
    details: Any | None = None,
    *,
    worker_id: str | None = None,
    challenge_id: str | None = None,
    db_path: str | Path | None = None,
    telemetry_path: str | Path | None = None,
) -> None:
    safe = _redact_details(details or {})
    record_event(event_type, status, safe, worker_id=worker_id, challenge_id=challenge_id, db_path=db_path)
    write_telemetry(event_type, status, safe, worker_id=worker_id, challenge_id=challenge_id, path=telemetry_path)


def _redact_details(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_details(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _public_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": challenge.get("id"),
        "name": redact_text(str(challenge.get("name") or "")),
        "category": redact_text(str(challenge.get("category") or "")),
        "status": challenge.get("status"),
        "source": challenge.get("source"),
    }


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


def _challenge_contest_id(challenge: dict[str, Any], *, override: str | None = None) -> str:
    if override:
        return str(override)
    metadata = _metadata_dict(challenge.get("metadata"))
    return str(challenge.get("contest_id") or metadata.get("contest_id") or "")


def _should_generate_postsolve(
    requested: bool | None,
    *,
    target_kind: str,
    run_mode: str,
    contest_flags: dict[str, Any],
) -> bool:
    if requested is False:
        return False
    if target_kind in {"fake", "local"}:
        return True if requested is None else bool(requested)
    if target_kind == "real_platform":
        return run_mode == "competition" and bool(contest_flags.get("contest_armed"))
    return bool(requested)


def _minimal_brief(challenge: dict[str, Any], metadata: dict[str, Any]) -> str:
    lines = [
        "# Challenge Brief",
        "",
        "## Metadata",
        f"- challenge_id: {challenge.get('id') or challenge.get('challenge_id')}",
        f"- name: {challenge.get('name') or ''}",
        f"- category: {challenge.get('category') or ''}",
        f"- contest_id: {challenge.get('contest_id') or metadata.get('contest_id') or 'manual'}",
        "",
        "## Warnings / Unknowns",
        "- generated minimal brief because ingest artifacts were not found",
        "",
        "## Recommended First Actions",
        "- Run ingest or attach local challenge files before a real solve attempt.",
        "",
    ]
    return redact_text("\n".join(lines))


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._-")
    return slug[:120] or "unknown"


def _expand_display_path(raw: str) -> Path:
    return Path(raw.replace("~/", str(Path.home()) + "/", 1)).expanduser()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve()).replace(str(Path.home()), "~", 1)
    except OSError:
        return str(path).replace(str(Path.home()), "~", 1)
