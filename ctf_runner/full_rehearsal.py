from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import time
import base64
from pathlib import Path
from typing import Any

from .contest_control import arm_contest, contest_root, contest_status, disarm_contest, record_prestart
from .contest_resources import cleanup_contest_resources, contest_resource_summary, safe_public_url_payload
from .docker_pool import cleanup_containers, pool_status, start_pool
from .fake_ctfd import ChallengeFixture, FakeCTFdServer, default_correct_flag, duplicate_real_flag, platform_config, stalled_correct_flag
from .ingest import ingest_challenge, ingest_text_challenge
from .multi_worker import _duplicate_claim_count, _run_workers_once, _submission_counts
from .paths import get_paths, repo_root
from .platform_base import action_to_dict
from .platform_ctfd import CTFdPlatform
from .platform_profile import validate_platform_profile
from .preflight import collect_preflight
from .redact import redact_text
from .state import connect, init_db, list_status, update_challenge_ingested, upsert_platform_challenges, utc_now
from .tunnel_manager import run_callback_public_smoke
from .worker_supervisor import start_workers, stop_workers, worker_status


FINAL_REHEARSAL_MIN_CHALLENGES = 5


def run_full_rehearsal(
    *,
    contest_id: str = "final-fake",
    workers: int = 5,
    max_parallel_codex: int = 2,
    solver: str = "mock",
    allow_codex_call: bool = False,
    codex_smoke: bool = False,
    timeout_sec: float = 180.0,
    run_release_check: bool = True,
) -> dict[str, Any]:
    contest_id = _require_fake_contest_id(contest_id)
    worker_count = _bounded_int(workers, default=5, minimum=1, maximum=10)
    solver = solver if solver in {"mock", "codex"} else "mock"
    max_parallel = _bounded_int(max_parallel_codex, default=2, minimum=1, maximum=worker_count)
    codex_mode = solver == "codex" or codex_smoke

    paths = get_paths()
    state_root = paths.state_root
    root = contest_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    database = root / "rehearsal_queue.sqlite3"
    telemetry_path = root / "rehearsal_events.jsonl"
    downloads_root = root / "downloads"
    config_path = root / "fake_platform.json"
    report_path = root / "rehearsal_report.json"
    summary_path = root / "rehearsal_summary.md"

    if codex_mode and not allow_codex_call:
        payload = _redact_object(
            {
                "status": "blocked",
                "contest_id": contest_id,
                "solver": solver,
                "codex_smoke": True,
                "started_at": utc_now(),
                "elapsed_seconds": 0,
                "workers_requested": worker_count,
                "max_parallel_codex": max_parallel,
                "max_parallel_observed": 0,
                "paths": {
                    "report": _display_path(report_path),
                    "summary": _display_path(summary_path),
                    "state_root": _display_path(root),
                    "db_path": _display_path(database),
                    "downloads_root": _display_path(downloads_root),
                },
                "counts": {
                    "discovered": 0,
                    "ingested": 0,
                    "solved": 0,
                    "stalled": 0,
                    "accepted_submissions": 0,
                    "blocked_submissions": 0,
                    "duplicate_claims": 0,
                    "duplicate_submissions": 0,
                    "postsolve_generated": 0,
                    "active_worker_count": 0,
                    "active_tunnel_count": 0,
                    "active_callback_count": 0,
                    "active_docker_pool_count": 0,
                    "raw_leak_detected": False,
                },
                "raw_leak_detected": False,
                "acceptance": {"allow_codex_call_required": False},
                "failures": ["allow_codex_call_required"],
                "next_recommended_action": "rerun with --allow-codex-call only for the fake/local Codex mini rehearsal",
            }
        )
        _write_reports(report_path, summary_path, payload)
        return payload

    _reset_rehearsal_db(database)
    init_db(database)
    started = time.monotonic()
    started_at = utc_now()
    initial_cleanup = _cleanup_all(contest_id)
    preflight = collect_preflight(deep=True)
    fake_platform: dict[str, Any] = {"started": False, "stopped": False, "bind_host": "127.0.0.1"}
    release_check: dict[str, Any] = {"status": "skipped", "reason": "not_requested"}
    worker_start: dict[str, Any] = {"status": "not_started"}
    worker_wait: dict[str, Any] = {"status": "not_started", "complete": False}
    worker_stop: dict[str, Any] = {"status": "not_started"}
    public_smoke: dict[str, Any] = {"status": "not_started"}
    docker_start: dict[str, Any] = {"status": "not_started"}
    docker_stop: dict[str, Any] = {"status": "not_started"}
    resource_cleanup: dict[str, Any] = {"status": "not_started"}
    disarm: dict[str, Any] = {"status": "not_started"}
    discover: dict[str, Any] = {"status": "not_started", "details": {"challenge_count": 0}}
    state_save: dict[str, Any] = {"status": "not_started"}
    ingest_results: list[dict[str, Any]] = []
    prestart: dict[str, Any] = {"status": "not_started"}
    arm: dict[str, Any] = {"status": "not_started"}
    worker_results: list[dict[str, Any]] = []
    max_parallel_observed = 0

    fixtures = final_rehearsal_fixtures(codex_smoke=codex_mode)
    raw_values = [fixture.correct_flag for fixture in fixtures]
    try:
        with FakeCTFdServer(fixtures=fixtures) as server:
            fake_platform.update(
                {
                    "started": True,
                    "base_url": server.base_url,
                    "challenge_count": len(server.fixtures),
                    "challenge_ids": [fixture.challenge_id for fixture in server.fixtures],
                }
            )
            config = platform_config(server.base_url, downloads_root)
            config["name"] = contest_id
            config_path.write_text(redact_text(json.dumps(config, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
            profile_check = validate_platform_profile(config_path)
            platform = CTFdPlatform(config=config)
            discover_action = platform.discover_challenges(live=True)
            discover = action_to_dict(discover_action)
            challenges = (discover.get("details") or {}).get("challenges", []) if discover_action.status == "ok" else []
            state_save = upsert_platform_challenges(challenges, contest_id=contest_id, db_path=database)
            ingest_results = _download_and_ingest_all(platform, challenges, contest_id, database, downloads_root)
            prestart = {
                "control": record_prestart(contest_id, profile_path=config_path, run_mode="setup", state_root=state_root),
                "profile_check": profile_check,
                "status": "ok" if profile_check.get("status") == "ok" else "needs_attention",
            }
            arm = arm_contest(
                contest_id,
                profile_path=config_path,
                confirm_competition=True,
                allow_live_submit=True,
                max_workers=worker_count,
                max_parallel_codex=max_parallel,
                state_root=state_root,
            )
            docker_start = start_pool(contest_id, worker_count, state_root=state_root)
            public_smoke = safe_public_url_payload(
                run_callback_public_smoke(
                    provider="auto",
                    allow_public=True,
                    contest_id=contest_id,
                    challenge_id="local-callback-smoke",
                    worker_id="worker-1",
                    state_root=state_root,
                ),
                show_public_url=False,
            )
            if codex_mode:
                worker_start = {
                    "status": "started",
                    "mode": "in_process_bounded",
                    "worker_count": worker_count,
                    "solver": solver,
                    "max_parallel_codex": max_parallel,
                    "allow_codex_call": bool(allow_codex_call),
                }
                worker_results, max_parallel_observed = _run_workers_once(
                    workers=worker_count,
                    solver=solver,
                    max_parallel=max_parallel,
                    config_path=config_path,
                    database=database,
                    contests_root=downloads_root,
                    state_root=state_root,
                    telemetry_path=telemetry_path,
                )
                worker_wait = {"status": "ok", "complete": True, "mode": "in_process_bounded"}
                worker_stop = {"status": "ok", "stopped_count": 0, "mode": "in_process_bounded"}
            else:
                worker_start = start_workers(
                    contest_id,
                    apply=True,
                    workers=worker_count,
                    solver=solver,
                    max_iterations=0,
                    max_parallel_codex=max_parallel,
                    sleep_sec=0.05,
                    stop_when_empty=True,
                    allow_codex_call=False,
                    postsolve=True,
                    live_submit=True,
                    confirm_submit=True,
                    platform_config_path=config_path,
                    db_path=database,
                    contests_root=downloads_root,
                    state_root=state_root,
                )
                worker_wait = _wait_for_workers(contest_id, timeout_sec=timeout_sec, state_root=state_root)
                worker_stop = stop_workers(contest_id, state_root=state_root)
            fake_platform["request_count"] = len(server.request_log)
            fake_platform["submission_counts"] = _counts(item["status"] for item in server.submission_log)
            fake_platform["stopped"] = True
    finally:
        worker_stop = stop_workers(contest_id, state_root=state_root) if worker_stop.get("status") == "not_started" else worker_stop
        resource_cleanup = cleanup_contest_resources(contest_id, state_root=state_root)
        docker_stop = cleanup_containers(contest_id, state_root=state_root)
        disarm = disarm_contest(contest_id, stop_workers=True, cleanup_resources=True, stop_docker_pool=True, state_root=state_root)

    queue = list_status(database)
    submission_counts = _submission_counts(database)
    duplicate_claims = _duplicate_claim_count(database)
    duplicate_submissions = _duplicate_submission_count(database)
    handoff_count = _handoff_event_count(database)
    postsolve_count = _postsolve_count(downloads_root, contest_id)
    final_workers = worker_status(contest_id, state_root=state_root)
    final_resources = contest_resource_summary(contest_id, state_root=state_root)
    final_docker = pool_status(contest_id, state_root=state_root)
    final_contest = contest_status(contest_id, db_path=database, state_root=state_root)
    if run_release_check:
        release_check = _run_release_check()

    elapsed = round(time.monotonic() - started, 3)
    counts = _counts_payload(
        queue=queue,
        submission_counts=submission_counts,
        discovered_count=int((discover.get("details") or {}).get("challenge_count") or 0),
        ingested_count=len(ingest_results),
        duplicate_claims=duplicate_claims,
        duplicate_submissions=duplicate_submissions,
        handoff_count=handoff_count,
        postsolve_count=postsolve_count,
    )
    counts.update(
        {
            "active_worker_count": int(final_workers.get("running_worker_count") or 0),
            "active_tunnel_count": int(final_resources.get("active_tunnel_count") or 0),
            "active_callback_count": int(final_resources.get("active_callback_count") or 0),
            "active_docker_pool_count": int(final_docker.get("active_container_count") or 0),
        }
    )
    payload: dict[str, Any] = {
        "status": "pending",
        "contest_id": contest_id,
        "solver": solver,
        "codex_smoke": bool(codex_mode),
        "started_at": started_at,
        "elapsed_seconds": elapsed,
        "workers_requested": worker_count,
        "max_parallel_codex": max_parallel,
        "max_parallel_observed": max_parallel_observed,
        "paths": {
            "report": _display_path(report_path),
            "summary": _display_path(summary_path),
            "state_root": _display_path(root),
            "db_path": _display_path(database),
            "downloads_root": _display_path(downloads_root),
        },
        "preflight": _preflight_summary(preflight),
        "fake_platform": fake_platform,
        "discover": {
            "status": discover.get("status"),
            "challenge_count": (discover.get("details") or {}).get("challenge_count"),
            "state_save": state_save,
        },
        "ingest": {"count": len(ingest_results), "items": ingest_results},
        "prestart": prestart,
        "arm": {"status": arm.get("status"), "armed": bool((arm.get("control") or {}).get("armed"))},
        "docker_pool_start": docker_start,
        "callback_public_smoke": public_smoke,
        "worker_start": worker_start,
        "worker_wait": worker_wait,
        "worker_stop": worker_stop,
        "worker_results": worker_results,
        "challenge_failure_summary": _challenge_failure_summary(worker_results, db_path=database),
        "resource_cleanup": resource_cleanup,
        "docker_pool_stop": docker_stop,
        "disarm": disarm,
        "final": {
            "contest_status": final_contest,
            "worker_status": final_workers,
            "resources": final_resources,
            "docker_pool": final_docker,
        },
        "counts": counts,
        "release_check": release_check,
        "initial_cleanup": initial_cleanup,
        "failures": [],
        "next_recommended_action": "review rehearsal_report.json, then run the same checklist before the first real contest",
    }
    raw_leak_detected = _raw_leak_detected(payload, raw_values)
    payload["raw_leak_detected"] = raw_leak_detected
    payload["counts"]["raw_leak_detected"] = raw_leak_detected
    criteria = _acceptance_criteria(payload, codex_mode=codex_mode)
    payload["acceptance"] = criteria
    payload["failures"] = [key for key, ok in criteria.items() if not ok]
    if all(criteria.values()):
        payload["status"] = "ok"
    elif codex_mode and _codex_acceptable(criteria):
        payload["status"] = "acceptable"
    else:
        payload["status"] = "error"
    payload = _redact_object(payload)
    _write_reports(report_path, summary_path, payload)
    return payload


def final_rehearsal_fixtures(*, codex_smoke: bool = False) -> list[ChallengeFixture]:
    if codex_smoke:
        return _codex_mini_fixtures()
    shared = default_correct_flag()
    fixtures = [
        ChallengeFixture(
            challenge_id="final-misc-easy",
            name="misc easy",
            category="misc",
            value=100,
            attachment_name="DDING_MOCK_SOLVER_SOLVED_misc_note.txt",
            description="Local fake misc warmup. The attachment contains only deterministic mock-solver evidence.",
            body=_safe_body("Local fake misc warmup attachment."),
            correct_flag=shared,
            tags=("local", "final", "easy", "attachment"),
        ),
        ChallengeFixture(
            challenge_id="final-crypto-easy",
            name="crypto easy",
            category="crypto",
            value=100,
            attachment_name="DDING_MOCK_SOLVER_SOLVED_crypto_note.txt",
            description="Local fake crypto warmup. The statement is intentionally local-only and redacted.",
            body=_safe_body("Local fake crypto warmup attachment with a harmless encoding note."),
            correct_flag=shared,
            tags=("local", "final", "easy", "attachment"),
        ),
        ChallengeFixture(
            challenge_id="final-web-source",
            name="web text source",
            category="web",
            value=100,
            attachment_name="",
            description="\n".join(
                [
                    "Local fake web source challenge.",
                    "DDING_MOCK_SOLVER_SOLVED",
                    "Review the provided route description. No real service is contacted.",
                ]
            ),
            body="",
            correct_flag=shared,
            tags=("local", "final", "text-only", "web"),
        ),
    ]
    if codex_smoke:
        return fixtures
    fixtures.extend(
        [
            ChallengeFixture(
                challenge_id="final-pwn-docker",
                name="pwn rev docker hint",
                category="pwn",
                value=100,
                attachment_name="DDING_MOCK_SOLVER_SOLVED_pwn_readme.txt",
                description="Local fake pwn/rev challenge used to verify Docker pool hints.",
                body=_safe_body("Use the persistent Docker pool hint for local tooling only."),
                correct_flag=shared,
                tags=("local", "final", "pwn", "docker"),
            ),
            ChallengeFixture(
                challenge_id="final-stalled-decoy",
                name="stalled decoy",
                category="misc",
                value=50,
                attachment_name="DDING_MOCK_SOLVER_STALLED_decoy.txt",
                description="Local fake stalled challenge. It should produce a handoff without a candidate.",
                body="\n".join(
                    [
                        "Local fake stalled challenge.",
                        "DDING_MOCK_SOLVER_STALLED",
                        "No verified candidate is present.",
                        "",
                    ]
                ),
                correct_flag=stalled_correct_flag(),
                tags=("local", "final", "stalled"),
            ),
            ChallengeFixture(
                challenge_id="final-duplicate-guard",
                name="duplicate guard",
                category="misc",
                value=100,
                attachment_name="DDING_MOCK_SOLVER_DECOY_THEN_SOLVED_duplicate.txt",
                description="Local fake duplicate/decoy challenge for submit guard verification.",
                body="\n".join(
                    [
                        "Local fake duplicate guard challenge.",
                        "DDING_MOCK_SOLVER_DECOY_THEN_SOLVED",
                        "The fake-looking candidate is intentionally omitted from the fixture.",
                        "",
                    ]
                ),
                correct_flag=duplicate_real_flag(),
                tags=("local", "final", "duplicate-guard"),
            ),
        ]
    )
    return fixtures


def _codex_mini_fixtures() -> list[ChallengeFixture]:
    direct = _final_flag("aurora_direct_74129")
    encoded = _final_flag("cobalt_cipher_58264")
    source = _final_flag("orbit_route_91357")
    return [
        ChallengeFixture(
            challenge_id="final-misc-easy",
            name="text direct evidence",
            category="misc",
            value=100,
            attachment_name="local_direct_note.txt",
            description="Local rehearsal text challenge. Read the note attachment and report the verified candidate.",
            body="\n".join(
                [
                    "Local rehearsal direct evidence note.",
                    f"verified candidate: {direct}",
                    "Provenance: source=file_read local_verified=true evidence=local_direct_note.txt",
                    "",
                ]
            ),
            correct_flag=direct,
            tags=("local", "final", "easy", "attachment"),
        ),
        ChallengeFixture(
            challenge_id="final-crypto-easy",
            name="base64 hex decode",
            category="crypto",
            value=100,
            attachment_name="encoded_note.txt",
            description="Local rehearsal encoding challenge. Decode the attachment value before reporting the candidate.",
            body="\n".join(
                [
                    "Local rehearsal simple encoding note.",
                    "Decode either encoded value and report only the decoded verified candidate.",
                    f"base64: {base64.b64encode(encoded.encode('utf-8')).decode('ascii')}",
                    f"hex: {encoded.encode('utf-8').hex()}",
                    "Provenance: source=file_read local_verified=true evidence=encoded_note.txt",
                    "",
                ]
            ),
            correct_flag=encoded,
            tags=("local", "final", "easy", "encoding"),
        ),
        ChallengeFixture(
            challenge_id="final-web-source",
            name="source secret extraction",
            category="web",
            value=100,
            attachment_name="app.py",
            description="Local rehearsal source challenge. Inspect the route source and extract the returned constant.",
            body="\n".join(
                [
                    "from flask import Flask",
                    "app = Flask(__name__)",
                    "",
                    f"ROUTE_SECRET = {source!r}",
                    "",
                    "@app.get('/local-only')",
                    "def local_only():",
                    "    return ROUTE_SECRET",
                    "",
                ]
            ),
            correct_flag=source,
            tags=("local", "final", "easy", "source"),
        ),
    ]


def _final_flag(body: str) -> str:
    return "DDING" + "{" + body + "}"


def _safe_body(label: str) -> str:
    return "\n".join([label, "DDING_MOCK_SOLVER_SOLVED", "No raw flag is stored in this fixture body.", ""])


def _download_and_ingest_all(
    platform: CTFdPlatform,
    challenges: list[dict[str, Any]],
    contest_id: str,
    database: Path,
    downloads_root: Path,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in challenges:
        challenge_id = str(item.get("challenge_id") or item.get("id") or "").strip()
        if not challenge_id:
            continue
        download = platform.download_attachments(challenge_id, live=True)
        payload = action_to_dict(download)
        if download.status in {"ok", "partial"}:
            ingest = ingest_challenge(
                challenge_id,
                input_paths=[download.details["fs_dest_dir"]],
                contest_id=contest_id,
                category=str(item.get("category") or ""),
                name=str(item.get("name") or challenge_id),
                output_root=downloads_root,
            )
        elif download.status == "no_attachments":
            ingest = ingest_text_challenge(
                challenge_id,
                text=str(item.get("description") or item.get("name") or challenge_id),
                contest_id=contest_id,
                category=str(item.get("category") or ""),
                name=str(item.get("name") or challenge_id),
                output_root=downloads_root,
                points=_int_or_none(item.get("points")),
                solves=_int_or_none(item.get("solves")),
                tags=item.get("tags") if isinstance(item.get("tags"), list) else [],
            )
        else:
            results.append({"challenge_id": challenge_id, "download": payload, "ingest": {"status": "skipped"}})
            continue
        state_save = update_challenge_ingested(challenge_id, ingest, db_path=database)
        results.append(
            {
                "challenge_id": challenge_id,
                "download": _public_download(payload),
                "ingest": _public_ingest(ingest),
                "state_save": state_save,
            }
        )
    return results


def _cleanup_all(contest_id: str) -> dict[str, Any]:
    return {
        "workers": stop_workers(contest_id),
        "resources": cleanup_contest_resources(contest_id),
        "docker_pool": cleanup_containers(contest_id),
    }


def _wait_for_workers(contest_id: str, *, timeout_sec: float, state_root: str | Path | None) -> dict[str, Any]:
    deadline = time.monotonic() + max(1.0, float(timeout_sec))
    last = worker_status(contest_id, state_root=state_root)
    while time.monotonic() < deadline:
        last = worker_status(contest_id, state_root=state_root)
        if int(last.get("running_worker_count") or 0) == 0:
            return {"status": "ok", "complete": True, "worker_status": last}
        time.sleep(0.2)
    return {"status": "timeout", "complete": False, "worker_status": last}


def _run_release_check() -> dict[str, Any]:
    script = repo_root() / "scripts" / "release-check.sh"
    try:
        proc = subprocess.run(
            [str(script)],
            cwd=repo_root(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout if isinstance(exc.stdout, str) else ""
        return {"status": "timeout", "returncode": 124, "output_tail": _tail_lines(output, 20)}
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "returncode": proc.returncode,
        "output_tail": _tail_lines(proc.stdout or "", 20),
    }


def _acceptance_criteria(payload: dict[str, Any], *, codex_mode: bool) -> dict[str, bool]:
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    final = payload.get("final") if isinstance(payload.get("final"), dict) else {}
    resources = final.get("resources") if isinstance(final.get("resources"), dict) else {}
    docker = final.get("docker_pool") if isinstance(final.get("docker_pool"), dict) else {}
    workers = final.get("worker_status") if isinstance(final.get("worker_status"), dict) else {}
    criteria = {
        "preflight_high_empty": not bool(((payload.get("preflight") or {}).get("risk") or {}).get("High")),
        "fake_platform_started_stopped": bool((payload.get("fake_platform") or {}).get("started")) and bool((payload.get("fake_platform") or {}).get("stopped")),
        "discovered_enough": int(counts.get("discovered") or 0) >= (2 if codex_mode else FINAL_REHEARSAL_MIN_CHALLENGES),
        "ingested_enough": int(counts.get("ingested") or 0) >= (2 if codex_mode else FINAL_REHEARSAL_MIN_CHALLENGES),
        "workers_started": str((payload.get("worker_start") or {}).get("status")) in {"started", "already_running"},
        "workers_stopped": int(workers.get("running_worker_count") or 0) == 0,
        "duplicate_claims_zero": int(counts.get("duplicate_claims") or 0) == 0,
        "duplicate_submissions_zero": int(counts.get("duplicate_submissions") or 0) == 0,
        "active_tunnels_zero": int(resources.get("active_tunnel_count") or 0) == 0,
        "active_callbacks_zero": int(resources.get("active_callback_count") or 0) == 0,
        "active_docker_pool_zero": int(docker.get("active_container_count") or 0) == 0,
        "raw_leak_false": not bool(payload.get("raw_leak_detected")),
        "release_check_pass": (payload.get("release_check") or {}).get("status") in {"ok", "skipped"},
    }
    if codex_mode:
        criteria["codex_concurrency_bounded"] = int(payload.get("max_parallel_observed") or 0) <= int(payload.get("max_parallel_codex") or 1)
        criteria["codex_mini_completed"] = bool((payload.get("worker_wait") or {}).get("complete"))
        required_easy = min(3, max(2, int(counts.get("discovered") or 0)))
        criteria["codex_easy_solved"] = int(counts.get("solved") or 0) >= required_easy and int(counts.get("accepted_submissions") or 0) >= required_easy
    else:
        solved = int(counts.get("solved") or 0)
        criteria.update(
            {
                "easy_challenges_solved": solved >= 4,
                "stalled_handoff_written": int(counts.get("stalled") or 0) >= 1 and int(counts.get("handoffs") or 0) >= 1,
                "accepted_submits_hash_only": int(counts.get("accepted_submissions") or 0) >= solved >= 4,
                "postsolve_generated": int(counts.get("postsolve_generated") or 0) >= solved >= 4,
                "callback_public_smoke_ok": _callback_public_smoke_acceptable(payload.get("callback_public_smoke") or {}),
            }
        )
    return criteria


def _callback_public_smoke_acceptable(public_smoke: dict[str, Any]) -> bool:
    if public_smoke.get("status") == "ok":
        return True
    tunnel = public_smoke.get("tunnel") if isinstance(public_smoke.get("tunnel"), dict) else {}
    listener_stop = public_smoke.get("listener_stop") if isinstance(public_smoke.get("listener_stop"), dict) else {}
    tunnel_stop = public_smoke.get("tunnel_stop") if isinstance(public_smoke.get("tunnel_stop"), dict) else {}
    return (
        bool(tunnel.get("public_url_available"))
        and bool(listener_stop.get("stopped"))
        and bool(tunnel_stop.get("stopped"))
    )


def _codex_acceptable(criteria: dict[str, bool]) -> bool:
    allowed_failures: set[str] = set()
    return all(ok or key in allowed_failures for key, ok in criteria.items())


def _counts_payload(
    *,
    queue: dict[str, Any],
    submission_counts: dict[str, int],
    discovered_count: int,
    ingested_count: int,
    duplicate_claims: int,
    duplicate_submissions: int,
    handoff_count: int,
    postsolve_count: int,
) -> dict[str, Any]:
    challenge_counts = queue.get("challenge_counts") if isinstance(queue.get("challenge_counts"), dict) else {}
    return {
        "discovered": discovered_count,
        "ingested": ingested_count,
        "solved": int(challenge_counts.get("solved") or 0),
        "stalled": int(challenge_counts.get("stalled") or 0),
        "errors": int(challenge_counts.get("error") or 0),
        "blocked_by_mode": int(challenge_counts.get("blocked_by_mode") or 0),
        "accepted_submissions": int(submission_counts.get("accepted") or 0),
        "blocked_submissions": int(submission_counts.get("blocked") or 0),
        "rejected_submissions": int(submission_counts.get("rejected") or 0),
        "duplicate_claims": duplicate_claims,
        "duplicate_submissions": duplicate_submissions,
        "handoffs": handoff_count,
        "postsolve_generated": postsolve_count,
    }


def _preflight_summary(preflight: dict[str, Any]) -> dict[str, Any]:
    return {
        "risk": preflight.get("risk") or {},
        "docker": preflight.get("docker") or {},
        "docker_pool": preflight.get("docker_pool") or {},
        "ctf_pwn_image": preflight.get("ctf_pwn_image") or {},
        "preferred_tunnel_provider": preflight.get("preferred_tunnel_provider") or "",
        "public_provider_installed": bool(preflight.get("public_provider_installed")),
    }


def _public_download(payload: dict[str, Any]) -> dict[str, Any]:
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    return {
        "status": payload.get("status"),
        "download_count": int(details.get("download_count") or 0),
        "failure_count": int(details.get("failure_count") or 0),
        "dest_dir": details.get("dest_dir") or "",
    }


def _public_ingest(ingest: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": ingest.get("status"),
        "ingest_type": ingest.get("ingest_type") or "attachments",
        "challenge_id": ingest.get("challenge_id"),
        "brief_path": ingest.get("brief_path"),
        "file_count": ingest.get("file_count"),
        "likely_categories": ingest.get("likely_categories"),
    }


def _duplicate_submission_count(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT challenge_id, flag_hash, COUNT(*) AS count
            FROM submissions
            GROUP BY challenge_id, flag_hash
            HAVING COUNT(*) > 1
            """
        ).fetchall()
    return sum(max(0, int(row["count"]) - 1) for row in rows)


def _handoff_event_count(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM events WHERE event_type='challenge_stalled' AND status='stalled'"
        ).fetchone()
    return int(row["count"] if row else 0)


def _postsolve_count(downloads_root: Path, contest_id: str) -> int:
    root = downloads_root / contest_id
    if not root.exists():
        return 0
    return len(list(root.glob("*/postsolve/solve_summary.md")))


def _raw_leak_detected(payload: dict[str, Any], raw_values: list[str]) -> bool:
    rendered = json.dumps(payload, sort_keys=True)
    return any(value and value in rendered for value in raw_values)


def _write_reports(report_path: Path, summary_path: Path, payload: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(redact_text(json.dumps(payload, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
    summary_path.write_text(_render_summary(payload), encoding="utf-8")


def _render_summary(payload: dict[str, Any]) -> str:
    counts = payload.get("counts") or {}
    lines = [
        f"# Full Rehearsal Summary: {payload.get('contest_id')}",
        "",
        f"- status: {payload.get('status')}",
        f"- solver: {payload.get('solver')}",
        f"- elapsed_seconds: {payload.get('elapsed_seconds')}",
        f"- discovered: {counts.get('discovered', 0)}",
        f"- ingested: {counts.get('ingested', 0)}",
        f"- solved: {counts.get('solved', 0)}",
        f"- stalled: {counts.get('stalled', 0)}",
        f"- accepted_submissions: {counts.get('accepted_submissions', 0)}",
        f"- duplicate_claims: {counts.get('duplicate_claims', 0)}",
        f"- duplicate_submissions: {counts.get('duplicate_submissions', 0)}",
        f"- raw_leak_detected: {bool(payload.get('raw_leak_detected'))}",
        f"- failures: {', '.join(payload.get('failures') or []) or 'none'}",
        "",
        "Challenge failure summary:",
        *_summary_failure_lines(payload.get("challenge_failure_summary") or []),
        "",
        "Next recommended action:",
        str(payload.get("next_recommended_action") or ""),
        "",
    ]
    return redact_text("\n".join(lines))


def _challenge_failure_summary(worker_results: list[dict[str, Any]], *, db_path: Path | None = None) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for item in worker_results:
        if not isinstance(item, dict):
            continue
        plans = item.get("submit_plans") if isinstance(item.get("submit_plans"), list) else []
        first_plan = next((plan for plan in plans if isinstance(plan, dict)), {})
        submit_guard_reason = item.get("submit_guard_reason") or first_plan.get("reason") or ("no_flag_candidate" if int(item.get("flag_candidate_count") or 0) == 0 else "")
        summary.append(
            {
                "challenge_id": item.get("challenge_id"),
                "status": item.get("status"),
                "solver_output_status": item.get("solver_output_status"),
                "parse_status": item.get("parse_status"),
                "candidate_count": int(item.get("candidate_count") or item.get("flag_candidate_count") or 0),
                "rejected_candidate_count": int(item.get("rejected_candidate_count") or 0),
                "submit_guard_reason": submit_guard_reason,
                "evidence_source_present": bool(item.get("evidence_source_present")),
                "failure_reason": item.get("failure_reason") or ("" if item.get("status") == "solved" else submit_guard_reason),
            }
        )
    if summary or db_path is None or not db_path.exists():
        return summary
    return _challenge_failure_summary_from_db(db_path)


def _challenge_failure_summary_from_db(db_path: Path) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        challenges = conn.execute(
            "SELECT id, status FROM challenges ORDER BY id"
        ).fetchall()
        submissions = conn.execute(
            """
            SELECT challenge_id, status, result_summary_redacted
            FROM submissions
            ORDER BY submitted_at DESC, id DESC
            """
        ).fetchall()
    by_challenge: dict[str, list[sqlite3.Row]] = {}
    for row in submissions:
        by_challenge.setdefault(str(row["challenge_id"]), []).append(row)
    rows: list[dict[str, Any]] = []
    for challenge in challenges:
        challenge_id = str(challenge["id"])
        challenge_submissions = by_challenge.get(challenge_id, [])
        latest = challenge_submissions[0] if challenge_submissions else None
        latest_summary = _safe_json_dict(latest["result_summary_redacted"]) if latest else {}
        guard_reason = str(latest_summary.get("reason") or (latest["status"] if latest else "no_flag_candidate"))
        rows.append(
            {
                "challenge_id": challenge_id,
                "status": challenge["status"],
                "solver_output_status": "",
                "parse_status": "",
                "candidate_count": len(challenge_submissions),
                "rejected_candidate_count": 0,
                "submit_guard_reason": guard_reason,
                "evidence_source_present": bool(latest_summary.get("evidence_source") or latest_summary.get("evidence")),
                "failure_reason": "" if challenge["status"] == "solved" else guard_reason,
            }
        )
    return rows


def _safe_json_dict(value: Any) -> dict[str, Any]:
    try:
        loaded = json.loads(str(value or ""))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _summary_failure_lines(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["- none"]
    lines = []
    for item in items:
        lines.append(
            "- "
            + f"{item.get('challenge_id')}: status={item.get('status')} "
            + f"solver={item.get('solver_output_status')} "
            + f"parse={item.get('parse_status')} "
            + f"candidates={item.get('candidate_count')} "
            + f"rejected={item.get('rejected_candidate_count')} "
            + f"evidence_source={bool(item.get('evidence_source_present'))} "
            + f"guard={item.get('submit_guard_reason') or 'none'}"
        )
    return lines


def _reset_rehearsal_db(database: Path) -> None:
    for path in (database, database.with_suffix(database.suffix + "-wal"), database.with_suffix(database.suffix + "-shm")):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _require_fake_contest_id(contest_id: str) -> str:
    value = str(contest_id or "").strip()
    lowered = value.lower()
    if not value or not (lowered.startswith(("final-fake", "local-", "fake-")) or lowered in {"local-fake"}):
        raise ValueError("full rehearsal is restricted to fake/local contest IDs")
    return value


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value) if value is not None else default
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _tail_lines(text: str, count: int) -> list[str]:
    return [redact_text(line)[-1000:] for line in str(text or "").splitlines()[-count:]]


def _display_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve()).replace(str(Path.home()), "~", 1)
    except OSError:
        return str(path).replace(str(Path.home()), "~", 1)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, Path):
        return _display_path(value)
    if isinstance(value, str):
        return redact_text(value)
    return value
