from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .fake_ctfd import FakeCTFdServer, platform_config
from .ingest import ingest_challenge
from .paths import get_paths
from .platform_base import action_to_dict
from .platform_ctfd import CTFdPlatform
from .redact import redact_text
from .state import connect, init_db, list_status, update_challenge_ingested, upsert_platform_challenges, utc_now
from .worker_loop import run_worker_once


def run_local_e2e(
    *,
    workers: int = 5,
    solver: str = "mock",
    fake_ctfd: bool = True,
    max_parallel: int | None = None,
    db_path: str | Path | None = None,
    run_root: str | Path | None = None,
) -> dict[str, Any]:
    if not fake_ctfd:
        raise ValueError("local-e2e currently supports only --fake-ctfd")
    workers = _bounded_int(workers, default=5, minimum=1, maximum=10)
    if solver not in {"mock", "codex"}:
        raise ValueError("solver must be mock or codex")
    max_parallel = _default_max_parallel(workers, solver, max_parallel)

    root = Path(run_root).expanduser().resolve() if run_root else _default_run_root("local-e2e")
    root.mkdir(parents=True, exist_ok=True)
    contests_root = root / "contests"
    state_root = root
    database = Path(db_path).expanduser().resolve() if db_path else root / "queue.sqlite3"
    telemetry_path = root / "events.jsonl"
    config_path = root / "platform.json"

    init_db(database)
    started_at = time.monotonic()
    with FakeCTFdServer() as server:
        config = platform_config(server.base_url, contests_root)
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
        platform = CTFdPlatform(config=config)

        discover = platform.discover_challenges(live=True)
        discover_payload = action_to_dict(discover)
        challenges = discover_payload.get("details", {}).get("challenges", []) if discover.status == "ok" else []
        state_save = upsert_platform_challenges(challenges, contest_id=platform.platform_name, db_path=database)
        ingest_results = _download_and_ingest_all(platform, challenges, database)

        worker_results, max_observed = _run_workers_once(
            workers=workers,
            solver=solver,
            max_parallel=max_parallel,
            config_path=config_path,
            database=database,
            contests_root=contests_root,
            state_root=state_root,
            telemetry_path=telemetry_path,
        )

        summary = _summary(
            workers=workers,
            solver=solver,
            max_parallel=max_parallel,
            max_parallel_observed=max_observed,
            run_root=root,
            database=database,
            contests_root=contests_root,
            discover=discover_payload,
            state_save=state_save,
            ingest_results=ingest_results,
            worker_results=worker_results,
            elapsed_seconds=time.monotonic() - started_at,
        )
        rendered = json.dumps(summary, sort_keys=True)
        raw_leak_detected = any(flag in rendered for flag in server.correct_flags)
        summary["raw_leak_detected"] = raw_leak_detected
        summary["status"] = "error" if raw_leak_detected else "ok"
        summary["fake_ctfd"] = {
            "base_url": server.base_url,
            "bind_host": "127.0.0.1",
            "challenge_count": len(server.fixtures),
            "request_count": len(server.request_log),
            "submission_counts": _counts(item["status"] for item in server.submission_log),
        }
        summary["expected_met"] = _expected_met(summary)
        return _redact_object(summary)


def run_parallel_smoke(
    *,
    workers: int = 5,
    solver: str = "mock",
    max_parallel: int | None = None,
    db_path: str | Path | None = None,
    run_root: str | Path | None = None,
) -> dict[str, Any]:
    return run_local_e2e(
        workers=workers,
        solver=solver,
        fake_ctfd=True,
        max_parallel=max_parallel,
        db_path=db_path,
        run_root=run_root or _default_run_root("parallel-smoke"),
    )


def worker_status(*, db_path: str | Path | None = None) -> dict[str, Any]:
    database = Path(db_path).expanduser().resolve() if db_path else None
    status = list_status(database)
    submission_counts = _submission_counts(database)
    return {
        "status": "ok",
        "queue": status,
        "submission_counts": submission_counts,
    }


def _download_and_ingest_all(platform: CTFdPlatform, challenges: list[dict[str, Any]], database: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in challenges:
        challenge_id = str(item.get("challenge_id") or item.get("id") or "").strip()
        if not challenge_id:
            continue
        download = platform.download_attachments(challenge_id, live=True)
        payload = action_to_dict(download)
        if download.status not in {"ok", "no_attachments"}:
            results.append({"challenge_id": challenge_id, "download": payload, "ingest": {"status": "skipped"}})
            continue
        ingest = ingest_challenge(
            challenge_id,
            input_paths=[download.details["fs_dest_dir"]],
            contest_id=platform.platform_name,
            category=str(item.get("category") or ""),
            name=str(item.get("name") or challenge_id),
            output_root=platform.downloads_root,
        )
        state_save = update_challenge_ingested(challenge_id, ingest, db_path=database)
        results.append(
            {
                "challenge_id": challenge_id,
                "download": payload,
                "ingest": _public_ingest(ingest),
                "state_save": state_save,
            }
        )
    return results


def _run_workers_once(
    *,
    workers: int,
    solver: str,
    max_parallel: int,
    config_path: Path,
    database: Path,
    contests_root: Path,
    state_root: Path,
    telemetry_path: Path,
) -> tuple[list[dict[str, Any]], int]:
    semaphore = threading.BoundedSemaphore(max_parallel)
    lock = threading.Lock()
    active = 0
    max_observed = 0
    barrier = threading.Barrier(workers)

    def run_one(index: int) -> dict[str, Any]:
        nonlocal active, max_observed
        worker_id = f"worker-{index}"
        worker_dir = state_root / "work" / worker_id
        worker_dir.mkdir(parents=True, exist_ok=True)
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        with semaphore:
            with lock:
                active += 1
                max_observed = max(max_observed, active)
            started = time.monotonic()
            try:
                result = run_worker_once(
                    worker_id,
                    mode="dry-run",
                    solver=solver,
                    live_submit=True,
                    allow_codex_call=(solver == "codex"),
                    confirm_submit=True,
                    platform_config=config_path,
                    db_path=database,
                    contests_root=contests_root,
                    state_root=state_root,
                    telemetry_path=telemetry_path,
                    stale_after_sec=3600,
                )
                result["worker_run_dir"] = _display_path(worker_dir)
                result["elapsed_seconds"] = round(time.monotonic() - started, 3)
                return _public_worker_result(result)
            finally:
                with lock:
                    active -= 1

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ctf-worker-smoke") as executor:
        futures = [executor.submit(run_one, index) for index in range(1, workers + 1)]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: str(item.get("worker_id") or "")), max_observed


def _summary(
    *,
    workers: int,
    solver: str,
    max_parallel: int,
    max_parallel_observed: int,
    run_root: Path,
    database: Path,
    contests_root: Path,
    discover: dict[str, Any],
    state_save: dict[str, Any],
    ingest_results: list[dict[str, Any]],
    worker_results: list[dict[str, Any]],
    elapsed_seconds: float,
) -> dict[str, Any]:
    queue = list_status(database)
    challenge_counts = queue.get("challenge_counts") or {}
    submission_counts = _submission_counts(database)
    duplicate_claims = _duplicate_claim_count(database)
    duplicate_submission_blocks = sum(
        1
        for result in worker_results
        for plan in result.get("submit_plans", [])
        if plan.get("reason") == "duplicate"
    )
    fake_like_blocks = sum(
        1
        for result in worker_results
        for plan in result.get("submit_plans", [])
        if plan.get("reason") == "fake_likely"
    )
    postsolve_count = len(list(contests_root.glob("fake_ctfd/*/postsolve/solve_summary.md")))
    postsolve_count += len(list(contests_root.glob("fake_ctfd/*/solve_summary.md")))
    return {
        "status": "ok",
        "run_id": run_root.name,
        "run_root": _display_path(run_root),
        "db_path": _display_path(database),
        "contest_root": _display_path(contests_root),
        "started_at": utc_now(),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "workers_requested": workers,
        "solver": solver,
        "max_parallel": max_parallel,
        "max_parallel_observed": max_parallel_observed,
        "total_challenges": int((discover.get("details") or {}).get("challenge_count") or len(ingest_results)),
        "solved": int(challenge_counts.get("solved") or 0),
        "stalled": int(challenge_counts.get("stalled") or 0),
        "submit_planned": int(challenge_counts.get("submit_planned") or 0),
        "errors": int(challenge_counts.get("error") or 0),
        "duplicate_claims": duplicate_claims,
        "duplicate_submissions": duplicate_submission_blocks,
        "duplicate_submission_blocks": duplicate_submission_blocks,
        "fake_like_blocks": fake_like_blocks,
        "accepted_submissions": int(submission_counts.get("accepted") or 0),
        "rejected_submissions": int(submission_counts.get("rejected") or 0),
        "blocked_submissions": int(submission_counts.get("blocked") or 0),
        "queue": queue,
        "discover": {
            "status": discover.get("status"),
            "challenge_count": (discover.get("details") or {}).get("challenge_count"),
            "state_save": state_save,
        },
        "ingest": {
            "count": len(ingest_results),
            "items": ingest_results,
        },
        "worker_stats": _worker_stats(worker_results),
        "worker_results": worker_results,
        "handoff_count": _handoff_count(run_root),
        "postsolve_summary_count": postsolve_count,
    }


def _public_worker_result(result: dict[str, Any]) -> dict[str, Any]:
    solver_result = result.get("solver_result") if isinstance(result.get("solver_result"), dict) else {}
    confidence_context = solver_result.get("confidence_context") if isinstance(solver_result.get("confidence_context"), dict) else {}
    plans = [plan for plan in result.get("submit_plans", []) if isinstance(plan, dict)]
    submit_guard_reason = next((str(plan.get("reason") or "") for plan in plans if plan.get("reason")), "")
    if not submit_guard_reason and int(result.get("flag_candidate_count") or 0) == 0:
        submit_guard_reason = "no_flag_candidate"
    return {
        "worker_id": result.get("worker_id"),
        "challenge_id": result.get("challenge_id"),
        "status": result.get("status"),
        "state_after": result.get("state_after"),
        "solver_backend": result.get("solver_backend") or result.get("solver"),
        "solver_output_status": result.get("solver_output_status") or solver_result.get("status"),
        "parse_status": result.get("parse_status") or ("ok" if solver_result else ""),
        "flag_candidate_count": int(result.get("flag_candidate_count") or 0),
        "candidate_count": int(result.get("candidate_count") or result.get("flag_candidate_count") or 0),
        "rejected_candidate_count": int(result.get("rejected_candidate_count") or len(solver_result.get("rejected_candidates") or [])),
        "submit_plan_status": result.get("submit_plan_status"),
        "submit_guard_reason": submit_guard_reason,
        "evidence_source_present": bool(result.get("evidence_source_present") or confidence_context.get("evidence_source") or confidence_context.get("evidence")),
        "failure_reason": result.get("failure_reason") or ("" if result.get("status") == "solved" else submit_guard_reason),
        "live_submit_called": bool(result.get("live_submit_called")),
        "handoff_written": bool(result.get("handoff_written")),
        "telemetry_event_count": int(result.get("telemetry_event_count") or 0),
        "worker_run_dir": result.get("worker_run_dir"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "submit_plans": [
            {
                "status": plan.get("status"),
                "reason": plan.get("reason"),
                "flag_hash": plan.get("flag_hash"),
                "fake_likely": bool(plan.get("fake_likely")),
                "live_submit_called": bool(plan.get("live_submit_called")),
                "platform_action_status": (plan.get("platform_action") or {}).get("status"),
            }
            for plan in plans
        ],
        "postsolve_summary": result.get("postsolve_summary"),
    }


def _worker_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    for result in results:
        worker_id = str(result.get("worker_id") or "unknown")
        stats[worker_id] = {
            "challenge_id": result.get("challenge_id"),
            "status": result.get("status"),
            "state_after": result.get("state_after"),
            "submit_plan_status": result.get("submit_plan_status"),
            "handoff_written": bool(result.get("handoff_written")),
            "elapsed_seconds": result.get("elapsed_seconds"),
        }
    return stats


def _submission_counts(db_path: str | Path | None) -> dict[str, int]:
    path = Path(db_path).expanduser() if db_path else None
    if path is None or not path.exists():
        return {}
    with connect(path) as conn:
        rows = conn.execute("SELECT status, COUNT(*) AS count FROM submissions GROUP BY status").fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def _duplicate_claim_count(db_path: Path) -> int:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT challenge_id, COUNT(*) AS count
            FROM events
            WHERE event_type='challenge_claim' AND status='ok'
            GROUP BY challenge_id
            HAVING COUNT(*) > 1
            """
        ).fetchall()
    return sum(max(0, int(row["count"]) - 1) for row in rows)


def _handoff_count(run_root: Path) -> int:
    path = run_root / "handoffs" / "handoff.jsonl"
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _public_ingest(ingest: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": ingest.get("status"),
        "challenge_id": ingest.get("challenge_id"),
        "brief_path": ingest.get("brief_path"),
        "file_count": ingest.get("file_count"),
        "likely_categories": ingest.get("likely_categories"),
    }


def _expected_met(summary: dict[str, Any]) -> bool:
    if summary.get("solver") == "mock":
        workers = int(summary.get("workers_requested") or 0)
        processed = int(summary.get("solved") or 0) + int(summary.get("stalled") or 0) + int(summary.get("submit_planned") or 0) + int(summary.get("errors") or 0)
        if workers and workers < int(summary.get("total_challenges") or 0):
            return (
                processed >= workers
                and int(summary.get("errors") or 0) == 0
                and int(summary.get("accepted_submissions") or 0) + int(summary.get("stalled") or 0) >= workers
                and int(summary.get("duplicate_claims") or 0) == 0
                and not bool(summary.get("raw_leak_detected"))
            )
        return (
            int(summary.get("total_challenges") or 0) >= 5
            and int(summary.get("solved") or 0) >= 4
            and int(summary.get("stalled") or 0) >= 1
            and int(summary.get("accepted_submissions") or 0) >= 4
            and int(summary.get("duplicate_claims") or 0) == 0
            and not bool(summary.get("raw_leak_detected"))
        )
    return int(summary.get("max_parallel_observed") or 0) <= int(summary.get("max_parallel") or 1)


def _default_max_parallel(workers: int, solver: str, value: int | None) -> int:
    if value is None:
        return min(workers, 2 if solver == "codex" else workers)
    return _bounded_int(value, default=1, minimum=1, maximum=workers)


def _bounded_int(value: int | None, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value) if value is not None else default
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _default_run_root(prefix: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return get_paths().state_root / prefix / f"{stamp}-{int(time.time() * 1000) % 1000:03d}"


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve()).replace(str(Path.home()), "~", 1)
    except OSError:
        return str(path).replace(str(Path.home()), "~", 1)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
