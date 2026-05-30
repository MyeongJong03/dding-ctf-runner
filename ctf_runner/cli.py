from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import __version__
from .auth import load_auth_metadata, load_config_metadata
from .browser_auth import capture_storage_state, storage_state_summary
from .browser_smoke import run_browser_smoke
from .callback_server import listener_hits, listener_status, start_listener, stop_listener
from .callback_smoke import run_callback_smoke
from .codex_doctor import choose_preferred_codex_binary, diagnose_codex_update_issue, diagnose_mcp_legacy
from .codex_notice import clear_notices, notice_status
from .codex_profile import (
    codex_model_status,
    init_worker_home,
    init_worker_range,
    launch_command,
    set_worker_model,
    set_worker_model_all,
    status_worker_home,
    unset_worker_model,
    unset_worker_model_all,
)
from .codex_smoke import default_model_smoke
from .contest_control import (
    arm_contest,
    contest_guard_flags,
    contest_status,
    disarm_contest,
    record_prestart,
    worker_commands,
)
from .contest_resources import (
    cleanup_contest_resources,
    list_contest_resources,
    record_callback_resource,
    record_tunnel_resource,
    safe_public_url_payload,
    update_callback_resource,
    update_tunnel_resource,
)
from .docker_pool import (
    DEFAULT_IMAGE as DEFAULT_DOCKER_IMAGE,
    benchmark as docker_benchmark,
    cleanup_containers,
    exec_in_container,
    pool_smoke,
    pool_status,
    start_persistent_container,
    start_pool,
    stop_container,
)
from .full_rehearsal import run_full_rehearsal
from .handoff import read_handoffs
from .ingest import brief_for_challenge, ingest_challenge, ingest_text_challenge, ingest_text_file, manifest_path, scan_path
from .interactive import (
    board_status as interactive_board_status,
    browser_attempt as interactive_browser_attempt,
    browser_probe as interactive_browser_probe,
    capabilities_report as interactive_capabilities_report,
    challenge_brief as interactive_challenge_brief,
    claim_challenge as interactive_claim_challenge,
    cleanup_challenge as interactive_cleanup_challenge,
    e2e_smoke as interactive_e2e_smoke,
    fallback_report as interactive_fallback_report,
    init_operator as interactive_init_operator,
    list_candidates as interactive_list_candidates,
    mark_external_solved as interactive_mark_external_solved,
    mark_stalled as interactive_mark_stalled,
    metrics_baseline as interactive_metrics_baseline,
    memo_update as interactive_memo_update,
    metrics_compare as interactive_metrics_compare,
    metrics_compare_public as interactive_metrics_compare_public,
    metrics_dashboard as interactive_metrics_dashboard,
    metrics_publish_snapshot as interactive_metrics_publish_snapshot,
    metrics_record as interactive_metrics_record,
    metrics_report as interactive_metrics_report,
    metrics_summary as interactive_metrics_summary,
    next_challenge as interactive_next_challenge,
    operator_status as interactive_operator_status,
    prepare_target as interactive_prepare_target,
    release_claim as interactive_release_claim,
    run_attempt as interactive_run_attempt,
    service_attempt as interactive_service_attempt,
    service_config as interactive_service_config,
    service_probe as interactive_service_probe,
    service_status as interactive_service_status,
    solve_loop as interactive_solve_loop,
    solver_prompt as interactive_solver_prompt,
    starter_challenge as interactive_starter_challenge,
    submit_config as interactive_submit_config,
    submit_flag_file as interactive_submit_flag_file,
    sync_operator as interactive_sync_operator,
    target_pack as interactive_target_pack,
    toolchain_doctor_report as interactive_toolchain_doctor_report,
    triage_challenge as interactive_triage_challenge,
    upload_submit as interactive_upload_submit,
    verify_candidate as interactive_verify_candidate,
    web_attempt as interactive_web_attempt,
    web_config as interactive_web_config,
    web_probe as interactive_web_probe,
    web_status as interactive_web_status,
    writeup_challenge as interactive_writeup_challenge,
)
from .multi_worker import run_local_e2e, run_parallel_smoke, worker_status
from .platform_base import PlatformAction, action_to_dict
from .platform_ctfd import load_platform_adapter
from .platform_profile import (
    add_platform_profile_auth_fallback,
    create_platform_profile,
    set_platform_profile_auth,
    show_platform_profile,
    validate_platform_profile,
)
from .preflight import collect_preflight
from .postsolve import (
    archive_postsolve,
    batch_generate_postsolve,
    generate_postsolve,
    postsolve_status,
    skill_candidates_for_contest,
)
from .public_check import run_public_check
from .redact import redact_text
from .run_mode import RUN_MODES, check_action_allowed, resolve_run_mode, target_kind_for_platform
from .solve_result import parse_solver_output, public_solver_result
from .state import (
    add_manual_challenge,
    claim_next_challenge,
    get_challenge_state,
    init_db,
    list_submissions,
    list_status,
    register_worker,
    release_claim,
    submission_status,
    update_challenge_ingested,
    update_challenge_solved,
    upsert_platform_challenges,
)
from .submit import detect_flag_candidates, load_submit_policy, record_submission_attempt, should_submit, submission_public_payload
from .tunnel import check_tunnel_providers
from .tunnel_manager import run_callback_public_smoke, start_tunnel, stop_tunnel, tunnel_logs, tunnel_status
from .web_payloads import generate_callback_payloads
from .worker_loop import build_prompt_for_challenge, run_worker_forever, run_worker_once
from .worker_supervisor import (
    restart_worker as supervisor_restart_worker,
    run_supervisor_smoke,
    start_workers as supervisor_start_workers,
    stop_workers as supervisor_stop_workers,
    worker_logs as supervisor_worker_logs,
    worker_status as supervisor_worker_status,
)


def _print_json(data: Any) -> None:
    print(redact_text(json.dumps(data, indent=2, sort_keys=True)))


def _print_local_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _print_public_json(data: Any, *, show_public_url: bool = False) -> None:
    _print_json(safe_public_url_payload(data, show_public_url=show_public_url))


def _args_run_mode(args: argparse.Namespace) -> str:
    return resolve_run_mode(getattr(args, "run_mode", None))


def _mode_flags(args: argparse.Namespace) -> dict[str, bool]:
    return {
        "allow_real_readonly": bool(getattr(args, "allow_real_readonly", False)),
        "allow_real_solve_dry_run": bool(getattr(args, "allow_real_solve_dry_run", False)),
        "allow_auth_capture": bool(getattr(args, "allow_auth_capture", False)),
        "confirm_competition": bool(getattr(args, "confirm_competition", False)),
        "confirm_submit": bool(getattr(args, "confirm_submit", False) or getattr(args, "confirm", False)),
        "confirm": bool(getattr(args, "confirm", False)),
    }


def _mode_decision_payload(mode: str, action: str, target_kind: str, decision: Any) -> dict[str, Any]:
    return {
        "run_mode": mode,
        "action": action,
        "target_kind": target_kind,
        "decision": decision.to_dict(),
    }


def _blocked_platform_action(action: str, live: bool, mode: str, target_kind: str, decision: Any, extra: dict[str, Any] | None = None) -> PlatformAction:
    details = {
        "reason": decision.reason,
        "run_mode": mode,
        "target_kind": target_kind,
        "required_flags": list(decision.required_flags),
        "safe_summary": decision.safe_summary,
    }
    if extra:
        details.update(extra)
    return PlatformAction(action=action, live=live, network=False, status="blocked", details=details)


def _platform_mode_decision(args: argparse.Namespace, platform: Any, action: str):
    mode = _args_run_mode(args)
    target_kind = target_kind_for_platform(platform)
    flags = _mode_flags(args)
    if action in {"real_challenge_solve", "live_submit", "instance_start"}:
        contest_id = str(getattr(args, "contest_id", "") or getattr(platform, "platform_name", "") or "")
        flags.update(contest_guard_flags(contest_id))
    decision = check_action_allowed(mode, action, target_kind, flags=flags, policy=getattr(platform, "policy", {}))
    return mode, target_kind, decision


def _cmd_preflight(args: argparse.Namespace) -> int:
    if args.model_smoke and not args.deep:
        raise ValueError("--model-smoke requires --deep")
    data = collect_preflight(include_timing=args.timing, deep=args.deep, model_smoke=args.model_smoke)
    if args.json:
        _print_json(data)
    else:
        risk = data["risk"]
        _print_json({"status": "ok", "risk": risk, "repo_under_mnt_c": data["paths"]["repo_under_mnt_c"]})
    return 0


def _cmd_repo_public_check(args: argparse.Namespace) -> int:
    data = run_public_check(include_preflight=not args.skip_preflight)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_contest_prestart(args: argparse.Namespace) -> int:
    mode = _args_run_mode(args)
    preflight = collect_preflight(deep=True)
    profile_check = validate_platform_profile(args.profile)
    storage_checks = _storage_state_checks(profile_check)
    record_prestart(args.contest_id, profile_path=args.profile, run_mode=mode)
    status = contest_status(args.contest_id, db_path=args.db)
    payload: dict[str, Any] = {
        "status": "ok" if not preflight.get("risk", {}).get("High") and profile_check.get("status") == "ok" else "needs_attention",
        "contest_id": args.contest_id,
        "run_mode": mode,
        "armed": status.get("armed"),
        "profile_path": _display_cli_path(Path(args.profile).expanduser()),
        "preflight": _contest_preflight_summary(preflight),
        "profile_check": profile_check,
        "storage_checks": storage_checks,
        "challenge_counts": status.get("challenge_counts", {}),
        "submit_counts": status.get("submit_counts", {}),
        "worker_counts": status.get("worker_counts", {}),
        "active_docker_container_count": status.get("active_docker_container_count", 0),
        "docker_pool": status.get("docker_pool", {}),
        "docker_warnings": _contest_docker_warnings(preflight, status),
        "live_readonly_check": {"attempted": False, "reason": "not_requested"},
    }
    if args.live_readonly_check:
        platform = _load_platform(args.profile)
        target_kind = target_kind_for_platform(platform)
        decision = check_action_allowed(mode, "real_platform_discover", target_kind, flags=_mode_flags(args), policy=getattr(platform, "policy", {}))
        if not decision.allowed:
            payload["live_readonly_check"] = {
                "attempted": False,
                "status": "blocked",
                **_mode_decision_payload(mode, "real_platform_discover", target_kind, decision),
            }
        else:
            action = platform.discover_challenges(live=True)
            action_payload = action_to_dict(action)
            payload["live_readonly_check"] = {
                "attempted": True,
                "status": action_payload.get("status"),
                "network": bool(action_payload.get("network")),
                "challenge_count": action_payload.get("details", {}).get("challenge_count"),
                "action": action_payload.get("action"),
            }
    _print_json(payload)
    return 0


def _cmd_contest_arm(args: argparse.Namespace) -> int:
    data = arm_contest(
        args.contest_id,
        profile_path=args.profile,
        confirm_competition=args.confirm_competition,
        allow_live_submit=args.allow_live_submit,
        allow_instance_start=args.allow_instance_start,
        max_workers=args.max_workers,
        max_parallel_codex=args.max_parallel_codex,
    )
    _print_json(data)
    return 0 if data.get("status") == "armed" else 1


def _cmd_contest_disarm(args: argparse.Namespace) -> int:
    _print_json(
        disarm_contest(
            args.contest_id,
            stop_workers=args.stop_workers,
            cleanup_resources=args.cleanup_resources,
            stop_docker_pool=args.stop_docker_pool,
        )
    )
    return 0


def _cmd_contest_status(args: argparse.Namespace) -> int:
    _print_json(contest_status(args.contest_id, db_path=args.db))
    return 0


def _cmd_contest_full_rehearsal(args: argparse.Namespace) -> int:
    data = run_full_rehearsal(
        contest_id=args.contest_id,
        workers=args.workers,
        max_parallel_codex=args.max_parallel_codex,
        solver=args.solver,
        allow_codex_call=args.allow_codex_call,
        codex_smoke=args.codex_smoke,
    )
    _print_public_json(data, show_public_url=False)
    return 0 if data.get("status") in {"ok", "acceptable"} else 1


def _cmd_interactive_init(args: argparse.Namespace) -> int:
    data = interactive_init_operator(
        args.contest_id,
        profile=args.profile,
        writeup_root=args.writeup_root,
        agents=args.agents,
    )
    _print_json(data)
    return 0


def _cmd_interactive_sync(args: argparse.Namespace) -> int:
    data = interactive_sync_operator(
        args.contest_id,
        profile=args.profile,
        live=args.live,
        download=args.download,
        ingest=args.ingest,
        pull_solved=args.pull_solved,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_board(args: argparse.Namespace) -> int:
    data = interactive_board_status(args.contest_id)
    if args.json:
        _print_json(data)
    else:
        _print_json({"status": data.get("status"), "contest_id": data.get("contest_id"), "counts": data.get("counts")})
    return 0


def _cmd_interactive_status(args: argparse.Namespace) -> int:
    data = interactive_operator_status(args.contest_id)
    _print_json(data)
    return 0


def _cmd_interactive_capabilities(args: argparse.Namespace) -> int:
    data = interactive_capabilities_report(
        args.contest_id,
        category=args.category,
        refresh=args.refresh,
    )
    if args.json:
        _print_json(data)
    elif data.get("capabilities_md_path"):
        path = Path(str(data.get("capabilities_md_path") or "").replace("~", str(Path.home()), 1))
        print(redact_text(path.read_text(encoding="utf-8", errors="replace")))
    else:
        _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_toolchain_doctor(args: argparse.Namespace) -> int:
    data = interactive_toolchain_doctor_report(category=args.category)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_fallback(args: argparse.Namespace) -> int:
    data = interactive_fallback_report(tool=args.tool)
    if args.json:
        _print_json(data)
    else:
        _print_json(data)
    return 0 if data.get("status") in {"ok", "unknown_tool"} else 1


def _cmd_interactive_claim(args: argparse.Namespace) -> int:
    data = interactive_claim_challenge(
        args.contest_id,
        agent=args.agent,
        challenge=args.challenge,
        allow_duplicate=args.allow_duplicate,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_next(args: argparse.Namespace) -> int:
    data = interactive_next_challenge(
        args.contest_id,
        agent=args.agent,
        category=args.category,
        allow_duplicate=args.allow_duplicate,
        dry_run=args.dry_run,
        refresh=args.refresh,
        profile=args.profile,
        pull_solved=args.pull_solved,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_target_pack(args: argparse.Namespace) -> int:
    data = interactive_target_pack(args.contest_id, challenge_id=args.challenge_id, agent=args.agent)
    if args.json:
        _print_json(data)
    else:
        if data.get("status") == "ok":
            path = Path(str(data.get("target_pack_path") or "").replace("~", str(Path.home()), 1))
            print(redact_text(path.read_text(encoding="utf-8", errors="replace")))
        else:
            _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_triage(args: argparse.Namespace) -> int:
    data = interactive_triage_challenge(
        args.contest_id,
        challenge_id=args.challenge_id,
        agent=args.agent,
        category=args.category,
    )
    if args.json:
        _print_json(data)
    else:
        if data.get("status") == "ok":
            path = Path(str(data.get("triage_summary_path") or "").replace("~", str(Path.home()), 1))
            print(redact_text(path.read_text(encoding="utf-8", errors="replace")))
        else:
            _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_starter(args: argparse.Namespace) -> int:
    data = interactive_starter_challenge(args.contest_id, challenge_id=args.challenge_id, category=args.category)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_prepare_target(args: argparse.Namespace) -> int:
    data = interactive_prepare_target(
        args.contest_id,
        agent=args.agent,
        challenge_id=args.challenge_id,
        refresh=args.refresh,
        profile=args.profile,
        pull_solved=args.pull_solved,
    )
    _print_json(data)
    return 0 if data.get("status") == "ok" or data.get("no_useful_work") else 1


def _cmd_interactive_run_attempt(args: argparse.Namespace) -> int:
    data = interactive_run_attempt(
        args.contest_id,
        challenge_id=args.challenge_id,
        agent=args.agent,
        command=args.command,
        script=args.script,
        timeout=args.timeout,
    )
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_service_config(args: argparse.Namespace) -> int:
    data = interactive_service_config(
        args.contest_id,
        challenge_id=args.challenge_id,
        host=args.host,
        port=args.port,
        tls=args.tls,
        plain=args.plain,
        token_source=args.token_source,
        token_file=args.token_file,
        token_env=args.token_env,
        pow_helper=args.pow_helper,
    )
    _print_local_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_service_probe(args: argparse.Namespace) -> int:
    data = interactive_service_probe(args.contest_id, challenge_id=args.challenge_id, timeout=args.timeout)
    _print_local_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_service_attempt(args: argparse.Namespace) -> int:
    data = interactive_service_attempt(
        args.contest_id,
        challenge_id=args.challenge_id,
        script=args.script,
        payload_file=args.payload_file,
        timeout=args.timeout,
    )
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_service_status(args: argparse.Namespace) -> int:
    data = interactive_service_status(args.contest_id, challenge_id=args.challenge_id)
    _print_local_json(data)
    return 0 if data.get("status") in {"ok", "unconfigured"} else 1


def _cmd_interactive_web_config(args: argparse.Namespace) -> int:
    data = interactive_web_config(
        args.contest_id,
        challenge_id=args.challenge_id,
        base_url=args.base_url,
        auth_source=args.auth_source,
        cookie_file=args.cookie_file,
        header_file=args.header_file,
        storage_state=args.storage_state,
        auth_env=args.auth_env,
    )
    _print_local_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_web_probe(args: argparse.Namespace) -> int:
    data = interactive_web_probe(args.contest_id, challenge_id=args.challenge_id, timeout=args.timeout)
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_browser_probe(args: argparse.Namespace) -> int:
    data = interactive_browser_probe(args.contest_id, challenge_id=args.challenge_id, timeout=args.timeout)
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_web_attempt(args: argparse.Namespace) -> int:
    data = interactive_web_attempt(
        args.contest_id,
        challenge_id=args.challenge_id,
        script=args.script,
        request_json=args.request_json,
        timeout=args.timeout,
    )
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_browser_attempt(args: argparse.Namespace) -> int:
    data = interactive_browser_attempt(
        args.contest_id,
        challenge_id=args.challenge_id,
        script=args.script,
        timeout=args.timeout,
    )
    _print_local_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_interactive_web_status(args: argparse.Namespace) -> int:
    data = interactive_web_status(args.contest_id, challenge_id=args.challenge_id)
    _print_local_json(data)
    return 0 if data.get("status") in {"ok", "unconfigured"} else 1


def _cmd_interactive_candidates(args: argparse.Namespace) -> int:
    data = interactive_list_candidates(args.contest_id, challenge_id=args.challenge_id)
    _print_local_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_verify_candidate(args: argparse.Namespace) -> int:
    data = interactive_verify_candidate(
        args.contest_id,
        challenge_id=args.challenge_id,
        candidate=args.candidate,
        candidate_file=args.candidate_file,
    )
    _print_local_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_solve_loop(args: argparse.Namespace) -> int:
    data = interactive_solve_loop(
        args.contest_id,
        agent=args.agent,
        challenge_id=args.challenge_id,
        max_attempts=args.max_attempts,
    )
    _print_local_json(data)
    return 0 if data.get("status") in {"solved", "stalled", "submit_planned"} else 1


def _cmd_interactive_brief(args: argparse.Namespace) -> int:
    data = interactive_challenge_brief(args.contest_id, challenge_id=args.challenge_id)
    if args.json:
        _print_json(data)
    else:
        if data.get("status") == "ok":
            print(redact_text(str(data.get("brief") or "")))
        else:
            _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_release(args: argparse.Namespace) -> int:
    _print_json(interactive_release_claim(args.contest_id, agent=args.agent, challenge=args.challenge, reason=args.reason))
    return 0


def _cmd_interactive_stalled(args: argparse.Namespace) -> int:
    data = interactive_mark_stalled(args.contest_id, agent=args.agent, challenge=args.challenge, reason=args.reason)
    _print_json(data)
    return 0 if data.get("status") != "not_found" else 1


def _cmd_interactive_external_solved(args: argparse.Namespace) -> int:
    data = interactive_mark_external_solved(args.contest_id, challenge=args.challenge)
    _print_json(data)
    return 0 if data.get("status") != "not_found" else 1


def _cmd_interactive_submit(args: argparse.Namespace) -> int:
    data = interactive_submit_flag_file(
        args.contest_id,
        challenge_id=args.challenge_id,
        flag_file=args.flag_file,
        confirm=args.confirm,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "rejected", "wrong", "incorrect"} else 1


def _cmd_interactive_upload_submit(args: argparse.Namespace) -> int:
    data = interactive_upload_submit(
        args.contest_id,
        challenge_id=args.challenge_id,
        artifact=args.artifact,
        confirm=args.confirm,
        endpoint=args.endpoint,
        field_name=args.field_name,
        method=args.method,
        status_url=args.status_url,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "rejected"} else 1


def _cmd_interactive_submit_config(args: argparse.Namespace) -> int:
    data = interactive_submit_config(
        args.contest_id,
        challenge_id=args.challenge_id,
        submit_type=args.submit_type,
        endpoint=args.endpoint,
        field_name=args.field_name,
        status_url=args.status_url,
    )
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_writeup(args: argparse.Namespace) -> int:
    data = interactive_writeup_challenge(
        args.contest_id,
        challenge_id=args.challenge_id,
        category=args.category,
        writeup_root=args.writeup_root,
        languages=args.languages,
        include_code=args.include_code,
    )
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_cleanup(args: argparse.Namespace) -> int:
    data = interactive_cleanup_challenge(args.contest_id, challenge_id=args.challenge_id, safe=args.safe)
    _print_json(data)
    return 0


def _cmd_interactive_memo(args: argparse.Namespace) -> int:
    data = interactive_memo_update(args.contest_id, challenge_id=args.challenge_id, kind=args.kind, append=args.append)
    _print_json(data)
    return 0


def _cmd_interactive_prompt(args: argparse.Namespace) -> int:
    data = interactive_solver_prompt(args.contest_id, agent=args.agent)
    if args.json:
        _print_json(data)
    else:
        print(redact_text(str(data.get("prompt") or "")))
    return 0


def _cmd_interactive_e2e_smoke(args: argparse.Namespace) -> int:
    data = interactive_e2e_smoke(
        args.contest_id,
        agents=args.agents,
        writeup_root=args.writeup_root,
        keep_runtime=args.keep_runtime,
    )
    if args.json:
        _print_json(data)
    else:
        _print_json({"status": data.get("status"), "contest_id": data.get("contest_id"), "checks": data.get("checks")})
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_metrics_record(args: argparse.Namespace) -> int:
    try:
        data_json = json.loads(args.data_json) if args.data_json else {}
    except json.JSONDecodeError as exc:
        _print_json({"status": "error", "reason": f"invalid_data_json:{exc.msg}"})
        return 2
    if not isinstance(data_json, dict):
        _print_json({"status": "error", "reason": "data_json_must_be_object"})
        return 2
    data = interactive_metrics_record(
        args.contest_id,
        agent=args.agent,
        event=args.event,
        challenge_id=args.challenge_id,
        data=data_json,
    )
    _print_json(data)
    return 0


def _cmd_interactive_metrics_summary(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_summary(args.contest_id))
    return 0


def _cmd_interactive_metrics_compare(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_compare(args.before, args.after))
    return 0


def _cmd_interactive_metrics_report(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_report(args.contest_id, output=args.output))
    return 0


def _cmd_interactive_metrics_publish_snapshot(args: argparse.Namespace) -> int:
    data = interactive_metrics_publish_snapshot(
        args.contest_id,
        output_root=args.output_root,
        contest_ended=args.contest_ended,
        confirm_public_safe=args.confirm_public_safe,
        allow_active_contest=args.allow_active_contest,
    )
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_interactive_metrics_dashboard(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_dashboard(output=args.output))
    return 0


def _cmd_interactive_metrics_baseline(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_baseline(name=args.name, output_dir=args.output_dir))
    return 0


def _cmd_interactive_metrics_compare_public(args: argparse.Namespace) -> int:
    _print_json(interactive_metrics_compare_public(args.before, args.after))
    return 0


def _cmd_contest_resources(args: argparse.Namespace) -> int:
    _print_json(list_contest_resources(args.contest_id, show_public_url=args.show_public_url))
    return 0


def _cmd_contest_cleanup_resources(args: argparse.Namespace) -> int:
    data = cleanup_contest_resources(args.contest_id)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_contest_worker_commands(args: argparse.Namespace) -> int:
    _print_json(worker_commands(args.contest_id))
    return 0


def _cmd_contest_start_workers(args: argparse.Namespace) -> int:
    data = supervisor_start_workers(
        args.contest_id,
        apply=args.apply,
        workers=args.workers,
        solver=args.solver,
        max_iterations=args.max_iterations,
        max_parallel_codex=args.max_parallel_codex,
        sleep_sec=args.sleep_sec,
        stop_when_empty=args.stop_when_empty,
        allow_codex_call=args.allow_codex_call,
        postsolve=args.postsolve,
        live_submit=args.live_submit,
        confirm_submit=args.confirm_submit,
        db_path=args.db,
    )
    _print_json(data)
    return 0 if data.get("status") not in {"blocked", "error"} else 1


def _cmd_contest_stop_workers(args: argparse.Namespace) -> int:
    _print_json(supervisor_stop_workers(args.contest_id))
    return 0


def _cmd_contest_restart_worker(args: argparse.Namespace) -> int:
    data = supervisor_restart_worker(args.contest_id, args.worker_id)
    _print_json(data)
    return 0 if data.get("status") != "blocked" else 1


def _cmd_contest_worker_status(args: argparse.Namespace) -> int:
    _print_json(supervisor_worker_status(args.contest_id))
    return 0


def _cmd_contest_worker_logs(args: argparse.Namespace) -> int:
    _print_json(supervisor_worker_logs(args.contest_id, args.worker_id, tail=args.tail))
    return 0


def _cmd_contest_supervisor_smoke(args: argparse.Namespace) -> int:
    data = run_supervisor_smoke(workers=args.workers, solver=args.solver, fake_ctfd=args.fake_ctfd, timeout_sec=args.timeout_sec)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _contest_preflight_summary(data: dict[str, Any]) -> dict[str, Any]:
    worker_homes = (((data.get("codex_worker_isolation") or {}).get("worker_homes")) or {})
    worker_auth = {
        worker_id: {
            "exists": bool(item.get("exists")),
            "auth_linked": bool(item.get("auth_linked")),
            "auth_json": {
                "exists": bool((item.get("auth_json") or {}).get("exists")),
                "is_symlink": bool((item.get("auth_json") or {}).get("is_symlink")),
            },
        }
        for worker_id, item in worker_homes.items()
        if isinstance(item, dict)
    }
    return {
        "risk": data.get("risk", {}),
        "paths": data.get("paths", {}),
        "browser_smoke": data.get("browser_smoke", {}),
        "callback_smoke": data.get("callback_smoke", {}),
        "docker": data.get("docker", {}),
        "ctf_pwn_image": data.get("ctf_pwn_image", {}),
        "docker_pool": data.get("docker_pool", {}),
        "worker_auth": worker_auth,
    }


def _contest_docker_warnings(preflight: dict[str, Any], status: dict[str, Any]) -> list[str]:
    warnings = list(status.get("docker_warnings") or [])
    docker = preflight.get("docker") if isinstance(preflight.get("docker"), dict) else {}
    image = preflight.get("ctf_pwn_image") if isinstance(preflight.get("ctf_pwn_image"), dict) else {}
    if not docker.get("reachable"):
        warnings.append("docker_unreachable")
    if image.get("checked") and not image.get("exists"):
        warnings.append("ctf_pwn_image_missing")
    return sorted(set(warnings))


def _storage_state_checks(profile_check: dict[str, Any]) -> list[dict[str, Any]]:
    auth = profile_check.get("auth") if isinstance(profile_check.get("auth"), dict) else {}
    entries: list[dict[str, Any]] = [auth]
    fallback = auth.get("fallback") if isinstance(auth, dict) else []
    if isinstance(fallback, list):
        entries.extend(item for item in fallback if isinstance(item, dict))
    checks: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("method") != "storage_state_file" or not entry.get("path"):
            continue
        summary = storage_state_summary(str(entry.get("path")))
        checks.append(
            {
                "source_role": entry.get("source_role", "primary"),
                "source_index": entry.get("source_index", 0),
                "summary": summary,
            }
        )
    return checks


def _display_cli_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _cmd_browser_smoke(args: argparse.Namespace) -> int:
    data = run_browser_smoke()
    if args.json:
        _print_json(data)
    else:
        _print_json({"ok": data["ok"], "reason": data["reason"]})
    return 0


def _cmd_callback_smoke(args: argparse.Namespace) -> int:
    data = run_callback_smoke()
    if args.json:
        _print_json(data)
    else:
        _print_json({"ok": data["ok"], "host": data["host"], "port": data["port"], "reason": data["reason"]})
    return 0


def _cmd_callback_start(args: argparse.Namespace) -> int:
    data = start_listener()
    if args.contest_id and data.get("status") == "running":
        data["contest_resource"] = record_callback_resource(
            args.contest_id,
            data,
            challenge_id=args.challenge_id,
            worker_id=args.worker_id,
        )
    _print_json(data if args.json else {"status": data.get("status"), "listener_id": data.get("listener_id"), "local_url": data.get("local_url")})
    return 0 if data.get("status") == "running" else 1


def _cmd_callback_status(args: argparse.Namespace) -> int:
    data = listener_status(args.listener_id)
    update_callback_resource(args.listener_id, contest_id=args.contest_id, listener=data)
    _print_json(data)
    return 0 if data.get("status") != "missing" else 1


def _cmd_callback_hits(args: argparse.Namespace) -> int:
    data = listener_hits(args.listener_id)
    if data.get("status") != "missing":
        update_callback_resource(args.listener_id, contest_id=args.contest_id)
    _print_json(data)
    return 0 if data.get("status") != "missing" else 1


def _cmd_callback_stop(args: argparse.Namespace) -> int:
    data = stop_listener(args.listener_id)
    update_callback_resource(args.listener_id, contest_id=args.contest_id, listener=data)
    _print_json(data)
    return 0 if data.get("status") != "missing" else 1


def _cmd_callback_public_smoke(args: argparse.Namespace) -> int:
    data = run_callback_public_smoke(
        provider=args.provider,
        allow_public=args.allow_public,
        contest_id=args.contest_id,
        challenge_id=args.challenge_id,
        worker_id=args.worker_id,
    )
    _print_public_json(data, show_public_url=args.show_public_url)
    return 0 if data.get("status") == "ok" else 1


def _cmd_tunnel_check(args: argparse.Namespace) -> int:
    data = check_tunnel_providers()
    if args.json:
        _print_json(data)
    else:
        _print_json({"recommendation": data["recommendation"], "public_provider_installed": data["public_provider_installed"]})
    return 0


def _cmd_tunnel_start(args: argparse.Namespace) -> int:
    listener = listener_status(args.listener_id)
    if listener.get("status") != "running":
        _print_json({"status": "error", "reason": "listener_not_running", "listener": listener})
        return 1
    data = start_tunnel(args.provider, int(listener["port"]), allow_public=args.allow_public)
    if args.contest_id and data.get("status") == "started":
        data["contest_resource"] = record_tunnel_resource(
            args.contest_id,
            data,
            challenge_id=args.challenge_id,
            worker_id=args.worker_id,
            listener_id=args.listener_id,
        )
    _print_public_json(data, show_public_url=args.show_public_url)
    return 0 if data.get("status") == "started" else 1


def _cmd_tunnel_status(args: argparse.Namespace) -> int:
    data = tunnel_status(args.tunnel_id)
    update_tunnel_resource(args.tunnel_id, contest_id=args.contest_id, tunnel=data)
    _print_public_json(data, show_public_url=args.show_public_url)
    return 0 if data.get("status") != "missing" else 1


def _cmd_tunnel_stop(args: argparse.Namespace) -> int:
    data = stop_tunnel(args.tunnel_id)
    update_tunnel_resource(args.tunnel_id, contest_id=args.contest_id, tunnel=data)
    _print_public_json(data, show_public_url=args.show_public_url)
    return 0 if data.get("status") != "missing" else 1


def _cmd_tunnel_logs(args: argparse.Namespace) -> int:
    data = tunnel_logs(args.tunnel_id, tail=args.tail)
    if args.json:
        _print_json(data)
    else:
        for line in data.get("lines") or []:
            print(redact_text(str(line)))
    return 0 if data.get("status") != "missing" else 1


def _cmd_web_payloads(args: argparse.Namespace) -> int:
    data = generate_callback_payloads(args.callback_url)
    _print_json(data)
    return 0


def _cmd_codex_init_worker(args: argparse.Namespace) -> int:
    _print_json(init_worker_home(args.worker_id, link_auth=args.link_auth))
    return 0


def _cmd_codex_init_workers(args: argparse.Namespace) -> int:
    _print_json({"workers": init_worker_range(args.count, link_auth=args.link_auth)})
    return 0


def _cmd_codex_status(args: argparse.Namespace) -> int:
    _print_json(status_worker_home(args.worker_id))
    return 0


def _cmd_codex_launch_cmd(args: argparse.Namespace) -> int:
    _print_json(launch_command(args.worker_id, args.mode))
    return 0


def _cmd_codex_doctor(args: argparse.Namespace) -> int:
    data = diagnose_codex_update_issue()
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "active_binary": data["active_binary"]["path"] if data["active_binary"] else "",
                "preferred_binary": data["preferred_binary"]["path"],
                "path_conflict": data["path_conflict"],
                "update_mismatch": data["update_mismatch"],
                "update_hint": data["update_hint"],
            }
        )
    return 0


def _cmd_codex_mcp_status(args: argparse.Namespace) -> int:
    data = diagnose_mcp_legacy()
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "global_servers": data["global_servers"],
                "worker_servers": data["worker_servers"],
                "legacy_dreamhack_present": data["legacy_dreamhack_present"],
                "canonical_ctf_solver_present": data["canonical_ctf_solver_present"],
                "reva_present": data["reva_present"],
                "recommended_action": data["recommended_action"],
            }
        )
    return 0


def _cmd_codex_preferred_bin(args: argparse.Namespace) -> int:
    data = choose_preferred_codex_binary()
    if args.json:
        _print_json(data)
    else:
        _print_json({"path": data["path"], "version": data["version"], "reason": data.get("selected_reason", "")})
    return 0


def _cmd_codex_set_model(args: argparse.Namespace) -> int:
    _print_json(set_worker_model(args.worker_id, args.model))
    return 0


def _cmd_codex_set_model_all(args: argparse.Namespace) -> int:
    _print_json(set_worker_model_all(args.model))
    return 0


def _cmd_codex_unset_model(args: argparse.Namespace) -> int:
    _print_json(unset_worker_model(args.worker_id))
    return 0


def _cmd_codex_unset_model_all(args: argparse.Namespace) -> int:
    _print_json(unset_worker_model_all())
    return 0


def _cmd_codex_model_status(args: argparse.Namespace) -> int:
    _print_json(codex_model_status(args.worker_id))
    return 0


def _cmd_codex_default_model_smoke(args: argparse.Namespace) -> int:
    data = default_model_smoke(args.worker_id)
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "ok": data["ok"],
                "observed_default_model": data["observed_default_model"],
                "codex_version": data["codex_version"],
                "model_flag_used": data["model_flag_used"],
                "response_ok": data["response_ok"],
            }
        )
    return 0


def _cmd_codex_notice_status(args: argparse.Namespace) -> int:
    _print_json(notice_status(args.worker_id))
    return 0


def _cmd_codex_clear_notices(args: argparse.Namespace) -> int:
    _print_json(clear_notices(args.worker_id, apply=args.apply))
    return 0


def _cmd_state_init(args: argparse.Namespace) -> int:
    path = init_db(args.db)
    _print_json({"status": "ok", "db_path": str(path)})
    return 0


def _cmd_state_status(args: argparse.Namespace) -> int:
    _print_json(list_status(args.db))
    return 0


def _cmd_worker_register(args: argparse.Namespace) -> int:
    _print_json(register_worker(args.worker_id, args.role, args.db))
    return 0


def _cmd_worker_once(args: argparse.Namespace) -> int:
    run_mode = _args_run_mode(args)
    data = run_worker_once(
        args.worker_id,
        mode="competition" if run_mode == "competition" else "dry-run",
        solver=args.solver,
        live_submit=args.live_submit,
        confirm_submit=args.confirm_submit,
        allow_codex_call=args.allow_codex_call,
        platform_config=args.platform_config,
        db_path=args.db,
        run_mode=run_mode,
        allow_real_solve_dry_run=args.allow_real_solve_dry_run,
        confirm_competition=args.confirm_competition,
        contest_id=args.contest_id,
        postsolve=args.postsolve,
    )
    if args.json:
        _print_json(_worker_once_public_payload(data))
    else:
        _print_json(
            {
                "status": data.get("status"),
                "challenge_id": data.get("challenge_id"),
                "solver": data.get("solver"),
                "run_mode": data.get("run_mode"),
                "reason": data.get("reason"),
            }
        )
    return 0


def _cmd_worker_loop(args: argparse.Namespace) -> int:
    run_mode = _args_run_mode(args)
    data = run_worker_forever(
        args.worker_id,
        mode="competition" if run_mode == "competition" else "dry-run",
        solver=args.solver,
        max_iterations=args.max_iterations,
        sleep_seconds=args.sleep_sec,
        stop_when_empty=args.stop_when_empty,
        live_submit=args.live_submit,
        confirm_submit=args.confirm_submit,
        allow_codex_call=args.allow_codex_call,
        platform_config=args.platform_config,
        db_path=args.db,
        contests_root=args.contests_root,
        state_root=args.state_root,
        run_mode=run_mode,
        allow_real_solve_dry_run=args.allow_real_solve_dry_run,
        confirm_competition=args.confirm_competition,
        contest_id=args.contest_id,
        postsolve=args.postsolve,
    )
    if args.json:
        _print_json(data)
    else:
        _print_json({"status": data.get("status"), "iterations": data.get("iterations")})
    return 0


def _cmd_worker_handoff(args: argparse.Namespace) -> int:
    from .paths import get_paths

    rows = read_handoffs(get_paths().state_root / "handoffs", args.challenge_id)
    payload = {"status": "ok", "challenge_id": args.challenge_id, "handoffs": rows}
    if args.json:
        _print_json(payload)
    else:
        _print_json({"status": payload["status"], "count": len(rows), "handoffs": rows})
    return 0


def _cmd_worker_status(args: argparse.Namespace) -> int:
    data = worker_status(db_path=args.db)
    if args.json:
        _print_json(data)
    else:
        queue = data.get("queue") or {}
        _print_json({"status": data.get("status"), "challenge_counts": queue.get("challenge_counts", {})})
    return 0


def _cmd_worker_local_e2e(args: argparse.Namespace) -> int:
    decision = check_action_allowed(_args_run_mode(args), "fake_local_e2e", "fake", flags=_mode_flags(args))
    if not decision.allowed:
        _print_json({"status": "blocked", **_mode_decision_payload(_args_run_mode(args), "fake_local_e2e", "fake", decision)})
        return 0
    data = run_local_e2e(
        workers=args.workers,
        solver=args.solver,
        fake_ctfd=args.fake_ctfd,
        max_parallel=args.max_parallel,
        db_path=args.db,
    )
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "status": data.get("status"),
                "expected_met": data.get("expected_met"),
                "total_challenges": data.get("total_challenges"),
                "solved": data.get("solved"),
                "stalled": data.get("stalled"),
                "duplicate_claims": data.get("duplicate_claims"),
                "accepted_submissions": data.get("accepted_submissions"),
            }
        )
    return 0


def _cmd_worker_parallel_smoke(args: argparse.Namespace) -> int:
    data = run_parallel_smoke(
        workers=args.workers,
        solver=args.solver,
        max_parallel=args.max_parallel,
        db_path=args.db,
    )
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "status": data.get("status"),
                "expected_met": data.get("expected_met"),
                "total_challenges": data.get("total_challenges"),
                "solved": data.get("solved"),
                "stalled": data.get("stalled"),
                "max_parallel_observed": data.get("max_parallel_observed"),
            }
        )
    return 0


def _cmd_queue_add_manual(args: argparse.Namespace) -> int:
    _print_json(
        add_manual_challenge(
            args.challenge_id,
            args.name,
            args.category,
            contest_id=args.contest_id,
            priority=args.priority,
            db_path=args.db,
        )
    )
    return 0


def _cmd_queue_next(args: argparse.Namespace) -> int:
    item = claim_next_challenge(args.worker_id, args.db)
    _print_json({"status": "empty"} if item is None else {"status": "claimed", "challenge": item})
    return 0


def _cmd_queue_release(args: argparse.Namespace) -> int:
    _print_json(release_claim(args.worker_id, args.challenge_id, args.state, args.reason, args.db))
    return 0


def _cmd_docker_start(args: argparse.Namespace) -> int:
    _print_json(start_persistent_container(args.worker_id, args.workspace, dry_run=args.dry_run))
    return 0


def _cmd_docker_stop(args: argparse.Namespace) -> int:
    _print_json(stop_container(args.worker_id, dry_run=args.dry_run))
    return 0


def _cmd_docker_pool_start(args: argparse.Namespace) -> int:
    data = start_pool(args.contest_id, args.workers, image=args.image)
    _print_json(data)
    return 0 if data.get("status") in {"ok", "skipped"} else 1


def _cmd_docker_pool_status(args: argparse.Namespace) -> int:
    _print_json(pool_status(args.contest_id))
    return 0


def _cmd_docker_pool_exec(args: argparse.Namespace) -> int:
    data = exec_in_container(args.contest_id, args.worker_id, args.command, timeout=args.timeout)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_docker_pool_stop(args: argparse.Namespace) -> int:
    data = cleanup_containers(args.contest_id)
    _print_json(data)
    return 0 if data.get("status") in {"ok", "skipped"} else 1


def _cmd_docker_pool_smoke(args: argparse.Namespace) -> int:
    data = pool_smoke(args.contest_id, args.workers, image=args.image)
    _print_json(data)
    return 0 if data.get("status") in {"ok", "skipped"} else 1


def _cmd_docker_benchmark(args: argparse.Namespace) -> int:
    data = docker_benchmark(image=args.image)
    _print_json(data)
    return 0 if data.get("status") in {"ok", "partial", "skipped"} else 1


def _cmd_auth_check(args: argparse.Namespace) -> int:
    _print_json(load_auth_metadata(args.config))
    return 0


def _cmd_auth_capture_storage(args: argparse.Namespace) -> int:
    auth = load_auth_metadata(args.config)
    mode = _args_run_mode(args)
    platform_meta = {"name": "", "base_url": ""}
    try:
        config_meta = load_config_metadata(args.config)
        platform_meta = dict(config_meta.get("data") or {}) if config_meta.get("exists") else platform_meta
    except Exception:
        platform_meta = {"name": "", "base_url": ""}
    target_kind = target_kind_for_platform(platform_meta)
    decision = check_action_allowed(mode, "browser_login", target_kind, flags=_mode_flags(args), policy=platform_meta.get("policy") if isinstance(platform_meta, dict) else {})
    if args.live and not decision.allowed:
        _print_json(
            {
                "status": "blocked",
                "reason": decision.reason,
                "auth_method": auth.get("method"),
                **_mode_decision_payload(mode, "browser_login", target_kind, decision),
            }
        )
        return 0
    _print_json(
        capture_storage_state(
            args.config,
            args.output,
            live=args.live,
            headed=args.headed,
            timeout_sec=args.timeout_sec,
        )
    )
    return 0


def _cmd_auth_storage_check(args: argparse.Namespace) -> int:
    _print_json(storage_state_summary(args.path))
    return 0


def _load_platform(config_path: str) -> Any:
    return load_platform_adapter(config_path)


def _cmd_platform_auth_check(args: argparse.Namespace) -> int:
    _print_json(load_auth_metadata(args.config))
    return 0


def _cmd_platform_profile_create(args: argparse.Namespace) -> int:
    _print_json(
        create_platform_profile(
            contest_id=args.contest_id,
            base_url=args.base_url,
            auth_method=args.auth_method,
            auth_path=args.auth_path,
            output_path=args.output,
            platform=args.platform,
            contest_url=args.contest_url,
        )
    )
    return 0


def _cmd_platform_profile_check(args: argparse.Namespace) -> int:
    _print_json(validate_platform_profile(args.config))
    return 0


def _cmd_platform_profile_set_auth(args: argparse.Namespace) -> int:
    _print_json(set_platform_profile_auth(args.config, args.method, args.path))
    return 0


def _cmd_platform_profile_add_auth_fallback(args: argparse.Namespace) -> int:
    _print_json(add_platform_profile_auth_fallback(args.config, args.method, args.path))
    return 0


def _cmd_platform_profile_show(args: argparse.Namespace) -> int:
    _print_json(show_platform_profile(args.config))
    return 0


def _cmd_platform_discover(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if args.live:
        mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_discover")
        if not decision.allowed:
            _print_json(action_to_dict(_blocked_platform_action("discover_challenges", True, mode, target_kind, decision)))
            return 0
    action = platform.discover_challenges(live=args.live)
    payload = action_to_dict(action)
    if args.save_state and action.status == "ok":
        save = upsert_platform_challenges(
            payload["details"].get("challenges", []),
            contest_id=platform.platform_name,
            db_path=args.db,
        )
        payload["details"]["state_save"] = save
    _print_json(payload)
    return 0


def _cmd_platform_get(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if args.live:
        mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_discover")
        if not decision.allowed:
            _print_json(
                action_to_dict(
                    _blocked_platform_action("get_challenge", True, mode, target_kind, decision, {"challenge_id": args.challenge_id})
                )
            )
            return 0
    _print_json(action_to_dict(platform.get_challenge(args.challenge_id, live=args.live)))
    return 0


def _cmd_platform_download(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if args.live:
        mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_download")
        if not decision.allowed:
            _print_json(
                action_to_dict(
                    _blocked_platform_action("download_attachments", True, mode, target_kind, decision, {"challenge_id": args.challenge_id})
                )
            )
            return 0
    _print_json(action_to_dict(platform.download_attachments(args.challenge_id, live=args.live)))
    return 0


def _cmd_platform_ingest(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if not args.live:
        _print_json(
            {
                "status": "planned",
                "platform_action": action_to_dict(platform.download_attachments(args.challenge_id, live=False)),
                "ingest": {
                    "challenge_id": args.challenge_id,
                    "contest_id": platform.platform_name,
                    "name": args.name,
                    "category": args.category,
                    "live_required": True,
                },
            }
        )
        return 0
    mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_ingest")
    if not decision.allowed:
        _print_json(
            {
                "status": "blocked",
                "challenge_id": args.challenge_id,
                **_mode_decision_payload(mode, "real_platform_ingest", target_kind, decision),
            }
        )
        return 0
    download_action = platform.download_attachments(args.challenge_id, live=True)
    if download_action.status not in {"ok", "no_attachments"}:
        _print_json(action_to_dict(download_action))
        return 0
    input_paths = [download_action.details["fs_dest_dir"]]
    ingest = ingest_challenge(
        args.challenge_id,
        input_paths=input_paths,
        contest_id=platform.platform_name,
        category=args.category,
        name=args.name,
        output_root=platform.downloads_root,
    )
    state_save = update_challenge_ingested(args.challenge_id, ingest, db_path=args.db)
    result = {
        "platform_action": action_to_dict(download_action),
        "ingest": ingest,
        "state_save": state_save,
    }
    _print_json(result)
    return 0


def _cmd_platform_generic_ingest(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if not args.live:
        _print_json(
            {
                "status": "planned",
                "platform_action": action_to_dict(platform.download_attachments(args.challenge_id, live=False)),
                "ingest": {
                    "challenge_id": args.challenge_id,
                    "contest_id": platform.platform_name,
                    "name": args.name,
                    "category": args.category,
                    "live_required": True,
                },
            }
        )
        return 0
    mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_ingest")
    if not decision.allowed:
        _print_json(
            {
                "status": "blocked",
                "challenge_id": args.challenge_id,
                **_mode_decision_payload(mode, "real_platform_ingest", target_kind, decision),
            }
        )
        return 0
    download_action = platform.download_attachments(args.challenge_id, live=True)
    download_payload = action_to_dict(download_action)
    if download_action.status != "ok":
        _print_json({"platform_action": download_payload, "ingest": {"status": "skipped", "reason": download_action.status}})
        return 0
    summary = download_payload.get("details", {}).get("summary") or {}
    ingest = ingest_challenge(
        args.challenge_id,
        input_paths=[download_payload["details"]["fs_dest_dir"]],
        contest_id=platform.platform_name,
        category=args.category or str(summary.get("category") or ""),
        name=args.name or str(summary.get("name") or args.challenge_id),
        output_root=platform.downloads_root,
    )
    state_save = update_challenge_ingested(args.challenge_id, ingest, db_path=args.db)
    _print_json({"platform_action": download_payload, "ingest": ingest, "state_save": state_save})
    return 0


def _cmd_platform_browser_discover(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if args.live:
        mode, target_kind, decision = _platform_mode_decision(args, platform, "real_platform_discover")
        if not decision.allowed:
            _print_json(action_to_dict(_blocked_platform_action("browser_discover", True, mode, target_kind, decision)))
            return 0
    browser_discover = getattr(platform, "browser_discover", None)
    if browser_discover is None:
        _print_json(
            action_to_dict(
                PlatformAction(
                    action="browser_discover",
                    live=args.live,
                    network=False,
                    status="blocked",
                    details={"reason": "browser_discover_supported_only_for_generic"},
                )
            )
        )
        return 0
    _print_json(action_to_dict(browser_discover(live=args.live)))
    return 0


def _cmd_platform_sync_challenges(args: argparse.Namespace) -> int:
    platform = _load_platform(args.config)
    if not args.live:
        _print_json(
            {
                "status": "planned",
                "live_required": True,
                "save_state": bool(args.save_state),
                "ingest_text": bool(args.ingest_text),
                "max_challenges": args.max_challenges,
                "max_detail_fetch": args.max_detail_fetch,
            }
        )
        return 0
    mode, target_kind, discover_decision = _platform_mode_decision(args, platform, "real_platform_discover")
    if not discover_decision.allowed:
        _print_json({"status": "blocked", **_mode_decision_payload(mode, "real_platform_discover", target_kind, discover_decision)})
        return 0
    if args.ingest_text:
        ingest_decision = check_action_allowed(
            mode,
            "real_platform_ingest",
            target_kind,
            flags=_mode_flags(args),
            policy=getattr(platform, "policy", {}),
        )
        if not ingest_decision.allowed:
            _print_json({"status": "blocked", **_mode_decision_payload(mode, "real_platform_ingest", target_kind, ingest_decision)})
            return 0
    text_candidates = getattr(platform, "text_ingest_candidates", None)
    if text_candidates is None:
        discover = platform.discover_challenges(live=True)
        challenges = action_to_dict(discover).get("details", {}).get("challenges", [])
        public_challenges = challenges
        internal_challenges = challenges
        source_status = discover.status
        warnings = []
    else:
        result = text_candidates(live=True, max_challenges=args.max_challenges, max_detail_fetch=args.max_detail_fetch)
        source_status = str(result.get("status") or "ok")
        internal_challenges = list(result.get("challenges") or [])
        public_challenges = list(result.get("public_challenges") or [])
        warnings = list(result.get("warnings") or [])
    if source_status not in {"ok", "partial"}:
        _print_json({"status": source_status, "challenge_count": 0, "state_save": None, "ingest": [], "warnings": warnings})
        return 0

    state_save = None
    if args.save_state:
        state_save = upsert_platform_challenges(public_challenges, contest_id=platform.platform_name, db_path=args.db)

    ingest_results: list[dict[str, Any]] = []
    if args.ingest_text:
        for challenge in internal_challenges[: args.max_challenges]:
            public = _public_sync_challenge(challenge)
            text = _challenge_text_for_ingest(challenge)
            if not text:
                ingest_results.append({**public, "ingest_status": "skipped", "reason": "detail_text_missing"})
                continue
            ingest = ingest_text_challenge(
                str(challenge.get("challenge_id") or ""),
                text=text,
                contest_id=platform.platform_name,
                category=str(challenge.get("category") or ""),
                name=str(challenge.get("name") or challenge.get("challenge_id") or ""),
                output_root=platform.downloads_root,
                points=_coerce_optional_int(challenge.get("points")),
                solves=_coerce_optional_int(challenge.get("solves")),
                hints=list(challenge.get("hints") or []),
                tags=list(challenge.get("tags") or []),
                links=list(challenge.get("_links_private") or challenge.get("links") or []),
                connection_info=str(challenge.get("connection_info") or ""),
                author=str(challenge.get("author") or ""),
                state=str(challenge.get("state") or ""),
                deadline=str(challenge.get("deadline") or ""),
            )
            if args.save_state:
                update_challenge_ingested(str(challenge.get("challenge_id") or ""), ingest, db_path=args.db)
            ingest_results.append(
                {
                    **public,
                    "ingest_status": ingest.get("status"),
                    "ingest_type": ingest.get("ingest_type"),
                    "brief_path": ingest.get("brief_path"),
                    "statement_bytes": ingest.get("statement_bytes"),
                }
            )
    _print_json(
        {
            "status": "ok",
            "challenge_count": len(public_challenges),
            "state_save": state_save,
            "ingest_text": bool(args.ingest_text),
            "ingest_attempted": len(ingest_results),
            "ingest_ready_count": sum(1 for item in ingest_results if item.get("ingest_status") == "ok"),
            "ingest": ingest_results,
            "warnings": sorted(set(warnings)),
        }
    )
    return 0


def _cmd_platform_live_readonly_smoke(args: argparse.Namespace) -> int:
    profile_check = validate_platform_profile(args.config)
    warnings = list(profile_check.get("warnings") or [])
    if profile_check.get("status") != "ok":
        _print_json(_live_readonly_result(status="invalid_profile", profile_check=profile_check, warnings=warnings))
        return 0

    platform = _load_platform(args.config)
    mode, target_kind, discover_decision = _platform_mode_decision(args, platform, "real_platform_discover")
    if not discover_decision.allowed:
        _print_json(
            _live_readonly_result(status="blocked", profile_check=profile_check, warnings=warnings)
            | _mode_decision_payload(mode, "real_platform_discover", target_kind, discover_decision)
        )
        return 0
    ingest_decision = check_action_allowed(
        mode,
        "real_platform_ingest",
        target_kind,
        flags=_mode_flags(args),
        policy=getattr(platform, "policy", {}),
    )
    allow_ingest_phase = ingest_decision.allowed
    discover = platform.discover_challenges(live=True)
    discover_payload = action_to_dict(discover)
    if discover.status != "ok":
        _print_json(
            _live_readonly_result(
                status=discover.status,
                profile_check=profile_check,
                warnings=warnings,
                discovered_count=discover_payload.get("details", {}).get("challenge_count", 0),
                discover_action=discover_payload,
            )
        )
        return 0

    challenges = list(discover_payload.get("details", {}).get("challenges") or [])
    state_saved = False
    if args.save_state:
        upsert_platform_challenges(challenges, contest_id=platform.platform_name, db_path=args.db)
        state_saved = True
    selected = _select_live_readonly_challenge(challenges)
    if selected is None:
        _print_json(
            _live_readonly_result(
                status="no_challenges",
                profile_check=profile_check,
                warnings=warnings,
                discovered_count=len(challenges),
                state_saved=state_saved,
            )
        )
        return 0

    challenge_id = str(selected.get("challenge_id") or "")
    detail = platform.get_challenge(challenge_id, live=True)
    detail_payload = action_to_dict(detail)
    detail_summary = detail_payload.get("details", {}).get("summary") if detail.status == "ok" else None
    selected_summary = detail_summary if isinstance(detail_summary, dict) else selected
    attachments = detail_payload.get("details", {}).get("attachments") if detail.status == "ok" else []
    attachment_count = len(attachments) if isinstance(attachments, list) else 0
    download_payload: dict[str, Any] | None = None
    ingest_result: dict[str, Any] | None = None
    downloaded_count = 0
    ingest_brief_path = None
    detail_text_found = bool(selected_summary.get("detail_text_found"))
    ingest_type = "none"

    if detail.status == "ok" and attachment_count > 0:
        if not allow_ingest_phase:
            warnings.append(ingest_decision.reason)
        elif platform.policy.get("allow_live_download"):
            download = platform.download_attachments(challenge_id, live=True)
            download_payload = action_to_dict(download)
            downloaded_count = int(download_payload.get("details", {}).get("download_count") or 0)
            if downloaded_count > 0 and download_payload.get("details", {}).get("fs_dest_dir"):
                ingest_result = ingest_challenge(
                    challenge_id,
                    input_paths=[download_payload["details"]["fs_dest_dir"]],
                    contest_id=platform.platform_name,
                    category=str(selected_summary.get("category") or ""),
                    name=str(selected_summary.get("name") or challenge_id),
                    output_root=platform.downloads_root,
                )
                ingest_brief_path = ingest_result.get("brief_path")
                ingest_type = "attachment"
                if args.save_state:
                    update_challenge_ingested(challenge_id, ingest_result, db_path=args.db)
                    state_saved = True
        else:
            warnings.append("live_download_not_allowed_by_policy")
    elif detail.status == "ok" and detail_text_found:
        get_text_detail = getattr(platform, "get_text_detail", None)
        if not allow_ingest_phase:
            warnings.append(ingest_decision.reason)
            get_text_detail = None
        if get_text_detail is not None:
            text_detail = get_text_detail(challenge_id, live=True)
            challenge_detail = text_detail.get("challenge") if isinstance(text_detail, dict) else None
            text = _challenge_text_for_ingest(challenge_detail or {})
            if text:
                ingest_result = ingest_text_challenge(
                    challenge_id,
                    text=text,
                    contest_id=platform.platform_name,
                    category=str(selected_summary.get("category") or ""),
                    name=str(selected_summary.get("name") or challenge_id),
                    output_root=platform.downloads_root,
                    points=_coerce_optional_int(selected_summary.get("points")),
                    solves=_coerce_optional_int(selected_summary.get("solves")),
                    hints=list((challenge_detail or {}).get("hints") or []),
                    tags=list((challenge_detail or {}).get("tags") or []),
                    links=list((challenge_detail or {}).get("_links_private") or (challenge_detail or {}).get("links") or []),
                    connection_info=str((challenge_detail or {}).get("connection_info") or ""),
                    author=str((challenge_detail or {}).get("author") or ""),
                    state=str((challenge_detail or {}).get("state") or ""),
                    deadline=str((challenge_detail or {}).get("deadline") or ""),
                )
                ingest_brief_path = ingest_result.get("brief_path")
                ingest_type = "text"
                if args.save_state:
                    update_challenge_ingested(challenge_id, ingest_result, db_path=args.db)
                    state_saved = True

    status = "ok"
    if detail.status != "ok":
        status = detail.status
    elif download_payload and str(download_payload.get("status")) not in {"ok", "no_attachments"}:
        status = str(download_payload.get("status"))

    _print_json(
        _live_readonly_result(
            status=status,
            profile_check=profile_check,
            warnings=warnings,
            discovered_count=len(challenges),
            selected=selected_summary,
            attachment_count=attachment_count,
            downloaded_count=downloaded_count,
            ingest_brief_path=ingest_brief_path,
            detail_text_found=detail_text_found,
            ingest_type=ingest_type,
            state_saved=state_saved,
            discover_action=discover_payload,
            detail_action=detail_payload,
            download_action=download_payload,
            ingest_result=ingest_result,
        )
    )
    return 0


def _select_live_readonly_challenge(challenges: list[dict[str, Any]]) -> dict[str, Any] | None:
    visible = [item for item in challenges if isinstance(item, dict) and item.get("challenge_id")]
    if not visible:
        return None
    for item in visible:
        if item.get("solved") is False:
            return item
    for item in visible:
        if item.get("has_files"):
            return item
    return visible[0]


def _live_readonly_result(
    *,
    status: str,
    profile_check: dict[str, Any],
    warnings: list[str],
    discovered_count: int = 0,
    selected: dict[str, Any] | None = None,
    attachment_count: int = 0,
    downloaded_count: int = 0,
    ingest_brief_path: str | None = None,
    detail_text_found: bool = False,
    ingest_type: str = "none",
    state_saved: bool = False,
    discover_action: dict[str, Any] | None = None,
    detail_action: dict[str, Any] | None = None,
    download_action: dict[str, Any] | None = None,
    ingest_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected = selected or {}
    result: dict[str, Any] = {
        "status": status,
        "auth_check": profile_check.get("auth"),
        "profile_status": profile_check.get("status"),
        "discovered_count": discovered_count,
        "selected_challenge_id": selected.get("challenge_id"),
        "selected_challenge_name": selected.get("name"),
        "selected_challenge_category": selected.get("category"),
        "selected_challenge_value": selected.get("points"),
        "selected_challenge_solves": selected.get("solves"),
        "attachment_count": attachment_count,
        "downloaded_count": downloaded_count,
        "detail_text_found": "yes" if detail_text_found else "no",
        "ingest_type": ingest_type,
        "ingest_brief_path": ingest_brief_path,
        "state_saved": "yes" if state_saved else "no",
        "warnings": sorted(set(warnings)),
    }
    if discover_action:
        result["discover_status"] = discover_action.get("status")
    if detail_action:
        result["detail_status"] = detail_action.get("status")
    if download_action:
        result["download_status"] = download_action.get("status")
        result["download_failure_count"] = download_action.get("details", {}).get("failure_count", 0)
    if ingest_result:
        result["ingest_status"] = ingest_result.get("status")
    if profile_check.get("errors"):
        result["profile_errors"] = profile_check.get("errors")
    return result


def _challenge_text_for_ingest(challenge: dict[str, Any]) -> str:
    if not isinstance(challenge, dict):
        return ""
    parts: list[str] = []
    statement = str(challenge.get("statement") or "").strip()
    if statement:
        parts.append(statement)
    hints = [str(item).strip() for item in challenge.get("hints") or [] if str(item).strip()]
    if hints:
        parts.append("Hints:\n" + "\n".join(f"- {item}" for item in hints))
    connection_info = str(challenge.get("connection_info") or "").strip()
    if connection_info:
        parts.append("Connection Info:\n" + connection_info)
    links = challenge.get("_links_private") or challenge.get("links") or []
    link_lines = []
    for link in links:
        if isinstance(link, dict) and link.get("url"):
            label = str(link.get("label") or "").strip()
            link_lines.append(f"- {label + ': ' if label else ''}{link.get('url')}")
        elif isinstance(link, str):
            link_lines.append(f"- {link}")
    if link_lines:
        parts.append("Links:\n" + "\n".join(link_lines))
    return redact_text("\n\n".join(parts).strip())


def _public_sync_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "challenge_id": str(challenge.get("challenge_id") or ""),
        "name": redact_text(str(challenge.get("name") or ""))[:200],
        "category": redact_text(str(challenge.get("category") or ""))[:120],
        "points": _coerce_optional_int(challenge.get("points")),
        "solves": _coerce_optional_int(challenge.get("solves")),
        "detail_text_found": bool(_challenge_text_for_ingest(challenge)),
        "attachment_count": len(challenge.get("_attachments_private") or []),
    }


def _coerce_optional_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _cmd_fake_ctfd_serve(args: argparse.Namespace) -> int:
    from .fake_ctfd import FakeCTFdServer

    server = FakeCTFdServer(port=args.port)
    if args.json:
        print(redact_text(json.dumps(server.public_info(), indent=2, sort_keys=True)), flush=True)
    else:
        _print_json({"status": "ok", "base_url": server.base_url, "challenge_id": server.public_info()["challenge_id"]})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.stop()
    return 0


def _cmd_fake_ctfd_smoke(args: argparse.Namespace) -> int:
    from .fake_ctfd import run_smoke

    data = run_smoke(port=args.port)
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "status": data.get("status"),
                "base_url": (data.get("server") or {}).get("base_url"),
                "challenge_id": (data.get("server") or {}).get("challenge_id"),
                "accepted_submit_status": data.get("accepted_submit_status"),
                "raw_leak_detected": data.get("raw_leak_detected"),
            }
        )
    return 0


def _default_submit_policy_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "submit_policy.yaml"


def _cmd_submit_detect(args: argparse.Namespace) -> int:
    policy = load_submit_policy()
    if args.flag_regex:
        policy["flag_regex"] = args.flag_regex
    candidates = detect_flag_candidates(args.text, flag_regex=args.flag_regex)
    _print_json(
        {
            "status": "ok",
            "count": len(candidates),
            "candidates": [submission_public_payload(item, context={"source": "detected_text"}, policy=policy) for item in candidates],
        }
    )
    return 0


def _cmd_submit_plan(args: argparse.Namespace) -> int:
    policy = load_submit_policy(args.policy or _default_submit_policy_path())
    previous = list_submissions(args.challenge_id, args.db)
    challenge_state = get_challenge_state(args.challenge_id, args.db)
    decision = should_submit(
        args.flag,
        policy,
        previous_submissions=previous,
        challenge_state=challenge_state,
        context={"source": "submit_plan"},
    )
    status = "planned" if decision["allowed"] else "blocked"
    record = record_submission_attempt(
        challenge_id=args.challenge_id,
        candidate=args.flag,
        status=status,
        confidence=str(decision.get("confidence") or ""),
        result_summary={"reason": decision["reason"], "candidate_preview": decision["candidate_preview"]},
        db_path=args.db,
    )
    _print_json({"status": status, "decision": decision, "record": record})
    return 0


def _cmd_submit_status(args: argparse.Namespace) -> int:
    _print_json(submission_status(args.challenge_id, args.db))
    return 0


def _platform_confirm_policy(platform: Any) -> bool:
    return bool(platform.policy.get("allow_submit_without_confirm") or platform.policy.get("allow_unconfirmed_submission"))


def _blocked_submit_action(challenge_id: str, reason: str, decision: dict[str, Any]) -> PlatformAction:
    return PlatformAction(
        action="submit_flag",
        live=True,
        network=False,
        status="blocked",
        details={
            "challenge_id": challenge_id,
            "reason": reason,
            "flag_hash": decision.get("flag_hash"),
            "candidate_preview": decision.get("candidate_preview"),
        },
    )


def _cmd_platform_submit(args: argparse.Namespace) -> int:
    policy = load_submit_policy(_default_submit_policy_path())
    previous = list_submissions(args.challenge_id, args.db)
    challenge_state = get_challenge_state(args.challenge_id, args.db)
    platform = _load_platform(args.config)
    mode, target_kind, mode_decision = _platform_mode_decision(args, platform, "live_submit")
    if not args.live:
        action = platform.submit_flag(args.challenge_id, args.flag, live=False, confirm=args.confirm)
        decision = should_submit(
            args.flag,
            policy,
            previous_submissions=previous,
            challenge_state=challenge_state,
            context={"source": "platform_submit_dry_run"},
        )
    elif not mode_decision.allowed:
        decision = should_submit(
            args.flag,
            policy,
            previous_submissions=previous,
            challenge_state=challenge_state,
            context={"source": "platform_submit_mode_blocked"},
        )
        action = _blocked_submit_action(args.challenge_id, mode_decision.reason, decision)
        action.details.update(
            {
                "run_mode": mode,
                "target_kind": target_kind,
                "required_flags": list(mode_decision.required_flags),
                "safe_summary": mode_decision.safe_summary,
            }
        )
    elif not platform.base_url or not platform.policy.get("allow_submission") or (not args.confirm and not _platform_confirm_policy(platform)):
        action = platform.submit_flag(args.challenge_id, args.flag, live=True, confirm=args.confirm)
        decision = should_submit(
            args.flag,
            policy,
            previous_submissions=previous,
            challenge_state=challenge_state,
            context={"source": "known_flag_source" if args.confirm else "platform_submit"},
        )
    else:
        decision = should_submit(
            args.flag,
            policy,
            previous_submissions=previous,
            challenge_state=challenge_state,
            context={"source": "known_flag_source"},
        )
        if decision["allowed"]:
            action = platform.submit_flag(args.challenge_id, args.flag, live=True, confirm=args.confirm)
        else:
            action = _blocked_submit_action(args.challenge_id, f"submit_guard_{decision['reason']}", decision)
    record_status = action.status if action.status in {"planned", "accepted", "rejected", "rate_limited"} else "blocked"
    record = record_submission_attempt(
        challenge_id=args.challenge_id,
        candidate=args.flag,
        status=record_status,
        confidence=str(decision.get("confidence") or ""),
        result_summary=action.details.get("result_summary_redacted") or {"reason": action.details.get("reason", action.status)},
        db_path=args.db,
    )
    if action.status == "accepted":
        update_challenge_solved(
            args.challenge_id,
            flag_hash=str(decision.get("flag_hash") or ""),
            confidence=str(decision.get("confidence") or ""),
            result_summary_redacted=action.details.get("result_summary_redacted", "accepted"),
            db_path=args.db,
        )
    _print_json({"status": action.status, "decision": decision, "platform_action": action_to_dict(action), "record": record})
    return 0


def _cmd_ingest_run(args: argparse.Namespace) -> int:
    _print_json(
        ingest_challenge(
            args.challenge_id,
            args.input,
            contest_id=args.contest_id,
            category=args.category,
            name=args.name,
            output_root=args.output_root,
        )
    )
    return 0


def _cmd_ingest_text(args: argparse.Namespace) -> int:
    _print_json(
        ingest_text_file(
            args.challenge_id,
            text_file=args.text_file,
            contest_id=args.contest_id,
            category=args.category,
            name=args.name,
            output_root=args.output_root,
        )
    )
    return 0


def _cmd_ingest_manifest(args: argparse.Namespace) -> int:
    data = manifest_path(args.path)
    if args.json:
        _print_json(data)
    else:
        _print_json({"file_count": data["file_count"], "summary": data["summary"], "git": data["git"]})
    return 0


def _cmd_ingest_scan(args: argparse.Namespace) -> int:
    data = scan_path(args.path)
    if args.json:
        _print_json(data)
    else:
        _print_json(
            {
                "likely_categories": data["likely_categories"],
                "recommended_first_actions": data["recommended_first_actions"],
                "interesting_files": data["interesting_files"][:10],
            }
        )
    return 0


def _cmd_ingest_brief(args: argparse.Namespace) -> int:
    brief = brief_for_challenge(args.challenge_id, contest_id=args.contest_id, output_root=args.output_root)
    print(redact_text(brief))
    return 0


def _cmd_solve_prompt(args: argparse.Namespace) -> int:
    data = build_prompt_for_challenge(args.challenge_id, db_path=args.db)
    if args.json:
        _print_json(data)
    else:
        print(redact_text(data["prompt"]))
    return 0


def _cmd_solve_parse(args: argparse.Namespace) -> int:
    data = public_solver_result(parse_solver_output(args.text))
    if args.json:
        _print_json(data)
    else:
        _print_json({"status": data["status"], "flag_candidates": data["flag_candidates"]})
    return 0


def _cmd_postsolve_generate(args: argparse.Namespace) -> int:
    data = generate_postsolve(args.contest_id, args.challenge_id, db_path=args.db)
    _print_json(data)
    return 0 if data.get("status") == "ok" else 1


def _cmd_postsolve_status(args: argparse.Namespace) -> int:
    _print_json(postsolve_status(args.contest_id, args.challenge_id, db_path=args.db))
    return 0


def _cmd_postsolve_archive(args: argparse.Namespace) -> int:
    _print_json(archive_postsolve(args.contest_id, args.challenge_id, db_path=args.db))
    return 0


def _cmd_postsolve_skill_candidates(args: argparse.Namespace) -> int:
    _print_json(skill_candidates_for_contest(args.contest_id, db_path=args.db))
    return 0


def _cmd_postsolve_batch(args: argparse.Namespace) -> int:
    _print_json(batch_generate_postsolve(args.contest_id, status=args.status, db_path=args.db))
    return 0


def _worker_once_public_payload(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "challenge_id": data.get("challenge_id"),
        "status": data.get("status"),
        "reason": data.get("reason"),
        "run_mode": data.get("run_mode"),
        "target_kind": data.get("target_kind"),
        "contest_id": data.get("contest_id"),
        "contest_armed": bool(data.get("contest_armed")),
        "mode_decision": data.get("mode_decision"),
        "solver_backend": data.get("solver_backend") or data.get("solver"),
        "flag_candidate_count": int(data.get("flag_candidate_count") or 0),
        "submit_plan_status": data.get("submit_plan_status") or "none",
        "state_after": data.get("state_after") or data.get("status"),
        "telemetry_event_count": int(data.get("telemetry_event_count") or 0),
        "handoff_written": bool(data.get("handoff_written")),
        "postsolve_status": (data.get("postsolve_summary") or {}).get("status") if isinstance(data.get("postsolve_summary"), dict) else None,
        "postsolve_dir": (data.get("postsolve_summary") or {}).get("postsolve_dir") if isinstance(data.get("postsolve_summary"), dict) else None,
    }


def _add_run_mode_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode",
        dest="run_mode",
        choices=list(RUN_MODES),
        default=argparse.SUPPRESS,
        help="execution guard mode; CLI value overrides CTF_RUN_MODE",
    )


def _add_real_readonly_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--allow-real-readonly", action="store_true", help="allow setup-mode real platform download/ingest")


def _add_confirm_competition_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--confirm-competition", action="store_true", help="explicitly confirm competition-mode destructive capability gates")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctfctl")
    parser.add_argument("--version", action="version", version=f"ctfctl {__version__}")
    parser.add_argument("--db", help="state DB path override")
    parser.add_argument("--mode", dest="run_mode", choices=list(RUN_MODES), default=None, help="execution guard mode")
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--json", action="store_true")
    preflight.add_argument("--timing", action="store_true", help="include optional docker one-shot timing")
    preflight.add_argument("--deep", action="store_true", help="run local browser smoke in addition to import checks")
    preflight.add_argument("--model-smoke", action="store_true", help="with --deep, observe the Codex CLI default model")
    preflight.set_defaults(func=_cmd_preflight)

    repo = sub.add_parser("repo")
    repo_sub = repo.add_subparsers(dest="repo_command", required=True)
    repo_public_check = repo_sub.add_parser("public-check")
    repo_public_check.add_argument("--json", action="store_true")
    repo_public_check.add_argument("--skip-preflight", action="store_true")
    repo_public_check.set_defaults(func=_cmd_repo_public_check)

    interactive = sub.add_parser("interactive")
    interactive_sub = interactive.add_subparsers(dest="interactive_command", required=True)
    interactive_init = interactive_sub.add_parser("init")
    interactive_init.add_argument("--contest-id", required=True)
    interactive_init.add_argument("--profile")
    interactive_init.add_argument("--writeup-root")
    interactive_init.add_argument("--agents", type=int)
    interactive_init.add_argument("--json", action="store_true")
    interactive_init.set_defaults(func=_cmd_interactive_init)
    interactive_sync = interactive_sub.add_parser("sync")
    interactive_sync.add_argument("--contest-id", required=True)
    interactive_sync.add_argument("--profile")
    interactive_sync.add_argument("--live", action="store_true")
    interactive_sync.add_argument("--download", action="store_true")
    interactive_sync.add_argument("--ingest", action="store_true")
    interactive_sync.add_argument("--pull-solved", action="store_true")
    interactive_sync.add_argument("--json", action="store_true")
    interactive_sync.set_defaults(func=_cmd_interactive_sync)
    interactive_board = interactive_sub.add_parser("board")
    interactive_board.add_argument("--contest-id", required=True)
    interactive_board.add_argument("--json", action="store_true")
    interactive_board.set_defaults(func=_cmd_interactive_board)
    interactive_status = interactive_sub.add_parser("status")
    interactive_status.add_argument("--contest-id", required=True)
    interactive_status.add_argument("--json", action="store_true")
    interactive_status.set_defaults(func=_cmd_interactive_status)
    interactive_capabilities = interactive_sub.add_parser("capabilities")
    interactive_capabilities.add_argument("--contest-id")
    interactive_capabilities.add_argument("--category")
    interactive_capabilities.add_argument("--refresh", action="store_true")
    interactive_capabilities.add_argument("--json", action="store_true")
    interactive_capabilities.set_defaults(func=_cmd_interactive_capabilities)
    interactive_toolchain = interactive_sub.add_parser("toolchain")
    interactive_toolchain_sub = interactive_toolchain.add_subparsers(dest="interactive_toolchain_command", required=True)
    interactive_toolchain_doctor = interactive_toolchain_sub.add_parser("doctor")
    interactive_toolchain_doctor.add_argument("--category")
    interactive_toolchain_doctor.add_argument("--json", action="store_true")
    interactive_toolchain_doctor.set_defaults(func=_cmd_interactive_toolchain_doctor)
    interactive_fallback = interactive_sub.add_parser("fallback")
    interactive_fallback.add_argument("--tool", required=True)
    interactive_fallback.add_argument("--json", action="store_true")
    interactive_fallback.set_defaults(func=_cmd_interactive_fallback)
    interactive_claim = interactive_sub.add_parser("claim")
    interactive_claim.add_argument("--contest-id", required=True)
    interactive_claim.add_argument("--agent", required=True)
    interactive_claim.add_argument("--challenge")
    interactive_claim.add_argument("--allow-duplicate", action="store_true")
    interactive_claim.add_argument("--json", action="store_true")
    interactive_claim.set_defaults(func=_cmd_interactive_claim)
    interactive_next = interactive_sub.add_parser("next")
    interactive_next.add_argument("--contest-id", required=True)
    interactive_next.add_argument("--agent", required=True)
    interactive_next.add_argument("--category")
    interactive_next.add_argument("--allow-duplicate", action="store_true")
    interactive_next.add_argument("--dry-run", action="store_true")
    interactive_next.add_argument("--refresh", action="store_true")
    interactive_next.add_argument("--profile")
    interactive_next.add_argument("--pull-solved", action="store_true")
    interactive_next.add_argument("--json", action="store_true")
    interactive_next.set_defaults(func=_cmd_interactive_next)
    interactive_target_pack = interactive_sub.add_parser("target-pack")
    interactive_target_pack.add_argument("--contest-id", required=True)
    interactive_target_pack.add_argument("--challenge-id", required=True)
    interactive_target_pack.add_argument("--agent")
    interactive_target_pack.add_argument("--json", action="store_true")
    interactive_target_pack.set_defaults(func=_cmd_interactive_target_pack)
    interactive_triage = interactive_sub.add_parser("triage")
    interactive_triage.add_argument("--contest-id", required=True)
    interactive_triage.add_argument("--challenge-id", required=True)
    interactive_triage.add_argument("--agent")
    interactive_triage.add_argument("--category")
    interactive_triage.add_argument("--json", action="store_true")
    interactive_triage.set_defaults(func=_cmd_interactive_triage)
    interactive_starter = interactive_sub.add_parser("starter")
    interactive_starter.add_argument("--contest-id", required=True)
    interactive_starter.add_argument("--challenge-id", required=True)
    interactive_starter.add_argument("--category")
    interactive_starter.add_argument("--json", action="store_true")
    interactive_starter.set_defaults(func=_cmd_interactive_starter)
    interactive_prepare_target = interactive_sub.add_parser("prepare-target")
    interactive_prepare_target.add_argument("--contest-id", required=True)
    interactive_prepare_target.add_argument("--agent", required=True)
    interactive_prepare_target.add_argument("--challenge-id")
    interactive_prepare_target.add_argument("--refresh", action="store_true")
    interactive_prepare_target.add_argument("--profile")
    interactive_prepare_target.add_argument("--pull-solved", action="store_true")
    interactive_prepare_target.add_argument("--json", action="store_true")
    interactive_prepare_target.set_defaults(func=_cmd_interactive_prepare_target)
    interactive_run_attempt = interactive_sub.add_parser("run-attempt")
    interactive_run_attempt.add_argument("--contest-id", required=True)
    interactive_run_attempt.add_argument("--challenge-id", required=True)
    interactive_run_attempt.add_argument("--agent")
    interactive_run_attempt.add_argument("--command")
    interactive_run_attempt.add_argument("--script")
    interactive_run_attempt.add_argument("--timeout", type=int, default=120)
    interactive_run_attempt.add_argument("--json", action="store_true")
    interactive_run_attempt.set_defaults(func=_cmd_interactive_run_attempt)
    interactive_service_config = interactive_sub.add_parser("service-config")
    interactive_service_config.add_argument("--contest-id", required=True)
    interactive_service_config.add_argument("--challenge-id", required=True)
    interactive_service_config.add_argument("--host")
    interactive_service_config.add_argument("--port", type=int)
    interactive_service_config.add_argument("--tls", action="store_true")
    interactive_service_config.add_argument("--plain", action="store_true")
    interactive_service_config.add_argument("--token-source", choices=["none", "profile", "file", "env"])
    interactive_service_config.add_argument("--token-file")
    interactive_service_config.add_argument("--token-env")
    interactive_service_config.add_argument("--pow-helper")
    interactive_service_config.add_argument("--json", action="store_true")
    interactive_service_config.set_defaults(func=_cmd_interactive_service_config)
    interactive_service_probe = interactive_sub.add_parser("service-probe")
    interactive_service_probe.add_argument("--contest-id", required=True)
    interactive_service_probe.add_argument("--challenge-id", required=True)
    interactive_service_probe.add_argument("--timeout", type=int, default=10)
    interactive_service_probe.add_argument("--json", action="store_true")
    interactive_service_probe.set_defaults(func=_cmd_interactive_service_probe)
    interactive_service_attempt = interactive_sub.add_parser("service-attempt")
    interactive_service_attempt.add_argument("--contest-id", required=True)
    interactive_service_attempt.add_argument("--challenge-id", required=True)
    interactive_service_attempt.add_argument("--script")
    interactive_service_attempt.add_argument("--payload-file")
    interactive_service_attempt.add_argument("--timeout", type=int, default=60)
    interactive_service_attempt.add_argument("--json", action="store_true")
    interactive_service_attempt.set_defaults(func=_cmd_interactive_service_attempt)
    interactive_service_status = interactive_sub.add_parser("service-status")
    interactive_service_status.add_argument("--contest-id", required=True)
    interactive_service_status.add_argument("--challenge-id", required=True)
    interactive_service_status.add_argument("--json", action="store_true")
    interactive_service_status.set_defaults(func=_cmd_interactive_service_status)
    interactive_web_config = interactive_sub.add_parser("web-config")
    interactive_web_config.add_argument("--contest-id", required=True)
    interactive_web_config.add_argument("--challenge-id", required=True)
    interactive_web_config.add_argument("--base-url")
    interactive_web_config.add_argument("--auth-source", choices=["none", "profile", "cookie-file", "header-file", "storage-state", "env"])
    interactive_web_config.add_argument("--cookie-file")
    interactive_web_config.add_argument("--header-file")
    interactive_web_config.add_argument("--storage-state")
    interactive_web_config.add_argument("--auth-env")
    interactive_web_config.add_argument("--json", action="store_true")
    interactive_web_config.set_defaults(func=_cmd_interactive_web_config)
    interactive_web_probe = interactive_sub.add_parser("web-probe")
    interactive_web_probe.add_argument("--contest-id", required=True)
    interactive_web_probe.add_argument("--challenge-id", required=True)
    interactive_web_probe.add_argument("--timeout", type=int, default=20)
    interactive_web_probe.add_argument("--json", action="store_true")
    interactive_web_probe.set_defaults(func=_cmd_interactive_web_probe)
    interactive_browser_probe = interactive_sub.add_parser("browser-probe")
    interactive_browser_probe.add_argument("--contest-id", required=True)
    interactive_browser_probe.add_argument("--challenge-id", required=True)
    interactive_browser_probe.add_argument("--timeout", type=int, default=30)
    interactive_browser_probe.add_argument("--json", action="store_true")
    interactive_browser_probe.set_defaults(func=_cmd_interactive_browser_probe)
    interactive_web_attempt = interactive_sub.add_parser("web-attempt")
    interactive_web_attempt.add_argument("--contest-id", required=True)
    interactive_web_attempt.add_argument("--challenge-id", required=True)
    interactive_web_attempt.add_argument("--script")
    interactive_web_attempt.add_argument("--request-json")
    interactive_web_attempt.add_argument("--timeout", type=int, default=60)
    interactive_web_attempt.add_argument("--json", action="store_true")
    interactive_web_attempt.set_defaults(func=_cmd_interactive_web_attempt)
    interactive_browser_attempt = interactive_sub.add_parser("browser-attempt")
    interactive_browser_attempt.add_argument("--contest-id", required=True)
    interactive_browser_attempt.add_argument("--challenge-id", required=True)
    interactive_browser_attempt.add_argument("--script", required=True)
    interactive_browser_attempt.add_argument("--timeout", type=int, default=90)
    interactive_browser_attempt.add_argument("--json", action="store_true")
    interactive_browser_attempt.set_defaults(func=_cmd_interactive_browser_attempt)
    interactive_web_status = interactive_sub.add_parser("web-status")
    interactive_web_status.add_argument("--contest-id", required=True)
    interactive_web_status.add_argument("--challenge-id", required=True)
    interactive_web_status.add_argument("--json", action="store_true")
    interactive_web_status.set_defaults(func=_cmd_interactive_web_status)
    interactive_candidates = interactive_sub.add_parser("candidates")
    interactive_candidates.add_argument("--contest-id", required=True)
    interactive_candidates.add_argument("--challenge-id", required=True)
    interactive_candidates.add_argument("--json", action="store_true")
    interactive_candidates.set_defaults(func=_cmd_interactive_candidates)
    interactive_verify_candidate = interactive_sub.add_parser("verify-candidate")
    interactive_verify_candidate.add_argument("--contest-id", required=True)
    interactive_verify_candidate.add_argument("--challenge-id", required=True)
    interactive_verify_candidate.add_argument("--candidate")
    interactive_verify_candidate.add_argument("--candidate-file")
    interactive_verify_candidate.add_argument("--json", action="store_true")
    interactive_verify_candidate.set_defaults(func=_cmd_interactive_verify_candidate)
    interactive_solve_loop = interactive_sub.add_parser("solve-loop")
    interactive_solve_loop.add_argument("--contest-id", required=True)
    interactive_solve_loop.add_argument("--agent", required=True)
    interactive_solve_loop.add_argument("--challenge-id")
    interactive_solve_loop.add_argument("--max-attempts", type=int, default=5)
    interactive_solve_loop.add_argument("--json", action="store_true")
    interactive_solve_loop.set_defaults(func=_cmd_interactive_solve_loop)
    interactive_brief = interactive_sub.add_parser("brief")
    interactive_brief.add_argument("--contest-id", required=True)
    interactive_brief.add_argument("--challenge-id", required=True)
    interactive_brief.add_argument("--json", action="store_true")
    interactive_brief.set_defaults(func=_cmd_interactive_brief)
    interactive_release = interactive_sub.add_parser("release")
    interactive_release.add_argument("--contest-id", required=True)
    interactive_release.add_argument("--agent", required=True)
    interactive_release.add_argument("--challenge")
    interactive_release.add_argument("--reason", required=True)
    interactive_release.add_argument("--json", action="store_true")
    interactive_release.set_defaults(func=_cmd_interactive_release)
    interactive_stalled = interactive_sub.add_parser("stalled")
    interactive_stalled.add_argument("--contest-id", required=True)
    interactive_stalled.add_argument("--agent", required=True)
    interactive_stalled.add_argument("--challenge", required=True)
    interactive_stalled.add_argument("--reason", required=True)
    interactive_stalled.add_argument("--json", action="store_true")
    interactive_stalled.set_defaults(func=_cmd_interactive_stalled)
    interactive_external_solved = interactive_sub.add_parser("external-solved")
    interactive_external_solved.add_argument("--contest-id", required=True)
    interactive_external_solved.add_argument("--challenge", required=True)
    interactive_external_solved.add_argument("--json", action="store_true")
    interactive_external_solved.set_defaults(func=_cmd_interactive_external_solved)
    interactive_submit = interactive_sub.add_parser("submit")
    interactive_submit.add_argument("--contest-id", required=True)
    interactive_submit.add_argument("--challenge-id", required=True)
    interactive_submit.add_argument("--flag-file", required=True)
    interactive_submit.add_argument("--confirm", action="store_true")
    interactive_submit.add_argument("--json", action="store_true")
    interactive_submit.set_defaults(func=_cmd_interactive_submit)
    interactive_upload_submit = interactive_sub.add_parser("upload-submit")
    interactive_upload_submit.add_argument("--contest-id", required=True)
    interactive_upload_submit.add_argument("--challenge-id", required=True)
    interactive_upload_submit.add_argument("--artifact", required=True)
    interactive_upload_submit.add_argument("--confirm", action="store_true")
    interactive_upload_submit.add_argument("--endpoint")
    interactive_upload_submit.add_argument("--field-name")
    interactive_upload_submit.add_argument("--method")
    interactive_upload_submit.add_argument("--status-url")
    interactive_upload_submit.add_argument("--json", action="store_true")
    interactive_upload_submit.set_defaults(func=_cmd_interactive_upload_submit)
    interactive_submit_config = interactive_sub.add_parser("submit-config")
    interactive_submit_config.add_argument("--contest-id", required=True)
    interactive_submit_config.add_argument("--challenge-id", required=True)
    interactive_submit_config.add_argument("--submit-type", choices=["flag", "artifact_upload", "manual"], required=True)
    interactive_submit_config.add_argument("--endpoint")
    interactive_submit_config.add_argument("--field-name")
    interactive_submit_config.add_argument("--status-url")
    interactive_submit_config.add_argument("--json", action="store_true")
    interactive_submit_config.set_defaults(func=_cmd_interactive_submit_config)
    interactive_writeup = interactive_sub.add_parser("writeup")
    interactive_writeup.add_argument("--contest-id", required=True)
    interactive_writeup.add_argument("--challenge-id", required=True)
    interactive_writeup.add_argument("--category", required=True)
    interactive_writeup.add_argument("--writeup-root")
    interactive_writeup.add_argument("--languages", default="ko,en")
    interactive_writeup.add_argument("--include-code", action="store_true")
    interactive_writeup.add_argument("--json", action="store_true")
    interactive_writeup.set_defaults(func=_cmd_interactive_writeup)
    interactive_cleanup = interactive_sub.add_parser("cleanup")
    interactive_cleanup.add_argument("--contest-id", required=True)
    interactive_cleanup.add_argument("--challenge-id", required=True)
    interactive_cleanup.add_argument("--safe", action="store_true")
    interactive_cleanup.add_argument("--json", action="store_true")
    interactive_cleanup.set_defaults(func=_cmd_interactive_cleanup)
    interactive_memo = interactive_sub.add_parser("memo")
    interactive_memo.add_argument("--contest-id", required=True)
    interactive_memo.add_argument("--challenge-id", required=True)
    interactive_memo.add_argument("--kind", choices=["memory", "evidence", "attempts", "next_steps", "operator_notes"], required=True)
    interactive_memo.add_argument("--append")
    interactive_memo.add_argument("--json", action="store_true")
    interactive_memo.set_defaults(func=_cmd_interactive_memo)
    interactive_prompt = interactive_sub.add_parser("prompt")
    interactive_prompt.add_argument("--contest-id", required=True)
    interactive_prompt.add_argument("--agent", required=True)
    interactive_prompt.add_argument("--json", action="store_true")
    interactive_prompt.set_defaults(func=_cmd_interactive_prompt)
    interactive_e2e = interactive_sub.add_parser("e2e-smoke")
    interactive_e2e.add_argument("--contest-id", required=True)
    interactive_e2e.add_argument("--agents", type=int, default=2)
    interactive_e2e.add_argument("--writeup-root")
    interactive_e2e.add_argument("--json", action="store_true")
    interactive_e2e.add_argument("--keep-runtime", action="store_true")
    interactive_e2e.set_defaults(func=_cmd_interactive_e2e_smoke)
    interactive_metrics = interactive_sub.add_parser("metrics")
    interactive_metrics_sub = interactive_metrics.add_subparsers(dest="interactive_metrics_command", required=True)
    interactive_metrics_record = interactive_metrics_sub.add_parser("record")
    interactive_metrics_record.add_argument("--contest-id", required=True)
    interactive_metrics_record.add_argument("--agent")
    interactive_metrics_record.add_argument("--event", required=True)
    interactive_metrics_record.add_argument("--challenge-id")
    interactive_metrics_record.add_argument("--data-json")
    interactive_metrics_record.add_argument("--json", action="store_true")
    interactive_metrics_record.set_defaults(func=_cmd_interactive_metrics_record)
    interactive_metrics_summary = interactive_metrics_sub.add_parser("summary")
    interactive_metrics_summary.add_argument("--contest-id", required=True)
    interactive_metrics_summary.add_argument("--json", action="store_true")
    interactive_metrics_summary.set_defaults(func=_cmd_interactive_metrics_summary)
    interactive_metrics_compare = interactive_metrics_sub.add_parser("compare")
    interactive_metrics_compare.add_argument("--before", required=True)
    interactive_metrics_compare.add_argument("--after", required=True)
    interactive_metrics_compare.add_argument("--json", action="store_true")
    interactive_metrics_compare.set_defaults(func=_cmd_interactive_metrics_compare)
    interactive_metrics_report = interactive_metrics_sub.add_parser("report")
    interactive_metrics_report.add_argument("--contest-id", required=True)
    interactive_metrics_report.add_argument("--output")
    interactive_metrics_report.add_argument("--json", action="store_true")
    interactive_metrics_report.set_defaults(func=_cmd_interactive_metrics_report)
    interactive_metrics_publish = interactive_metrics_sub.add_parser("publish-snapshot")
    interactive_metrics_publish.add_argument("--contest-id", required=True)
    interactive_metrics_publish.add_argument("--output-root")
    interactive_metrics_publish.add_argument("--contest-ended", action="store_true")
    interactive_metrics_publish.add_argument("--confirm-public-safe", action="store_true")
    interactive_metrics_publish.add_argument("--allow-active-contest", action="store_true")
    interactive_metrics_publish.add_argument("--json", action="store_true")
    interactive_metrics_publish.set_defaults(func=_cmd_interactive_metrics_publish_snapshot)
    interactive_metrics_dashboard = interactive_metrics_sub.add_parser("dashboard")
    interactive_metrics_dashboard.add_argument("--output")
    interactive_metrics_dashboard.add_argument("--json", action="store_true")
    interactive_metrics_dashboard.set_defaults(func=_cmd_interactive_metrics_dashboard)
    interactive_metrics_baseline = interactive_metrics_sub.add_parser("baseline")
    interactive_metrics_baseline.add_argument("--name")
    interactive_metrics_baseline.add_argument("--output-dir")
    interactive_metrics_baseline.add_argument("--json", action="store_true")
    interactive_metrics_baseline.set_defaults(func=_cmd_interactive_metrics_baseline)
    interactive_metrics_compare_public = interactive_metrics_sub.add_parser("compare-public")
    interactive_metrics_compare_public.add_argument("--before", required=True)
    interactive_metrics_compare_public.add_argument("--after", required=True)
    interactive_metrics_compare_public.add_argument("--json", action="store_true")
    interactive_metrics_compare_public.set_defaults(func=_cmd_interactive_metrics_compare_public)

    contest = sub.add_parser("contest")
    contest_sub = contest.add_subparsers(dest="contest_command", required=True)
    contest_prestart = contest_sub.add_parser("prestart")
    _add_run_mode_argument(contest_prestart)
    contest_prestart.add_argument("--contest-id", required=True)
    contest_prestart.add_argument("--profile", required=True)
    contest_prestart.add_argument("--live-readonly-check", action="store_true")
    contest_prestart.add_argument("--json", action="store_true")
    contest_prestart.set_defaults(func=_cmd_contest_prestart)
    contest_arm = contest_sub.add_parser("arm")
    contest_arm.add_argument("--contest-id", required=True)
    contest_arm.add_argument("--profile", required=True)
    contest_arm.add_argument("--confirm-competition", action="store_true")
    contest_arm_live_submit = contest_arm.add_mutually_exclusive_group()
    contest_arm_live_submit.add_argument("--allow-live-submit", dest="allow_live_submit", action="store_true", default=None)
    contest_arm_live_submit.add_argument("--no-live-submit", dest="allow_live_submit", action="store_false")
    contest_arm.add_argument("--allow-instance-start", action="store_true")
    contest_arm.add_argument("--max-workers", type=int, default=5)
    contest_arm.add_argument("--max-parallel-codex", type=int, default=2)
    contest_arm.add_argument("--json", action="store_true")
    contest_arm.set_defaults(func=_cmd_contest_arm)
    contest_disarm = contest_sub.add_parser("disarm")
    contest_disarm.add_argument("--contest-id", required=True)
    contest_disarm.add_argument("--stop-workers", action="store_true")
    contest_disarm.add_argument("--cleanup-resources", action="store_true")
    contest_disarm.add_argument("--stop-docker-pool", action="store_true")
    contest_disarm.add_argument("--json", action="store_true")
    contest_disarm.set_defaults(func=_cmd_contest_disarm)
    contest_status_cmd = contest_sub.add_parser("status")
    contest_status_cmd.add_argument("--contest-id", required=True)
    contest_status_cmd.add_argument("--json", action="store_true")
    contest_status_cmd.set_defaults(func=_cmd_contest_status)
    contest_full_rehearsal = contest_sub.add_parser("full-rehearsal")
    contest_full_rehearsal.add_argument("--contest-id", default="final-fake")
    contest_full_rehearsal.add_argument("--workers", type=int, default=5)
    contest_full_rehearsal.add_argument("--max-parallel-codex", type=int, default=2)
    contest_full_rehearsal.add_argument("--solver", choices=["mock", "codex"], default="mock")
    contest_full_rehearsal.add_argument("--allow-codex-call", action="store_true")
    contest_full_rehearsal.add_argument("--codex-smoke", action="store_true")
    contest_full_rehearsal.add_argument("--json", action="store_true")
    contest_full_rehearsal.set_defaults(func=_cmd_contest_full_rehearsal)
    contest_resources_cmd = contest_sub.add_parser("resources")
    contest_resources_cmd.add_argument("--contest-id", required=True)
    contest_resources_cmd.add_argument("--show-public-url", action="store_true")
    contest_resources_cmd.add_argument("--json", action="store_true")
    contest_resources_cmd.set_defaults(func=_cmd_contest_resources)
    contest_cleanup_resources = contest_sub.add_parser("cleanup-resources")
    contest_cleanup_resources.add_argument("--contest-id", required=True)
    contest_cleanup_resources.add_argument("--json", action="store_true")
    contest_cleanup_resources.set_defaults(func=_cmd_contest_cleanup_resources)
    contest_worker_commands = contest_sub.add_parser("worker-commands")
    contest_worker_commands.add_argument("--contest-id", required=True)
    contest_worker_commands.add_argument("--json", action="store_true")
    contest_worker_commands.set_defaults(func=_cmd_contest_worker_commands)
    contest_start_workers = contest_sub.add_parser("start-workers")
    contest_start_workers.add_argument("--contest-id", required=True)
    contest_start_workers.add_argument("--dry-run", action="store_true", default=True)
    contest_start_workers.add_argument("--apply", action="store_true")
    contest_start_workers.add_argument("--workers", type=int)
    contest_start_workers.add_argument("--solver", choices=["mock", "codex"], default="mock")
    contest_start_workers.add_argument("--max-iterations", type=int)
    contest_start_workers.add_argument("--max-parallel-codex", type=int)
    contest_start_workers.add_argument("--sleep-sec", type=float, default=2.0)
    contest_start_workers.add_argument("--stop-when-empty", action=argparse.BooleanOptionalAction, default=True)
    contest_start_workers.add_argument("--allow-codex-call", action="store_true")
    contest_start_workers_live_submit = contest_start_workers.add_mutually_exclusive_group()
    contest_start_workers_live_submit.add_argument("--live-submit", dest="live_submit", action="store_true", default=None)
    contest_start_workers_live_submit.add_argument("--no-live-submit", dest="live_submit", action="store_false")
    contest_start_workers.add_argument("--confirm-submit", action="store_true", default=None)
    contest_start_workers.add_argument("--postsolve", dest="postsolve", action="store_true", default=None)
    contest_start_workers.add_argument("--no-postsolve", dest="postsolve", action="store_false")
    contest_start_workers.add_argument("--json", action="store_true")
    contest_start_workers.set_defaults(func=_cmd_contest_start_workers)
    contest_stop_workers = contest_sub.add_parser("stop-workers")
    contest_stop_workers.add_argument("--contest-id", required=True)
    contest_stop_workers.add_argument("--json", action="store_true")
    contest_stop_workers.set_defaults(func=_cmd_contest_stop_workers)
    contest_restart_worker = contest_sub.add_parser("restart-worker")
    contest_restart_worker.add_argument("--contest-id", required=True)
    contest_restart_worker.add_argument("--worker-id", required=True)
    contest_restart_worker.add_argument("--json", action="store_true")
    contest_restart_worker.set_defaults(func=_cmd_contest_restart_worker)
    contest_worker_status = contest_sub.add_parser("worker-status")
    contest_worker_status.add_argument("--contest-id", required=True)
    contest_worker_status.add_argument("--json", action="store_true")
    contest_worker_status.set_defaults(func=_cmd_contest_worker_status)
    contest_worker_logs = contest_sub.add_parser("worker-logs")
    contest_worker_logs.add_argument("--contest-id", required=True)
    contest_worker_logs.add_argument("--worker-id", required=True)
    contest_worker_logs.add_argument("--tail", type=int, default=50)
    contest_worker_logs.add_argument("--json", action="store_true")
    contest_worker_logs.set_defaults(func=_cmd_contest_worker_logs)
    contest_supervisor_smoke = contest_sub.add_parser("supervisor-smoke")
    contest_supervisor_smoke.add_argument("--workers", type=int, default=3)
    contest_supervisor_smoke.add_argument("--solver", choices=["mock", "codex"], default="mock")
    contest_supervisor_smoke.add_argument("--fake-ctfd", action="store_true")
    contest_supervisor_smoke.add_argument("--timeout-sec", type=float, default=30.0)
    contest_supervisor_smoke.add_argument("--json", action="store_true")
    contest_supervisor_smoke.set_defaults(func=_cmd_contest_supervisor_smoke)

    browser = sub.add_parser("browser")
    browser_sub = browser.add_subparsers(dest="browser_command", required=True)
    browser_smoke = browser_sub.add_parser("smoke")
    browser_smoke.add_argument("--json", action="store_true")
    browser_smoke.set_defaults(func=_cmd_browser_smoke)

    callback = sub.add_parser("callback")
    callback_sub = callback.add_subparsers(dest="callback_command", required=True)
    callback_smoke = callback_sub.add_parser("smoke")
    callback_smoke.add_argument("--json", action="store_true")
    callback_smoke.set_defaults(func=_cmd_callback_smoke)
    callback_start = callback_sub.add_parser("start")
    callback_start.add_argument("--contest-id")
    callback_start.add_argument("--challenge-id")
    callback_start.add_argument("--worker-id")
    callback_start.add_argument("--json", action="store_true")
    callback_start.set_defaults(func=_cmd_callback_start)
    callback_status = callback_sub.add_parser("status")
    callback_status.add_argument("--listener-id", required=True)
    callback_status.add_argument("--contest-id")
    callback_status.add_argument("--json", action="store_true")
    callback_status.set_defaults(func=_cmd_callback_status)
    callback_hits = callback_sub.add_parser("hits")
    callback_hits.add_argument("--listener-id", required=True)
    callback_hits.add_argument("--contest-id")
    callback_hits.add_argument("--json", action="store_true")
    callback_hits.set_defaults(func=_cmd_callback_hits)
    callback_stop = callback_sub.add_parser("stop")
    callback_stop.add_argument("--listener-id", required=True)
    callback_stop.add_argument("--contest-id")
    callback_stop.add_argument("--json", action="store_true")
    callback_stop.set_defaults(func=_cmd_callback_stop)
    callback_public_smoke = callback_sub.add_parser("public-smoke")
    callback_public_smoke.add_argument("--provider", choices=["cloudflared", "bore", "auto"], default="auto")
    callback_public_smoke.add_argument("--allow-public", action="store_true")
    callback_public_smoke.add_argument("--contest-id")
    callback_public_smoke.add_argument("--challenge-id")
    callback_public_smoke.add_argument("--worker-id")
    callback_public_smoke.add_argument("--show-public-url", action="store_true")
    callback_public_smoke.add_argument("--json", action="store_true")
    callback_public_smoke.set_defaults(func=_cmd_callback_public_smoke)

    tunnel = sub.add_parser("tunnel")
    tunnel_sub = tunnel.add_subparsers(dest="tunnel_command", required=True)
    tunnel_check = tunnel_sub.add_parser("check")
    tunnel_check.add_argument("--json", action="store_true")
    tunnel_check.set_defaults(func=_cmd_tunnel_check)
    tunnel_start = tunnel_sub.add_parser("start")
    tunnel_start.add_argument("--listener-id", required=True)
    tunnel_start.add_argument("--contest-id")
    tunnel_start.add_argument("--challenge-id")
    tunnel_start.add_argument("--worker-id")
    tunnel_start.add_argument("--provider", choices=["cloudflared", "bore", "auto"], default="auto")
    tunnel_start.add_argument("--allow-public", action="store_true")
    tunnel_start.add_argument("--show-public-url", action="store_true")
    tunnel_start.add_argument("--json", action="store_true")
    tunnel_start.set_defaults(func=_cmd_tunnel_start)
    tunnel_status_cmd = tunnel_sub.add_parser("status")
    tunnel_status_cmd.add_argument("--tunnel-id", required=True)
    tunnel_status_cmd.add_argument("--contest-id")
    tunnel_status_cmd.add_argument("--show-public-url", action="store_true")
    tunnel_status_cmd.add_argument("--json", action="store_true")
    tunnel_status_cmd.set_defaults(func=_cmd_tunnel_status)
    tunnel_stop_cmd = tunnel_sub.add_parser("stop")
    tunnel_stop_cmd.add_argument("--tunnel-id", required=True)
    tunnel_stop_cmd.add_argument("--contest-id")
    tunnel_stop_cmd.add_argument("--show-public-url", action="store_true")
    tunnel_stop_cmd.add_argument("--json", action="store_true")
    tunnel_stop_cmd.set_defaults(func=_cmd_tunnel_stop)
    tunnel_logs_cmd = tunnel_sub.add_parser("logs")
    tunnel_logs_cmd.add_argument("--tunnel-id", required=True)
    tunnel_logs_cmd.add_argument("--tail", type=int, default=80)
    tunnel_logs_cmd.add_argument("--json", action="store_true")
    tunnel_logs_cmd.set_defaults(func=_cmd_tunnel_logs)

    web = sub.add_parser("web")
    web_sub = web.add_subparsers(dest="web_command", required=True)
    web_payloads = web_sub.add_parser("payloads")
    web_payloads.add_argument("--callback-url", required=True)
    web_payloads.add_argument("--json", action="store_true")
    web_payloads.set_defaults(func=_cmd_web_payloads)

    codex = sub.add_parser("codex")
    codex_sub = codex.add_subparsers(dest="codex_command", required=True)
    codex_init_worker = codex_sub.add_parser("init-worker")
    codex_init_worker.add_argument("--worker-id", required=True)
    codex_init_worker.add_argument("--link-auth", action="store_true")
    codex_init_worker.set_defaults(func=_cmd_codex_init_worker)
    codex_status = codex_sub.add_parser("status")
    codex_status.add_argument("--worker-id", required=True)
    codex_status.set_defaults(func=_cmd_codex_status)
    codex_init_workers = codex_sub.add_parser("init-workers")
    codex_init_workers.add_argument("--count", type=int, default=5)
    codex_init_workers.add_argument("--link-auth", action="store_true")
    codex_init_workers.set_defaults(func=_cmd_codex_init_workers)
    codex_launch_cmd = codex_sub.add_parser("launch-cmd")
    codex_launch_cmd.add_argument("--worker-id", required=True)
    codex_launch_cmd.add_argument("--mode", choices=["interactive", "exec"], required=True)
    codex_launch_cmd.set_defaults(func=_cmd_codex_launch_cmd)
    codex_doctor = codex_sub.add_parser("doctor")
    codex_doctor.add_argument("--json", action="store_true")
    codex_doctor.set_defaults(func=_cmd_codex_doctor)
    codex_mcp_status = codex_sub.add_parser("mcp-status")
    codex_mcp_status.add_argument("--json", action="store_true")
    codex_mcp_status.set_defaults(func=_cmd_codex_mcp_status)
    codex_preferred_bin = codex_sub.add_parser("preferred-bin")
    codex_preferred_bin.add_argument("--json", action="store_true")
    codex_preferred_bin.set_defaults(func=_cmd_codex_preferred_bin)
    codex_set_model = codex_sub.add_parser("set-model")
    codex_set_model.add_argument("--worker-id", required=True)
    codex_set_model.add_argument("--model", required=True)
    codex_set_model.set_defaults(func=_cmd_codex_set_model)
    codex_set_model_all = codex_sub.add_parser("set-model-all")
    codex_set_model_all.add_argument("--model", required=True)
    codex_set_model_all.set_defaults(func=_cmd_codex_set_model_all)
    codex_unset_model = codex_sub.add_parser("unset-model")
    codex_unset_model.add_argument("--worker-id", required=True)
    codex_unset_model.set_defaults(func=_cmd_codex_unset_model)
    codex_unset_model_all = codex_sub.add_parser("unset-model-all")
    codex_unset_model_all.set_defaults(func=_cmd_codex_unset_model_all)
    codex_model_status = codex_sub.add_parser("model-status")
    codex_model_status.add_argument("--worker-id")
    codex_model_status.add_argument("--json", action="store_true")
    codex_model_status.set_defaults(func=_cmd_codex_model_status)
    codex_default_model_smoke = codex_sub.add_parser("default-model-smoke")
    codex_default_model_smoke.add_argument("--worker-id", default="worker-1")
    codex_default_model_smoke.add_argument("--json", action="store_true")
    codex_default_model_smoke.set_defaults(func=_cmd_codex_default_model_smoke)
    codex_notice_status = codex_sub.add_parser("notice-status")
    codex_notice_status.add_argument("--worker-id")
    codex_notice_status.add_argument("--json", action="store_true")
    codex_notice_status.set_defaults(func=_cmd_codex_notice_status)
    codex_clear_notices = codex_sub.add_parser("clear-notices")
    codex_clear_notices.add_argument("--worker-id", required=True)
    codex_clear_notices.add_argument("--apply", action="store_true")
    codex_clear_notices.set_defaults(func=_cmd_codex_clear_notices)

    state = sub.add_parser("state")
    state_sub = state.add_subparsers(dest="state_command", required=True)
    state_init = state_sub.add_parser("init")
    state_init.set_defaults(func=_cmd_state_init)
    state_status = state_sub.add_parser("status")
    state_status.set_defaults(func=_cmd_state_status)

    worker = sub.add_parser("worker")
    worker_sub = worker.add_subparsers(dest="worker_command", required=True)
    worker_register = worker_sub.add_parser("register")
    worker_register.add_argument("--worker-id", required=True)
    worker_register.add_argument("--role", required=True)
    worker_register.set_defaults(func=_cmd_worker_register)
    worker_once = worker_sub.add_parser("once")
    _add_run_mode_argument(worker_once)
    worker_once.add_argument("--worker-id", required=True)
    worker_once.add_argument("--solver", choices=["mock", "codex"], default="mock")
    worker_once.add_argument("--allow-codex-call", action="store_true")
    worker_once.add_argument("--allow-real-solve-dry-run", action="store_true")
    worker_once.add_argument("--live-submit", action="store_true")
    worker_once.add_argument("--confirm-submit", action="store_true")
    _add_confirm_competition_flag(worker_once)
    worker_once.add_argument("--contest-id")
    worker_once.add_argument("--postsolve", dest="postsolve", action="store_true", default=None)
    worker_once.add_argument("--no-postsolve", dest="postsolve", action="store_false")
    worker_once.add_argument("--platform-config")
    worker_once.add_argument("--json", action="store_true")
    worker_once.set_defaults(func=_cmd_worker_once)
    worker_loop = worker_sub.add_parser("loop")
    _add_run_mode_argument(worker_loop)
    worker_loop.add_argument("--worker-id", required=True)
    worker_loop.add_argument("--solver", choices=["mock", "codex"], default="mock")
    worker_loop.add_argument("--allow-codex-call", action="store_true")
    worker_loop.add_argument("--allow-real-solve-dry-run", action="store_true")
    worker_loop.add_argument("--live-submit", action="store_true")
    worker_loop.add_argument("--confirm-submit", action="store_true")
    _add_confirm_competition_flag(worker_loop)
    worker_loop.add_argument("--contest-id")
    worker_loop.add_argument("--postsolve", dest="postsolve", action="store_true", default=None)
    worker_loop.add_argument("--no-postsolve", dest="postsolve", action="store_false")
    worker_loop.add_argument("--max-iterations", type=int, default=1)
    worker_loop.add_argument("--sleep-sec", type=float, default=2.0)
    worker_loop.add_argument("--stop-when-empty", action=argparse.BooleanOptionalAction, default=True)
    worker_loop.add_argument("--platform-config")
    worker_loop.add_argument("--contests-root")
    worker_loop.add_argument("--state-root")
    worker_loop.add_argument("--json", action="store_true")
    worker_loop.set_defaults(func=_cmd_worker_loop)
    worker_handoff = worker_sub.add_parser("handoff")
    worker_handoff.add_argument("--challenge-id", required=True)
    worker_handoff.add_argument("--json", action="store_true")
    worker_handoff.set_defaults(func=_cmd_worker_handoff)
    worker_status_cmd = worker_sub.add_parser("status")
    worker_status_cmd.add_argument("--json", action="store_true")
    worker_status_cmd.set_defaults(func=_cmd_worker_status)
    worker_local_e2e = worker_sub.add_parser("local-e2e")
    _add_run_mode_argument(worker_local_e2e)
    worker_local_e2e.add_argument("--workers", type=int, default=5)
    worker_local_e2e.add_argument("--solver", choices=["mock", "codex"], default="mock")
    worker_local_e2e.add_argument("--fake-ctfd", action="store_true")
    worker_local_e2e.add_argument("--max-parallel", type=int)
    worker_local_e2e.add_argument("--json", action="store_true")
    worker_local_e2e.set_defaults(func=_cmd_worker_local_e2e)
    worker_parallel_smoke = worker_sub.add_parser("parallel-smoke")
    worker_parallel_smoke.add_argument("--workers", type=int, default=5)
    worker_parallel_smoke.add_argument("--solver", choices=["mock", "codex"], default="mock")
    worker_parallel_smoke.add_argument("--max-parallel", type=int)
    worker_parallel_smoke.add_argument("--json", action="store_true")
    worker_parallel_smoke.set_defaults(func=_cmd_worker_parallel_smoke)

    queue = sub.add_parser("queue")
    queue_sub = queue.add_subparsers(dest="queue_command", required=True)
    add_manual = queue_sub.add_parser("add-manual")
    add_manual.add_argument("--challenge-id", required=True)
    add_manual.add_argument("--name", required=True)
    add_manual.add_argument("--category", required=True)
    add_manual.add_argument("--contest-id")
    add_manual.add_argument("--priority", type=int, default=100)
    add_manual.set_defaults(func=_cmd_queue_add_manual)
    next_cmd = queue_sub.add_parser("next")
    next_cmd.add_argument("--worker-id", required=True)
    next_cmd.set_defaults(func=_cmd_queue_next)
    release = queue_sub.add_parser("release")
    release.add_argument("--worker-id", required=True)
    release.add_argument("--challenge-id", required=True)
    release.add_argument("--state", choices=["queued", "stalled", "abandoned"], required=True)
    release.add_argument("--reason", default="")
    release.set_defaults(func=_cmd_queue_release)

    docker = sub.add_parser("docker")
    docker_sub = docker.add_subparsers(dest="docker_command", required=True)
    docker_start = docker_sub.add_parser("start")
    docker_start.add_argument("--worker-id", required=True)
    docker_start.add_argument("--workspace", required=True)
    docker_start.add_argument("--dry-run", action="store_true")
    docker_start.set_defaults(func=_cmd_docker_start)
    docker_stop = docker_sub.add_parser("stop")
    docker_stop.add_argument("--worker-id", required=True)
    docker_stop.add_argument("--dry-run", action="store_true")
    docker_stop.set_defaults(func=_cmd_docker_stop)
    docker_pool_start = docker_sub.add_parser("pool-start")
    docker_pool_start.add_argument("--contest-id", required=True)
    docker_pool_start.add_argument("--workers", type=int, required=True)
    docker_pool_start.add_argument("--image", default=DEFAULT_DOCKER_IMAGE)
    docker_pool_start.add_argument("--json", action="store_true")
    docker_pool_start.set_defaults(func=_cmd_docker_pool_start)
    docker_pool_status = docker_sub.add_parser("pool-status")
    docker_pool_status.add_argument("--contest-id", required=True)
    docker_pool_status.add_argument("--json", action="store_true")
    docker_pool_status.set_defaults(func=_cmd_docker_pool_status)
    docker_pool_exec = docker_sub.add_parser("pool-exec")
    docker_pool_exec.add_argument("--contest-id", required=True)
    docker_pool_exec.add_argument("--worker-id", required=True)
    docker_pool_exec.add_argument("--command", required=True)
    docker_pool_exec.add_argument("--timeout", type=float, default=120.0)
    docker_pool_exec.add_argument("--json", action="store_true")
    docker_pool_exec.set_defaults(func=_cmd_docker_pool_exec)
    docker_pool_stop = docker_sub.add_parser("pool-stop")
    docker_pool_stop.add_argument("--contest-id", required=True)
    docker_pool_stop.add_argument("--json", action="store_true")
    docker_pool_stop.set_defaults(func=_cmd_docker_pool_stop)
    docker_pool_smoke = docker_sub.add_parser("pool-smoke")
    docker_pool_smoke.add_argument("--contest-id", required=True)
    docker_pool_smoke.add_argument("--workers", type=int, required=True)
    docker_pool_smoke.add_argument("--image", default=DEFAULT_DOCKER_IMAGE)
    docker_pool_smoke.add_argument("--json", action="store_true")
    docker_pool_smoke.set_defaults(func=_cmd_docker_pool_smoke)
    docker_benchmark_cmd = docker_sub.add_parser("benchmark")
    docker_benchmark_cmd.add_argument("--image", default=DEFAULT_DOCKER_IMAGE)
    docker_benchmark_cmd.add_argument("--json", action="store_true")
    docker_benchmark_cmd.set_defaults(func=_cmd_docker_benchmark)

    auth = sub.add_parser("auth")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_check = auth_sub.add_parser("check")
    auth_check.add_argument("--config", required=True)
    auth_check.set_defaults(func=_cmd_auth_check)
    auth_capture_storage = auth_sub.add_parser("capture-storage")
    _add_run_mode_argument(auth_capture_storage)
    auth_capture_storage.add_argument("--config", required=True)
    auth_capture_storage.add_argument("--output", required=True)
    auth_capture_storage.add_argument("--live", action="store_true")
    auth_capture_storage.add_argument("--headed", action="store_true")
    auth_capture_storage.add_argument("--allow-auth-capture", action="store_true")
    _add_confirm_competition_flag(auth_capture_storage)
    auth_capture_storage.add_argument("--timeout-sec", type=int, default=300)
    auth_capture_storage.set_defaults(func=_cmd_auth_capture_storage)
    auth_storage_check = auth_sub.add_parser("storage-check")
    auth_storage_check.add_argument("--path", required=True)
    auth_storage_check.add_argument("--json", action="store_true")
    auth_storage_check.set_defaults(func=_cmd_auth_storage_check)

    platform = sub.add_parser("platform")
    platform_sub = platform.add_subparsers(dest="platform_command", required=True)
    platform_auth = platform_sub.add_parser("auth-check")
    platform_auth.add_argument("--config", required=True)
    platform_auth.set_defaults(func=_cmd_platform_auth_check)
    profile_create = platform_sub.add_parser("profile-create")
    profile_create.add_argument("--contest-id", required=True)
    profile_create.add_argument("--base-url", required=True)
    profile_create.add_argument("--contest-url")
    profile_create.add_argument("--platform", choices=["ctfd", "generic"], default="ctfd")
    profile_create.add_argument("--auth-method", required=True)
    profile_create.add_argument("--auth-path")
    profile_create.add_argument("--output", required=True)
    profile_create.add_argument("--json", action="store_true")
    profile_create.set_defaults(func=_cmd_platform_profile_create)
    profile_check = platform_sub.add_parser("profile-check")
    _add_run_mode_argument(profile_check)
    profile_check.add_argument("--config", required=True)
    profile_check.add_argument("--json", action="store_true")
    profile_check.set_defaults(func=_cmd_platform_profile_check)
    profile_set_auth = platform_sub.add_parser("profile-set-auth")
    profile_set_auth.add_argument("--config", required=True)
    profile_set_auth.add_argument("--method", required=True)
    profile_set_auth.add_argument("--path")
    profile_set_auth.set_defaults(func=_cmd_platform_profile_set_auth)
    profile_add_auth_fallback = platform_sub.add_parser("profile-add-auth-fallback")
    profile_add_auth_fallback.add_argument("--config", required=True)
    profile_add_auth_fallback.add_argument("--method", required=True)
    profile_add_auth_fallback.add_argument("--path")
    profile_add_auth_fallback.set_defaults(func=_cmd_platform_profile_add_auth_fallback)
    profile_show = platform_sub.add_parser("profile-show")
    profile_show.add_argument("--config", required=True)
    profile_show.add_argument("--json", action="store_true")
    profile_show.set_defaults(func=_cmd_platform_profile_show)
    live_readonly_smoke = platform_sub.add_parser("live-readonly-smoke")
    _add_run_mode_argument(live_readonly_smoke)
    live_readonly_smoke.add_argument("--config", required=True)
    live_readonly_smoke.add_argument("--json", action="store_true")
    live_readonly_smoke.add_argument("--save-state", action="store_true")
    _add_real_readonly_flag(live_readonly_smoke)
    live_readonly_smoke.set_defaults(func=_cmd_platform_live_readonly_smoke)
    discover = platform_sub.add_parser("discover")
    _add_run_mode_argument(discover)
    discover.add_argument("--config", required=True)
    discover.add_argument("--live", action="store_true")
    discover.add_argument("--json", action="store_true")
    discover.add_argument("--save-state", action="store_true")
    discover.set_defaults(func=_cmd_platform_discover)
    generic_discover = platform_sub.add_parser("generic-discover")
    _add_run_mode_argument(generic_discover)
    generic_discover.add_argument("--config", required=True)
    generic_discover.add_argument("--live", action="store_true")
    generic_discover.add_argument("--json", action="store_true")
    generic_discover.add_argument("--save-state", action="store_true")
    generic_discover.set_defaults(func=_cmd_platform_discover)
    browser_discover = platform_sub.add_parser("browser-discover")
    _add_run_mode_argument(browser_discover)
    browser_discover.add_argument("--config", required=True)
    browser_discover.add_argument("--live", action="store_true")
    browser_discover.add_argument("--json", action="store_true")
    browser_discover.set_defaults(func=_cmd_platform_browser_discover)
    sync_challenges = platform_sub.add_parser("sync-challenges")
    _add_run_mode_argument(sync_challenges)
    sync_challenges.add_argument("--config", required=True)
    sync_challenges.add_argument("--live", action="store_true")
    sync_challenges.add_argument("--save-state", action="store_true")
    sync_challenges.add_argument("--ingest-text", action="store_true")
    _add_real_readonly_flag(sync_challenges)
    sync_challenges.add_argument("--max-challenges", type=int, default=20)
    sync_challenges.add_argument("--max-detail-fetch", type=int, default=20)
    sync_challenges.add_argument("--json", action="store_true")
    sync_challenges.set_defaults(func=_cmd_platform_sync_challenges)
    get_cmd = platform_sub.add_parser("get")
    _add_run_mode_argument(get_cmd)
    get_cmd.add_argument("--config", required=True)
    get_cmd.add_argument("--challenge-id", required=True)
    get_cmd.add_argument("--live", action="store_true")
    get_cmd.add_argument("--json", action="store_true")
    get_cmd.set_defaults(func=_cmd_platform_get)
    download = platform_sub.add_parser("download")
    _add_run_mode_argument(download)
    download.add_argument("--config", required=True)
    download.add_argument("--challenge-id", required=True)
    download.add_argument("--live", action="store_true")
    _add_real_readonly_flag(download)
    download.add_argument("--json", action="store_true")
    download.set_defaults(func=_cmd_platform_download)
    generic_download = platform_sub.add_parser("generic-download")
    _add_run_mode_argument(generic_download)
    generic_download.add_argument("--config", required=True)
    generic_download.add_argument("--challenge-id", required=True)
    generic_download.add_argument("--live", action="store_true")
    _add_real_readonly_flag(generic_download)
    generic_download.add_argument("--json", action="store_true")
    generic_download.set_defaults(func=_cmd_platform_download)
    platform_ingest = platform_sub.add_parser("ingest")
    _add_run_mode_argument(platform_ingest)
    platform_ingest.add_argument("--config", required=True)
    platform_ingest.add_argument("--challenge-id", required=True)
    platform_ingest.add_argument("--name", required=True)
    platform_ingest.add_argument("--category", required=True)
    platform_ingest.add_argument("--live", action="store_true")
    _add_real_readonly_flag(platform_ingest)
    platform_ingest.add_argument("--json", action="store_true")
    platform_ingest.set_defaults(func=_cmd_platform_ingest)
    generic_ingest = platform_sub.add_parser("generic-ingest")
    _add_run_mode_argument(generic_ingest)
    generic_ingest.add_argument("--config", required=True)
    generic_ingest.add_argument("--challenge-id", required=True)
    generic_ingest.add_argument("--name")
    generic_ingest.add_argument("--category")
    generic_ingest.add_argument("--live", action="store_true")
    _add_real_readonly_flag(generic_ingest)
    generic_ingest.add_argument("--json", action="store_true")
    generic_ingest.set_defaults(func=_cmd_platform_generic_ingest)
    submit = platform_sub.add_parser("submit")
    _add_run_mode_argument(submit)
    submit.add_argument("--config", required=True)
    submit.add_argument("--contest-id")
    submit.add_argument("--challenge-id", required=True)
    submit.add_argument("--flag", required=True)
    submit.add_argument("--live", action="store_true")
    submit.add_argument("--confirm", action="store_true")
    _add_confirm_competition_flag(submit)
    submit.add_argument("--json", action="store_true")
    submit.set_defaults(func=_cmd_platform_submit)

    submit_ctl = sub.add_parser("submit")
    submit_sub = submit_ctl.add_subparsers(dest="submit_command", required=True)
    submit_detect = submit_sub.add_parser("detect")
    submit_detect.add_argument("--text", required=True)
    submit_detect.add_argument("--flag-regex")
    submit_detect.add_argument("--json", action="store_true")
    submit_detect.set_defaults(func=_cmd_submit_detect)
    submit_plan = submit_sub.add_parser("plan")
    submit_plan.add_argument("--challenge-id", required=True)
    submit_plan.add_argument("--flag", required=True)
    submit_plan.add_argument("--policy")
    submit_plan.add_argument("--json", action="store_true")
    submit_plan.set_defaults(func=_cmd_submit_plan)
    submit_status_cmd = submit_sub.add_parser("status")
    submit_status_cmd.add_argument("--challenge-id", required=True)
    submit_status_cmd.add_argument("--json", action="store_true")
    submit_status_cmd.set_defaults(func=_cmd_submit_status)

    solve = sub.add_parser("solve")
    solve_sub = solve.add_subparsers(dest="solve_command", required=True)
    solve_prompt = solve_sub.add_parser("prompt")
    solve_prompt.add_argument("--challenge-id", required=True)
    solve_prompt.add_argument("--json", action="store_true")
    solve_prompt.set_defaults(func=_cmd_solve_prompt)
    solve_parse = solve_sub.add_parser("parse")
    solve_parse.add_argument("--text", required=True)
    solve_parse.add_argument("--json", action="store_true")
    solve_parse.set_defaults(func=_cmd_solve_parse)

    postsolve = sub.add_parser("postsolve")
    postsolve_sub = postsolve.add_subparsers(dest="postsolve_command", required=True)
    postsolve_generate = postsolve_sub.add_parser("generate")
    postsolve_generate.add_argument("--contest-id", required=True)
    postsolve_generate.add_argument("--challenge-id", required=True)
    postsolve_generate.add_argument("--json", action="store_true")
    postsolve_generate.set_defaults(func=_cmd_postsolve_generate)
    postsolve_status_cmd = postsolve_sub.add_parser("status")
    postsolve_status_cmd.add_argument("--contest-id", required=True)
    postsolve_status_cmd.add_argument("--challenge-id", required=True)
    postsolve_status_cmd.add_argument("--json", action="store_true")
    postsolve_status_cmd.set_defaults(func=_cmd_postsolve_status)
    postsolve_archive = postsolve_sub.add_parser("archive")
    postsolve_archive.add_argument("--contest-id", required=True)
    postsolve_archive.add_argument("--challenge-id", required=True)
    postsolve_archive.add_argument("--json", action="store_true")
    postsolve_archive.set_defaults(func=_cmd_postsolve_archive)
    postsolve_skill = postsolve_sub.add_parser("skill-candidates")
    postsolve_skill.add_argument("--contest-id", required=True)
    postsolve_skill.add_argument("--json", action="store_true")
    postsolve_skill.set_defaults(func=_cmd_postsolve_skill_candidates)
    postsolve_batch = postsolve_sub.add_parser("batch")
    postsolve_batch.add_argument("--contest-id", required=True)
    postsolve_batch.add_argument("--status", default="solved")
    postsolve_batch.add_argument("--json", action="store_true")
    postsolve_batch.set_defaults(func=_cmd_postsolve_batch)

    ingest = sub.add_parser("ingest")
    ingest_sub = ingest.add_subparsers(dest="ingest_command", required=True)
    ingest_run = ingest_sub.add_parser("run")
    ingest_run.add_argument("--challenge-id", required=True)
    ingest_run.add_argument("--name")
    ingest_run.add_argument("--category")
    ingest_run.add_argument("--input", action="append", required=True)
    ingest_run.add_argument("--contest-id")
    ingest_run.add_argument("--output-root")
    ingest_run.set_defaults(func=_cmd_ingest_run)
    ingest_text = ingest_sub.add_parser("text")
    ingest_text.add_argument("--challenge-id", required=True)
    ingest_text.add_argument("--name", required=True)
    ingest_text.add_argument("--category", required=True)
    ingest_text.add_argument("--text-file", required=True)
    ingest_text.add_argument("--contest-id")
    ingest_text.add_argument("--output-root")
    ingest_text.set_defaults(func=_cmd_ingest_text)
    ingest_manifest = ingest_sub.add_parser("manifest")
    ingest_manifest.add_argument("--path", required=True)
    ingest_manifest.add_argument("--json", action="store_true")
    ingest_manifest.set_defaults(func=_cmd_ingest_manifest)
    ingest_scan = ingest_sub.add_parser("scan")
    ingest_scan.add_argument("--path", required=True)
    ingest_scan.add_argument("--json", action="store_true")
    ingest_scan.set_defaults(func=_cmd_ingest_scan)
    ingest_brief = ingest_sub.add_parser("brief")
    ingest_brief.add_argument("--challenge-id", required=True)
    ingest_brief.add_argument("--contest-id")
    ingest_brief.add_argument("--output-root")
    ingest_brief.set_defaults(func=_cmd_ingest_brief)

    fake_ctfd = sub.add_parser("fake-ctfd")
    fake_ctfd_sub = fake_ctfd.add_subparsers(dest="fake_ctfd_command", required=True)
    fake_serve = fake_ctfd_sub.add_parser("serve")
    fake_serve.add_argument("--port", type=int, default=0)
    fake_serve.add_argument("--json", action="store_true")
    fake_serve.set_defaults(func=_cmd_fake_ctfd_serve)
    fake_smoke = fake_ctfd_sub.add_parser("smoke")
    fake_smoke.add_argument("--port", type=int, default=0)
    fake_smoke.add_argument("--json", action="store_true")
    fake_smoke.set_defaults(func=_cmd_fake_ctfd_smoke)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001 - CLI must redact failures.
        _print_json({"status": "error", "error": redact_text(str(exc))})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
