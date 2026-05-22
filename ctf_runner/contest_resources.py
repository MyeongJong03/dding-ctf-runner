from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any, Mapping

from .callback_server import callback_root, listener_status, stop_listener
from .contest_control import contest_root
from .redact import redact_text
from .state import utc_now
from .tunnel_manager import stop_tunnel, tunnel_root, tunnel_status
from .url_safety import public_url_display, public_url_fields, redacted_public_url, strip_public_url_query


ACTIVE_STATUSES = {"active"}
OPEN_STATUSES = {"active", "stale"}


def resources_root(contest_id: str, *, state_root: str | Path | None = None) -> Path:
    return contest_root(contest_id, state_root=state_root) / "resources"


def resource_paths(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, str]:
    root = resources_root(contest_id, state_root=state_root)
    return {
        "resources_root": _display_path(root),
        "resources_json": _display_path(root / "resources.json"),
        "callbacks_jsonl": _display_path(root / "callbacks.jsonl"),
        "tunnels_jsonl": _display_path(root / "tunnels.jsonl"),
        "cleanup_events_jsonl": _display_path(root / "cleanup_events.jsonl"),
    }


def record_callback_resource(
    contest_id: str,
    listener: Mapping[str, Any],
    *,
    challenge_id: str | None = None,
    worker_id: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    listener_id = str(listener.get("listener_id") or "")
    record = {
        "resource_id": _safe_id(listener_id, "resource_id"),
        "contest_id": _safe_contest_id(contest_id),
        "challenge_id": _safe_optional_id(challenge_id),
        "worker_id": _safe_optional_id(worker_id),
        "type": "callback_listener",
        "provider": "local",
        "created_at": str(listener.get("started_at") or utc_now()),
        "closed_at": _closed_at_for_status(_callback_resource_status(listener), listener),
        "status": _callback_resource_status(listener),
        "local_url": _safe_local_url(str(listener.get("local_url") or "")),
        "public_url": "",
        "public_url_redacted": "",
        "runtime_path": _display_path(callback_root(listener_id, state_root=state_root)),
        "pid": _coerce_int(listener.get("pid")),
        "alive": bool(listener.get("alive")),
        "hit_count": _coerce_int(listener.get("hit_count")) or 0,
        "last_callback_hit_at": str(listener.get("last_hit_at") or ""),
    }
    return _upsert_resource(contest_id, record, state_root=state_root)


def record_tunnel_resource(
    contest_id: str,
    tunnel: Mapping[str, Any],
    *,
    challenge_id: str | None = None,
    worker_id: str | None = None,
    listener_id: str | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    tunnel_id = str(tunnel.get("tunnel_id") or "")
    raw_public_url = str(tunnel.get("public_url") or "")
    record = {
        "resource_id": _safe_id(tunnel_id, "resource_id"),
        "contest_id": _safe_contest_id(contest_id),
        "challenge_id": _safe_optional_id(challenge_id),
        "worker_id": _safe_optional_id(worker_id),
        "listener_id": _safe_optional_id(listener_id),
        "type": "public_tunnel",
        "provider": _safe_provider(str(tunnel.get("provider") or "manual")),
        "created_at": str(tunnel.get("started_at") or utc_now()),
        "closed_at": _closed_at_for_status(_tunnel_resource_status(tunnel), tunnel),
        "status": _tunnel_resource_status(tunnel),
        "local_url": _safe_local_url(str(tunnel.get("local_url") or "")),
        "public_url": redacted_public_url(raw_public_url),
        "public_url_redacted": redacted_public_url(raw_public_url),
        "runtime_path": _display_path(tunnel_root(tunnel_id, state_root=state_root)),
        "pid": _coerce_int(tunnel.get("pid")),
        "alive": bool(tunnel.get("alive")),
        "hit_count": 0,
    }
    return _upsert_resource(contest_id, record, state_root=state_root)


def update_callback_resource(
    listener_id: str,
    *,
    contest_id: str | None = None,
    listener: Mapping[str, Any] | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contexts = _resource_contexts(listener_id, contest_id=contest_id, resource_type="callback_listener", state_root=state_root)
    if not contexts:
        return {"status": "missing_resource", "resource_id": _safe_id(listener_id, "resource_id"), "updated": False}
    payload = dict(listener or listener_status(listener_id, state_root=state_root))
    updates = []
    for item in contexts:
        record = dict(item["record"])
        status = _callback_resource_status(payload)
        record.update(
            {
                "status": status,
                "closed_at": _closed_at_for_status(status, payload, previous=record.get("closed_at")),
                "local_url": _safe_local_url(str(payload.get("local_url") or record.get("local_url") or "")),
                "runtime_path": _display_path(callback_root(listener_id, state_root=state_root)),
                "pid": _coerce_int(payload.get("pid")),
                "alive": bool(payload.get("alive")),
                "hit_count": _coerce_int(payload.get("hit_count")) or 0,
                "last_callback_hit_at": str(payload.get("last_hit_at") or record.get("last_callback_hit_at") or ""),
            }
        )
        updates.append(_upsert_resource(item["contest_id"], record, state_root=state_root))
    return {"status": "ok", "resource_id": _safe_id(listener_id, "resource_id"), "updated": True, "resources": updates}


def update_tunnel_resource(
    tunnel_id: str,
    *,
    contest_id: str | None = None,
    tunnel: Mapping[str, Any] | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contexts = _resource_contexts(tunnel_id, contest_id=contest_id, resource_type="public_tunnel", state_root=state_root)
    if not contexts:
        return {"status": "missing_resource", "resource_id": _safe_id(tunnel_id, "resource_id"), "updated": False}
    payload = dict(tunnel or tunnel_status(tunnel_id, state_root=state_root))
    updates = []
    for item in contexts:
        record = dict(item["record"])
        status = _tunnel_resource_status(payload)
        raw_public_url = str(payload.get("public_url") or "")
        record.update(
            {
                "status": status,
                "closed_at": _closed_at_for_status(status, payload, previous=record.get("closed_at")),
                "provider": _safe_provider(str(payload.get("provider") or record.get("provider") or "manual")),
                "local_url": _safe_local_url(str(payload.get("local_url") or record.get("local_url") or "")),
                "public_url": redacted_public_url(raw_public_url or str(record.get("public_url") or "")),
                "public_url_redacted": redacted_public_url(raw_public_url or str(record.get("public_url_redacted") or "")),
                "runtime_path": _display_path(tunnel_root(tunnel_id, state_root=state_root)),
                "pid": _coerce_int(payload.get("pid")),
                "alive": bool(payload.get("alive")),
            }
        )
        updates.append(_upsert_resource(item["contest_id"], record, state_root=state_root))
    return {"status": "ok", "resource_id": _safe_id(tunnel_id, "resource_id"), "updated": True, "resources": updates}


def list_contest_resources(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
    refresh: bool = True,
    show_public_url: bool = False,
) -> dict[str, Any]:
    contest_id = _safe_contest_id(contest_id)
    raw_records = list(_load_resources(contest_id, state_root=state_root).values())
    full_public_urls: dict[str, str] = {}
    if refresh:
        refreshed = []
        for record in raw_records:
            record, raw_public_url = _refresh_record(record, state_root=state_root)
            if raw_public_url:
                full_public_urls[str(record.get("resource_id") or "")] = raw_public_url
            refreshed.append(record)
        raw_records = refreshed
    records = [_public_record(record, show_public_url=show_public_url, raw_public_url=full_public_urls.get(str(record.get("resource_id") or ""), "")) for record in raw_records]
    summary = _summary_from_records(records)
    return {
        "status": "ok",
        "contest_id": contest_id,
        **summary,
        "resources": records,
        "paths": resource_paths(contest_id, state_root=state_root),
    }


def contest_resource_summary(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    listed = list_contest_resources(contest_id, state_root=state_root, refresh=True, show_public_url=False)
    return {
        "active_callback_count": listed["active_callback_count"],
        "active_tunnel_count": listed["active_tunnel_count"],
        "stale_resource_count": listed["stale_resource_count"],
        "last_callback_hit_at": listed["last_callback_hit_at"],
        "resource_warnings": listed["resource_warnings"],
        "resource_count": listed["resource_count"],
    }


def cleanup_contest_resources(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    contest_id = _safe_contest_id(contest_id)
    listed = list_contest_resources(contest_id, state_root=state_root, refresh=True, show_public_url=False)
    events = []
    for record in listed["resources"]:
        if str(record.get("status") or "") not in OPEN_STATUSES:
            continue
        resource_id = str(record.get("resource_id") or "")
        resource_type = str(record.get("type") or "")
        previous_status = str(record.get("status") or "")
        if resource_type == "callback_listener":
            result = stop_listener(resource_id, state_root=state_root, timeout=min(timeout_sec, 5.0))
            update_callback_resource(resource_id, contest_id=contest_id, listener=result, state_root=state_root)
        elif resource_type == "public_tunnel":
            result = stop_tunnel(resource_id, state_root=state_root, timeout=timeout_sec)
            update_tunnel_resource(resource_id, contest_id=contest_id, tunnel=result, state_root=state_root)
        else:
            result = {"status": "skipped", "reason": "unknown_resource_type"}
        event = {
            "event": "cleanup_resource",
            "ts": utc_now(),
            "contest_id": contest_id,
            "resource_id": resource_id,
            "type": resource_type,
            "previous_status": previous_status,
            "cleanup_status": result.get("status") or "",
            "stopped": bool(result.get("stopped")),
            "reason": result.get("reason") or "",
        }
        _append_cleanup_event(contest_id, event, state_root=state_root)
        events.append(event)
    after = list_contest_resources(contest_id, state_root=state_root, refresh=True, show_public_url=False)
    status = "ok" if after["active_callback_count"] == 0 and after["active_tunnel_count"] == 0 else "partial"
    return {
        "status": status,
        "contest_id": contest_id,
        "cleaned_count": len(events),
        "events": events,
        "remaining": {
            "active_callback_count": after["active_callback_count"],
            "active_tunnel_count": after["active_tunnel_count"],
            "stale_resource_count": after["stale_resource_count"],
        },
        "paths": resource_paths(contest_id, state_root=state_root),
    }


def safe_public_url_payload(data: Any, *, show_public_url: bool = False) -> Any:
    if isinstance(data, dict):
        output: dict[str, Any] = {}
        for key, value in data.items():
            if key == "public_url":
                output.update(public_url_fields(str(value or ""), show_public_url=show_public_url))
            else:
                output[str(key)] = safe_public_url_payload(value, show_public_url=show_public_url)
        return output
    if isinstance(data, list):
        return [safe_public_url_payload(item, show_public_url=show_public_url) for item in data]
    return data


def _refresh_record(record: Mapping[str, Any], *, state_root: str | Path | None = None) -> tuple[dict[str, Any], str]:
    resource_id = str(record.get("resource_id") or "")
    resource_type = str(record.get("type") or "")
    contest_id = str(record.get("contest_id") or "")
    status = str(record.get("status") or "")
    if status not in OPEN_STATUSES:
        return dict(record), ""
    if resource_type == "callback_listener":
        payload = listener_status(resource_id, state_root=state_root)
        update = update_callback_resource(resource_id, contest_id=contest_id, listener=payload, state_root=state_root)
        records = update.get("resources") if isinstance(update, dict) else []
        return dict(records[0]) if records else dict(record), ""
    if resource_type == "public_tunnel":
        payload = tunnel_status(resource_id, state_root=state_root)
        update = update_tunnel_resource(resource_id, contest_id=contest_id, tunnel=payload, state_root=state_root)
        records = update.get("resources") if isinstance(update, dict) else []
        return (dict(records[0]) if records else dict(record)), str(payload.get("public_url") or "")
    return dict(record), ""


def _upsert_resource(contest_id: str, record: Mapping[str, Any], *, state_root: str | Path | None = None) -> dict[str, Any]:
    contest_id = _safe_contest_id(contest_id)
    root = resources_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    resources = _load_resources(contest_id, state_root=state_root)
    resource_id = _safe_id(str(record.get("resource_id") or ""), "resource_id")
    previous = resources.get(resource_id, {})
    merged = dict(previous)
    merged.update(_redact_record(dict(record)))
    merged["resource_id"] = resource_id
    merged["contest_id"] = contest_id
    if previous.get("created_at") and not record.get("created_at"):
        merged["created_at"] = previous["created_at"]
    if merged.get("status") in {"closed", "stale", "error"} and not merged.get("closed_at") and merged.get("status") == "closed":
        merged["closed_at"] = utc_now()
    resources[resource_id] = merged
    payload = {"contest_id": contest_id, "updated_at": utc_now(), "resources": resources}
    _write_json(root / "resources.json", payload)
    _append_resource_event(contest_id, merged, state_root=state_root)
    return dict(merged)


def _load_resources(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, dict[str, Any]]:
    path = resources_root(contest_id, state_root=state_root) / "resources.json"
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    resources = loaded.get("resources") if isinstance(loaded, dict) else {}
    if not isinstance(resources, dict):
        return {}
    return {str(key): dict(value) for key, value in resources.items() if isinstance(value, dict)}


def _resource_contexts(
    resource_id: str,
    *,
    contest_id: str | None,
    resource_type: str,
    state_root: str | Path | None = None,
) -> list[dict[str, Any]]:
    safe_id = _safe_id(resource_id, "resource_id")
    contests = [_safe_contest_id(contest_id)] if contest_id else _known_contests(state_root=state_root)
    contexts = []
    for item in contests:
        record = _load_resources(item, state_root=state_root).get(safe_id)
        if record and record.get("type") == resource_type:
            contexts.append({"contest_id": item, "record": record})
    return contexts


def _known_contests(*, state_root: str | Path | None = None) -> list[str]:
    root = Path(state_root).expanduser().resolve() if state_root else contest_root("_placeholder").parents[0]
    contests_root = root / "contests" if root.name != "contests" else root
    try:
        return sorted(path.name for path in contests_root.iterdir() if (path / "resources" / "resources.json").exists())
    except FileNotFoundError:
        return []


def _summary_from_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    active_callbacks = [item for item in records if item.get("type") == "callback_listener" and item.get("status") == "active"]
    active_tunnels = [item for item in records if item.get("type") == "public_tunnel" and item.get("status") == "active"]
    stale = [item for item in records if item.get("status") == "stale"]
    last_hits = [str(item.get("last_callback_hit_at") or "") for item in records if str(item.get("last_callback_hit_at") or "")]
    warnings = []
    if active_tunnels:
        warnings.append("active_public_tunnel")
    if active_callbacks:
        warnings.append("active_callback_listener")
    if stale:
        warnings.append("stale_resource")
    return {
        "resource_count": len(records),
        "active_callback_count": len(active_callbacks),
        "active_tunnel_count": len(active_tunnels),
        "stale_resource_count": len(stale),
        "last_callback_hit_at": max(last_hits) if last_hits else "",
        "resource_warnings": warnings,
    }


def _public_record(record: Mapping[str, Any], *, show_public_url: bool, raw_public_url: str = "") -> dict[str, Any]:
    item = dict(record)
    item.pop("public_url", None)
    raw = raw_public_url or str(record.get("public_url_redacted") or "")
    item["public_url_redacted"] = str(record.get("public_url_redacted") or redacted_public_url(raw))
    item["public_url_display"] = public_url_display(raw, show_public_url=show_public_url) if raw else ""
    item["public_url_available"] = bool(raw)
    return _redact_record(item)


def _append_resource_event(contest_id: str, record: Mapping[str, Any], *, state_root: str | Path | None = None) -> None:
    filename = "callbacks.jsonl" if record.get("type") == "callback_listener" else "tunnels.jsonl"
    _append_jsonl(resources_root(contest_id, state_root=state_root) / filename, _redact_record(dict(record)))


def _append_cleanup_event(contest_id: str, event: Mapping[str, Any], *, state_root: str | Path | None = None) -> None:
    _append_jsonl(resources_root(contest_id, state_root=state_root) / "cleanup_events.jsonl", _redact_record(dict(event)))


def _append_jsonl(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_redact_record(dict(data)), sort_keys=True) + "\n")


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(redact_text(json.dumps(data, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _callback_resource_status(listener: Mapping[str, Any]) -> str:
    status = str(listener.get("status") or "").lower()
    if status == "running":
        return "active"
    if status in {"stopped", "closed"}:
        return "closed"
    if status == "stale" or status == "missing":
        return "stale"
    if status == "error":
        return "error"
    return "active" if status in {"starting", "started"} else "error"


def _tunnel_resource_status(tunnel: Mapping[str, Any]) -> str:
    status = str(tunnel.get("status") or "").lower()
    if status in {"started", "running"}:
        return "active"
    if status in {"stopped", "closed"}:
        return "closed"
    if status == "stale" or status == "missing":
        return "stale"
    if status in {"error", "blocked"}:
        return "error"
    return "active" if status in {"starting", "manual_required"} else "error"


def _closed_at_for_status(status: str, payload: Mapping[str, Any], *, previous: Any = None) -> str:
    if previous:
        return str(previous)
    if status == "closed":
        return str(payload.get("stopped_at") or utc_now())
    if status == "error":
        return str(payload.get("stopped_at") or "")
    return ""


def _safe_local_url(url: str) -> str:
    stripped = strip_public_url_query(url)
    return redact_text(stripped)


def _safe_contest_id(value: str | None) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()).strip("._-")
    if not slug:
        raise ValueError("contest_id is required")
    return slug[:120]


def _safe_optional_id(value: str | None) -> str:
    if value is None or str(value).strip() == "":
        return ""
    return re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value).strip())[:160]


def _safe_id(value: str, label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(value).strip())
    if not safe or safe in {".", ".."}:
        raise ValueError(f"{label} is required")
    return safe


def _safe_provider(value: str) -> str:
    provider = str(value or "manual").strip().lower()
    return provider if provider in {"local", "cloudflared", "bore", "manual"} else "manual"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _redact_record(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(redact_text(json.dumps(value, sort_keys=True)))


def port_bound(host: str, port: int, *, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
