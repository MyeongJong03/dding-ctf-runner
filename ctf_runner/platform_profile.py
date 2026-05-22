from __future__ import annotations

import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from .auth import SUPPORTED_METHODS, load_auth_metadata, load_config_metadata
from .redact import redact_text


READONLY_POLICY_KEYS = ("allow_live_discovery", "allow_live_download")
DESTRUCTIVE_POLICY_KEYS = ("allow_submission", "allow_instance_start")
POLICY_KEYS = (*READONLY_POLICY_KEYS, *DESTRUCTIVE_POLICY_KEYS)
SUPPORTED_PLATFORMS = ("ctfd", "generic")


def create_platform_profile(
    contest_id: str,
    base_url: str,
    auth_method: str,
    auth_path: str | None,
    output_path: str | Path,
    platform: str = "ctfd",
    contest_url: str | None = None,
) -> dict[str, Any]:
    """Create a local-only platform profile without reading auth material."""
    method = _normalize_auth_method(auth_method)
    if method is None:
        raise ValueError(f"unsupported auth method: {auth_method}")
    platform_name = _normalize_platform(platform)
    if platform_name is None:
        raise ValueError(f"unsupported platform: {platform}")
    if method != "manual" and not str(auth_path or "").strip():
        raise ValueError("auth_path is required for file-backed auth methods")

    profile = {
        "platform": platform_name,
        "name": _safe_slug(contest_id, "contest"),
        "base_url": str(base_url).rstrip("/"),
        "auth": {"method": method},
        "policy": {
            "allow_live_discovery": True,
            "allow_live_download": True,
            "allow_submission": False,
            "allow_instance_start": False,
        },
        "downloads": {"root": "~/CTF/contests"},
    }
    if contest_url:
        profile["contest_url"] = str(contest_url).strip()
    if method != "manual":
        profile["auth"]["path"] = str(auth_path)

    output = Path(output_path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_render_profile_yaml(profile), encoding="utf-8")

    checked = validate_platform_profile(output)
    checked["created"] = True
    return checked


def validate_platform_profile(path: str | Path) -> dict[str, Any]:
    """Validate a profile and return display-safe metadata only."""
    config_path = Path(path).expanduser()
    warnings: list[str] = []
    errors: list[str] = []
    loaded = load_config_metadata(config_path)
    data = dict(loaded.get("data", {})) if loaded.get("exists") else {}
    if not loaded.get("exists"):
        errors.append("profile_config_missing")

    base_url = str(data.get("base_url") or data.get("url") or "").strip()
    base_check = _validate_base_url(base_url)
    warnings.extend(base_check["warnings"])
    errors.extend(base_check["errors"])

    platform = str(data.get("platform") or "ctfd").strip().lower()
    if platform not in SUPPORTED_PLATFORMS:
        errors.append("unsupported_platform")
    if platform == "generic":
        contest_url = str(data.get("contest_url") or "").strip()
        if not contest_url:
            errors.append("contest_url_missing")
        else:
            contest_check = _validate_base_url(contest_url, label="contest_url")
            warnings.extend(contest_check["warnings"])
            errors.extend(contest_check["errors"])

    auth = _auth_metadata(config_path, data, bool(loaded.get("exists")))
    for entry in _auth_metadata_entries(auth):
        method = entry.get("method")
        role = str(entry.get("source_role") or "primary")
        prefix = "auth" if role == "primary" else "auth_fallback"
        if method and method not in SUPPORTED_METHODS:
            errors.append(f"unsupported_{prefix}_method")
        if method not in (None, "manual") and not entry.get("path"):
            errors.append(f"{prefix}_path_missing")
        if method not in (None, "manual") and not entry.get("path_exists"):
            warnings.append(f"{prefix}_path_missing")
        if entry.get("permission_warning"):
            warnings.append(f"{prefix}_path_permission_warning")

    policy = _effective_policy(data.get("policy") if isinstance(data.get("policy"), Mapping) else {})
    missing_policy = _missing_policy_keys(data.get("policy") if isinstance(data.get("policy"), Mapping) else {})
    warnings.extend([f"policy_missing_{key}" for key in missing_policy])
    if policy.get("allow_submission"):
        warnings.append("allow_submission_enabled_live_readonly_should_not_submit")
    if policy.get("allow_instance_start"):
        warnings.append("allow_instance_start_enabled_live_readonly_should_not_start")

    profile = redact_platform_profile(data)
    result = {
        "status": "ok" if not errors else "invalid",
        "config_path": _display_path(config_path),
        "profile": profile,
        "auth": auth,
        "policy": policy,
        "warnings": sorted(set(warnings)),
        "errors": sorted(set(errors)),
    }
    return result


def redact_platform_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    auth = profile.get("auth") if isinstance(profile.get("auth"), Mapping) else {}
    policy = _effective_policy(profile.get("policy") if isinstance(profile.get("policy"), Mapping) else {})
    base_url = str(profile.get("base_url") or profile.get("url") or "").strip()
    display_base_url = _display_url(base_url) if base_url else ""
    redacted: dict[str, Any] = {
        "platform": str(profile.get("platform") or "ctfd"),
        "name": str(profile.get("name") or ""),
        "base_url": display_base_url,
        "auth": {"method": str(auth.get("method") or "")},
        "policy": policy,
    }
    contest_url = str(profile.get("contest_url") or "").strip()
    if contest_url:
        redacted["contest_url"] = _display_url(contest_url)
    if auth.get("path"):
        redacted["auth"]["path"] = _display_path(Path(str(auth.get("path"))).expanduser())
    fallback = auth.get("fallback")
    fallback_items: list[dict[str, str]] = []
    if isinstance(fallback, list):
        for entry in fallback:
            if not isinstance(entry, Mapping):
                continue
            item = {"method": str(entry.get("method") or "")}
            if entry.get("path"):
                item["path"] = _display_path(Path(str(entry.get("path"))).expanduser()) or ""
            fallback_items.append(item)
    elif isinstance(fallback, Mapping):
        item = {"method": str(fallback.get("method") or "")}
        if fallback.get("path"):
            item["path"] = _display_path(Path(str(fallback.get("path"))).expanduser()) or ""
        fallback_items.append(item)
    if fallback_items:
        redacted["auth"]["fallback"] = fallback_items
    downloads = profile.get("downloads")
    if isinstance(downloads, Mapping) and downloads.get("root"):
        redacted["downloads"] = {"root": _display_path(Path(str(downloads.get("root"))).expanduser())}
    return redacted


def _auth_metadata(path: Path, data: Mapping[str, Any], config_exists: bool) -> dict[str, Any]:
    if config_exists:
        return load_auth_metadata(path)
    return {"config_exists": False, "method": None, "path": None, "path_exists": False, "permission_warning": None}


def _auth_metadata_entries(auth: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entries: list[Mapping[str, Any]] = [auth]
    fallback = auth.get("fallback")
    if isinstance(fallback, list):
        entries.extend(entry for entry in fallback if isinstance(entry, Mapping))
    return entries


def set_platform_profile_auth(path: str | Path, method: str, auth_path: str | None) -> dict[str, Any]:
    """Set primary auth metadata without reading auth material."""
    config_path = Path(path).expanduser()
    loaded = load_config_metadata(config_path)
    if not loaded.get("exists"):
        raise FileNotFoundError("platform profile not found")
    profile = dict(loaded.get("data") or {})
    normalized = _normalize_auth_method(method)
    if normalized is None:
        raise ValueError(f"unsupported auth method: {method}")
    if normalized != "manual" and not str(auth_path or "").strip():
        raise ValueError("path is required for file-backed auth methods")
    old_auth = profile.get("auth") if isinstance(profile.get("auth"), Mapping) else {}
    new_auth: dict[str, Any] = {"method": normalized}
    if normalized != "manual":
        new_auth["path"] = str(auth_path)
    if isinstance(old_auth, Mapping) and old_auth.get("fallback"):
        new_auth["fallback"] = old_auth.get("fallback")
    profile["auth"] = new_auth
    config_path.write_text(_render_profile_yaml(profile), encoding="utf-8")
    return validate_platform_profile(config_path)


def add_platform_profile_auth_fallback(path: str | Path, method: str, auth_path: str | None) -> dict[str, Any]:
    """Append fallback auth metadata without reading auth material."""
    config_path = Path(path).expanduser()
    loaded = load_config_metadata(config_path)
    if not loaded.get("exists"):
        raise FileNotFoundError("platform profile not found")
    profile = dict(loaded.get("data") or {})
    normalized = _normalize_auth_method(method)
    if normalized is None:
        raise ValueError(f"unsupported auth method: {method}")
    if normalized != "manual" and not str(auth_path or "").strip():
        raise ValueError("path is required for file-backed auth methods")
    auth = dict(profile.get("auth") if isinstance(profile.get("auth"), Mapping) else {"method": "manual"})
    fallback = auth.get("fallback")
    if isinstance(fallback, list):
        fallback_items = [dict(entry) for entry in fallback if isinstance(entry, Mapping)]
    elif isinstance(fallback, Mapping):
        fallback_items = [dict(fallback)]
    else:
        fallback_items = []
    new_entry: dict[str, Any] = {"method": normalized}
    if normalized != "manual":
        new_entry["path"] = str(auth_path)
    if not _auth_entry_already_present(auth, fallback_items, new_entry):
        fallback_items.append(new_entry)
    auth["fallback"] = fallback_items
    profile["auth"] = auth
    config_path.write_text(_render_profile_yaml(profile), encoding="utf-8")
    return validate_platform_profile(config_path)


def show_platform_profile(path: str | Path) -> dict[str, Any]:
    return validate_platform_profile(path)


def _auth_entry_already_present(primary: Mapping[str, Any], fallback: list[Mapping[str, Any]], entry: Mapping[str, Any]) -> bool:
    wanted = (str(entry.get("method") or ""), str(entry.get("path") or ""))
    primary_key = (str(primary.get("method") or ""), str(primary.get("path") or ""))
    if wanted == primary_key:
        return True
    return any(wanted == (str(item.get("method") or ""), str(item.get("path") or "")) for item in fallback)


def _normalize_auth_method(method: str) -> str | None:
    normalized = str(method or "").strip().lower().replace("-", "_")
    aliases = {
        "token": "api_token_file",
        "api_token": "api_token_file",
        "api_token_file": "api_token_file",
        "cookie": "cookie_header_file",
        "cookie_header": "cookie_header_file",
        "cookie_header_file": "cookie_header_file",
        "storage": "storage_state_file",
        "storage_state": "storage_state_file",
        "storage_state_file": "storage_state_file",
        "manual": "manual",
    }
    return aliases.get(normalized)


def _normalize_platform(platform: str) -> str | None:
    normalized = str(platform or "").strip().lower().replace("-", "_")
    aliases = {
        "ctfd": "ctfd",
        "generic": "generic",
    }
    return aliases.get(normalized)


def _validate_base_url(base_url: str, *, label: str = "base_url") -> dict[str, list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    if not base_url:
        errors.append(f"{label}_missing")
        return {"warnings": warnings, "errors": errors}
    try:
        parsed = urllib.parse.urlsplit(base_url)
    except ValueError:
        return {"warnings": warnings, "errors": [f"{label}_invalid"]}
    if parsed.scheme not in {"http", "https"}:
        errors.append(f"{label}_scheme_not_http_or_https")
    if not parsed.netloc:
        errors.append(f"{label}_missing_host")
    if parsed.username or parsed.password:
        warnings.append(f"{label}_embedded_credentials")
        errors.append(f"{label}_embedded_credentials")
    if parsed.query:
        warnings.append(f"{label}_query_string_present")
    return {"warnings": warnings, "errors": errors}


def _effective_policy(policy: Mapping[str, Any]) -> dict[str, bool]:
    return {key: bool(policy.get(key, False)) for key in POLICY_KEYS}


def _missing_policy_keys(policy: Mapping[str, Any]) -> list[str]:
    return [key for key in POLICY_KEYS if key not in policy]


def _display_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return redact_text(value)
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), "", ""))


def _display_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _safe_slug(value: str | None, fallback: str) -> str:
    import re

    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()).strip("._-")
    return slug[:120] or fallback


def _quote_yaml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _render_profile_yaml(profile: Mapping[str, Any]) -> str:
    auth = profile.get("auth") if isinstance(profile.get("auth"), Mapping) else {}
    policy = profile.get("policy") if isinstance(profile.get("policy"), Mapping) else {}
    downloads = profile.get("downloads") if isinstance(profile.get("downloads"), Mapping) else {}
    lines = [
        "# Local-only platform profile. Keep this file untracked.",
        f"platform: {_quote_yaml(profile.get('platform') or 'ctfd')}",
        f"name: {_quote_yaml(profile.get('name') or '')}",
        f"base_url: {_quote_yaml(profile.get('base_url') or '')}",
    ]
    if profile.get("contest_url"):
        lines.append(f"contest_url: {_quote_yaml(profile.get('contest_url'))}")
    lines.extend(
        [
            "auth:",
            f"  method: {_quote_yaml(auth.get('method') or 'manual')}",
        ]
    )
    if auth.get("path"):
        lines.append(f"  path: {_quote_yaml(auth.get('path'))}")
    fallback = auth.get("fallback")
    fallback_items: list[Mapping[str, Any]] = []
    if isinstance(fallback, list):
        fallback_items = [entry for entry in fallback if isinstance(entry, Mapping)]
    elif isinstance(fallback, Mapping):
        fallback_items = [fallback]
    if fallback_items:
        lines.append("  fallback:")
        for entry in fallback_items:
            lines.append(f"    - method: {_quote_yaml(entry.get('method') or 'manual')}")
            if entry.get("path"):
                lines.append(f"      path: {_quote_yaml(entry.get('path'))}")
    lines.extend(
        [
            "policy:",
            f"  allow_live_discovery: {_quote_yaml(policy.get('allow_live_discovery', False))}",
            f"  allow_live_download: {_quote_yaml(policy.get('allow_live_download', False))}",
            f"  allow_submission: {_quote_yaml(policy.get('allow_submission', False))}",
            f"  allow_instance_start: {_quote_yaml(policy.get('allow_instance_start', False))}",
        ]
    )
    if profile.get("max_api_requests") is not None:
        lines.append(f"max_api_requests: {_quote_yaml(profile.get('max_api_requests'))}")
    if profile.get("max_downloads_per_challenge") is not None:
        lines.append(f"max_downloads_per_challenge: {_quote_yaml(profile.get('max_downloads_per_challenge'))}")
    lines.extend(
        [
            "downloads:",
            f"  root: {_quote_yaml(downloads.get('root') or '~/CTF/contests')}",
            "",
        ]
    )
    return "\n".join(lines)
