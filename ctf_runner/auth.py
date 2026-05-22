from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


SUPPORTED_METHODS = (
    "api_token_file",
    "cookie_header_file",
    "storage_state_file",
    "manual",
)


def _parse_scalar(value: str) -> Any:
    value = value.strip().strip('"').strip("'")
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def _parse_minimal_yaml(path: Path) -> dict[str, Any]:
    raw_lines: list[tuple[int, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        raw_lines.append((len(line) - len(line.lstrip(" ")), line.strip()))
    if not raw_lines:
        return {}
    parsed, _ = _parse_yaml_block(raw_lines, 0, raw_lines[0][0])
    return parsed if isinstance(parsed, dict) else {}


def _parse_yaml_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    if lines[index][1].startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line_indent, stripped = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            index += 1
            continue
        if stripped.startswith("- ") or ":" not in stripped:
            break
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        index += 1
        if value:
            result[key] = _parse_scalar(value)
            continue
        if index < len(lines) and lines[index][0] > line_indent:
            child, index = _parse_yaml_block(lines, index, lines[index][0])
            result[key] = child
        else:
            result[key] = {}
    return result, index


def _parse_yaml_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        line_indent, stripped = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent or not stripped.startswith("- "):
            break
        body = stripped[2:].strip()
        index += 1
        if not body:
            if index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                result.append(child)
            else:
                result.append(None)
            continue
        if ":" in body:
            key, value = body.split(":", 1)
            item: dict[str, Any] = {}
            if value.strip():
                item[key.strip()] = _parse_scalar(value.strip())
            elif index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                item[key.strip()] = child
            else:
                item[key.strip()] = {}
            if index < len(lines) and lines[index][0] > line_indent:
                child, index = _parse_yaml_block(lines, index, lines[index][0])
                if isinstance(child, Mapping):
                    item.update(dict(child))
            result.append(item)
        else:
            result.append(_parse_scalar(body))
    return result, index


def load_config_metadata(config_path: str | Path) -> dict[str, Any]:
    path = Path(config_path).expanduser()
    if not path.exists():
        return {"exists": False, "data": {}}
    if path.suffix == ".toml":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    elif path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        data = _parse_minimal_yaml(path)
    return {"exists": True, "data": data}


def _resolve_config(config: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    if isinstance(config, Mapping):
        return dict(config), True
    loaded = load_config_metadata(config)
    return dict(loaded.get("data", {})), bool(loaded.get("exists"))


def _auth_section(data: Mapping[str, Any]) -> dict[str, Any]:
    entries = _auth_entries(data)
    return dict(entries[0]) if entries else {}


def _auth_entries(data: Mapping[str, Any]) -> list[dict[str, Any]]:
    auth = data.get("auth")
    if isinstance(auth, Mapping):
        primary = {key: value for key, value in dict(auth).items() if key != "fallback"}
        entries: list[dict[str, Any]] = [primary] if primary else []
        fallback = auth.get("fallback")
        if isinstance(fallback, list):
            for entry in fallback:
                if isinstance(entry, Mapping):
                    entries.append(dict(entry))
        elif isinstance(fallback, Mapping):
            entries.append(dict(fallback))
        return entries
    if isinstance(auth, list):
        return [dict(entry) for entry in auth if isinstance(entry, Mapping)]
    methods = data.get("methods")
    if isinstance(methods, Mapping):
        for method in SUPPORTED_METHODS:
            entry = methods.get(method)
            if entry:
                if method == "manual":
                    return {"method": method, "enabled": bool(entry)}
                if isinstance(entry, Mapping):
                    payload = dict(entry)
                    payload["method"] = method
                    return payload
                return {"method": method, "path": str(entry)}
    for method in SUPPORTED_METHODS:
        entry = data.get(method)
        if entry:
            if method == "manual":
                return {"method": method, "enabled": bool(entry)}
            if isinstance(entry, Mapping):
                payload = dict(entry)
                payload["method"] = method
                return payload
                return {"method": method, "path": str(entry)}
    return []


def _permission_warning(path: Path) -> str | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None
    if os.name != "nt" and mode & 0o077:
        return "file readable by group/other"
    return None


def _display_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


@dataclass(frozen=True)
class AuthSecret:
    method: str
    path: str | None = None
    source_index: int = 0
    source_role: str = "primary"
    _secret_text: str | None = field(default=None, repr=False)
    _storage_state: dict[str, Any] | None = field(default=None, repr=False)

    @property
    def loaded(self) -> bool:
        return bool(self._secret_text or self._storage_state or self.method == "manual")

    def __repr__(self) -> str:
        return f"AuthSecret(method={self.method!r}, path={self.path!r}, loaded={self.loaded})"

    def build_headers(self, *, base_url: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.method == "api_token_file" and self._secret_text:
            headers["Authorization"] = f"Token {self._secret_text}"
        elif self.method == "cookie_header_file" and self._secret_text:
            headers["Cookie"] = _normalize_cookie_header(self._secret_text)
        elif self.method == "storage_state_file":
            cookie_header = self._storage_state_cookie_header(base_url=base_url)
            if cookie_header:
                headers["Cookie"] = cookie_header
        return headers

    def _storage_state_cookie_header(self, *, base_url: str | None = None) -> str | None:
        state = self._storage_state or {}
        cookies = state.get("cookies")
        if not isinstance(cookies, list):
            return None
        host = urlparse(base_url).hostname if base_url else None
        values: list[str] = []
        for cookie in cookies:
            if not isinstance(cookie, Mapping):
                continue
            name = str(cookie.get("name") or "").strip()
            value = str(cookie.get("value") or "").strip()
            if not name or not value:
                continue
            domain = str(cookie.get("domain") or "").lstrip(".")
            if host and domain and not (host == domain or host.endswith(f".{domain}")):
                continue
            values.append(f"{name}={value}")
        if not values:
            return None
        return "; ".join(values)


def load_auth_metadata(config: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    """Return auth method metadata without reading secret file contents."""
    data, exists = _resolve_config(config)
    if not exists:
        return {
            "config_exists": False,
            "method": None,
            "path": None,
            "path_exists": False,
            "permission_warning": None,
            "fallback": [],
            "effective_method": None,
        }
    entries = _auth_entries(data)
    if not entries:
        return {
            "config_exists": True,
            "method": None,
            "path": None,
            "path_exists": False,
            "permission_warning": None,
            "fallback": [],
            "effective_method": None,
        }
    primary = _auth_entry_metadata(entries[0], config_exists=True, source_index=0, source_role="primary")
    fallback = [
        _auth_entry_metadata(entry, config_exists=True, source_index=index, source_role="fallback")
        for index, entry in enumerate(entries[1:], start=1)
    ]
    primary["fallback"] = fallback
    usable = [entry for entry in [primary, *fallback] if entry.get("usable")]
    primary["effective_method"] = usable[0].get("method") if usable else None
    primary["effective_source_index"] = usable[0].get("source_index") if usable else None
    primary["effective_source_role"] = usable[0].get("source_role") if usable else None
    return primary


def _auth_entry_metadata(entry: Mapping[str, Any], *, config_exists: bool, source_index: int, source_role: str) -> dict[str, Any]:
    method = str(entry.get("method") or "").strip() or None
    metadata: dict[str, Any] = {
        "config_exists": config_exists,
        "method": method,
        "path": None,
        "path_exists": False,
        "permission_warning": None,
        "source_index": source_index,
        "source_role": source_role,
        "usable": False,
    }
    if method not in SUPPORTED_METHODS:
        return metadata
    if method == "manual":
        metadata["path_exists"] = None
        metadata["usable"] = True
        return metadata
    secret_path = Path(str(entry.get("path") or "")).expanduser() if entry.get("path") else None
    metadata["path"] = _display_path(secret_path)
    metadata["path_exists"] = secret_path.exists() if secret_path else False
    metadata["permission_warning"] = _permission_warning(secret_path) if secret_path else None
    metadata["usable"] = bool(secret_path and secret_path.exists())
    return metadata


def load_auth_secret(config: str | Path | Mapping[str, Any], live: bool = False) -> AuthSecret:
    """Read a secret only for a guarded live request. Never print or serialize the result."""
    if not live:
        raise ValueError("auth secret loading requires live=True")
    data, exists = _resolve_config(config)
    if not exists:
        raise FileNotFoundError("auth config not found")
    errors: list[str] = []
    for index, auth in enumerate(_auth_entries(data)):
        try:
            return _load_auth_entry(auth, source_index=index, source_role="primary" if index == 0 else "fallback")
        except FileNotFoundError:
            errors.append("path_missing")
            continue
        except ValueError as exc:
            errors.append(exc.__class__.__name__)
            continue
    if not errors:
        raise KeyError("auth method not configured")
    raise FileNotFoundError("no usable auth method found")


def _load_auth_entry(auth: Mapping[str, Any], *, source_index: int = 0, source_role: str = "primary") -> AuthSecret:
    method = str(auth.get("method") or "").strip()
    if method not in SUPPORTED_METHODS:
        raise KeyError(f"auth method not configured: {method}")
    if method == "manual":
        return AuthSecret(method=method, path=None, source_index=source_index, source_role=source_role)
    path_value = auth.get("path")
    if not path_value:
        raise ValueError("auth method has no path")
    secret_path = Path(str(path_value)).expanduser()
    if not secret_path.exists():
        raise FileNotFoundError("auth path missing")
    if method == "storage_state_file":
        return AuthSecret(
            method=method,
            path=_display_path(secret_path),
            source_index=source_index,
            source_role=source_role,
            _storage_state=json.loads(secret_path.read_text(encoding="utf-8")),
        )
    return AuthSecret(
        method=method,
        path=_display_path(secret_path),
        source_index=source_index,
        source_role=source_role,
        _secret_text=secret_path.read_text(encoding="utf-8").strip(),
    )


def read_secret_for_live_use(config_path: str | Path, method: str) -> str:
    """Backward-compatible helper for legacy callers."""
    secret = load_auth_secret(config_path, live=True)
    if secret.method != method:
        raise KeyError(f"auth method not configured: {method}")
    if secret._secret_text is None:
        raise ValueError(f"auth method {method} does not expose text secret")
    return secret._secret_text


def _normalize_cookie_header(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("cookie:"):
            line = line.split(":", 1)[1].strip()
        if ";" in line and "=" in line:
            parts.extend(part.strip() for part in line.split(";") if part.strip())
            continue
        if "=" in line:
            parts.append(line)
            continue
        if ":" in line:
            name, cookie_value = line.split(":", 1)
            name = name.strip()
            cookie_value = cookie_value.strip()
            if name and cookie_value and re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                parts.append(f"{name}={cookie_value}")
    if parts:
        return "; ".join(parts)
    return re.sub(r"[\r\n]+", "; ", text)
