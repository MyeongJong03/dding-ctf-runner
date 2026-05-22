from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping

from .auth import load_auth_secret, load_config_metadata
from .paths import get_paths
from .platform_base import PlatformAction, PlatformAdapter
from .redact import redact_text
from .submit import hash_flag, redact_flag


def _safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_slug(value: str | None, fallback: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()).strip("._-")
    return (slug or fallback)[:120]


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _sanitize_filename(name: str, fallback: str = "attachment.bin") -> str:
    base = Path(name or fallback).name
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return base[:160] or fallback


def _redact_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _status_for_http_code(code: int) -> str:
    if code in {401, 403}:
        return "auth_required"
    if code == 404:
        return "not_found"
    if code == 429:
        return "rate_limited"
    return "http_error"


def _http_error_message(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read(8 * 1024).decode("utf-8", errors="replace")
    except Exception:
        body = ""
    message = body or str(exc.reason or exc)
    return redact_text(message)[:500]


class CTFdPlatform:
    def __init__(
        self,
        config_path: str | Path | None = None,
        config: dict[str, Any] | None = None,
        *,
        urlopen: Callable[..., Any] | None = None,
    ):
        self.config_path = Path(config_path).expanduser() if config_path else None
        if config is not None:
            self.config = dict(config)
        elif self.config_path and self.config_path.exists():
            loaded = load_config_metadata(self.config_path)
            self.config = dict(loaded.get("data", {}))
        else:
            self.config = {}
        self._urlopen = urlopen or urllib.request.urlopen

    @property
    def platform_name(self) -> str:
        return _safe_slug(str(self.config.get("name") or "platform"), "platform")

    @property
    def base_url(self) -> str | None:
        value = self.config.get("base_url") or self.config.get("url")
        return str(value).rstrip("/") if value else None

    @property
    def policy(self) -> dict[str, Any]:
        policy = self.config.get("policy")
        return dict(policy) if isinstance(policy, Mapping) else {}

    @property
    def downloads_root(self) -> Path:
        downloads = self.config.get("downloads")
        if isinstance(downloads, Mapping) and downloads.get("root"):
            return Path(str(downloads["root"])).expanduser().resolve()
        return get_paths().contests_root

    def _result(self, action: str, live: bool, network: bool, status: str, details: dict[str, Any]) -> PlatformAction:
        return PlatformAction(action=action, live=live, network=network, status=status, details=details)

    def _planned(self, action: str, details: dict[str, Any]) -> PlatformAction:
        return self._result(action, live=False, network=False, status="planned", details=details)

    def _blocked(self, action: str, reason: str, *, live: bool = True, details: dict[str, Any] | None = None) -> PlatformAction:
        payload = {"reason": reason}
        if details:
            payload.update(details)
        return self._result(action, live=live, network=False, status="blocked", details=payload)

    def _policy_allowed(self, key: str) -> bool:
        return bool(self.policy.get(key, False))

    def _auth_headers(self) -> dict[str, str]:
        secret = load_auth_secret(self.config, live=True)
        headers = {"Accept": "application/json"}
        headers.update(secret.build_headers(base_url=self.base_url))
        return headers

    def _request_json(self, path: str) -> dict[str, Any]:
        if not self.base_url:
            raise ValueError("missing base_url")
        url = urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
        request = urllib.request.Request(url, headers=self._auth_headers(), method="GET")
        with self._urlopen(request, timeout=15) as response:  # noqa: S310 - live use is gated by policy and --live.
            body = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
        parsed = json.loads(body)
        if isinstance(parsed, dict):
            return parsed
        return {"data": parsed}

    def _http_error_action(
        self,
        action: str,
        exc: urllib.error.HTTPError,
        *,
        live: bool,
        details: dict[str, Any] | None = None,
    ) -> PlatformAction:
        status = _status_for_http_code(int(exc.code))
        payload = {"http_status": int(exc.code), "message": _http_error_message(exc)}
        if details:
            payload.update(details)
        return self._result(action, live=live, network=True, status=status, details=payload)

    def _network_error_action(
        self,
        action: str,
        exc: urllib.error.URLError,
        *,
        live: bool,
        details: dict[str, Any] | None = None,
    ) -> PlatformAction:
        payload = {"message": redact_text(str(getattr(exc, "reason", exc)))[:500]}
        if details:
            payload.update(details)
        return self._result(action, live=live, network=True, status="network_error", details=payload)

    def _auth_config_error_action(self, action: str, exc: Exception, *, details: dict[str, Any] | None = None) -> PlatformAction:
        payload = {"reason": "auth_or_config_missing", "error": redact_text(str(exc))[:500]}
        if details:
            payload.update(details)
        return self._result(action, live=True, network=False, status="blocked", details=payload)

    def _post_json(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if not self.base_url:
            raise ValueError("missing base_url")
        url = urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with self._urlopen(request, timeout=15) as response:  # noqa: S310 - live use is gated by policy and --live.
                body = response.read(512 * 1024).decode("utf-8", errors="replace")
                status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
        except urllib.error.HTTPError as exc:
            body = exc.read(512 * 1024).decode("utf-8", errors="replace")
            status_code = int(exc.code)
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"message": redact_text(body)[:500]}
        if isinstance(parsed, dict):
            return status_code, parsed
        return status_code, {"data": parsed}

    def _download_file(self, url: str, dest: Path) -> tuple[int, str]:
        request = urllib.request.Request(url, headers=self._auth_headers(), method="GET")
        sha256 = hashlib.sha256()
        total = 0
        with self._urlopen(request, timeout=30) as response:  # noqa: S310 - live use is gated by policy and --live.
            with dest.open("wb") as fh:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    fh.write(chunk)
                    total += len(chunk)
                    sha256.update(chunk)
        return total, sha256.hexdigest()

    def _extract_data(self, payload: dict[str, Any]) -> Any:
        if "data" in payload:
            return payload["data"]
        return payload

    def _normalize_tags(self, tags: Any) -> list[str]:
        if isinstance(tags, str):
            return [tags] if tags.strip() else []
        if not isinstance(tags, list):
            return []
        result: list[str] = []
        for item in tags:
            if isinstance(item, Mapping):
                value = item.get("value") or item.get("name")
            else:
                value = item
            if value:
                result.append(str(value))
        return result[:20]

    def _challenge_summary(self, item: Mapping[str, Any]) -> dict[str, Any]:
        files = item.get("files")
        challenge_id = str(item.get("id") or item.get("challenge_id") or item.get("name") or "")
        file_count = len(files) if isinstance(files, list) else (1 if isinstance(files, (str, Mapping)) else 0)
        solved = item.get("solved")
        if solved is None:
            solved = item.get("solved_by_me")
        if solved is None:
            solved = item.get("completed")
        return {
            "challenge_id": challenge_id,
            "name": str(item.get("name") or challenge_id),
            "category": str(item.get("category") or ""),
            "points": _coerce_int(item.get("value")),
            "solves": _coerce_int(item.get("solves")),
            "solved": bool(solved) if solved is not None else None,
            "tags": self._normalize_tags(item.get("tags")),
            "has_connection_info": bool(item.get("connection_info")),
            "has_files": file_count > 0,
            "file_count": file_count,
            "description": redact_text(str(item.get("description") or ""))[:2000],
        }

    def _attachment_metadata(self, challenge: Mapping[str, Any]) -> list[dict[str, Any]]:
        files = challenge.get("files")
        if isinstance(files, (str, Mapping)):
            file_items = [files]
        elif isinstance(files, list):
            file_items = files
        else:
            return []
        attachments: list[dict[str, Any]] = []
        for index, item in enumerate(file_items, start=1):
            raw_url = ""
            raw_name = ""
            if isinstance(item, str):
                raw_url = item
            elif isinstance(item, Mapping):
                raw_url = str(item.get("url") or item.get("location") or item.get("path") or item.get("href") or "")
                raw_name = str(item.get("name") or item.get("filename") or "")
            if not raw_url:
                continue
            absolute_url = urllib.parse.urljoin(f"{self.base_url or ''}/", raw_url)
            parsed = urllib.parse.urlsplit(absolute_url)
            fallback_name = Path(parsed.path).name or f"attachment-{index}.bin"
            filename = _sanitize_filename(raw_name or fallback_name, fallback=f"attachment-{index}.bin")
            attachments.append(
                {
                    "filename": filename,
                    "source": _redact_url(absolute_url),
                    "url": absolute_url,
                }
            )
        return attachments

    def _challenge_list_items(self, data: Any) -> list[Any]:
        if isinstance(data, list):
            return data
        if isinstance(data, Mapping):
            for key in ("challenges", "items", "results"):
                value = data.get(key)
                if isinstance(value, list):
                    return value
        return []

    def _challenge_detail_item(self, data: Any) -> Any:
        if isinstance(data, Mapping):
            for key in ("challenge", "item"):
                value = data.get(key)
                if isinstance(value, Mapping):
                    return value
        return data

    def _challenge_default_raw_dir(self, challenge_id: str) -> Path:
        return (self.downloads_root / self.platform_name / _safe_slug(challenge_id, "challenge") / "raw").resolve()

    def discover_challenges(self, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned(
                "discover_challenges",
                {"endpoint": "/api/v1/challenges", "platform": self.config.get("platform", "ctfd"), "live_required": True},
            )
        if not self.base_url:
            return self._blocked("discover_challenges", "missing_base_url")
        if not self._policy_allowed("allow_live_discovery"):
            return self._blocked("discover_challenges", "live_discovery_not_allowed_by_policy")
        try:
            data = self._extract_data(self._request_json("/api/v1/challenges"))
        except urllib.error.HTTPError as exc:
            return self._http_error_action("discover_challenges", exc, live=True, details={"endpoint": "/api/v1/challenges"})
        except urllib.error.URLError as exc:
            return self._network_error_action("discover_challenges", exc, live=True, details={"endpoint": "/api/v1/challenges"})
        except (FileNotFoundError, KeyError, ValueError) as exc:
            return self._auth_config_error_action("discover_challenges", exc, details={"endpoint": "/api/v1/challenges"})
        except json.JSONDecodeError as exc:
            return self._result(
                "discover_challenges",
                live=True,
                network=True,
                status="unexpected_response",
                details={"endpoint": "/api/v1/challenges", "error": redact_text(str(exc))[:500], "challenges": []},
            )
        items = self._challenge_list_items(data)
        challenges = [self._challenge_summary(item) for item in items if isinstance(item, Mapping)]
        return self._result(
            "discover_challenges",
            live=True,
            network=True,
            status="ok",
            details={
                "endpoint": "/api/v1/challenges",
                "platform": self.config.get("platform", "ctfd"),
                "challenge_count": len(challenges),
                "challenges": challenges,
            },
        )

    def get_challenge(self, challenge_id: str, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned("get_challenge", {"challenge_id": challenge_id, "endpoint": f"/api/v1/challenges/{challenge_id}"})
        if not self.base_url:
            return self._blocked("get_challenge", "missing_base_url")
        if not self._policy_allowed("allow_live_discovery"):
            return self._blocked("get_challenge", "live_discovery_not_allowed_by_policy", details={"challenge_id": challenge_id})
        endpoint = f"/api/v1/challenges/{urllib.parse.quote(str(challenge_id), safe='')}"
        try:
            payload = self._request_json(endpoint)
            data = self._challenge_detail_item(self._extract_data(payload))
        except urllib.error.HTTPError as exc:
            return self._http_error_action("get_challenge", exc, live=True, details={"challenge_id": challenge_id, "endpoint": endpoint})
        except urllib.error.URLError as exc:
            return self._network_error_action("get_challenge", exc, live=True, details={"challenge_id": challenge_id, "endpoint": endpoint})
        except (FileNotFoundError, KeyError, ValueError) as exc:
            return self._auth_config_error_action("get_challenge", exc, details={"challenge_id": challenge_id, "endpoint": endpoint})
        except json.JSONDecodeError as exc:
            return self._result(
                "get_challenge",
                live=True,
                network=True,
                status="unexpected_response",
                details={"challenge_id": challenge_id, "endpoint": endpoint, "error": redact_text(str(exc))[:500], "attachments": []},
            )
        if not isinstance(data, Mapping):
            return self._result(
                "get_challenge",
                live=True,
                network=True,
                status="unexpected_response",
                details={"challenge_id": challenge_id, "attachments": [], "summary": {}},
            )
        summary = self._challenge_summary(data)
        attachments = self._attachment_metadata(data)
        return self._result(
            "get_challenge",
            live=True,
            network=True,
            status="ok",
            details={
                "challenge_id": challenge_id,
                "summary": summary,
                "attachments": [{"filename": item["filename"], "source": item["source"]} for item in attachments],
                "attachment_count": len(attachments),
            },
        )

    def download_attachments(self, challenge_id: str, dest_dir: str | None = None, live: bool = False) -> PlatformAction:
        raw_dir = Path(dest_dir).expanduser().resolve() if dest_dir else self._challenge_default_raw_dir(challenge_id)
        if not live:
            return self._planned(
                "download_attachments",
                {"challenge_id": challenge_id, "dest_dir": _display_path(raw_dir), "live_required": True},
            )
        if not self.base_url:
            return self._blocked("download_attachments", "missing_base_url", details={"challenge_id": challenge_id})
        if not self._policy_allowed("allow_live_download"):
            return self._blocked("download_attachments", "live_download_not_allowed_by_policy", details={"challenge_id": challenge_id})
        endpoint = f"/api/v1/challenges/{urllib.parse.quote(str(challenge_id), safe='')}"
        try:
            payload = self._request_json(endpoint)
            data = self._challenge_detail_item(self._extract_data(payload))
        except urllib.error.HTTPError as exc:
            return self._http_error_action(
                "download_attachments",
                exc,
                live=True,
                details={"challenge_id": challenge_id, "endpoint": endpoint, "downloads": [], "dest_dir": _display_path(raw_dir)},
            )
        except urllib.error.URLError as exc:
            return self._network_error_action(
                "download_attachments",
                exc,
                live=True,
                details={"challenge_id": challenge_id, "endpoint": endpoint, "downloads": [], "dest_dir": _display_path(raw_dir)},
            )
        except (FileNotFoundError, KeyError, ValueError) as exc:
            return self._auth_config_error_action(
                "download_attachments",
                exc,
                details={"challenge_id": challenge_id, "endpoint": endpoint, "downloads": [], "dest_dir": _display_path(raw_dir)},
            )
        except json.JSONDecodeError as exc:
            return self._result(
                "download_attachments",
                live=True,
                network=True,
                status="unexpected_response",
                details={
                    "challenge_id": challenge_id,
                    "endpoint": endpoint,
                    "error": redact_text(str(exc))[:500],
                    "downloads": [],
                    "dest_dir": _display_path(raw_dir),
                },
            )
        if not isinstance(data, Mapping):
            return self._result(
                "download_attachments",
                live=True,
                network=True,
                status="unexpected_response",
                details={"challenge_id": challenge_id, "downloads": [], "dest_dir": _display_path(raw_dir)},
            )
        attachments = self._attachment_metadata(data)
        raw_dir.mkdir(parents=True, exist_ok=True)
        downloads: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for attachment in attachments:
            target = raw_dir / attachment["filename"]
            counter = 1
            while target.exists():
                target = raw_dir / f"{target.stem}.{counter}{target.suffix}"
                counter += 1
            try:
                size, sha256 = self._download_file(attachment["url"], target)
            except urllib.error.HTTPError as exc:
                failures.append(
                    {
                        "filename": attachment["filename"],
                        "source": attachment["source"],
                        "status": _status_for_http_code(int(exc.code)),
                        "http_status": int(exc.code),
                        "message": _http_error_message(exc),
                    }
                )
                continue
            except urllib.error.URLError as exc:
                failures.append(
                    {
                        "filename": attachment["filename"],
                        "source": attachment["source"],
                        "status": "network_error",
                        "message": redact_text(str(getattr(exc, "reason", exc)))[:500],
                    }
                )
                continue
            downloads.append(
                {
                    "filename": target.name,
                    "path": _display_path(target),
                    "fs_path": str(target),
                    "size": size,
                    "sha256": sha256,
                    "source": attachment["source"],
                }
            )
        if downloads and not failures:
            status = "ok"
        elif downloads:
            status = "partial"
        elif not attachments:
            status = "no_attachments"
        elif len({str(item.get("status")) for item in failures}) == 1:
            status = str(failures[0].get("status") or "download_failed")
        else:
            status = "download_failed"
        return self._result(
            "download_attachments",
            live=True,
            network=True,
            status=status,
            details={
                "challenge_id": challenge_id,
                "dest_dir": _display_path(raw_dir),
                "fs_dest_dir": str(raw_dir),
                "download_count": len(downloads),
                "downloads": downloads,
                "failure_count": len(failures),
                "failures": failures,
            },
        )

    def start_instance(self, challenge_id: str, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned(
                "start_instance",
                {"challenge_id": challenge_id, "note": "CTFd instancer endpoints are deployment-specific"},
            )
        if not self._policy_allowed("allow_instance_start"):
            return self._blocked("start_instance", "instance_start_not_allowed_by_policy", details={"challenge_id": challenge_id})
        return self._result(
            "start_instance",
            live=True,
            network=False,
            status="not_implemented",
            details={"challenge_id": challenge_id, "note": "Phase 4 keeps instancer as a skeleton only"},
        )

    def submit_flag(self, challenge_id: str, flag: str, live: bool = False, confirm: bool = False) -> PlatformAction:
        endpoint = "/api/v1/challenges/attempt"
        details = {
            "challenge_id": str(challenge_id),
            "endpoint": endpoint,
            "flag_hash": hash_flag(flag),
            "candidate_preview": redact_flag(flag),
            "confirm_requested": bool(confirm),
        }
        if not live:
            return self._planned("submit_flag", {**details, "live_required": True})
        if not self.base_url:
            return self._blocked("submit_flag", "missing_base_url", details=details)
        if not self._policy_allowed("allow_submission"):
            return self._blocked("submit_flag", "submission_not_allowed_by_policy", details=details)
        explicit_no_confirm_policy = bool(
            self.policy.get("allow_submit_without_confirm") or self.policy.get("allow_unconfirmed_submission")
        )
        if not confirm and not explicit_no_confirm_policy:
            return self._blocked("submit_flag", "live_submit_requires_confirm", details=details)
        challenge_value: str | int = _coerce_int(challenge_id) if _coerce_int(challenge_id) is not None else str(challenge_id)
        payload = {"challenge_id": challenge_value, "submission": flag}
        try:
            status_code, response = self._post_json(endpoint, payload)
        except (FileNotFoundError, KeyError, ValueError) as exc:
            return self._blocked("submit_flag", "auth_or_config_missing", details={**details, "error": redact_text(str(exc))})
        submit_status, summary = self._normalize_submit_response(status_code, response)
        return self._result(
            "submit_flag",
            live=True,
            network=True,
            status=submit_status,
            details={**details, "result_summary_redacted": summary},
        )

    def _normalize_submit_response(self, status_code: int, response: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        data = response.get("data") if isinstance(response.get("data"), Mapping) else {}
        status_text = str(data.get("status") or response.get("status") or "").strip().lower()
        message = str(data.get("message") or response.get("message") or "").strip()
        combined = f"{status_text} {message}".lower()
        if status_code == 429 or "rate limit" in combined or "too many" in combined or "slow down" in combined:
            status = "rate_limited"
        elif status_text in {"incorrect", "wrong", "rejected"} or "incorrect" in combined or "wrong" in combined:
            status = "rejected"
        elif status_text in {"correct", "accepted", "solved", "already_solved"} or "correct" in combined or "already solved" in combined:
            status = "accepted"
        else:
            status = "unknown"
        return status, {
            "http_status": status_code,
            "ctfd_status": status_text or "unknown",
            "message": redact_text(message)[:500],
        }


def load_platform_adapter(
    config_path: str | Path,
    *,
    urlopen: Callable[..., Any] | None = None,
) -> PlatformAdapter:
    loaded = load_config_metadata(config_path)
    if not loaded.get("exists"):
        raise FileNotFoundError("platform config not found")
    data = dict(loaded.get("data", {}))
    platform = str(data.get("platform") or "ctfd").strip().lower()
    if platform == "generic":
        from .platform_generic import GenericPlatform

        return GenericPlatform(config_path=config_path, config=data, urlopen=urlopen)
    if platform != "ctfd":
        raise ValueError(f"unsupported platform: {platform}")
    return CTFdPlatform(config_path=config_path, config=data, urlopen=urlopen)
