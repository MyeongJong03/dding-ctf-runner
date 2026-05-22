from __future__ import annotations

import hashlib
import html as html_lib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .auth import AuthSecret, load_auth_metadata, load_auth_secret, load_config_metadata
from .paths import get_paths
from .platform_base import PlatformAction
from .redact import redact_text


DEFAULT_MAX_API_REQUESTS = 15
DEFAULT_MAX_DOWNLOADS_PER_CHALLENGE = 5
MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_JSON_SCAN_CHARS = 512 * 1024
MAX_BROWSER_RESPONSE_BODIES = 20
MAX_BROWSER_RESPONSE_BYTES = 256 * 1024
USER_AGENT = "dding-ctf-runner-live-readonly/0.1"

CHALLENGE_WORDS = ("challenge", "challenges", "problem", "problems", "task", "tasks", "card", "cards")
CONTEST_WORDS = ("contest", "contests", "competition", "competitions")
FILE_WORDS = ("file", "files", "attachment", "attachments", "download", "downloads")
API_WORDS = ("api", "graphql", "trpc")
DESTRUCTIVE_WORDS = (
    "attempt",
    "submit",
    "submission",
    "start",
    "instance",
    "deploy",
    "reset",
    "delete",
    "logout",
    "register",
    "password",
    "admin",
)
FILE_EXTENSIONS = {
    ".7z",
    ".apk",
    ".bin",
    ".bz2",
    ".cap",
    ".csv",
    ".dll",
    ".dmp",
    ".docx",
    ".elf",
    ".exe",
    ".gz",
    ".img",
    ".jar",
    ".json",
    ".log",
    ".pcap",
    ".pcapng",
    ".pdf",
    ".png",
    ".py",
    ".tar",
    ".tgz",
    ".txt",
    ".wasm",
    ".wav",
    ".zip",
}


@dataclass(frozen=True)
class FetchResult:
    status: str
    url: str
    final_url: str
    final_path: str
    http_status: int | None
    content_type: str
    body: str

    def public_summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "url": _redact_url(self.url),
            "final_url": _redact_url(self.final_url),
            "final_path": self.final_path,
            "http_status": self.http_status,
            "content_type": self.content_type,
        }


class _HTMLDiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, Any]] = []
        self.scripts: list[dict[str, str]] = []
        self.data_attributes: list[dict[str, str]] = []
        self._active_link: dict[str, Any] | None = None
        self._active_script: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        for name, value in attr_map.items():
            if name.startswith("data-") and value.strip():
                self.data_attributes.append({"tag": tag, "name": name, "value": value[:4096]})
        if tag in {"a", "area", "link", "button"}:
            href = attr_map.get("href") or attr_map.get("data-href") or attr_map.get("data-url")
            if href:
                entry = {
                    "tag": tag,
                    "href": href,
                    "text": "",
                    "id": attr_map.get("id", ""),
                    "class": attr_map.get("class", ""),
                    "download": "download" in attr_map,
                    "role": attr_map.get("role", ""),
                }
                self.links.append(entry)
                if tag == "a":
                    self._active_link = entry
        if tag == "script":
            self._active_script = {
                "id": attr_map.get("id", ""),
                "type": attr_map.get("type", ""),
                "src": attr_map.get("src", ""),
                "text": "",
            }

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a":
            self._active_link = None
        elif tag == "script" and self._active_script is not None:
            text = str(self._active_script.get("text") or "")
            self.scripts.append(
                {
                    "id": str(self._active_script.get("id") or ""),
                    "type": str(self._active_script.get("type") or ""),
                    "src": str(self._active_script.get("src") or ""),
                    "text": text[:MAX_JSON_SCAN_CHARS],
                }
            )
            self._active_script = None

    def handle_data(self, data: str) -> None:
        if self._active_link is not None:
            existing = str(self._active_link.get("text") or "")
            self._active_link["text"] = (existing + " " + data.strip()).strip()[:500]
        if self._active_script is not None:
            self._active_script["text"] = str(self._active_script.get("text") or "") + data


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = " ".join(data.split())
        if text:
            self.parts.append(text)


def fetch_page(
    url: str,
    auth: AuthSecret | Mapping[str, str] | None = None,
    *,
    live: bool = True,
    base_url: str | None = None,
    urlopen: Callable[..., Any] | None = None,
    timeout: int = 15,
    max_bytes: int = MAX_HTML_BYTES,
) -> FetchResult:
    """Fetch a page with GET only. The returned body is for internal parsing only."""
    if not live:
        return FetchResult(
            status="planned",
            url=url,
            final_url=url,
            final_path=_url_path(url),
            http_status=None,
            content_type="",
            body="",
        )
    opener = urlopen or urllib.request.urlopen
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "User-Agent": USER_AGENT,
    }
    if isinstance(auth, AuthSecret):
        headers.update(auth.build_headers(base_url=base_url or url))
    elif isinstance(auth, Mapping):
        headers.update(dict(auth))
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener(request, timeout=timeout) as response:  # noqa: S310 - live use is explicitly gated.
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raw = raw[:max_bytes]
            final_url = str(getattr(response, "url", "") or getattr(response, "geturl", lambda: url)() or url)
            status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
            content_type = str(response.headers.get("content-type", "")) if getattr(response, "headers", None) else ""
    except urllib.error.HTTPError as exc:
        return FetchResult(
            status=_status_for_http_code(int(exc.code)),
            url=url,
            final_url=str(getattr(exc, "url", "") or url),
            final_path=_url_path(str(getattr(exc, "url", "") or url)),
            http_status=int(exc.code),
            content_type=str(exc.headers.get("content-type", "")) if exc.headers else "",
            body="",
        )
    body = _decode_body(raw, content_type)
    return FetchResult(
        status="ok",
        url=url,
        final_url=final_url,
        final_path=_url_path(final_url),
        http_status=status_code,
        content_type=content_type,
        body=body,
    )


def discover_from_html(html: str, base_url: str, contest_url: str | None = None) -> dict[str, Any]:
    return _discover_from_html_internal(html, base_url=base_url, contest_url=contest_url, include_private=False)


def discover_api_candidates(
    html: str,
    network_hints: Iterable[Mapping[str, Any]] | None = None,
    *,
    base_url: str,
    contest_url: str | None = None,
    limit: int = 30,
) -> list[str]:
    candidates: list[str] = []
    base = base_url.rstrip("/")
    contest = contest_url or base_url
    contest_path = urllib.parse.urlsplit(contest).path.strip("/")
    contest_parts = [part for part in contest_path.split("/") if part]
    contest_id = contest_parts[-1] if contest_parts else ""

    for raw in _extract_urlish_strings(html[:MAX_JSON_SCAN_CHARS]):
        _append_candidate(candidates, raw, base_url=base, contest_url=contest)
    for hint in network_hints or []:
        raw_path = str(hint.get("path") or hint.get("url") or "")
        if raw_path:
            _append_candidate(candidates, raw_path, base_url=base, contest_url=contest)

    if contest_id:
        for template in (
            "/api/contests/{id}",
            "/api/contests/{id}/challenges",
            "/api/contests/{id}/problems",
            "/api/contests/{id}/tasks",
            "/api/contest/{id}",
            "/api/contest/{id}/challenges",
            "/api/contest/{id}/problems",
            "/api/contest/{id}/tasks",
            "/api/challenges",
            "/api/problems",
            "/api/tasks",
            "/contests/{id}/challenges",
            "/contests/{id}/problems",
            "/contests/{id}/tasks",
        ):
            _append_candidate(candidates, template.format(id=urllib.parse.quote(contest_id, safe="")), base_url=base, contest_url=contest)
    for fixed in ("/api/challenges", "/api/problems", "/api/tasks", "/trpc"):
        _append_candidate(candidates, fixed, base_url=base, contest_url=contest)

    deduped = _dedupe(candidates)
    return deduped[:limit]


def try_readonly_api_candidates(
    candidates: Iterable[str],
    auth: AuthSecret | Mapping[str, str] | None = None,
    *,
    live: bool = True,
    base_url: str | None = None,
    urlopen: Callable[..., Any] | None = None,
    max_requests: int = DEFAULT_MAX_API_REQUESTS,
) -> dict[str, Any]:
    if not live:
        return {"status": "planned", "max_requests": max_requests, "tried": [], "challenges": []}
    tried: list[dict[str, Any]] = []
    challenges: list[dict[str, Any]] = []
    for candidate in list(candidates)[:max_requests]:
        if _is_destructive_url(candidate):
            tried.append({"endpoint": _redact_url(candidate), "status": "blocked_destructive_path"})
            continue
        headers = {"Accept": "application/json,text/html;q=0.8,*/*;q=0.5", "User-Agent": USER_AGENT}
        if isinstance(auth, AuthSecret):
            headers.update(auth.build_headers(base_url=base_url or candidate))
        elif isinstance(auth, Mapping):
            headers.update(dict(auth))
        request = urllib.request.Request(candidate, headers=headers, method="GET")
        try:
            with (urlopen or urllib.request.urlopen)(request, timeout=15) as response:  # noqa: S310 - live use is gated.
                raw = response.read(MAX_HTML_BYTES + 1)
                if len(raw) > MAX_HTML_BYTES:
                    raw = raw[:MAX_HTML_BYTES]
                content_type = str(response.headers.get("content-type", "")) if getattr(response, "headers", None) else ""
                status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
        except urllib.error.HTTPError as exc:
            tried.append(
                {
                    "endpoint": _redact_url(candidate),
                    "status": _status_for_http_code(int(exc.code)),
                    "http_status": int(exc.code),
                }
            )
            continue
        except urllib.error.URLError as exc:
            tried.append({"endpoint": _redact_url(candidate), "status": "network_error", "message": redact_text(str(exc.reason))[:200]})
            continue

        body = _decode_body(raw, content_type)
        found: list[dict[str, Any]] = []
        parsed = _loads_json_maybe(body)
        if parsed is not None:
            found = _parse_challenges_from_json_internal(parsed, base_url=base_url or candidate, include_private=True)
            challenges.extend(found)
        elif "html" in content_type.lower():
            findings = _discover_from_html_internal(body, base_url=base_url or candidate, contest_url=candidate, include_private=True)
            found = list(findings.get("challenges") or [])
            challenges.extend(found)
        tried.append(
            {
                "endpoint": _redact_url(candidate),
                "status": "ok",
                "http_status": status_code,
                "content_type": content_type.split(";", 1)[0],
                "challenge_count": len(found),
            }
        )
    return {"status": "ok", "max_requests": max_requests, "tried": tried, "challenges": _merge_challenges(challenges)}


def parse_challenges_from_json(obj: Any, *, base_url: str | None = None) -> list[dict[str, Any]]:
    return _public_challenges(_parse_challenges_from_json_internal(obj, base_url=base_url, include_private=False))


def parse_next_data(html: str, *, base_url: str | None = None, contest_url: str | None = None) -> dict[str, Any]:
    parser = _HTMLDiscoveryParser()
    parser.feed(html or "")
    challenges: list[dict[str, Any]] = []
    embedded_json_count = 0
    for script in parser.scripts:
        script_id = str(script.get("id") or "").lower()
        script_type = str(script.get("type") or "").lower()
        text = html_lib.unescape(str(script.get("text") or ""))
        if not text.strip():
            continue
        parsed = _loads_json_maybe(text) if script_id == "__next_data__" or "json" in script_type else None
        if parsed is not None:
            embedded_json_count += 1
            challenges.extend(_parse_challenges_from_json_internal(parsed, base_url=base_url, include_private=True))
        if "self.__next_f.push" in text:
            rsc = _parse_rsc_payload_internal(text, base_url=base_url or contest_url, include_private=True)
            embedded_json_count += rsc["embedded_json_count"]
            challenges.extend(rsc["challenges"])
    merged = _merge_challenges(challenges)
    return {
        "challenge_count": len(merged),
        "challenges": _public_challenges(merged),
        "embedded_json_count": embedded_json_count,
    }


def parse_rsc_payload(text: str, *, base_url: str | None = None) -> list[dict[str, Any]]:
    result = _parse_rsc_payload_internal(text, base_url=base_url, include_private=False)
    return list(result.get("challenges") or [])


def parse_network_json(response: Any, *, base_url: str | None = None) -> list[dict[str, Any]]:
    if isinstance(response, bytes):
        text = _decode_body(response[:MAX_JSON_SCAN_CHARS], "application/json")
        parsed = _loads_json_maybe(text)
        if parsed is not None:
            return parse_challenges_from_json(parsed, base_url=base_url)
        return _discover_from_text_payload(text, base_url=base_url or "", contest_url=base_url, include_private=False)["challenges"]
    if isinstance(response, str):
        text = response[:MAX_JSON_SCAN_CHARS]
        parsed = _loads_json_maybe(text)
        if parsed is not None:
            return parse_challenges_from_json(parsed, base_url=base_url)
        return _discover_from_text_payload(text, base_url=base_url or "", contest_url=base_url, include_private=False)["challenges"]
    return parse_challenges_from_json(response, base_url=base_url)


def should_block_browser_request(method: str, url: str) -> tuple[bool, str]:
    if method.upper() not in {"GET", "HEAD"}:
        return True, "non_get_head_blocked"
    if _is_destructive_url(url):
        return True, "destructive_path_blocked"
    return False, ""


def browser_network_summary(url: str, method: str, status: int | None, content_type: str | None) -> dict[str, Any]:
    return {
        "method": method.upper(),
        "path": _url_path(url),
        "status": status,
        "content_type": str(content_type or "").split(";", 1)[0],
    }


class GenericPlatform:
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
        self._discovery_cache: dict[str, Any] | None = None

    @property
    def platform_name(self) -> str:
        return _safe_slug(str(self.config.get("name") or "generic"), "generic")

    @property
    def base_url(self) -> str | None:
        value = self.config.get("base_url") or self.config.get("url")
        return str(value).rstrip("/") if value else None

    @property
    def contest_url(self) -> str | None:
        value = self.config.get("contest_url") or self.config.get("contest")
        return str(value).strip() if value else None

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

    @property
    def max_api_requests(self) -> int:
        return _coerce_positive_int(self.config.get("max_api_requests"), DEFAULT_MAX_API_REQUESTS)

    @property
    def max_downloads_per_challenge(self) -> int:
        return _coerce_positive_int(self.config.get("max_downloads_per_challenge"), DEFAULT_MAX_DOWNLOADS_PER_CHALLENGE)

    def _result(self, action: str, live: bool, network: bool, status: str, details: dict[str, Any]) -> PlatformAction:
        return PlatformAction(action=action, live=live, network=network, status=status, details=details)

    def _planned(self, action: str, details: dict[str, Any]) -> PlatformAction:
        return self._result(action, live=False, network=False, status="planned", details=details)

    def _blocked(self, action: str, reason: str, *, live: bool = True, details: dict[str, Any] | None = None) -> PlatformAction:
        payload = {"reason": reason}
        if details:
            payload.update(details)
        return self._result(action, live=live, network=False, status="blocked", details=payload)

    def _challenge_default_raw_dir(self, challenge_id: str) -> Path:
        return (self.downloads_root / self.platform_name / _safe_slug(challenge_id, "challenge") / "raw").resolve()

    def discover_challenges(self, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned(
                "generic_discover",
                {
                    "platform": "generic",
                    "contest_url": _redact_url(self.contest_url or ""),
                    "live_required": True,
                    "max_api_requests": self.max_api_requests,
                },
            )
        precheck = self._live_discovery_precheck("generic_discover")
        if precheck is not None:
            return precheck
        try:
            result = self._discover_internal()
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return self._result(
                "generic_discover",
                live=True,
                network=False,
                status="blocked",
                details={"reason": "auth_or_config_missing", "error_type": exc.__class__.__name__},
            )
        return self._result(
            "generic_discover",
            live=True,
            network=True,
            status=result["status"],
            details=result["public"],
        )

    def get_challenge(self, challenge_id: str, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned("generic_get_challenge", {"challenge_id": str(challenge_id), "live_required": True})
        precheck = self._live_discovery_precheck("generic_get_challenge")
        if precheck is not None:
            return precheck
        try:
            result = self._discover_internal()
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return self._result(
                "generic_get_challenge",
                live=True,
                network=False,
                status="blocked",
                details={"reason": "auth_or_config_missing", "error_type": exc.__class__.__name__, "challenge_id": str(challenge_id)},
            )
        challenge = _find_challenge(result["internal_challenges"], challenge_id)
        if challenge is None:
            return self._result(
                "generic_get_challenge",
                live=True,
                network=True,
                status="not_found",
                details={"challenge_id": str(challenge_id), "attachments": [], "attachment_count": 0},
            )
        detail = self._enrich_challenge_detail(challenge)
        public = _public_challenge(detail)
        attachments = _public_attachments(detail.get("_attachments_private") or [])
        return self._result(
            "generic_get_challenge",
            live=True,
            network=True,
            status="ok",
            details={
                "challenge_id": str(challenge_id),
                "summary": public,
                "attachments": attachments,
                "attachment_count": len(attachments),
                "warnings": list(result["public"].get("warnings") or []),
            },
        )

    def download_attachments(self, challenge_id: str, dest_dir: str | None = None, live: bool = False) -> PlatformAction:
        raw_dir = Path(dest_dir).expanduser().resolve() if dest_dir else self._challenge_default_raw_dir(challenge_id)
        if not live:
            return self._planned(
                "generic_download_attachments",
                {
                    "challenge_id": str(challenge_id),
                    "dest_dir": _display_path(raw_dir),
                    "max_downloads": self.max_downloads_per_challenge,
                    "live_required": True,
                },
            )
        precheck = self._live_download_precheck("generic_download_attachments", challenge_id=str(challenge_id))
        if precheck is not None:
            return precheck
        try:
            result = self._discover_internal()
        except (FileNotFoundError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return self._result(
                "generic_download_attachments",
                live=True,
                network=False,
                status="blocked",
                details={"reason": "auth_or_config_missing", "error_type": exc.__class__.__name__, "challenge_id": str(challenge_id)},
            )
        challenge = _find_challenge(result["internal_challenges"], challenge_id)
        if challenge is None:
            return self._result(
                "generic_download_attachments",
                live=True,
                network=True,
                status="not_found",
                details={"challenge_id": str(challenge_id), "dest_dir": _display_path(raw_dir), "downloads": []},
            )
        detail = self._enrich_challenge_detail(challenge)
        attachments = list(detail.get("_attachments_private") or [])[: self.max_downloads_per_challenge]
        raw_dir.mkdir(parents=True, exist_ok=True)
        downloads: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        auth = load_auth_secret(self.config, live=True)
        for index, attachment in enumerate(attachments, start=1):
            url = str(attachment.get("url") or "")
            if not _is_http_url(url) or _is_destructive_url(url):
                failures.append({"filename": str(attachment.get("filename") or ""), "source": _redact_url(url), "status": "blocked_url"})
                continue
            filename = _sanitize_filename(str(attachment.get("filename") or ""), fallback=f"attachment-{index}.bin")
            target = _unique_path(raw_dir / filename)
            try:
                size, sha256 = self._download_file(url, target, auth)
            except urllib.error.HTTPError as exc:
                failures.append(
                    {
                        "filename": filename,
                        "source": _redact_url(url),
                        "status": _status_for_http_code(int(exc.code)),
                        "http_status": int(exc.code),
                    }
                )
                continue
            except urllib.error.URLError as exc:
                failures.append({"filename": filename, "source": _redact_url(url), "status": "network_error", "message": redact_text(str(exc.reason))[:200]})
                continue
            downloads.append(
                {
                    "filename": target.name,
                    "path": _display_path(target),
                    "fs_path": str(target),
                    "size": size,
                    "sha256": sha256,
                    "source": _redact_url(url),
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
            "generic_download_attachments",
            live=True,
            network=True,
            status=status,
            details={
                "challenge_id": str(challenge_id),
                "summary": _public_challenge(detail),
                "dest_dir": _display_path(raw_dir),
                "fs_dest_dir": str(raw_dir),
                "max_downloads": self.max_downloads_per_challenge,
                "attachment_count": len(detail.get("_attachments_private") or []),
                "download_count": len(downloads),
                "downloads": downloads,
                "failure_count": len(failures),
                "failures": failures,
            },
        )

    def get_text_detail(self, challenge_id: str, live: bool = False) -> dict[str, Any]:
        if not live:
            return {"status": "planned", "challenge_id": str(challenge_id), "live_required": True}
        precheck = self._live_discovery_precheck("generic_get_text_detail")
        if precheck is not None:
            return {"status": precheck.status, "challenge_id": str(challenge_id), "reason": precheck.details.get("reason")}
        result = self._discover_internal()
        challenge = _find_challenge(result["internal_challenges"], challenge_id)
        if challenge is None:
            return {"status": "not_found", "challenge_id": str(challenge_id)}
        detail = self._enrich_challenge_detail(challenge)
        return {"status": "ok", "challenge": detail, "public": _public_challenge(detail)}

    def text_ingest_candidates(self, live: bool = False, *, max_challenges: int = 20, max_detail_fetch: int = 20) -> dict[str, Any]:
        if not live:
            return {"status": "planned", "live_required": True, "challenges": []}
        precheck = self._live_discovery_precheck("generic_text_ingest_candidates")
        if precheck is not None:
            return {"status": precheck.status, "reason": precheck.details.get("reason"), "challenges": []}
        result = self._discover_internal()
        base_challenges = list(result["internal_challenges"] or [])[: max(1, max_challenges)]
        enriched: list[dict[str, Any]] = []
        detail_budget = max(0, max_detail_fetch)
        for index, challenge in enumerate(base_challenges):
            if index < detail_budget:
                enriched.append(self._enrich_challenge_detail(dict(challenge)))
            else:
                enriched.append(dict(challenge))
        return {
            "status": result["status"],
            "challenge_count": len(enriched),
            "challenges": enriched,
            "public_challenges": _public_challenges(enriched),
            "source_challenge_count": len(result["internal_challenges"] or []),
            "warnings": list(result["public"].get("warnings") or []),
        }

    def browser_discover(self, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned(
                "browser_discover",
                {
                    "platform": "generic",
                    "contest_url": _redact_url(self.contest_url or ""),
                    "live_required": True,
                    "read_only_navigation": True,
                },
            )
        precheck = self._live_discovery_precheck("browser_discover")
        if precheck is not None:
            return precheck
        assert self.base_url is not None and self.contest_url is not None
        network: list[dict[str, Any]] = []
        network_candidate_hints: list[dict[str, Any]] = []
        network_payloads: list[dict[str, str]] = []
        blocked: list[dict[str, Any]] = []
        context_metadata: dict[str, Any] = {}
        storage_key_summary: dict[str, Any] = {}
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # noqa: BLE001 - fallback to HTTP discovery.
            fallback = self.discover_challenges(live=True)
            return self._result(
                "browser_discover",
                live=True,
                network=fallback.network,
                status=fallback.status,
                details={
                    "browser_status": "unavailable",
                    "browser_error_type": exc.__class__.__name__,
                    "fallback": fallback.details,
                },
            )
        try:
            context_options, context_metadata = self._browser_context_options()
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(**context_options)

                def route_handler(route: Any, request: Any) -> None:
                    should_block, reason = should_block_browser_request(str(request.method), str(request.url))
                    if should_block:
                        blocked.append({"method": str(request.method).upper(), "path": _url_path(str(request.url)), "reason": reason})
                        route.abort()
                    else:
                        route.continue_()

                context.route("**/*", route_handler)

                def response_handler(response: Any) -> None:
                    headers = response.headers or {}
                    content_type = headers.get("content-type", "")
                    url = str(response.url)
                    network.append(
                        browser_network_summary(
                            url,
                            str(response.request.method),
                            int(response.status),
                            content_type,
                        )
                    )
                    if _same_origin(self.base_url or "", url):
                        network_candidate_hints.append({"url": url})
                    content_length = _coerce_int(headers.get("content-length"))
                    if (
                        len(network_payloads) < MAX_BROWSER_RESPONSE_BODIES
                        and _should_capture_browser_payload(url, str(content_type), self.base_url or "")
                        and (content_length is None or content_length <= MAX_BROWSER_RESPONSE_BYTES)
                    ):
                        try:
                            body = response.body()
                        except Exception:
                            return
                        if len(body) <= MAX_BROWSER_RESPONSE_BYTES:
                            network_payloads.append(
                                {
                                    "url": url,
                                    "content_type": str(content_type),
                                    "body": _decode_body(body, str(content_type))[:MAX_JSON_SCAN_CHARS],
                                }
                            )

                page = context.new_page()
                page.on("response", response_handler)
                page.goto(self.contest_url, wait_until="domcontentloaded", timeout=15000)
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except PlaywrightTimeoutError:
                    pass
                content = page.content()
                final_url = page.url
                storage_key_summary = _browser_storage_key_summary(page)
                context.close()
                browser.close()
        except Exception as exc:  # noqa: BLE001 - browser discovery must fail closed and fall back.
            fallback = self.discover_challenges(live=True)
            return self._result(
                "browser_discover",
                live=True,
                network=True,
                status=fallback.status,
                details={
                    "browser_status": "fallback_http",
                    "browser_error_type": exc.__class__.__name__,
                    "auth_context": context_metadata,
                    "network_requests": network[:100],
                    "blocked_requests": blocked[:100],
                    "storage_keys": storage_key_summary,
                    "fallback": fallback.details,
                },
            )

        findings = _discover_from_html_internal(content, base_url=self.base_url, contest_url=self.contest_url, include_private=True)
        network_challenges: list[dict[str, Any]] = []
        for payload in network_payloads:
            network_challenges.extend(
                _discover_from_text_payload(
                    payload.get("body", ""),
                    base_url=self.base_url,
                    contest_url=payload.get("url") or self.contest_url,
                    include_private=True,
                ).get("challenges", [])
            )
        candidates = discover_api_candidates(content, network_candidate_hints, base_url=self.base_url, contest_url=self.contest_url)
        api_probe = try_readonly_api_candidates(
            candidates,
            load_auth_secret(self.config, live=True),
            live=True,
            base_url=self.base_url,
            urlopen=self._urlopen,
            max_requests=self.max_api_requests,
        )
        challenges = _merge_challenges(
            list(findings.get("challenges") or []) + network_challenges + list(api_probe.get("challenges") or [])
        )
        return self._result(
            "browser_discover",
            live=True,
            network=True,
            status="ok",
            details={
                "browser_status": "ok",
                "auth_context": context_metadata,
                "contest_url": _redact_url(self.contest_url),
                "final_url": _redact_url(final_url),
                "final_path": _url_path(final_url),
                "challenge_count": len(challenges),
                "challenges": _public_challenges(challenges),
                "challenge_like_links": findings.get("challenge_like_links", []),
                "api_candidates": [_redact_url(item) for item in candidates],
                "api_results": api_probe.get("tried", []),
                "network_requests": network[:100],
                "captured_response_count": len(network_payloads),
                "blocked_requests": blocked[:100],
                "blocked_request_count": len(blocked),
                "storage_keys": storage_key_summary,
                "warnings": _browser_warnings(final_url, challenges, network, blocked),
            },
        )

    def start_instance(self, challenge_id: str, live: bool = False) -> PlatformAction:
        if not live:
            return self._planned("start_instance", {"challenge_id": str(challenge_id), "note": "generic live-readonly forbids instance start"})
        return self._blocked("start_instance", "instance_start_not_allowed_for_generic_live_readonly", details={"challenge_id": str(challenge_id)})

    def submit_flag(self, challenge_id: str, flag: str, live: bool = False, confirm: bool = False) -> PlatformAction:
        details = {"challenge_id": str(challenge_id), "confirm_requested": bool(confirm), "flag_hash": hashlib.sha256(flag.encode()).hexdigest()}
        if not live:
            return self._planned("submit_flag", {**details, "live_required": True})
        return self._blocked("submit_flag", "submission_not_supported_for_generic_live_readonly", details=details)

    def _live_discovery_precheck(self, action: str) -> PlatformAction | None:
        if not self.base_url:
            return self._blocked(action, "missing_base_url")
        if not self.contest_url:
            return self._blocked(action, "missing_contest_url")
        if not self.policy.get("allow_live_discovery", False):
            return self._blocked(action, "live_discovery_not_allowed_by_policy")
        auth = load_auth_metadata(self.config)
        if auth.get("method") not in {"manual", "cookie_header_file", "api_token_file", "storage_state_file"}:
            return self._blocked(action, "unsupported_auth_method", details={"auth_method": auth.get("method")})
        for fallback in auth.get("fallback") or []:
            if isinstance(fallback, Mapping) and fallback.get("method") not in {"manual", "cookie_header_file", "api_token_file", "storage_state_file"}:
                return self._blocked(action, "unsupported_auth_fallback_method", details={"auth_method": fallback.get("method")})
        if auth.get("effective_method") is None:
            return self._blocked(action, "auth_path_missing", details={"auth_method": auth.get("method")})
        return None

    def _live_download_precheck(self, action: str, *, challenge_id: str) -> PlatformAction | None:
        discovery = self._live_discovery_precheck(action)
        if discovery is not None:
            discovery.details["challenge_id"] = challenge_id
            return discovery
        if not self.policy.get("allow_live_download", False):
            return self._blocked(action, "live_download_not_allowed_by_policy", details={"challenge_id": challenge_id})
        return None

    def _discover_internal(self) -> dict[str, Any]:
        if self._discovery_cache is not None:
            return self._discovery_cache
        assert self.base_url is not None and self.contest_url is not None
        auth = load_auth_secret(self.config, live=True)
        page = fetch_page(self.contest_url, auth, live=True, base_url=self.base_url, urlopen=self._urlopen)
        warnings: list[str] = []
        if page.final_path.rstrip("/") in {"/login", "/signin"}:
            warnings.append("final_url_is_login_path")
        if page.status != "ok":
            result = {
                "status": page.status,
                "internal_challenges": [],
                "public": {
                    "platform": "generic",
                    "contest_url": _redact_url(self.contest_url),
                    "page": page.public_summary(),
                    "challenge_count": 0,
                    "challenges": [],
                    "api_candidates": [],
                    "api_results": [],
                    "warnings": warnings,
                },
            }
            self._discovery_cache = result
            return result
        html = page.body
        findings = _discover_from_html_internal(html, base_url=self.base_url, contest_url=self.contest_url, include_private=True)
        page_payload = _discover_from_text_payload(html, base_url=self.base_url, contest_url=self.contest_url, include_private=True)
        candidates = discover_api_candidates(html, [], base_url=self.base_url, contest_url=self.contest_url)
        api_probe = try_readonly_api_candidates(
            candidates,
            auth,
            live=True,
            base_url=self.base_url,
            urlopen=self._urlopen,
            max_requests=self.max_api_requests,
        )
        challenges = _merge_challenges(
            list(findings.get("challenges") or []) + list(page_payload.get("challenges") or []) + list(api_probe.get("challenges") or [])
        )
        if not challenges:
            warnings.append("no_challenges_found_by_http_discovery")
        result = {
            "status": "ok",
            "internal_challenges": challenges,
            "public": {
                "platform": "generic",
                "contest_url": _redact_url(self.contest_url),
                "page": page.public_summary(),
                "challenge_count": len(challenges),
                "challenges": _public_challenges(challenges),
                "challenge_like_links": findings.get("challenge_like_links", []),
                "embedded_json_count": int(findings.get("embedded_json_count") or 0) + int(page_payload.get("embedded_json_count") or 0),
                "api_candidates": [_redact_url(item) for item in candidates],
                "api_results": api_probe.get("tried", []),
                "selected_challenge": _public_challenge(challenges[0]) if challenges else None,
                "warnings": sorted(set(warnings + list(findings.get("warnings") or []))),
            },
        }
        self._discovery_cache = result
        return result

    def _enrich_challenge_detail(self, challenge: dict[str, Any]) -> dict[str, Any]:
        try:
            auth = load_auth_secret(self.config, live=True)
        except (FileNotFoundError, KeyError, ValueError):
            return challenge
        enriched = dict(challenge)
        for url in self._detail_url_candidates(challenge):
            page = fetch_page(url, auth, live=True, base_url=self.base_url, urlopen=self._urlopen, max_bytes=MAX_HTML_BYTES)
            if page.status != "ok" or not page.body:
                continue
            findings = _discover_from_html_internal(page.body, base_url=self.base_url or url, contest_url=url, include_private=True)
            nested = list(findings.get("challenges") or [])
            text_detail = _challenge_detail_from_html(page.body, url=url, base_url=self.base_url or url, challenge=enriched)
            candidates = [enriched, text_detail] if text_detail else [enriched]
            if nested:
                nested_match = _find_challenge(nested, str(challenge.get("challenge_id") or "")) or _best_detail_candidate(nested, challenge) or nested[0]
                candidates.append(nested_match)
            enriched = _merge_challenges(candidates)[0]
            attachments = list(enriched.get("_attachments_private") or []) + list(findings.get("_attachments_private") or [])
            enriched["_attachments_private"] = _dedupe_attachments(attachments)
            if _challenge_text_material(enriched) or attachments:
                break
        return enriched

    def _detail_url_candidates(self, challenge: Mapping[str, Any]) -> list[str]:
        candidates: list[str] = []
        base_url = self.base_url or ""
        contest_url = self.contest_url or base_url
        for raw in (challenge.get("url"),):
            if raw:
                _append_detail_candidate(candidates, str(raw), base_url=base_url, contest_url=contest_url)
        challenge_id = str(challenge.get("challenge_id") or "").strip()
        slug = str(challenge.get("slug") or "").strip()
        values = [value for value in (slug, challenge_id) if value]
        contest_path = urllib.parse.urlsplit(contest_url).path.rstrip("/")
        for value in values:
            quoted = urllib.parse.quote(value, safe="")
            for template in (
                "/challenges/{id}",
                "/challenge/{id}",
                "/problems/{id}",
                "/problem/{id}",
                "/tasks/{id}",
                "/task/{id}",
                f"{contest_path}/challenges/{{id}}",
                f"{contest_path}/challenge/{{id}}",
                f"{contest_path}/problems/{{id}}",
                f"{contest_path}/problem/{{id}}",
                f"{contest_path}/tasks/{{id}}",
                f"{contest_path}/task/{{id}}",
            ):
                _append_detail_candidate(candidates, template.format(id=quoted), base_url=base_url, contest_url=contest_url)
        return candidates[:8]

    def _download_file(self, url: str, dest: Path, auth: AuthSecret) -> tuple[int, str]:
        headers = {"Accept": "*/*", "User-Agent": USER_AGENT}
        headers.update(auth.build_headers(base_url=self.base_url or url))
        request = urllib.request.Request(url, headers=headers, method="GET")
        sha256 = hashlib.sha256()
        total = 0
        with self._urlopen(request, timeout=30) as response:  # noqa: S310 - live use is gated.
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

    def _browser_context_options(self) -> tuple[dict[str, Any], dict[str, Any]]:
        auth = load_auth_secret(self.config, live=True)
        metadata = {"auth_method": auth.method, "auth_source_role": auth.source_role, "auth_source_index": auth.source_index}
        if auth.method == "storage_state_file" and auth.path:
            metadata["storage_state"] = "configured"
            return {"storage_state": str(Path(auth.path.replace("~/", str(Path.home()) + "/", 1)).expanduser())}, metadata
        if auth.method == "cookie_header_file" and self.base_url:
            cookie_header = auth.build_headers(base_url=self.base_url).get("Cookie", "")
            cookies = cookie_header_to_browser_cookies(cookie_header, self.base_url)
            metadata["cookie_count"] = len(cookies)
            metadata["storage_state"] = "cookie_header_imported"
            return {"extra_http_headers": {"User-Agent": USER_AGENT}, "storage_state": {"cookies": cookies, "origins": []}}, metadata
        metadata["storage_state"] = "not_configured"
        return {"extra_http_headers": {"User-Agent": USER_AGENT}}, metadata


def cookie_header_to_browser_cookies(cookie_header: str, base_url: str) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlsplit(base_url)
    host = parsed.hostname or ""
    if not host:
        return []
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return []
    cookies: list[dict[str, Any]] = []
    for name, morsel in jar.items():
        if not name or not morsel.value:
            continue
        cookies.append(
            {
                "name": str(name),
                "value": str(morsel.value),
                "domain": host,
                "path": "/",
                "secure": parsed.scheme == "https",
                "httpOnly": False,
                "sameSite": "Lax",
            }
        )
    return cookies


def _discover_from_html_internal(html: str, *, base_url: str, contest_url: str | None, include_private: bool) -> dict[str, Any]:
    parser = _HTMLDiscoveryParser()
    parser.feed(html or "")
    url_base = contest_url or base_url
    warnings: list[str] = []
    challenge_like_links: list[dict[str, Any]] = []
    link_challenges: list[dict[str, Any]] = []
    page_attachments: list[dict[str, Any]] = []
    for link in parser.links:
        absolute = _absolute_url(url_base, str(link.get("href") or ""))
        if not absolute:
            continue
        text = " ".join(str(link.get(key) or "") for key in ("text", "id", "class", "role")).strip()
        if _is_attachment_link(absolute, text, bool(link.get("download"))):
            page_attachments.append(_attachment_from_url(absolute, text or Path(urllib.parse.urlsplit(absolute).path).name))
        if _is_challenge_like_url(absolute) or _contains_any(text.lower(), CHALLENGE_WORDS):
            summary = _challenge_from_link(absolute, text, base_url=base_url)
            if summary:
                link_challenges.append(summary)
                challenge_like_links.append(
                    {
                        "path": _url_path(absolute),
                        "url": _redact_url(absolute),
                        "text": redact_text(str(link.get("text") or ""))[:120],
                    }
                )
    json_values: list[Any] = []
    rsc_challenges: list[dict[str, Any]] = []
    rsc_embedded_json_count = 0
    for script in parser.scripts:
        script_id = str(script.get("id") or "").lower()
        script_type = str(script.get("type") or "").lower()
        text = html_lib.unescape(str(script.get("text") or ""))
        if not text.strip():
            continue
        if script_id == "__next_data__" or "json" in script_type:
            parsed = _loads_json_maybe(text)
            if parsed is not None:
                json_values.append(parsed)
                continue
        json_values.extend(_extract_json_values_from_text(text))
        if "self.__next_f.push" in text:
            rsc_findings = _parse_rsc_payload_internal(text, base_url=base_url, include_private=True)
            rsc_embedded_json_count += int(rsc_findings.get("embedded_json_count") or 0)
            rsc_challenges.extend(list(rsc_findings.get("challenges") or []))
    for attr in parser.data_attributes:
        value = html_lib.unescape(str(attr.get("value") or ""))
        parsed = _loads_json_maybe(value)
        if parsed is not None:
            json_values.append(parsed)
    json_challenges: list[dict[str, Any]] = []
    for value in json_values:
        json_challenges.extend(_parse_challenges_from_json_internal(value, base_url=base_url, include_private=True))
    challenges = _merge_challenges(link_challenges + json_challenges + rsc_challenges)
    if len(parser.scripts) > 0 and not json_values:
        warnings.append("scripts_present_no_parseable_embedded_json")
    result: dict[str, Any] = {
        "challenge_count": len(challenges),
        "challenges": challenges if include_private else _public_challenges(challenges),
        "challenge_like_links": challenge_like_links[:100],
        "embedded_json_count": len(json_values) + rsc_embedded_json_count,
        "warnings": warnings,
    }
    if include_private:
        result["_attachments_private"] = _dedupe_attachments(page_attachments)
    else:
        result["attachments"] = _public_attachments(page_attachments)
    return result


def _discover_from_text_payload(text: str, *, base_url: str, contest_url: str | None, include_private: bool) -> dict[str, Any]:
    parsed = _loads_json_maybe(text)
    challenges: list[dict[str, Any]] = []
    embedded_json_count = 0
    if parsed is not None:
        embedded_json_count += 1
        challenges.extend(_parse_challenges_from_json_internal(parsed, base_url=base_url, include_private=True))
    for value in _extract_json_values_from_text(text):
        embedded_json_count += 1
        challenges.extend(_parse_challenges_from_json_internal(value, base_url=base_url, include_private=True))
    html_findings = _discover_from_html_internal(text, base_url=base_url, contest_url=contest_url, include_private=True)
    challenges.extend(list(html_findings.get("challenges") or []))
    rsc_findings = _parse_rsc_payload_internal(text, base_url=base_url or contest_url, include_private=True)
    embedded_json_count += int(rsc_findings.get("embedded_json_count") or 0)
    challenges.extend(list(rsc_findings.get("challenges") or []))
    merged = _merge_challenges(challenges)
    return {
        "challenge_count": len(merged),
        "challenges": merged if include_private else _public_challenges(merged),
        "embedded_json_count": embedded_json_count + int(html_findings.get("embedded_json_count") or 0),
    }


def _parse_rsc_payload_internal(text: str, *, base_url: str | None, include_private: bool) -> dict[str, Any]:
    scan = (text or "")[:MAX_JSON_SCAN_CHARS]
    containers: list[Any] = []
    embedded_json_count = 0
    decoder = json.JSONDecoder()
    for match in re.finditer(r"self\.__next_f\.push\(", scan):
        start = match.end()
        while start < len(scan) and scan[start].isspace():
            start += 1
        try:
            parsed, _ = decoder.raw_decode(scan[start:])
        except json.JSONDecodeError:
            continue
        containers.append(parsed)
        embedded_json_count += 1
        if len(containers) >= 30:
            break
    for value in _extract_json_values_from_text(scan):
        containers.append(value)
        embedded_json_count += 1
        if len(containers) >= 60:
            break

    challenges: list[dict[str, Any]] = []
    strings: list[str] = []
    for container in containers:
        challenges.extend(_parse_challenges_from_json_internal(container, base_url=base_url, include_private=True))
        strings.extend(_collect_strings(container, limit=200))
    for chunk in strings[:200]:
        for candidate_text in _rsc_string_variants(chunk):
            parsed = _loads_json_maybe(candidate_text)
            if parsed is not None:
                embedded_json_count += 1
                challenges.extend(_parse_challenges_from_json_internal(parsed, base_url=base_url, include_private=True))
            for value in _extract_json_values_from_text(candidate_text):
                embedded_json_count += 1
                challenges.extend(_parse_challenges_from_json_internal(value, base_url=base_url, include_private=True))
    merged = _merge_challenges(challenges)
    return {
        "challenge_count": len(merged),
        "challenges": merged if include_private else _public_challenges(merged),
        "embedded_json_count": embedded_json_count,
    }


def _collect_strings(value: Any, *, limit: int) -> list[str]:
    found: list[str] = []

    def walk(item: Any) -> None:
        if len(found) >= limit:
            return
        if isinstance(item, str):
            if _contains_any(item.lower(), CHALLENGE_WORDS + FILE_WORDS + CONTEST_WORDS):
                found.append(item[:MAX_JSON_SCAN_CHARS])
            return
        if isinstance(item, Mapping):
            for child in item.values():
                walk(child)
                if len(found) >= limit:
                    return
        elif isinstance(item, list):
            for child in item[:500]:
                walk(child)
                if len(found) >= limit:
                    return

    walk(value)
    return found


def _rsc_string_variants(text: str) -> list[str]:
    variants = [html_lib.unescape(text)]
    if "\\\"" in text or "\\u" in text:
        try:
            decoded = bytes(text, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            decoded = ""
        if decoded:
            variants.append(html_lib.unescape(decoded))
    deduped: list[str] = []
    for variant in variants:
        if variant and variant not in deduped:
            deduped.append(variant[:MAX_JSON_SCAN_CHARS])
    return deduped


def _parse_challenges_from_json_internal(obj: Any, *, base_url: str | None, include_private: bool) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(value: Any, path: tuple[str, ...], depth: int) -> None:
        if depth > 12:
            return
        if isinstance(value, Mapping):
            if _looks_like_challenge(value, path):
                summary = _challenge_from_mapping(value, base_url=base_url)
                if summary:
                    found.append(summary)
            for key, child in value.items():
                walk(child, path + (str(key).lower(),), depth + 1)
        elif isinstance(value, list):
            for child in value[:500]:
                walk(child, path, depth + 1)

    walk(obj, tuple(), 0)
    challenges = _merge_challenges(found)
    return challenges if include_private else _public_challenges(challenges)


def _looks_like_challenge(item: Mapping[str, Any], path: tuple[str, ...]) -> bool:
    keys = {str(key).lower() for key in item.keys()}
    path_text = "/".join(path)
    if "flag" in keys or "submission" in keys:
        return False
    has_name = bool(keys & {"name", "title", "displayname", "display_name"})
    has_id = bool(keys & {"id", "challenge_id", "slug", "uuid"})
    indicators = keys & {
        "category",
        "points",
        "value",
        "score",
        "solves",
        "solve_count",
        "solved_count",
        "files",
        "attachments",
        "downloads",
        "description",
        "prompt",
        "connection_info",
    }
    if _contains_any(path_text, FILE_WORDS) and not indicators and not has_id:
        return False
    if (has_name or has_id) and indicators:
        return True
    if (has_name or has_id) and _contains_any(path_text, CHALLENGE_WORDS + ("cards",)):
        return True
    url = str(item.get("url") or item.get("href") or item.get("path") or "")
    return (has_name or has_id) and bool(url) and _is_challenge_like_url(url)


def _challenge_from_mapping(item: Mapping[str, Any], *, base_url: str | None) -> dict[str, Any] | None:
    raw_id = item.get("id") or item.get("challenge_id") or item.get("slug") or item.get("uuid")
    slug = _first_string(item, ("slug", "handle", "key"))
    raw_url = _first_string(item, ("url", "href", "path", "link"))
    url = _absolute_url(base_url or "", raw_url) if raw_url else ""
    name = _first_string(item, ("name", "title", "display_name", "displayName")) or str(raw_id or "")
    challenge_id = str(raw_id or _id_from_url(url) or name).strip()
    if not challenge_id and not name:
        return None
    category = item.get("category")
    if isinstance(category, Mapping):
        category_value = _first_string(category, ("name", "title", "slug"))
    else:
        category_value = str(category or "")
    attachments = _extract_attachments_from_mapping(item, base_url=base_url)
    solved = item.get("solved")
    if solved is None:
        solved = item.get("solved_by_me", item.get("completed"))
    statement = _first_text(item, ("description", "body", "statement", "prompt", "content", "text", "markdown", "instructions", "details"))
    hints = _extract_text_list(item, ("hints", "hint", "tips"))
    tags = _extract_text_list(item, ("tags", "tag", "labels", "topics"))
    connection_info = _first_text(
        item,
        ("connection_info", "connectionInfo", "connection", "server", "service", "host", "netcat", "nc", "remote"),
        max_len=2000,
    )
    author = _first_text(item, ("author", "creator", "created_by", "createdBy"), max_len=500)
    deadline = _first_text(item, ("deadline", "ends_at", "endsAt", "end_time", "endTime", "visible_until", "visibleUntil"), max_len=500)
    state = _first_text(item, ("state", "status", "phase"), max_len=500)
    links = _extract_links_from_mapping(item, base_url=base_url)
    summary = {
        "challenge_id": challenge_id or name,
        "slug": slug,
        "name": name or challenge_id,
        "category": category_value,
        "points": _coerce_int(item.get("points", item.get("value", item.get("score")))),
        "solves": _coerce_int(item.get("solves", item.get("solve_count", item.get("solved_count")))),
        "solved": bool(solved) if solved is not None else None,
        "has_files": bool(attachments),
        "file_count": len(attachments),
        "url": url,
        "statement": redact_text(statement) if statement else "",
        "hints": [redact_text(str(hint)) for hint in hints],
        "tags": [redact_text(str(tag)) for tag in tags],
        "connection_info": redact_text(connection_info) if connection_info else "",
        "author": redact_text(author) if author else "",
        "deadline": redact_text(deadline) if deadline else "",
        "state": redact_text(state) if state else "",
        "_links_private": links,
        "_attachments_private": attachments,
    }
    return summary


def _challenge_from_link(url: str, text: str, *, base_url: str) -> dict[str, Any] | None:
    parsed = urllib.parse.urlsplit(url)
    challenge_id = _id_from_url(url) or parsed.path.strip("/").split("/")[-1]
    if not challenge_id:
        return None
    name = text.strip() or challenge_id
    return {
        "challenge_id": challenge_id,
        "name": name[:160],
        "category": "",
        "points": None,
        "solves": None,
        "solved": None,
        "has_files": False,
        "file_count": 0,
        "url": _absolute_url(base_url, url) or url,
        "_attachments_private": [],
    }


def _challenge_detail_from_html(html: str, *, url: str, base_url: str, challenge: Mapping[str, Any]) -> dict[str, Any] | None:
    visible = _visible_text_from_html(html)
    if not visible:
        return None
    name = str(challenge.get("name") or "").strip()
    statement = _trim_visible_detail_text(visible, name)
    if not statement:
        return None
    parser = _HTMLDiscoveryParser()
    parser.feed(html or "")
    links: list[dict[str, str]] = []
    attachments: list[dict[str, Any]] = []
    for link in parser.links:
        absolute = _absolute_url(url, str(link.get("href") or ""))
        if not absolute:
            continue
        text = " ".join(str(link.get(key) or "") for key in ("text", "id", "class", "role")).strip()
        if _is_attachment_link(absolute, text, bool(link.get("download"))):
            attachments.append(_attachment_from_url(absolute, text or Path(urllib.parse.urlsplit(absolute).path).name))
        elif _same_origin(base_url, absolute):
            links.append({"label": redact_text(text)[:200], "url": _redact_url(absolute)})
    return {
        "challenge_id": str(challenge.get("challenge_id") or _id_from_url(url) or name),
        "slug": str(challenge.get("slug") or ""),
        "name": name or str(challenge.get("challenge_id") or ""),
        "category": str(challenge.get("category") or ""),
        "points": _coerce_int(challenge.get("points")),
        "solves": _coerce_int(challenge.get("solves")),
        "solved": challenge.get("solved"),
        "url": url,
        "statement": redact_text(statement),
        "hints": _extract_hint_lines(statement),
        "tags": list(challenge.get("tags") or []),
        "_links_private": _dedupe_links(links),
        "_attachments_private": _dedupe_attachments(attachments),
    }


def _visible_text_from_html(html: str) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(html or "")
    except Exception:
        return ""
    text = "\n".join(parser.parts)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return redact_text(text[:MAX_JSON_SCAN_CHARS]).strip()


def _trim_visible_detail_text(text: str, name: str) -> str:
    cleaned = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    if not cleaned:
        return ""
    if name and name in cleaned:
        start = cleaned.find(name)
        cleaned = cleaned[start:]
    return cleaned[:20000]


def _extract_hint_lines(text: str) -> list[str]:
    hints: list[str] = []
    for line in text.splitlines():
        if "hint" in line.lower():
            hints.append(line.strip()[:1200])
    return _dedupe_texts(hints[:20])


def _best_detail_candidate(challenges: Iterable[Mapping[str, Any]], target: Mapping[str, Any]) -> dict[str, Any] | None:
    target_name = str(target.get("name") or "").strip().lower()
    for item in challenges:
        if str(item.get("name") or "").strip().lower() == target_name and target_name:
            return dict(item)
    return None


def _challenge_text_material(challenge: Mapping[str, Any]) -> str:
    parts = [
        str(challenge.get("statement") or ""),
        "\n".join(str(item) for item in challenge.get("hints") or []),
        str(challenge.get("connection_info") or ""),
    ]
    return redact_text("\n".join(part for part in parts if part).strip())


def _extract_attachments_from_mapping(item: Mapping[str, Any], *, base_url: str | None) -> list[dict[str, Any]]:
    raw_items: list[Any] = []
    for key in ("files", "attachments", "downloads", "downloadables"):
        value = item.get(key)
        if isinstance(value, list):
            raw_items.extend(value)
        elif isinstance(value, (str, Mapping)):
            raw_items.append(value)
    attachments: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_items, start=1):
        raw_url = ""
        raw_name = ""
        if isinstance(raw, str):
            raw_url = raw
        elif isinstance(raw, Mapping):
            raw_url = _first_string(raw, ("url", "href", "path", "location", "download_url", "signed_url"))
            raw_name = _first_string(raw, ("name", "filename", "title"))
        if not raw_url:
            continue
        absolute = _absolute_url(base_url or "", raw_url)
        if not absolute:
            continue
        fallback = Path(urllib.parse.urlsplit(absolute).path).name or f"attachment-{index}.bin"
        attachments.append(_attachment_from_url(absolute, raw_name or fallback, index=index))
    return _dedupe_attachments(attachments)


def _extract_links_from_mapping(item: Mapping[str, Any], *, base_url: str | None) -> list[dict[str, str]]:
    raw_items: list[Any] = []
    for key in ("links", "resources", "urls", "references"):
        value = item.get(key)
        if isinstance(value, list):
            raw_items.extend(value)
        elif isinstance(value, (str, Mapping)):
            raw_items.append(value)
    links: list[dict[str, str]] = []
    for raw in raw_items[:100]:
        label = ""
        raw_url = ""
        if isinstance(raw, str):
            raw_url = raw
        elif isinstance(raw, Mapping):
            raw_url = _first_string(raw, ("url", "href", "path", "link"))
            label = _first_string(raw, ("name", "title", "label"))
        absolute = _absolute_url(base_url or "", raw_url) if raw_url else ""
        if not absolute:
            continue
        links.append({"label": redact_text(label)[:200], "url": _redact_url(absolute)})
    deduped: dict[str, dict[str, str]] = {}
    for link in links:
        deduped.setdefault(link["url"], link)
    return list(deduped.values())


def _first_text(item: Mapping[str, Any], keys: Iterable[str], *, max_len: int = 12000) -> str:
    for key in keys:
        value = item.get(key)
        text = _text_from_value(value)
        if text:
            return text[:max_len]
    return ""


def _text_from_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, Mapping):
        return _first_text(value, ("text", "body", "content", "description", "value", "message", "title", "name"))
    if isinstance(value, list):
        parts = [_text_from_value(item) for item in value[:20]]
        return "\n".join(part for part in parts if part).strip()
    return ""


def _extract_text_list(item: Mapping[str, Any], keys: Iterable[str]) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = item.get(key)
        if raw is None:
            continue
        if isinstance(raw, list):
            for child in raw[:50]:
                text = _text_from_value(child)
                if text:
                    values.append(text[:1200])
        else:
            text = _text_from_value(raw)
            if text:
                values.append(text[:1200])
    deduped: list[str] = []
    for value in values:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _attachment_from_url(url: str, name: str = "", *, index: int = 1) -> dict[str, Any]:
    fallback = Path(urllib.parse.urlsplit(url).path).name or f"attachment-{index}.bin"
    filename = _sanitize_filename(name or fallback, fallback=f"attachment-{index}.bin")
    return {"filename": filename, "url": url, "source": _redact_url(url)}


def _public_challenges(challenges: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [_public_challenge(item) for item in challenges]


def _public_challenge(item: Mapping[str, Any]) -> dict[str, Any]:
    attachments = list(item.get("_attachments_private") or [])
    hints = list(item.get("hints") or [])
    tags = list(item.get("tags") or [])
    links = list(item.get("_links_private") or item.get("links") or [])
    statement = str(item.get("statement") or "").strip()
    connection_info = str(item.get("connection_info") or "").strip()
    public = {
        "challenge_id": str(item.get("challenge_id") or ""),
        "name": redact_text(str(item.get("name") or ""))[:200],
        "category": redact_text(str(item.get("category") or ""))[:120],
        "points": _coerce_int(item.get("points")),
        "solves": _coerce_int(item.get("solves")),
        "solved": item.get("solved") if item.get("solved") is None else bool(item.get("solved")),
        "has_files": bool(attachments) or bool(item.get("has_files")),
        "file_count": len(attachments) if attachments else _coerce_int(item.get("file_count")) or 0,
        "detail_text_found": bool(statement or hints or connection_info),
        "statement_bytes": len(statement.encode("utf-8")),
        "hint_count": len(hints),
        "tag_count": len(tags),
        "link_count": len(links),
        "connection_info_present": bool(connection_info),
    }
    if item.get("slug"):
        public["slug"] = redact_text(str(item.get("slug")))[:160]
    if item.get("url"):
        public["url"] = _redact_url(str(item.get("url")))
    if attachments:
        public["attachments"] = _public_attachments(attachments)
    if links:
        public["links"] = _public_links(links)
    return public


def _public_attachments(attachments: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "filename": _sanitize_filename(str(item.get("filename") or ""), fallback="attachment.bin"),
            "source": _redact_url(str(item.get("source") or item.get("url") or "")),
        }
        for item in attachments
        if item.get("source") or item.get("url")
    ]


def _public_links(links: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "label": redact_text(str(item.get("label") or ""))[:160],
            "url": _redact_url(str(item.get("url") or "")),
        }
        for item in links
        if item.get("url")
    ][:50]


def _merge_challenges(challenges: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in challenges:
        if not isinstance(raw, Mapping):
            continue
        item = dict(raw)
        key = str(item.get("challenge_id") or item.get("url") or item.get("name") or "").strip()
        if not key:
            continue
        if key not in merged:
            merged[key] = item
            order.append(key)
            continue
        current = merged[key]
        for field in (
            "slug",
            "name",
            "category",
            "points",
            "solves",
            "solved",
            "url",
            "statement",
            "connection_info",
            "author",
            "deadline",
            "state",
        ):
            if current.get(field) in {None, ""} and item.get(field) not in {None, ""}:
                current[field] = item[field]
            elif field == "statement" and len(str(item.get(field) or "")) > len(str(current.get(field) or "")):
                current[field] = item[field]
        for list_field in ("hints", "tags"):
            current[list_field] = _dedupe_texts(list(current.get(list_field) or []) + list(item.get(list_field) or []))
        links = list(current.get("_links_private") or []) + list(item.get("_links_private") or item.get("links") or [])
        current["_links_private"] = _dedupe_links(links)
        attachments = list(current.get("_attachments_private") or []) + list(item.get("_attachments_private") or [])
        current["_attachments_private"] = _dedupe_attachments(attachments)
        current["has_files"] = bool(current["_attachments_private"]) or bool(current.get("has_files")) or bool(item.get("has_files"))
        current["file_count"] = len(current["_attachments_private"]) if current["_attachments_private"] else max(
            _coerce_int(current.get("file_count")) or 0,
            _coerce_int(item.get("file_count")) or 0,
        )
    return [merged[key] for key in order]


def _find_challenge(challenges: Iterable[Mapping[str, Any]], challenge_id: str) -> dict[str, Any] | None:
    target = str(challenge_id)
    for item in challenges:
        if str(item.get("challenge_id") or "") == target:
            return dict(item)
    for item in challenges:
        if _safe_slug(str(item.get("challenge_id") or ""), "x") == _safe_slug(target, "x"):
            return dict(item)
    return None


def _extract_json_values_from_text(text: str) -> list[Any]:
    values: list[Any] = []
    decoder = json.JSONDecoder()
    scan = text[:MAX_JSON_SCAN_CHARS]
    for match in re.finditer(r"[\[{]", scan):
        try:
            parsed, end = decoder.raw_decode(scan[match.start() :])
        except json.JSONDecodeError:
            continue
        if end > 2 and _json_value_interesting(parsed):
            values.append(parsed)
            if len(values) >= 20:
                break
    return values


def _json_value_interesting(value: Any) -> bool:
    rendered = json.dumps(value, sort_keys=True, default=str)[:4096].lower()
    return _contains_any(rendered, CHALLENGE_WORDS + FILE_WORDS + API_WORDS)


def _loads_json_maybe(text: str) -> Any | None:
    text = text.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_urlish_strings(text: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"""["']((?:https?://[^"'<>\\\s]+)|(?:/(?:api|graphql|trpc|contests?|challenges?|problems?|tasks?)[^"'<>\\\s]*))["']""", text, re.I):
        values.append(html_lib.unescape(match.group(1)))
    return values


def _append_candidate(candidates: list[str], raw: str, *, base_url: str, contest_url: str) -> None:
    absolute = _absolute_url(base_url, raw)
    if not absolute:
        return
    if not _same_origin(base_url, absolute):
        return
    parsed = urllib.parse.urlsplit(absolute)
    lowered = parsed.path.lower()
    if _is_destructive_url(absolute):
        return
    if not (_contains_any(lowered, API_WORDS) or _same_path_family(contest_url, absolute)):
        return
    candidates.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")))


def _append_detail_candidate(candidates: list[str], raw: str, *, base_url: str, contest_url: str) -> None:
    absolute = _absolute_url(base_url, raw)
    if not absolute:
        return
    if not _same_origin(base_url, absolute):
        return
    if _is_destructive_url(absolute):
        return
    parsed = urllib.parse.urlsplit(absolute)
    normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    if normalized == _redact_url(contest_url):
        return
    if normalized not in candidates:
        candidates.append(normalized)


def _same_path_family(contest_url: str, candidate: str) -> bool:
    contest_parts = [part for part in urllib.parse.urlsplit(contest_url).path.split("/") if part]
    candidate_path = urllib.parse.urlsplit(candidate).path
    return bool(contest_parts and contest_parts[-1] in candidate_path)


def _browser_warnings(final_url: str, challenges: list[dict[str, Any]], network: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    if _url_path(final_url).rstrip("/") in {"/login", "/signin"}:
        warnings.append("final_url_is_login_path")
    if not challenges:
        warnings.append("no_challenges_found_by_browser_discovery")
    if blocked:
        warnings.append("browser_blocked_non_get_or_destructive_requests")
    if any(item.get("status") == 429 for item in network):
        warnings.append("rate_limited_response_seen")
    return sorted(set(warnings))


def _browser_storage_key_summary(page: Any) -> dict[str, Any]:
    try:
        summary = page.evaluate(
            """() => ({
                localStorageKeys: Object.keys(window.localStorage || {}),
                sessionStorageKeys: Object.keys(window.sessionStorage || {})
            })"""
        )
    except Exception:
        return {"local_storage_key_count": 0, "session_storage_key_count": 0, "keys_available": False}
    local_keys = summary.get("localStorageKeys") if isinstance(summary, Mapping) else []
    session_keys = summary.get("sessionStorageKeys") if isinstance(summary, Mapping) else []
    if not isinstance(local_keys, list):
        local_keys = []
    if not isinstance(session_keys, list):
        session_keys = []
    return {
        "keys_available": True,
        "local_storage_key_count": len(local_keys),
        "session_storage_key_count": len(session_keys),
        "local_storage_keys": [redact_text(str(key))[:120] for key in local_keys[:50]],
        "session_storage_keys": [redact_text(str(key))[:120] for key in session_keys[:50]],
    }


def _should_capture_browser_payload(url: str, content_type: str, base_url: str) -> bool:
    if not _same_origin(base_url, url):
        return False
    lowered = content_type.lower()
    return any(marker in lowered for marker in ("application/json", "text/x-component"))


def _is_attachment_link(url: str, text: str, download_attr: bool) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    suffix = Path(path).suffix.lower()
    lowered = text.lower()
    return download_attr or suffix in FILE_EXTENSIONS or _contains_any(path, FILE_WORDS) or _contains_any(lowered, FILE_WORDS)


def _is_challenge_like_url(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return _contains_any(path, CHALLENGE_WORDS)


def _is_destructive_url(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return _contains_any(path, DESTRUCTIVE_WORDS)


def _is_http_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _absolute_url(base_url: str, value: str) -> str:
    value = str(value or "").strip()
    if not value or value.startswith(("javascript:", "mailto:", "tel:", "#")):
        return ""
    absolute = urllib.parse.urljoin(base_url.rstrip("/") + "/", value)
    return absolute if _is_http_url(absolute) else ""


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urllib.parse.urlsplit(base_url)
    other = urllib.parse.urlsplit(candidate)
    return base.scheme == other.scheme and base.netloc == other.netloc


def _redact_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return redact_text(value)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _url_path(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    return parsed.path or "/"


def _status_for_http_code(code: int) -> str:
    if code in {401, 403}:
        return "auth_required"
    if code == 404:
        return "not_found"
    if code == 429:
        return "rate_limited"
    return "http_error"


def _decode_body(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _first_string(item: Mapping[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and not isinstance(value, (Mapping, list)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _id_from_url(url: str) -> str:
    try:
        parts = [part for part in urllib.parse.urlsplit(url).path.split("/") if part]
    except ValueError:
        return ""
    for marker in ("challenge", "challenges", "problem", "problems", "task", "tasks"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    return parts[-1] if parts else ""


def _coerce_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_positive_int(value: Any, fallback: int) -> int:
    parsed = _coerce_int(value)
    return parsed if parsed and parsed > 0 else fallback


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


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}.{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def _contains_any(value: str, needles: Iterable[str]) -> bool:
    return any(needle in value for needle in needles)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _dedupe_texts(values: Iterable[Any]) -> list[str]:
    return _dedupe(redact_text(str(value)).strip() for value in values if str(value or "").strip())


def _dedupe_links(links: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for item in links:
        url = _redact_url(str(item.get("url") or ""))
        if not url or url in seen:
            continue
        seen.add(url)
        result.append({"label": redact_text(str(item.get("label") or ""))[:200], "url": url})
    return result


def _dedupe_attachments(attachments: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in attachments:
        url = str(item.get("url") or item.get("source") or "")
        filename = str(item.get("filename") or "")
        key = url or filename
        if not url or key in seen:
            continue
        seen.add(key)
        result.append(dict(item))
    return result
