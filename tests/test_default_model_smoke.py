from __future__ import annotations

import json

from ctf_runner import codex_smoke


def test_parse_observed_default_model_from_codex_header():
    output = """
OpenAI Codex
--------
workdir: /tmp/repo
model: gpt-5.3-codex
approval: never
--------
DEFAULT_MODEL_SMOKE_OK
"""

    assert codex_smoke.parse_observed_default_model(output) == "gpt-5.3-codex"


def test_default_model_smoke_uses_no_model_flag_and_does_not_emit_auth_or_config(monkeypatch, tmp_path):
    repo = tmp_path / "dding-ctf-runner"
    repo.mkdir()
    worker_home = tmp_path / ".codex-workers" / "worker-1"
    worker_home.mkdir(parents=True)
    (worker_home / "AGENTS.md").write_text("# slim\n", encoding="utf-8")
    (worker_home / "config.toml").write_text('model = "secret-config-model"\n', encoding="utf-8")
    auth_dir = tmp_path / ".codex"
    auth_dir.mkdir()
    (auth_dir / "auth.json").write_text('{"credential":"sensitive-auth-value"}\n', encoding="utf-8")

    fake_codex = tmp_path / "bin" / "codex"
    fake_codex.parent.mkdir()
    fake_codex.write_text(
        """#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo 'codex-cli 0.130.0'
  exit 0
fi
for arg in "$@"; do
  if [[ "$arg" == "--model" ]]; then
    echo 'unexpected model flag' >&2
    exit 9
  fi
done
printf 'OpenAI Codex\\n--------\\nmodel: gpt-5.3-codex\\n--------\\nDEFAULT_MODEL_SMOKE_OK\\n'
""",
        encoding="utf-8",
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CTF_CODEX_BIN", str(fake_codex))
    monkeypatch.setenv("CTF_CODEX_MODEL", "gpt-should-be-ignored")
    monkeypatch.setattr(codex_smoke, "repo_root", lambda: repo)

    result = codex_smoke.default_model_smoke("worker-1", timeout=5)
    encoded = json.dumps(result, sort_keys=True)

    assert result["ok"] is True
    assert result["observed_default_model"] == "gpt-5.3-codex"
    assert result["codex_version"] == "0.130.0"
    assert result["model_flag_used"] is False
    assert result["response_ok"] is True
    assert "sensitive-auth-value" not in encoded
    assert "secret-config-model" not in encoded
    assert "auth.json" not in encoded
    assert "config.toml" not in encoded
