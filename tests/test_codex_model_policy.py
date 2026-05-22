from __future__ import annotations

from ctf_runner import codex_profile


def _launch_argv(monkeypatch, tmp_path, model_value: str | None):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CTF_CODEX_BIN", str(tmp_path / "codex"))
    if model_value is None:
        monkeypatch.delenv("CTF_CODEX_MODEL", raising=False)
    else:
        monkeypatch.setenv("CTF_CODEX_MODEL", model_value)
    return codex_profile.codex_launch_plan("worker-1", "interactive")["argv"]


def test_default_wrapper_command_has_no_model_flag(monkeypatch, tmp_path):
    argv = _launch_argv(monkeypatch, tmp_path, None)

    assert "--model" not in argv


def test_empty_model_env_has_no_model_flag(monkeypatch, tmp_path):
    argv = _launch_argv(monkeypatch, tmp_path, "")

    assert "--model" not in argv


def test_auto_model_env_has_no_model_flag(monkeypatch, tmp_path):
    argv = _launch_argv(monkeypatch, tmp_path, "auto")

    assert "--model" not in argv


def test_concrete_model_env_adds_exactly_one_model_flag(monkeypatch, tmp_path):
    argv = _launch_argv(monkeypatch, tmp_path, "gpt-test")

    assert argv.count("--model") == 1
    model_index = argv.index("--model")
    assert argv[model_index + 1] == "gpt-test"
