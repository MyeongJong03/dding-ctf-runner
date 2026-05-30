import contextlib
import io
import json
import re
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.prompt_templates import prompt_template


ROOT = Path(__file__).resolve().parents[1]


def test_readme_has_korean_quick_start():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## 한국어 Quick Start" in text
    assert "### 가장 쉬운 사용법" in text
    assert "Windows WSL: 최대 6개" in text
    assert "Mac: 최대 4개" in text
    assert "복잡한 `ctfctl` 명령은 Codex가 필요할 때 사용합니다" in text


def test_korean_prompt_template_doc_contains_required_policies():
    path = ROOT / "docs" / "prompt-templates.ko.md"
    text = path.read_text(encoding="utf-8")

    assert path.exists()
    assert "## 1. 일반 CTF 자동화 프롬프트" in text
    assert "## 2. DreamHack sessionid/csrf_token 프롬프트" in text
    assert "sessionid: [SESSIONID]" in text
    assert "csrf_token: [CSRF_TOKEN]" in text
    assert "raw flag는 풀이, 검증, 로컬 운영자 확인을 위해 로컬 터미널에 출력해도 된다" in text
    assert "public upload/commit/push/paste/writeup/snapshot" in text
    assert "accepted된 문제만 한국어 writeup" in text
    assert "못 푼 문제" in text


def test_prompt_template_has_placeholders_without_real_secret_values():
    result = prompt_template("dreamhack")
    prompt = result["prompt"]

    assert result["status"] == "ok"
    assert "sessionid: [SESSIONID]" in prompt
    assert "csrf_token: [CSRF_TOKEN]" in prompt
    assert "SESSIONID]" in prompt
    assert "CSRF_TOKEN]" in prompt
    assert not re.search(r"sessionid:\s*(?!\[SESSIONID\])\S+", prompt)
    assert not re.search(r"csrf_token:\s*(?!\[CSRF_TOKEN\])\S+", prompt)
    assert "Bearer " not in prompt
    assert "local raw flag output" not in prompt
    assert "flag 후보는 로컬 터미널에 출력해도 된다" in prompt
    assert "public repo, public paste, public issue, public writeup" in prompt


def test_prompt_template_cli_preserves_dreamhack_placeholders_in_json():
    data = _run_json(["interactive", "prompt-template", "--kind", "dreamhack", "--json"])
    prompt = data["prompt"]

    assert data["status"] == "ok"
    assert data["kind"] == "dreamhack"
    assert "sessionid: [SESSIONID]" in prompt
    assert "csrf_token: [CSRF_TOKEN]" in prompt
    assert "[REDACTED]" not in prompt
    assert "never accepts raw sessionid" in data["secret_handling"]


def _run_json(argv: list[str]) -> dict:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = main(argv)
    assert code == 0, output.getvalue()
    return json.loads(output.getvalue())
