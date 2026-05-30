# 대회 당일 Runbook

이것만 하면 됩니다. 복잡한 내부 명령은 Codex가 필요할 때 사용합니다.

## 1. 시작

1. 대회 정보 준비:
   - 대회 이름: `[대회명]`
   - 대회 URL: `[대회 URL]`
   - 플랫폼: `[DreamHack / CTFd / Generic / 기타]`
   - 라이트업 저장 경로: `[로컬 경로]`

2. Codex 터미널 열기:
   - Windows WSL: 최대 6개 권장.
   - Mac: 최대 4개 권장.

   ```bash
   cd ~/CTF
   codex
   ```

3. 프롬프트 붙여넣기:
   - 일반 대회: [docs/prompt-templates.ko.md](docs/prompt-templates.ko.md)의 일반 템플릿.
   - DreamHack: 같은 문서의 `sessionid`/`csrf_token` 템플릿.
   - `[]` 부분만 바꿉니다.

   템플릿만 출력:

   ```bash
   ./scripts/ctfctl interactive prompt-template --kind general
   ./scripts/ctfctl interactive prompt-template --kind dreamhack
   ```

`sessionid`, `csrf_token`, cookie, token 같은 raw secret은 CLI 인자로 넘기지 않습니다.

## 2. 중단

Codex에게 이렇게 말합니다.

```text
지금 진행 중인 시도를 안전하게 정리하고 멈춰라. raw secret이나 flag를 public에 남기지 말고, memory/evidence/attempts/next_steps만 compact하게 기록해라.
```

Codex는 사용자가 중단하라고 하기 전까지, 대회가 끝나기 전까지, 또는 모든 문제가 solved/stalled 처리되기 전까지 임의로 멈추지 않아야 합니다.

## 3. 재개

새 Codex 터미널을 열고 [docs/prompt-templates.ko.md](docs/prompt-templates.ko.md)의 "이어서 진행 프롬프트"를 붙여넣습니다. `[]` 부분에 기존 작업 디렉터리와 agent id만 채웁니다.

Codex는 먼저 아래 파일을 읽고 이어서 진행해야 합니다.

- `memory.md`
- `evidence.md`
- `attempts.md`
- `next_steps.md`
- `operator_notes.md`
- 기존 solver/exploit 파일

## 4. 팀원이 푼 문제 반영

플랫폼 sync가 팀 solve 상태를 자동으로 보여주지 않으면, Codex에게 "팀원이 푼 문제 반영 프롬프트"를 붙여넣거나 아래처럼 지시합니다.

```text
[문제명 또는 challenge id]는 팀원이 이미 풀었다. ctfctl interactive external-solved로 로컬 보드에 반영하고, 이 문제는 다시 풀지 마라. 내 accepted 증거가 없으므로 writeup은 작성하지 마라.
```

Codex가 사용할 핵심 명령:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id-or-alias> --json
```

## 5. Metrics Snapshot

대회 중에는 public snapshot, public paste, public writeup, public commit/push를 하지 않습니다.

대회가 끝난 뒤에만 public-safe snapshot을 만듭니다.

```bash
ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json
ctfctl interactive metrics dashboard --json
```

public-safe snapshot에는 raw flag, raw candidate, token, cookie, session, csrf_token, storage_state, private key, auth header, private artifact 내용이 들어가면 안 됩니다.

## 6. 절대 지킬 정책

- 로컬 터미널 raw flag 출력은 풀이, 검증, 로컬 운영자 확인 목적이면 허용됩니다.
- public upload/commit/push/paste/writeup/snapshot에는 flag, exploit, solver, writeup, token, cookie, session, csrf_token, storage_state, private key, auth header를 절대 넣지 않습니다.
- writeup은 accepted된 문제만 한국어로 작성합니다.
- 파일명은 `[분야]문제명_WriteUp.md` 형식을 사용합니다.
- exploit/solver code가 있으면 전체 코드를 포함합니다.
- 못 푼 문제와 stalled 문제의 writeup은 금지입니다.
- background worker 방식은 legacy/advanced입니다. 기본 대회 운영에서는 보이는 Codex 터미널을 사용합니다.

## Advanced

세부 명령과 내부 동작은 [GUIDE.md](GUIDE.md)와 [docs/interactive-operations.md](docs/interactive-operations.md)를 봅니다. legacy background worker 문서는 [docs/contest-operations.md](docs/contest-operations.md)와 [docs/worker-loop.md](docs/worker-loop.md)에만 둡니다.
