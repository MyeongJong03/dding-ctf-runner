# dding-ctf-runner Operations Guide

## 1. 기본 실행 방식

- 기본은 interactive Codex swarm이다.
- 사용자는 `cd ~/CTF` 후 여러 Codex 터미널을 직접 실행한다.
- 각 Codex는 autonomous solver로 claim/solve/submit/writeup/cleanup/next 루프를 계속 돈다.
- Controller와 solver를 나누지 않는다.
- 실제 작업 repo는 `~/dding-ctf-runner`.
- Background worker/supervisor/start-workers는 legacy/advanced로만 사용한다.

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml

./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 4 --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

각 Codex 터미널:

```bash
cd ~/CTF
codex
```

붙여넣을 prompt는 `interactive prompt` 출력에서 가져온다. Windows는 6 terminals,
Mac은 4 terminals를 기본값으로 운영한다.

MacBook secondary/mobile runner에서는 Docker workspace를 `~/CTF` 밖으로 둔다.
Apple Silicon에서 `ctf-pwn:latest` linux/amd64 이미지는 emulation으로 동작하므로
pwn/rev-heavy 작업은 Windows WSL을 우선한다.

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
```

## 2. 대회 profile 준비

Profile과 secrets는 repo 밖에 둔다.

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.cookie
~/.ctf-solver/secrets/<contest>.token
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Auth 예시:

```yaml
auth:
  method: cookie_header_file
  path: "~/.ctf-solver/secrets/<contest>.cookie"
```

```yaml
auth:
  method: api_token_file
  path: "~/.ctf-solver/secrets/<contest>.token"
```

```yaml
auth:
  method: storage_state_file
  path: "~/.ctf-solver/secrets/<contest>.storage_state.json"
```

Submit policy:

```yaml
policy:
  allow_submission: true
```

`allow_submission: false`이면 solve는 가능하지만 실제 제출은 막힌다. Setup/rehearsal에서는 `allow_submission: true`여도 제출은 막힌다.

## 3. Solver Prompt

대회 시작 때 각 Codex에 붙여넣기:

```bash
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

Prompt 정책에는 다음이 포함된다: 한 문제만 풀고 멈추지 않기, solved/stalled/contest ended/user stop 외에는 계속 진행하기, 장황한 중간 보고 금지, accepted solve만 writeup 작성, 한국어/영어 writeup 작성, self memo 지속, 같은 컴퓨터 내 중복 claim 기본 방지, raw secret/flag 출력 금지.

## 4. 자동 제출 정책

- Competition arm 이후 기본 on.
- Setup/rehearsal에서는 off.
- Profile `policy.allow_submission: true` 필요.
- High confidence 필요.
- Duplicate, wrong-limit, cooldown, fake-like guard 유지.
- 끄려면 `contest arm --no-live-submit` 또는 profile `allow_submission: false`.

## 5. 실제 대회 시작 순서

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml

./scripts/ctfctl preflight --deep --json
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 4 --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

## 6. 모니터링

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

## 7. 종료/정리

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

## 8. 문제 발생 시

- Docker 안 켜짐: `./scripts/ctfctl preflight --deep --json`, Docker Desktop WSL integration 확인.
- `cloudflared` 없음: public callback이 필요한 문제에서만 설치. 필요 없으면 Medium으로 둔다.
- `storage_state` 만료: 새 storage 파일을 repo 밖 `~/.ctf-solver/secrets`에 저장하고 `auth storage-check` 실행.
- Claim 중복: 기본 lock은 같은 컴퓨터 내 중복을 막는다. 의도한 중복 풀이만 `--allow-duplicate`.
- Context drift: `interactive memo`로 `memory/evidence/attempts/next_steps/operator_notes` 갱신.
- Submit blocked: `submit_plan_status`, `live_submit_mode_decision.reason`, profile `policy.allow_submission`, `config/submit_policy.yaml` guard 확인.

## 9. 대회 후

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

- Accepted solve만 `interactive writeup --languages ko,en --include-code`로 한국어/영어 두 파일 작성.
- Solver/exploit 코드가 있으면 writeup에 전체 코드 포함.
- `skill_candidate`는 수동 review 후 sanitized pattern만 승격.
- Contest 종료 및 rules 허용 전 public push 금지.

## 10. Legacy background workers

`worker_loop`, `worker_supervisor`, `multi_worker`, `contest start-workers`는 legacy/advanced flow다. 삭제하지 않지만 기본 운영 순서에서는 사용하지 않는다.
