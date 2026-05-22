# dding-ctf-runner Operations Guide

## 1. 기본 실행 방식

- Plain `codex` 금지.
- Operator는 `ctf-worker-1`로 실행.
- 실제 작업 repo는 `~/dding-ctf-runner`.
- MacBook에서는 기존 `~/CTF`/global Codex 세팅을 유지하고 runner wrapper만 사용.

```bash
cd ~/dding-ctf-runner
ctf-worker-1
```

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

## 3. Operator Prompt

대회 시작 때 operator Codex에 붙여넣기:

```text
Operate ~/dding-ctf-runner for this CTF. Do not use plain codex, do not print secrets or raw flags, and do not push git changes.

Set:
CONTEST_ID=<contest>
PROFILE=~/.ctf-solver/platforms/<contest>.yaml

Run:
cd ~/dding-ctf-runner
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl platform sync-challenges --mode rehearsal --config "$PROFILE" --live --save-state --ingest-text --json
./scripts/ctfctl contest prestart --contest-id "$CONTEST_ID" --profile "$PROFILE" --json
./scripts/ctfctl contest arm --contest-id "$CONTEST_ID" --profile "$PROFILE" --confirm-competition --max-workers 5 --max-parallel-codex 2 --json
./scripts/ctfctl docker pool-start --contest-id "$CONTEST_ID" --workers 5 --image ctf-pwn:latest --json
./scripts/ctfctl contest start-workers --contest-id "$CONTEST_ID" --dry-run --json
./scripts/ctfctl contest start-workers --contest-id "$CONTEST_ID" --apply --workers 5 --solver codex --allow-codex-call --max-parallel-codex 2 --no-stop-when-empty --postsolve --json
./scripts/ctfctl contest status --contest-id "$CONTEST_ID" --json

Auto-submit is on by default only in armed competition mode, and only when the profile has policy.allow_submission=true. If confidence or submit guards block a candidate, inspect the blocked reason without printing the raw candidate.

At shutdown:
./scripts/ctfctl contest disarm --contest-id "$CONTEST_ID" --stop-workers --cleanup-resources --stop-docker-pool --json
```

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
./scripts/ctfctl platform sync-challenges --mode rehearsal --config "$PROFILE" --live --save-state --ingest-text --json
./scripts/ctfctl contest prestart --contest-id "$CONTEST_ID" --profile "$PROFILE" --json
./scripts/ctfctl contest arm --contest-id "$CONTEST_ID" --profile "$PROFILE" --confirm-competition --max-workers 5 --max-parallel-codex 2 --json
./scripts/ctfctl docker pool-start --contest-id "$CONTEST_ID" --workers 5 --image ctf-pwn:latest --json
./scripts/ctfctl contest start-workers --contest-id "$CONTEST_ID" --dry-run --json
./scripts/ctfctl contest start-workers --contest-id "$CONTEST_ID" --apply --workers 5 --solver codex --allow-codex-call --max-parallel-codex 2 --no-stop-when-empty --postsolve --json
```

## 6. 모니터링

```bash
./scripts/ctfctl contest status --contest-id "$CONTEST_ID" --json
./scripts/ctfctl contest worker-status --contest-id "$CONTEST_ID" --json
./scripts/ctfctl contest worker-logs --contest-id "$CONTEST_ID" --worker-id worker-1 --tail 80 --json
```

## 7. 종료/정리

```bash
./scripts/ctfctl contest disarm --contest-id "$CONTEST_ID" --stop-workers --cleanup-resources --stop-docker-pool --json
./scripts/ctfctl contest status --contest-id "$CONTEST_ID" --json
```

## 8. 문제 발생 시

- Docker 안 켜짐: `./scripts/ctfctl preflight --deep --json`, Docker Desktop WSL integration 확인.
- `cloudflared` 없음: public callback이 필요한 문제에서만 설치. 필요 없으면 Medium으로 둔다.
- `storage_state` 만료: 새 storage 파일을 repo 밖 `~/.ctf-solver/secrets`에 저장하고 `auth storage-check` 실행.
- Worker 안 돎: `contest worker-status`, `contest worker-logs`, `contest restart-worker` 확인.
- `global_long_agents`: `ctf-worker-*` wrapper만 사용.
- Submit blocked: `submit_plan_status`, `live_submit_mode_decision.reason`, profile `policy.allow_submission`, `config/submit_policy.yaml` guard 확인.

## 9. 대회 후

```bash
./scripts/ctfctl postsolve batch --contest-id "$CONTEST_ID" --status solved --json
./scripts/ctfctl postsolve skill-candidates --contest-id "$CONTEST_ID" --json
./scripts/ctfctl contest disarm --contest-id "$CONTEST_ID" --stop-workers --cleanup-resources --stop-docker-pool --json
```

- Postsolve와 writeup draft는 local-only로 review.
- `skill_candidate`는 수동 review 후 sanitized pattern만 승격.
- Contest 종료 및 rules 허용 전 public push 금지.
