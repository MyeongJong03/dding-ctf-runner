# dding CTF Runner Guide

이 문서는 대회 중 한국어 사용자가 바로 운영할 수 있게 정리한 상세 가이드입니다. 기본 흐름은 여러 개의 보이는 Codex 터미널을 열고, 각 터미널에 복붙용 프롬프트를 넣어 autonomous solver로 돌리는 방식입니다.

For the shortest contest-day checklist, see [OPERATIONS.md](OPERATIONS.md).

## 한국어 상세 가이드

### 1. 준비

대회 전에 아래만 준비합니다.

- 대회 이름, 대회 URL, 플랫폼 종류.
- 사용할 Codex 터미널 개수: Windows WSL은 최대 6개, Mac은 최대 4개 권장.
- 로컬 라이트업 저장 경로.
- 필요한 경우 `~/dding-ctf-runner` 설치와 `~/CTF` 작업 디렉터리.

복잡한 `ctfctl` 명령은 처음부터 외우지 않아도 됩니다. Codex가 템플릿 지시에 따라 필요할 때 `ctfctl interactive status`, `prepare-target`, `next`, `run-attempt`, `submit`, `writeup`, `cleanup` 등을 사용합니다.

### 2. 인증 정보 제공

인증 정보는 로컬 작업에만 사용합니다. DreamHack이면 보통 `sessionid`와 `csrf_token`을 템플릿의 `[]` 부분에 채웁니다. raw 값을 CLI 인자로 넘기지 마세요. shell history에 남을 수 있습니다.

절대 public에 포함하면 안 되는 값:

- token
- cookie
- session 또는 sessionid
- csrf_token
- storage_state
- private key
- auth header

### 3. Codex 실행

각 solver 터미널에서 아래처럼 실행합니다.

```bash
cd ~/CTF
codex
```

그 다음 [docs/prompt-templates.ko.md](docs/prompt-templates.ko.md)에서 맞는 템플릿을 복사하고 `[]` 부분만 바꿔 붙여넣습니다. 템플릿만 출력하려면 runner repo에서 아래 명령을 사용할 수 있습니다.

```bash
./scripts/ctfctl interactive prompt-template --kind general
./scripts/ctfctl interactive prompt-template --kind dreamhack
./scripts/ctfctl interactive prompt-template --kind dreamhack --json
```

기본 사용법에서는 background worker를 시작하지 않습니다. `contest start-workers`, `worker_loop`, `worker_supervisor`, `multi_worker`, `scripts/ctf-worker-*`는 legacy/advanced입니다.

### 4. 문제 풀이 루프

각 Codex 터미널은 아래 순서를 계속 반복합니다.

1. 문제 목록과 현재 상태를 확인합니다.
2. 다른 로컬 Codex가 잡지 않은 문제를 고릅니다.
3. 문제 설명과 첨부 파일을 확인합니다.
4. 로컬 분석을 먼저 합니다.
5. 꼭 필요할 때만 VM, 원격 서버, instance를 발급합니다.
6. flag 후보를 검증합니다.
7. high-confidence일 때 제출합니다.
8. accepted이면 한국어 writeup을 작성합니다.
9. cleanup 후 다음 문제로 넘어갑니다.

중간 보고를 위해 멈추지 않습니다. 사용자가 물으면 짧게 답하고, 답한 뒤 계속 진행합니다. 멈추는 조건은 사용자의 중단 지시, 대회 종료, 모든 문제가 solved 처리됨, 또는 모든 남은 문제가 충분히 stalled 기록됨뿐입니다.

### 5. 제출

제출은 high-confidence 후보에 대해서만 합니다. 중복 제출, fake-like 후보, 이미 wrong 처리된 후보는 피합니다.

로컬 터미널에는 raw flag를 출력해도 됩니다. 단, 대회 중 flag, exploit, solver, writeup을 public repo, public paste, public issue, public snapshot, public writeup, 외부 공개 경로에 업로드/커밋/푸시/붙여넣기 하지 않습니다.

### 6. 라이트업

writeup은 accepted된 문제만 한국어로 작성합니다.

파일명:

```text
[분야]문제명_WriteUp.md
```

포함할 내용:

- 문제 개요
- 풀이 과정
- 취약점 또는 핵심 원리
- 실행 방법
- 제출 결과
- exploit/solver code 전체
- 정리

못 푼 문제, stalled 문제, 팀원이 풀었지만 내 accepted 증거가 없는 문제의 writeup은 작성하지 않습니다. 그런 문제는 `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, `operator_notes.md`에 compact handoff만 남깁니다.

### 7. Cleanup

accepted 또는 stalled 처리 후에는 불필요한 임시 파일을 정리합니다. 원격 서버, VM, instance, callback, tunnel 같은 리소스를 만들었다면 상태와 종료 필요 여부를 기록하고 정리합니다.

### 8. Metrics

metrics는 로컬 운영 상태를 보는 용도입니다. public-safe snapshot에는 hash, length, status, confidence, high-level blocker만 들어가야 합니다. raw flag, raw candidate, token, cookie, session, csrf_token, storage_state, private key, auth header, private artifact 내용은 public snapshot에 넣지 않습니다.

대회가 끝난 뒤에만 public-safe snapshot을 만들 수 있습니다. 대회 중 public upload/commit/paste/writeup은 금지입니다.

## Advanced / Reference

This guide is the user-facing operating manual for the interactive Codex swarm workflow. Commands use placeholders only. Local terminal output may include raw flags when needed for solving, verification, and local operator visibility. Keep real contest URLs, cookies, tokens, browser storage, downloads, writeups, and raw flags outside this repository, public snapshots, public pastes, and public services.

## 1. Operating Model

The default live model is interactive:

- Use `ctfctl` from `~/dding-ctf-runner` for setup, sync, board, submit, writeup, and cleanup helpers.
- Start visible Codex sessions yourself with `cd ~/CTF && codex`.
- Every Codex terminal is an autonomous solver. Do not split terminals into controller and solver roles.
- Same-machine duplicate claims are blocked by default.
- Windows WSL can run up to 6 Codex terminals when resources allow.
- MacBook secondary runners should use up to 4 Codex terminals by default.
- Background workers and `contest start-workers` are legacy/advanced, not the default live path.

## 2. Install

Windows WSL primary runner:

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl interactive toolchain doctor --json
```

Keep the repo on WSL ext4, not `/mnt/c`. Enable Docker Desktop WSL integration for pwn/rev work.

macOS secondary runner:

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner
python3 -m pip install -e . pytest
```

Keep the existing `~/CTF`, global Codex config, and personal CTF tooling unchanged. For Apple Silicon Docker smoke checks:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
./scripts/ctfctl interactive toolchain doctor --json
```

## 3. Profile And Auth

Store platform profiles and secrets outside git:

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.cookie
~/.ctf-solver/secrets/<contest>.token
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Common auth shapes:

```yaml
auth:
  method: cookie_header_file
  path: "~/.ctf-solver/secrets/<contest>.cookie"
policy:
  allow_live_discovery: true
  allow_live_download: true
  allow_submission: true
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
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

Validate without printing raw auth:

```bash
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Capture browser storage only when needed, by manual login:

```bash
./scripts/ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --output ~/.ctf-solver/secrets/<contest>.storage_state.json \
  --live \
  --headed \
  --timeout-sec 300
```

## 4. Interactive Init And Sync

From the runner repo:

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml
export AGENTS=4

./scripts/ctfctl preflight --deep --json
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --pull-solved --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

If the operator directory does not exist, the first agent or operator runs `interactive init` and creates it.

Generate one prompt per Codex terminal:

```bash
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-2
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-3
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-4
```

For Windows, use up to six agents:

```bash
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 6 --json
```

## 5. Start Codex Terminals

In each solver terminal:

```bash
cd ~/CTF
codex
```

Paste a different generated prompt into each Codex session. These are CTF-solving Codex sessions, separate from any Codex you use to develop this repo. Repo development happens in `~/dding-ctf-runner`; challenge solving happens in `~/CTF`.

Each solver should:

- run `interactive solve-loop` to pick or prepare one high-signal canonical challenge and execute the starter harness
- use `prepare-target -> run-attempt -> candidates -> verify-candidate` when manual experiment control is needed
- read the generated target pack, triage summary, and starter before solving
- solve and verify locally
- submit only through `ctfctl interactive submit` or `upload-submit`
- write accepted-only ko/en writeups
- clean safe temporary files
- move to the next challenge unless the user stops the loop, the contest ends, or all challenges are solved/external_solved/stalled-documented
- keep self memos current to prevent context drift

`interactive sync` canonicalizes platform challenge rows before this loop starts. Static shell pages, `-static` slugs, case/spacing variants, and phase metadata are kept under the canonical row in `board.json` as `aliases`, `artifact_sources`, and `source_ids`. Default `interactive next` and `interactive claim` return canonical, claimable rows; `interactive board --json` exposes `canonical_count`, `alias_count`, `skipped_static_count`, and `claimable_count`. Use `interactive sync --pull-solved` when the platform exposes team solved/submission state. Platform solved IDs, aliases, or static names mark the canonical row `solved_by_platform` with `solved_source=platform`; sync JSON also reports `new_count`, `updated_count`, `solved_synced_count`, `external_solved_count`, `solved_alias_resolved_count`, and `solved_status_source`.

No background refresh loop runs during a contest. New problems and teammate solves are picked up only when a visible Codex/operator command performs a refresh: `interactive sync --live --pull-solved`, `interactive next --refresh`, or `interactive prepare-target --refresh`. The refresh paths used by `next` and `prepare-target` pull solved status when available before ranking targets.

## 6. Interactive Commands

Board:

```bash
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive status --contest-id "$CONTEST_ID" --json
```

Pick and claim the next target:

```bash
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive next --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
```

`next` scores canonical challenges by attachments, remote endpoints, category confidence, existing progress, and clear `next_steps`. It skips alias/static/artifact-source rows, locally solved/platform-solved/external-solved/stalled-documented challenges, and generic no-file shells. Use `--refresh --profile "$PROFILE"` to run one live sync before ranking; newly discovered challenges become claimable immediately, platform solved rows are excluded, and sync deltas are recorded in metrics. Use `--category <category>` to focus one category, `--dry-run` to inspect the selected target without claiming, and `--allow-duplicate` only for intentional same-machine duplicate solving. The JSON includes `target_pack_path`; the solver should read that file before trying payloads.

Prepare a target for immediate solving:

```bash
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive solve-loop --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --max-attempts 5 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --refresh --profile "$PROFILE" --json
ctfctl interactive prepare-target --contest-id "$CONTEST_ID" --agent agent-1 --challenge-id <id-or-alias> --json
```

`solve-loop` is the standard experiment harness. It runs `prepare-target` when needed, executes the starter in the challenge directory, records `attempts/<timestamp>.json`, updates `attempts.md` and `evidence.md`, detects local candidates, verifies format/duplicate/fake-like/previous-wrong guards, and submits only high-confidence candidates through the interactive submit path. If accepted, it writes ko/en writeups, runs safe cleanup, updates metrics, and the solver continues to the next challenge. If no accepted candidate appears after `--max-attempts`, it updates `next_steps.md`, records stalled metrics, creates no writeup, and continues to the next challenge.

`prepare-target` runs the target planner, target pack, local auto-triage, and starter generation as one shell-first step. If `--challenge-id` is omitted, it runs `interactive next`; otherwise it prepares the specified canonical challenge or alias. With `--refresh`, it performs the same one-shot sync path as `next --refresh` first. The JSON returns `target_pack_path`, `triage_summary_path`, `starter_path`, `top_files`, `first_commands`, and `next_steps`. Read the target pack, triage summary, and starter file before manual analysis.

`interactive status` reports `completion_status`: `active`, `needs_sync`, `no_claimable`, `all_solved`, or `all_solved_or_stalled`. It also reports `solved_by_platform_count`, `solved_by_external_count`, and `solved_sync_available`. `active` means keep solving. `needs_sync` means a profile is configured but the board has not been refreshed. `no_claimable` means no fresh canonical target is currently available, often because work is already claimed locally. `all_solved` and `all_solved_or_stalled` are stop conditions; platform solved rows count toward completion. 대회 중 사용자의 중단 지시, 대회 종료, 모든 문제 solved/stalled-documented 외에는 계속 진행한다.

Generate or refresh the solver launch pack:

```bash
ctfctl interactive target-pack --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
```

The pack is written under `operator/target-packs/` and includes canonical name, aliases, artifact sources, real challenge/brief/raw/extracted paths, web metadata, remote connection info, top interesting files, current memory/evidence/attempts/next_steps/operator_notes summaries, recommended first commands, a category playbook, stall criteria, and accepted-only writeup/cleanup reminders. It does not include raw auth material, cookies, tokens, sessions, browser storage, or private keys.

Run local auto-triage and create a starter explicitly:

```bash
ctfctl interactive triage --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --agent agent-1 --json
ctfctl interactive starter --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --category <category> --json
```

`triage` reads local raw/handout/extracted files, `brief.md`, manifests, and memos, then writes `triage/summary.md`, `triage/files.json`, `triage/commands.jsonl`, and `triage/findings.jsonl`. For web challenges with configured `base_url`, it also runs the bounded `web-probe` harness and records only summarized page structure, not raw bodies. It updates `memory.md`, `evidence.md`, `attempts.md`, `next_steps.md`, and `operator_notes.md`. `starter` creates a category-specific skeleton such as `solve_web.py`, `exploit.py`, `solve_rev.py`, `solve_crypto.py`, or `solve_misc.py`, and records the path in board/operator metadata. The web starter uses a `requests.Session`/urllib skeleton plus an optional Playwright hook for DOM-only bugs. These commands do not create writeups; writeups remain accepted-only.

Run and verify manual experiments:

```bash
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script <path> --timeout 120 --json
ctfctl interactive run-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --command "python3 solve.py" --json
ctfctl interactive candidates --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
ctfctl interactive verify-candidate --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

`run-attempt` executes from the challenge directory and stores raw local stdout/stderr/returncode/runtime in `attempts/`. It appends compact attempt/evidence notes and records `attempt_started`/`attempt_completed` metrics. Raw candidates are allowed in local terminal output and `candidates.jsonl`; public-safe snapshots use only hash, length, source, status, confidence, and timestamp.

Web/browser workflow:

```bash
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --base-url <url> --auth-source none --json
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --base-url <url> --auth-source cookie-file --cookie-file <path> --json
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --base-url <url> --auth-source header-file --header-file <path> --json
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --base-url <url> --auth-source storage-state --storage-state <path> --json
ctfctl interactive web-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --base-url <url> --auth-source env --auth-env <name> --json
ctfctl interactive web-probe --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --timeout 20 --json
ctfctl interactive browser-probe --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --timeout 30 --json
ctfctl interactive web-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script solve_web.py --timeout 60 --json
ctfctl interactive web-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --request-json request.json --json
ctfctl interactive browser-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script solve_browser.py --timeout 90 --json
ctfctl interactive web-status --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

`web-config` records challenge web metadata in board/operator state. It stores `base_url`, base URL source, auth source type, file paths, or environment variable names only; raw cookie/header/storage-state/env values are never stored or printed. Base URLs must be HTTP/HTTPS without embedded credentials or secret-bearing query keys; profile-origin differences are reported as warnings because challenge hosts can differ from the scoreboard host. `web-probe` performs a bounded GET with the configured auth source and stores title, forms, links, scripts, static-link path/hash summaries, endpoint candidates, and response header summaries in `web/probes/<timestamp>.json`; raw response bodies are not stored. `browser-probe` loads the page with Playwright when available, stores screenshot path, page title, console summary, network method/path/status/content-type summary, and blocked destructive request summaries in `web/browser_probes/<timestamp>.json`. If Playwright is unavailable, it reports `unavailable` rather than requiring external browser setup.

`web-attempt` runs a local script or JSON request spec from the challenge directory. Scripts receive `CTF_WEB_BASE_URL`, `CTF_WEB_AUTH_SOURCE`, and source metadata such as `CTF_WEB_COOKIE_FILE`, `CTF_WEB_HEADER_FILE`, `CTF_WEB_STORAGE_STATE`, or `CTF_WEB_AUTH_ENV`; they do not receive raw cookie/header/storage values from the harness. Request specs may define method/path/url/body/json and are executed against the configured base URL with configured auth headers. `browser-attempt` runs a Playwright-capable local script with `CTF_BROWSER_ARTIFACT_DIR`, `CTF_BROWSER_SCREENSHOT`, `CTF_BROWSER_CONSOLE_JSONL`, and `CTF_BROWSER_NETWORK_JSONL`, then records screenshot/console/network summaries. Local raw flags and solver output are allowed in terminal output and local attempt records; public-safe metrics exclude raw responses, cookies, headers, storage state, and raw candidate values.

Remote service workflow:

```bash
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --host <host> --port <port> --tls --token-source file --token-file <path> --json
ctfctl interactive service-config --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --host <host> --port <port> --plain --token-source env --token-env <name> --json
ctfctl interactive service-probe --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --timeout 10 --json
ctfctl interactive service-attempt --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --script <path> --timeout 60 --json
ctfctl interactive service-status --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

`service-config` records endpoint metadata from explicit host/port input or challenge text such as nc/ncat/openssl connection hints. Use `--tls` or `--plain` when the transport is known; otherwise probe can auto-fallback between Python TLS and plain sockets. Token sources are `none`, `profile`, `file`, or `env`; only the source kind, file path, or environment variable name is stored. `service-probe` captures banner/prompt evidence and detects service token, PoW, and menu prompts without printing token values. `service-attempt` connects to the configured service, injects a configured service token only after a token prompt, runs the optional PoW helper with the prompt on stdin, sends a payload file or script stdout, stores sanitized local-only transcripts, and extracts local candidates. Public-safe snapshots exclude raw transcripts, tokens, and raw candidate values.

Compact current-target status:

```bash
ctfctl interactive brief --contest-id "$CONTEST_ID" --challenge-id <id-or-alias> --json
```

Use `brief` when the user asks "지금 뭐 하고 있음?" so the solver can answer from local state and continue the loop.

Manual claim remains available:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --json
```

The returned `challenge_id`, name, path, memos, and writeup paths are canonical even when the platform also published static or alias rows for the same task.

Claim a specific challenge:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --json
```

Allow intentional same-machine duplicate solving:

```bash
ctfctl interactive claim --contest-id "$CONTEST_ID" --agent agent-2 --challenge <id> --allow-duplicate --json
```

Release a claim when abandoning a live attempt:

```bash
ctfctl interactive release --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "switching tasks" --json
```

Record self memo:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "known fact" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind evidence --append "local evidence path or result" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind attempts --append "tried X, result Y" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next concrete action" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "operator hint" --json
```

Submit a flag from a local file:

```bash
ctfctl interactive submit --contest-id "$CONTEST_ID" --challenge-id <id> --flag-file <path> --confirm --json
```

Submit an upload artifact:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id <id> --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id <id> --artifact <path> --confirm --json
```

Artifact upload challenges, including rfc1149b-like wasm tasks, are metadata-first. Store the challenge submit metadata under the local operator state, then upload only to the official endpoint:

```bash
ctfctl interactive submit-config --contest-id "$CONTEST_ID" --challenge-id rfc1149b --submit-type artifact_upload --endpoint https://example.invalid/submit --field-name file --status-url https://example.invalid/status/rfc1149b --json
ctfctl interactive upload-submit --contest-id "$CONTEST_ID" --challenge-id rfc1149b --artifact ./solution.wasm --confirm --json
```

The endpoint must be HTTP/HTTPS, must not embed credentials or secret-bearing query parameters, and must match the origin of the configured platform profile `base_url`. If metadata and `--endpoint` are both missing, `upload-submit` records a planned/blocked local submission and does not perform live network traffic. Successful and failed upload attempts append public-safe local records to `submissions.jsonl` with artifact SHA-256, size, submit timestamp, response status, and active status.

Mark stalled:

```bash
ctfctl interactive stalled --contest-id "$CONTEST_ID" --agent agent-1 --challenge <id> --reason "short blocker and next step" --json
```

Record a challenge solved outside this machine:

```bash
ctfctl interactive external-solved --contest-id "$CONTEST_ID" --challenge <id> --json
```

`external-solved` accepts a canonical ID, canonical name, alias, static slug, or artifact source. It resolves to the canonical challenge, marks it `external_solved`/`solved_by_external` with `solved_source=external_solved_txt`, writes local `external_solved.txt` entries, records `external_solved_recorded`, and releases any claim locks for the canonical challenge, aliases, source IDs, and artifact sources. Use this manual fallback when a teammate solves a problem and the platform sync does not automatically expose team-solved state. Platform-solved teammate work does not create this agent's accepted writeup; writeups remain accepted-only unless there is local evidence and the user asks.

Write accepted-only writeups:

```bash
ctfctl interactive writeup --contest-id "$CONTEST_ID" --challenge-id <id> --category <category> --languages ko --include-code --json
```

Safe cleanup:

```bash
ctfctl interactive cleanup --contest-id "$CONTEST_ID" --challenge-id <id> --safe --json
```

## 7. Giving Solvers New Information

When the user/operator learns something mid-contest, update the local memos rather than relying on chat history:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind operator_notes --append "Hint from organizer: <short sanitized note>" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "Use the new hint to test <action>" --json
```

Then paste the short sanitized note into the affected Codex terminal. Local terminal output may include raw flags, solver output, and exploit output when needed for solving, verification, and local operator visibility, but do not commit, push, paste publicly, publish, upload, or place cookies, tokens, sessions, browser storage, private keys, auth headers, auth material, flags, writeups, or exploits in public chats, public pastes, issue trackers, public repositories, public snapshots, or external writeup locations during the contest.

## 8. Writeup Policy

Only write a writeup after an accepted solve is confirmed. The Korean contest template policy creates one Korean file:

```text
[category]ChallengeName_WriteUp.md
```

If solver or exploit code exists, include the complete code in fenced markdown blocks. Do not write a public-style writeup for unsolved, skipped, or stalled problems. For unsolved problems, leave only local `memory`, `evidence`, `attempts`, `next_steps`, `operator_notes`, and `stalled` records. The advanced command still supports explicit multi-language local output, but public-facing contest handoff should follow accepted-only Korean writeups.

## 8.1. Interactive Metrics

Each operator root has local-only metrics files:

```text
metrics/events.jsonl
metrics/sessions.jsonl
metrics/challenge_metrics.jsonl
metrics/tool_benchmarks.jsonl
metrics/summary.json
metrics/regression_report.md
```

Use `ctfctl interactive metrics record` for manual observations, including optional token usage:

```bash
ctfctl interactive metrics record --contest-id "$CONTEST_ID" --event usage_observed --data-json '{"tokens_used": 1234}' --json
ctfctl interactive metrics summary --contest-id "$CONTEST_ID" --json
ctfctl interactive metrics report --contest-id "$CONTEST_ID" --json
```

Metrics are for local performance tracking across updates. Local raw metrics are private operator state and must not be copied into public repos during an active contest.

GitHub metrics are public-safe snapshots only. Use:

```bash
ctfctl interactive metrics baseline --name before-change --json
ctfctl interactive metrics publish-snapshot --contest-id "$CONTEST_ID" --contest-ended --json
ctfctl interactive metrics dashboard --json
ctfctl interactive metrics compare-public --before old-summary.public.json --after metrics/contests/$CONTEST_ID/summary.public.json --json
```

`publish-snapshot` writes `summary.public.json`, `solved.public.md`, `stalled.public.md`, `approaches.public.md`, and `regression.public.md`. These files include counts, elapsed times, high-level approaches, stalled blockers, cleanup/writeup counts, observed token totals when present, candidate hash/length/source/status metadata, and artifact upload SHA-256/size/status when present. They must not include raw candidates, raw flags, writeup bodies, exploit bodies, artifact contents, upload endpoints, local artifact paths, cookies, tokens, sessions, browser storage or storage state, auth headers, private keys, raw responses, or auth material.

During an active contest, public snapshot export is blocked unless both `--allow-active-contest` and `--confirm-public-safe` are provided. The normal flow is: accepted solve -> submit or accepted/active artifact upload -> ko/en writeup -> cleanup -> metrics update -> next challenge. For stalled challenges: attempts/next_steps -> stalled metrics update -> next challenge. At contest end: publish-snapshot -> dashboard -> optional git commit.

## 9. Callback, Docker, Submit, And Cleanup Helpers

The interactive workflow still uses runner helpers for live platform operations:

```bash
./scripts/ctfctl docker pool-start --contest-id "$CONTEST_ID" --workers 4 --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-status --contest-id "$CONTEST_ID" --json
./scripts/ctfctl docker pool-stop --contest-id "$CONTEST_ID" --json
```

```bash
./scripts/ctfctl callback start --contest-id "$CONTEST_ID" --challenge-id <id> --worker-id agent-1 --json
./scripts/ctfctl tunnel start --contest-id "$CONTEST_ID" --challenge-id <id> --worker-id agent-1 --listener-id <listener> --provider auto --allow-public --json
./scripts/ctfctl contest cleanup-resources --contest-id "$CONTEST_ID" --json
```

Use public tunnels only when a challenge requires them. Do not paste tunnel URLs, callback logs, or payload transcripts into git or public writeups.

## 10. Troubleshooting

Profile/auth failure:

```bash
./scripts/ctfctl platform profile-check --config "$PROFILE" --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Board stale or missing:

```bash
./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents "$AGENTS" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --pull-solved --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
```

Duplicate claim:

- Default locks block duplicate claims only on the same computer.
- Use `--allow-duplicate` only when intentionally racing one problem locally.
- Ignore duplicate claims on other computers unless the team wants manual coordination.

Context drift:

```bash
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind memory --append "current state summary" --json
ctfctl interactive memo --contest-id "$CONTEST_ID" --challenge-id <id> --kind next_steps --append "next action" --json
```

Submit blocked:

- Check profile `policy.allow_submission`.
- Confirm `--confirm` was used.
- Inspect the submit JSON for duplicate, cooldown, wrong-limit, confidence, or fake-like guard reasons.

Tool missing:

```bash
ctfctl interactive capabilities --contest-id "$CONTEST_ID" --category pwn --refresh --json
ctfctl interactive fallback --tool ncat --json
ctfctl interactive fallback --tool cpio --json
```

- The runner records capability reports under `operator/toolchain/`.
- Target packs, triage, starters, and solve-loop prefer available tools and documented fallbacks.
- Do not run sudo or auto-install during a live solve loop; install hints are planned operator actions.
- If a missing tool blocks an attempt, `attempts.md`, `next_steps.md`, and metrics record the blocker so the solver can use a fallback or switch targets.

Docker on Windows WSL:

```bash
docker info >/dev/null
./scripts/ctfctl preflight --deep --json
```

macOS Docker:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
```

Interactive E2E before the next contest:

```bash
./scripts/ctfctl interactive e2e-smoke --contest-id fake-interactive-smoke --agents 2 --json
```

This is the current full-loop rehearsal for the interactive swarm. It is
fake/local only and checks accepted-only writeups, full solver code capture,
cleanup, stalled metrics without writeups, metrics summary, next claim, and
same-machine duplicate-claim behavior. Use `--keep-runtime` when inspecting
`~/CTF/contests/fake-interactive-smoke/operator`.

## 11. Legacy Background Workers

The old background flow remains for advanced testing:

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1 --dry-run
./scripts/ctfctl contest start-workers --contest-id <contest> --dry-run --json
```

Do not use this as the default live contest workflow. See [docs/contest-operations.md](docs/contest-operations.md) and [docs/worker-loop.md](docs/worker-loop.md) only when intentionally running legacy/advanced automation.

## 12. Public Safety

Before publishing, use the interactive-first release gate:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl interactive init --contest-id release-interactive-smoke --writeup-root /tmp/dding-ctf-runner-release-writeups --agents 2 --json
./scripts/ctfctl interactive e2e-smoke --contest-id release-interactive-e2e --agents 2 --json
./scripts/ctfctl interactive metrics baseline --name release-smoke --output-dir /tmp/dding-ctf-runner-release-metrics --json
./scripts/ctfctl interactive metrics publish-snapshot --contest-id active-contest-block-smoke --json  # expected blocked
./scripts/ctfctl interactive prompt --contest-id release-interactive-smoke --agent smoke-1
./scripts/release-check.sh
./scripts/ctfctl repo public-check --json
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
git diff --check
```

`public-check` exposes the default release commands under `interactive_test_commands`. Background worker full-rehearsal commands are still available, but they are legacy/advanced checks rather than the default release summary.

Do not push public git changes from this repo during active CTF work.
