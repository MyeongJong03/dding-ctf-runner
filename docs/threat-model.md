# Threat Model

Primary risks:

- Cookie, token, browser storage, or API key leakage.
- Raw flag leakage through commits, pushes, public pastes, public repositories, public services, issue trackers, screenshots, public writeups, or telemetry.
- Interactive Codex pasted prompts leaking raw secrets, auth headers, storage state, sessions, cookies, tokens, private keys, or flags to public locations.
- Operator files under `~/CTF/contests/<contest>/operator/` accidentally storing raw secrets, callback payloads, or private exploit transcripts that later get published.
- Solver output mixing raw flags or raw secrets into public summaries, handoffs, telemetry, or state.
- Raw exploit transcript leakage through worker handoff files.
- Writeup draft or skill candidate leakage through git, chat, public pastes, uploads, or public issue trackers.
- Raw flag or exploit secret leakage through artifact archives.
- Accidental live platform action during bootstrap or dry-run.
- Accidental real challenge solve while the operator is only configuring an open event.
- Accidental competition mode caused by an inherited `CTF_RUN_MODE=competition` environment variable.
- Stale `arm.lock` leaving a contest armed after the operator intended to return to rehearsal.
- Accidental live submit after a solve candidate appears in competition mode.
- Accidental browser auth capture during setup.
- Duplicate or low-confidence submissions consuming limited attempts.
- Artifact upload challenges sending generated files to an unofficial endpoint or leaking uploaded artifacts, local paths, raw responses, or auth headers into public snapshots.
- Web challenge auth/session leakage through configured cookie files, header files, environment variables, profile auth, Playwright storage state, screenshots, console logs, network summaries, or raw response bodies.
- Browser automation accidentally sending destructive web requests while probing a challenge app.
- Remote service token leakage through service transcripts, command output, metrics, public snapshots, or target packs.
- PoW helper output or remote transcripts accidentally carrying service auth material into public artifacts.
- Concurrent workers racing into duplicate claims or duplicate submits.
- Interactive same-machine Codex sessions duplicating claims unintentionally.
- Background worker processes running after the operator believes a contest is paused.
- Stale worker PID files causing false running status or missed restarts.
- Worker logs leaking raw candidates, auth material, or exploit output.
- SQLite state corruption or lock contention during parallel worker claims.
- Auto-submit lockouts from repeated wrong answers.
- Decoy or fake flag strings being submitted as real solves.
- Current-event writeup search spoiling live competition integrity.
- Public tunnel exposure leaking unintended local services.
- Secret-bearing callback URL or callback log leakage.
- Stale tunnel processes remaining reachable after a challenge.
- Stale contest-level callback/tunnel leases remaining reachable after workers are stopped or the contest is disarmed.
- Public callback hit logs retaining raw headers, query values, request bodies, or browser-submitted secrets.
- Public tunnel URL leakage causing unrelated third parties to hit the callback listener.
- Docker secret env leakage from pwn/rev worker containers.
- Workspace persistence carrying exploit transcripts, downloaded private files, or candidate material between attempts.
- Stale Docker pool containers continuing to run after a contest pause.
- Accidental host mount exposing broad home directories or Windows `/mnt/c` content to a challenge process.
- Stale Codex binary symlinks causing plain `codex` to run an older CLI than the runner wrappers.
- Hard-pinned Codex models silently aging into outdated defaults.
- Default `danger-full-access` worker mode enabling broader filesystem modification and secret exposure risk.
- Default no-prompt execution increasing the chance of unintended destructive live actions if higher-level guards fail.
- Public release of local runtime directories, queue databases, generated challenge material, or commit history that predates the final public checks.

Controls:

- Strong `.gitignore` for runtime, secret, flag, download, browser, callback, and writeup paths.
- `redact_text` on CLI and telemetry output.
- Local-only writeups and private artifacts.
- Local terminal output may include flags, solver output, and exploit output when needed for solving and verification.
- No public git push from runner workflows.
- The default live workflow is interactive Codex swarm: operators run `ctfctl interactive ...`, then launch visible Codex sessions with `cd ~/CTF && codex`.
- Every interactive Codex terminal is an autonomous solver. There is no controller/solver split in the default path.
- Windows WSL defaults to at most six Codex terminals; MacBook defaults to at most four.
- Interactive `init` creates the operator directory when it is missing.
- Interactive board state lives under `~/CTF/contests/<contest>/operator/`, outside this repo.
- Operator files may contain `BOARD.md`, `board.json`, `solved.jsonl`, `external_solved.txt`, `stalled.jsonl`, `claims/`, `memos/`, and `metrics/`, but must not contain raw cookies, tokens, auth headers, browser storage, passwords, private keys, or shell history.
- Artifact submit metadata is local operator state. `ctfctl interactive submit-config` records submit type, endpoint, method, field name, auth source, and optional status URL without reading auth material.
- `ctfctl interactive upload-submit` computes artifact SHA-256 and size before upload, blocks when no endpoint/config exists, and allows live upload only to HTTP/HTTPS endpoints on the configured profile `base_url` origin with submission policy enabled.
- Artifact upload records store artifact SHA-256, size, submit timestamp, response status, and active status. They do not store auth headers, cookies, browser storage, private keys, raw response bodies, or artifact contents.
- Accepted/active artifact uploads may update `solved.jsonl`; blocked, rejected, planned, or inactive uploads do not enable writeup generation.
- Web metadata is local operator state. `ctfctl interactive web-config` stores the challenge base URL, auth source type, file path, storage-state path, or environment variable name without reading or storing raw cookie values, header values, environment values, storage contents, passwords, private keys, or flags.
- Web auth sources are `none`, `profile`, `cookie-file`, `header-file`, `storage-state`, and `env`. Scripts receive base URL and source metadata through `CTF_WEB_*` environment variables, not raw secret values from the harness.
- `ctfctl interactive web-probe` writes summarized page structure under `web/probes/`: status, title, forms, links, scripts, endpoint candidates, static path/hash summaries, body length/hash, and header summaries. It does not store raw response bodies, cookie/header values, browser storage values, or raw candidates.
- `ctfctl interactive browser-probe` writes local-only screenshots and browser summaries under `web/browser_probes/`. Network rows store method, path, status, and content type only; console text is auth-sanitized; storage state is referenced by path only.
- Browser probing route-blocks non-GET/HEAD and destructive-looking request paths before they are sent. Browser probe tests use only local fake web apps, and Playwright absence is reported as unavailable.
- `ctfctl interactive web-attempt` and `browser-attempt` store local-only attempts under `web/attempts/` and `web/browser_attempts/`, extract local candidates into `candidates.jsonl`, and record metrics with status/counts/lengths/hashes only. Public-safe snapshots exclude raw web responses, cookies, headers, storage-state values, console/network bodies, screenshots, and raw candidate values.
- Remote service metadata is local operator state. `ctfctl interactive service-config` stores endpoint, transport, token source kind, token file path or environment variable name, and optional PoW helper path without reading or storing the token value.
- `ctfctl interactive service-probe` and `service-attempt` write sanitized local-only transcripts under the challenge directory. Token values, cookies, sessions, auth headers, and private keys are redacted before display or record storage; local raw flags may remain visible for solving.
- Service scripts receive endpoint and token-source metadata through environment variables, not the token value. Token injection happens only after a detected token prompt.
- Public-safe service metrics include status, transport, prompt booleans, counts, lengths, and candidate hashes only. They must not include raw transcripts, token values, or raw candidate values.
- Same-machine interactive claims use local claim locks by default. `--allow-duplicate` is explicit and should be used only for intentional local duplicate solving. Cross-machine duplicate claims are out of scope and must be handled manually if the team cares.
- Interactive self memos are limited to sanitized `memory`, `evidence`, `attempts`, `next_steps`, and `operator_notes`.
- Stalled interactive challenges keep compact local handoffs only. They do not get writeups.
- Interactive writeups are accepted-only and must be generated as Korean and English files named `[category]ChallengeNameWriteup.ko.md` and `[category]ChallengeNameWriteup.en.md`.
- Solver or exploit code should be included completely in accepted writeups. Writeups are local-only during the contest and must not be published or uploaded externally until reviewed after the event.
- Interactive metrics are local-only under `metrics/events.jsonl`, `metrics/sessions.jsonl`, `metrics/challenge_metrics.jsonl`, `metrics/tool_benchmarks.jsonl`, `metrics/summary.json`, and `metrics/regression_report.md`.
- Public-safe metric snapshots may include artifact SHA-256, size, response status, and active status only. They must not include upload endpoints, local artifact paths, raw responses, auth material, or artifact contents.
- Background worker/supervisor/start-workers flows are legacy/advanced and should not be the normal live operation path.
- Platform actions require `ctfctl` gates, `--live`, and `--confirm` where needed.
- `ctfctl --mode setup|rehearsal|competition` separates setup, read-only rehearsal, and live competition execution. Setup blocks real challenge solve, live submit, instance start, browser login automation, and public tunnel exposure. Rehearsal permits real read-only ingest but blocks live submit and blocks real solve unless `--allow-real-solve-dry-run` is present. Competition requires `--confirm-competition`, an armed contest, and policy gates.
- `ctfctl contest prestart` reports preflight, profile, storage-state summary, worker auth metadata, and queue counts without live traffic by default.
- `ctfctl contest arm --confirm-competition` writes `control.json` and `arm.lock` under `~/.ctf-solver/runner-state/contests/<contest_id>/`; it does not start workers, sync challenges, submit flags, start instances, automate login, or expose tunnels.
- `ctfctl contest disarm` clears the active arm lock, marks the run mode back to rehearsal, and appends a local disarm log without deleting artifacts.
- `ctfctl contest disarm --stop-workers` also stops supervised worker processes. Without `--stop-workers`, status reports warn when supervised workers are still running.
- `ctfctl contest disarm --cleanup-resources` also stops tracked callback listeners and public tunnel provider processes. Without `--cleanup-resources`, disarm warns when active or stale callback/tunnel resources remain.
- `ctfctl contest disarm --stop-docker-pool` also stops contest Docker pool containers. Without it, disarm warns when tracked pool containers remain active.
- `control.json` stores only profile path and control booleans/timestamps; it must not contain raw auth values, browser storage, cookies, tokens, passwords, private keys, or flags.
- The worker supervisor stores PID, status, redacted command, and log files under `~/.ctf-solver/runner-state/contests/<contest>/workers/`, outside git. Command files keep only safe control env such as `CTF_RUN_MODE` and `CTF_CONTEST_ID`.
- `ctfctl contest start-workers` is dry-run by default and requires `--apply` to launch processes. Real platform workers are blocked unless the contest is armed; fake/local smoke is allowed in setup.
- `ctfctl contest full-rehearsal` is restricted to fake/local contest IDs such as `final-fake`. It starts only a loopback fake CTFd server, uses local fake fixtures, runs the callback public-smoke only against the local dummy listener, and performs cleanup before reporting readiness.
- Full rehearsal checks for raw leakage, duplicate claim races, duplicate submissions, postsolve generation, and stale resources. Acceptance requires zero active workers, zero active callback/tunnel resources, and zero active Docker pool containers after cleanup.
- Release readiness requires the mock full rehearsal and Codex mini rehearsal to report `status: ok`. The current deterministic Codex mini target is 3/3 local easy fixtures solved and accepted.
- Full rehearsal reports live under `~/.ctf-solver/runner-state/contests/<contest_id>/` and are local-only. The CLI output is redacted and does not include raw flags, auth material, callback payload bodies, or public tunnel hosts by default.
- Submit policy uses confidence, duplicate hash, wrong limit, and cooldown.
- Submit policy rejects fake/test/example-like candidates and blocks already solved challenges.
- Submission state stores SHA-256 hashes and redacted summaries only.
- Queue claims are atomic under SQLite WAL, busy timeout, and immediate transactions.
- Solved, submit-planned, stalled, error, and abandoned states are not immediately claimable.
- Active claims carry worker ID and heartbeat timestamps; stale claims are archived before reclaim.
- Solver parsing keeps raw candidates in memory for submit planning and exposes only hash/redacted previews in public payloads.
- Worker handoffs store compact facts, attempts, next ideas, and flag hashes only.
- Worker telemetry records candidate hashes or redacted details, never raw solver transcripts.
- Current-event writeup search is forbidden; official docs and CVE search need local evidence.
- Tunnel checks are detection-only by default; public exposure requires explicit operator action.
- Callback listeners bind to challenge/run-specific local state and store redacted hit summaries only.
- Tunnel cleanup is part of challenge teardown; stale tunnel logs and PID files stay out of git.
- Public tunnel start requires `--allow-public`; preflight never starts a public tunnel.
- Callback public smoke starts only a local dummy listener, sends at most one safe HTTP `GET /ping` through HTTP providers, and auto-stops the tunnel and listener.
- Callback summaries omit raw request values and replace secret-like values with `[REDACTED]`.
- Contest-linked callback and tunnel resources are recorded under `~/.ctf-solver/runner-state/contests/<contest>/resources/` with safe IDs, status, PID/alive checks, redacted public URL summaries, hit counts, and local runtime paths. Records do not store raw callback query strings, headers, request bodies, or secret-bearing URL queries.
- `ctfctl contest resources` refreshes active resources, marks dead or missing PIDs as stale, and reports active callback/tunnel counts for contest status. `ctfctl contest cleanup-resources` stops open resources and records local cleanup events without deleting logs by default.
- Default public URL output uses a redacted host summary; `--show-public-url` is explicit and still strips query strings before display.
- Tunnel state, PID files, provider logs, and callback hit JSONL files live under `~/.ctf-solver/runner-state/` and are ignored if a local override places them in the repo.
- Docker pool state lives under `~/.ctf-solver/runner-state/contests/<contest>/docker/`. It stores container names, worker IDs, image names, workspace paths, lifecycle timestamps, exec counts, average timings, and redacted command output only.
- Docker pool workspaces live under `~/CTF/workspaces/<contest>/<worker>` on Linux/WSL, and under `~/.ctf-solver/runner-state/docker-workspaces/<contest>/<worker>` on macOS, then mount as `/workspace`. The runner does not pass secret env vars or auth files into pool containers.
- The default Docker mount is the per-worker workspace only. Avoid broad host mounts and avoid `/mnt/c` default workspaces.
- `ctfctl docker pool-stop` and `contest disarm --stop-docker-pool` are the explicit stale-container cleanup paths.
- Competition workers run in a dedicated runner repo and add only specific writable directories rather than arbitrary shell state.
- Worker wrappers omit `--model` by default so Codex product defaults can advance; concrete model pins are explicit reproducibility overrides and are reported by preflight.
- Stale Codex install cleanup is dry-run by default and only renames confirmed older symlinks when `--apply` is passed.
- Secrets stay outside git, runtime artifacts stay ignored, and CLI output is redacted before display.
- `ctfctl repo public-check --json` rejects required-doc gaps, missing release scripts, repo-local runtime directories, sensitive filenames, public doc flag-like literals, and non-generic real-event references.
- `scripts/fresh-clone-check.sh` validates a temporary public-style clone with compile, tests, release-check, preflight, interactive e2e smoke, fake CTFd smoke, and mock local E2E.
- `scripts/history-scan.sh` reports sensitive path names across git history and sensitive HEAD patterns by file/pattern only. It does not print matched values.
- Live platform actions remain gated through `ctfctl`, `--live`, and `--confirm` instead of direct worker shell shortcuts.
- Operators can opt down from default danger mode with `CTF_CODEX_DANGER=0` and a narrower `CTF_CODEX_SANDBOX`.

Postsolve and archive risks and controls:

- Generated postsolve files live under ignored local contest directories, normally `~/CTF/contests/<contest>/<challenge>/postsolve/`.
- `solve_summary.md`, `writeup_draft.md`, `skill_candidate.md`, `timeline.jsonl`, and `postsolve_summary.json` use redacted text and flag hashes only.
- `skill_candidate.md` is a review artifact, not an automatic write to the existing personal skill repository.
- Artifact manifests store paths, sizes, hashes, and metadata only; they do not embed file contents.
- Archive copy mode excludes sensitive filenames such as auth, cookie, token, password, session, and storage-state files.
- Archive copy mode also marks obvious flag-like or secret-like file contents as metadata-only, so logs containing raw candidates are not copied into the archive.
- Cleanup/delete behavior is not part of default archive mode and requires a future explicit destructive flag.

Platform live-readonly risks and controls:

- Discovery and download can leak cookies, bearer tokens, or signed attachment URLs through stdout if raw headers or raw URLs are logged.
- The platform adapter loads secrets only for `--live` execution and returns only redacted metadata; signed URL query strings are stripped from displayed attachment sources.
- Browser `storage_state` files are treated as secret-bearing inputs and are never echoed back.
- Storage state capture can leak full browser sessions if the JSON is copied to chat, logs, git, screenshots, or issue trackers. Capture writes only under `~/.ctf-solver/secrets`, applies chmod `600`, and reports only size, cookie count, origin count, domain summaries, and storage key names.
- Storage-state rehearsal against an open real event can blur setup and solve phases because authenticated challenge details are locally ingested before competition mode. The mitigation is to keep setup-mode sync blocked unless `--allow-real-readonly` is explicit, run authenticated discovery/sync only in rehearsal, and leave worker solve blocked by default until the operator switches to competition mode.
- Browser discovery network capture can leak auth headers, signed URLs, or response bodies if dumped raw. The browser adapter stores only method/status/content-type/path summaries, strips query strings from output, bounds small JSON/RSC body parsing, and never prints captured response bodies or storage values.
- Attachment filenames may try path traversal or unsafe characters. Phase 4 sanitizes download filenames, and Phase 3 ingest continues to defend extraction-time traversal and link abuse inside archives.
- Profile validation reports auth path existence and permission warnings only; it does not read cookie, token, or browser storage contents.
- Base URLs are limited to HTTP/HTTPS, embedded credentials are invalid, and query strings are warned because they can carry auth or tracking material.
- The Phase 7 `live-readonly-smoke` command never calls submit or instance-start paths, even when a profile accidentally enables those policy bits.
- Signed attachment URLs are used only for the immediate download request. Displayed sources drop query strings so temporary signatures are not copied into logs.
- Rate limits and platform rules still apply to read-only traffic. Operators should run one bounded smoke first, avoid repeated polling, and follow the event rules and ToS.
- Automated browser login and public tunnel exposure are outside the live-readonly path and remain forbidden. Manual headed storage capture is allowed only when the operator performs the login directly; the runner never enters credentials.
- Manual storage capture is planned-only by default and requires `--allow-auth-capture` for live headed capture in setup or rehearsal mode.
- Generic discovery has extra over-probing risk because custom platforms do not share one stable API shape.
- Generic API probing is limited to same-origin candidates discovered from the contest page, browser network hints, or the configured contest path. It uses GET only, caps requests at fifteen by default, normalizes 401/403/404/429, strips URL queries from output, and filters submit/attempt/start/instance/deploy/reset/delete/logout/admin paths.
- Browser-assisted generic discovery route-blocks non-GET/HEAD and destructive requests before they are sent. Its network summary stores URL paths, method, status, and content type only.
- Generic submit is disabled in live-readonly mode; the adapter returns a blocked action rather than constructing a platform-specific submit request.

Auto-submit risks and controls:

- Wrong answer lockout: `max_wrong_per_challenge` and `cooldown_seconds` stop repeated attempts after rejected submissions.
- Decoy flags: `reject_fake_like` and confidence classification block placeholder, example, dummy, and bait-like candidates.
- Flag leakage: raw flags stay in memory only for the immediate submit call; DB rows, CLI output, and summaries store hashes and redacted previews.
- Duplicate spam: `duplicate_detection: sha256` blocks repeated terminal submissions of the same candidate.
- Accidental live action: competition auto-submit is now default after arm, so the controls are the arm state, `--no-live-submit` opt-out, platform `allow_submission`, worker confirmation, and submit-policy approval.
- Mode confusion: setup and rehearsal block real live submit before platform submit code is called; competition submit requires contest arm, `--confirm-competition`, profile policy, and submit policy.
- Stale arm lock: operators should run `ctfctl contest status --contest-id <id> --json` before starting workers and `ctfctl contest disarm --contest-id <id> --json` after the event.

Concurrent worker risks and controls:

- Duplicate claim race: multiple workers can ask for next challenge at the same time. `claim_next_challenge` runs inside `BEGIN IMMEDIATE`, excludes active claims, and records one active claim per challenge.
- Stale worker ownership: a crashed worker can leave a challenge in `claimed` or `solving`. Heartbeats plus `stale_after_sec` allow controlled reclaim and move the old claim to `claim_history`.
- Runaway supervisor workers: `worker-status`, `worker-logs`, `restart-worker`, `stop-workers`, and `disarm --stop-workers` provide explicit lifecycle control.
- Stale PID confusion: supervisor status treats dead PIDs as exited or stale and updates status files before reporting counts.
- Log leakage: worker loop output is already public/redacted, and `worker-logs` redacts tail output before display. Runtime log files remain outside git and must be treated as local-only.
- Accidental live submit from background workers: supervised competition workers include `--live-submit` and `--confirm-submit` by default only when the armed contest has `allow_live_submit`; profile policy and submit policy still gate the endpoint call, and command files do not store raw candidates.
- Stale arm lock plus background workers: operators should check `contest status`, review `running_worker_count`, and disarm with `--stop-workers` after the event.
- Duplicate submit race: workers use per-challenge flag hashes and already-solved state before live submit. The fake CTFd smoke also verifies already-solved responses.
- Raw flag leakage in handoff: handoffs use `public_solver_result`, facts/attempts are redacted, and candidates are stored as hashes only.
- Runtime artifact leakage: local E2E state, queue DB, telemetry, fake attachments, handoffs, and solve summaries live under ignored runtime directories.
