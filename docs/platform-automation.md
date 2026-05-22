# Platform Automation

Phase 7 keeps real-platform automation in live-readonly rehearsal mode. Against a real CTFd-like platform, the allowed path is discovery, challenge detail lookup, attachment download, and local ingest only. Phase 7.1 adds a generic read-only path for platforms that are not CTFd, such as event sites that serve challenge data through a SPA or a custom API.

Use `--mode setup` or `--mode rehearsal` while configuring an active real event. In setup mode, real discovery is allowed but real platform download/ingest requires `--allow-real-readonly`; worker solve and submit are blocked. In rehearsal mode, authenticated read-only ingest can prepare local briefs, but real solve is still blocked unless a dry-run solve override is explicit. Switch to `--mode competition --confirm-competition` only after the operator explicitly decides the event is in solve mode and arms the contest.

The implemented read path is:

- auth metadata check
- challenge discovery
- challenge detail lookup
- attachment download
- immediate handoff into `ctfctl ingest run`

Live platform traffic is denied unless both of the following are true:

- `--live` is present
- the platform config explicitly enables the matching policy gate

Discovery and attachment download are read-only actions. In Phase 7, real submit and real instance start are not part of rehearsal and must not be used.

Example config lives in `config/platforms.yaml.example`. Real auth material stays outside this repo.

Local profile locations:

- `contests/<contest_id>/platform.local.yaml`
- `~/.ctf-solver/platforms/<contest_id>.yaml`

Secret file locations:

- `~/.ctf-solver/secrets/ctfd.cookie`
- `~/.ctf-solver/secrets/ctfd.token`
- `~/.ctf-solver/secrets/storage_state.json`

Do not place cookies, tokens, browser storage, downloaded attachments, state DBs, writeups, or real flags in this repository.

For public release, keep profile examples generic and keep all concrete event URLs, generated challenge names, auth paths, browser storage paths, and downloaded material out of README, GUIDE, docs, tests, and git history.

Public callback/tunnel workflow is separate from platform automation. Use `docs/callbacks.md` and `ctfctl callback public-smoke --allow-public` only against the local dummy listener; do not use public tunnel smoke against a real CTF platform.

Create local-only secret directories with restrictive permissions:

```bash
mkdir -p ~/.ctf-solver/secrets ~/.ctf-solver/platforms
chmod 700 ~/.ctf-solver ~/.ctf-solver/secrets ~/.ctf-solver/platforms
printf '%s\n' '<CTFd API token>' > ~/.ctf-solver/secrets/ctfd.token
printf '%s\n' 'session=<redacted>; csrf_nonce=<redacted>' > ~/.ctf-solver/secrets/ctfd.cookie
chmod 600 ~/.ctf-solver/secrets/ctfd.token ~/.ctf-solver/secrets/ctfd.cookie
```

Profiles can use one primary auth method plus an ordered fallback list. This is useful for custom SPA platforms where a cookie header reaches the landing page but challenge data requires browser storage, localStorage-backed tokens, or framework-specific session state. The runner reports only method/path existence and permission metadata for every auth entry.

Auth methods:

1. API token file: preferred for stable CTFd API access, easiest to scope, lowest parsing complexity.
2. Cookie header file: useful when the platform has no API token flow, but carries direct header leakage risk if mishandled and may be insufficient for SPA/custom platforms.
3. Browser `storage_state_file`: stores Playwright cookies and origin storage outside the repo. It is often needed when challenge data is loaded by browser-authenticated Next/RSC, localStorage, JWT, or CSRF flows.
4. Manual: records intent only and does not read a secret file.

## CTFd vs Generic

Use `platform: ctfd` when the site exposes the standard CTFd API:

- `GET /api/v1/challenges`
- `GET /api/v1/challenges/{id}`

Use `platform: generic` when the event site may be custom or SPA-backed. Generic discovery starts from `contest_url`, fetches the contest page with GET only, extracts challenge-like links and embedded JSON, then probes a bounded set of same-origin read-only candidates such as `/api`, `/graphql`, `/trpc`, and contest/challenge paths inferred from the page. It never brute-forces endpoint dictionaries and does not call submit, attempt, instance, start, deploy, reset, delete, logout, or admin paths.

Generic profile examples:

```yaml
platform: generic
name: example_event
base_url: "https://ctf.example.com"
contest_url: "https://ctf.example.com/contests/<contest-id>"
auth:
  method: cookie_header_file
  path: "~/.ctf-solver/secrets/<contest>.cookie"
policy:
  allow_live_discovery: true
  allow_live_download: true
  allow_submission: false
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
```

```yaml
platform: generic
name: custom_api_event
base_url: "https://ctf.example.com"
contest_url: "https://ctf.example.com/events/current"
auth:
  method: api_token_file
  path: "~/.ctf-solver/secrets/ctfd.token"
policy:
  allow_live_discovery: true
  allow_live_download: false
  allow_submission: false
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
```

```yaml
platform: generic
name: browser_state_event
base_url: "https://ctf.example.com"
contest_url: "https://ctf.example.com/contests/current"
auth:
  method: storage_state_file
  path: "~/.ctf-solver/secrets/storage_state.json"
  fallback:
    - method: cookie_header_file
      path: "~/.ctf-solver/secrets/ctfd.cookie"
policy:
  allow_live_discovery: true
  allow_live_download: false
  allow_submission: false
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
```

Profile commands:

```bash
ctfctl platform profile-create \
  --contest-id example \
  --base-url https://ctf.example.com \
  --auth-method api_token_file \
  --auth-path ~/.ctf-solver/secrets/ctfd.token \
  --output ~/.ctf-solver/platforms/example.yaml \
  --json

ctfctl platform profile-check \
  --config ~/.ctf-solver/platforms/example.yaml \
  --json

ctfctl platform profile-set-auth \
  --config ~/.ctf-solver/platforms/example.yaml \
  --method storage_state_file \
  --path ~/.ctf-solver/secrets/example.storage_state.json

ctfctl platform profile-add-auth-fallback \
  --config ~/.ctf-solver/platforms/example.yaml \
  --method cookie_header_file \
  --path ~/.ctf-solver/secrets/ctfd.cookie

ctfctl platform profile-show \
  --config ~/.ctf-solver/platforms/example.yaml \
  --json
```

`profile-check` and `profile-show` read profile metadata and auth path metadata only. They report whether each primary/fallback auth path exists and whether permissions are broad; they do not read or print raw cookies, tokens, storage state, or browser storage values. A missing primary `storage_state_file` is a warning when a fallback exists.

Manual storage capture:

```bash
ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/example.yaml \
  --output ~/.ctf-solver/secrets/example.storage_state.json

ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/example.yaml \
  --output ~/.ctf-solver/secrets/example.storage_state.json \
  --live \
  --headed \
  --allow-auth-capture \
  --timeout-sec 300

ctfctl auth storage-check \
  --path ~/.ctf-solver/secrets/example.storage_state.json \
  --json
```

Without `--live`, capture is planned only. With `--live --headed --allow-auth-capture`, Playwright opens Chromium at `contest_url` or `<base_url>/login` and waits for the operator to log in manually. The runner never types usernames or passwords. Setup and rehearsal modes require the explicit allow flag; competition mode also requires its policy/confirmation gate. After capture, the output file is chmod `600`; CLI output includes path existence, size, cookie count, origin count, and domain/key summaries only.

Live-readonly rehearsal:

```bash
ctfctl platform live-readonly-smoke \
  --config ~/.ctf-solver/platforms/example.yaml \
  --json
```

The smoke command performs auth metadata check, live discovery, one live detail lookup, optional live attachment download when `policy.allow_live_download` is true, and local ingest. If a challenge has no attachments but has extracted detail text, it writes a text-only `raw/challenge.md` and `brief.md`. It does not call submit or instance-start code. Add `--save-state` only when you want discovered/ingested metadata written to the local runner DB.

Generic commands:

```bash
ctfctl platform generic-discover --config ~/.ctf-solver/platforms/example.yaml --live --json
ctfctl platform browser-discover --config ~/.ctf-solver/platforms/example.yaml --live --json
ctfctl platform sync-challenges --config ~/.ctf-solver/platforms/example.yaml --live --save-state --ingest-text --json
ctfctl platform generic-download --config ~/.ctf-solver/platforms/example.yaml --challenge-id <id> --live --json
ctfctl platform generic-ingest --config ~/.ctf-solver/platforms/example.yaml --challenge-id <id> --live --json
```

`browser-discover` uses Playwright for read-only page navigation only. It applies the first usable primary/fallback auth entry: `storage_state_file` starts the browser context with saved state, while `cookie_header_file` is converted into same-origin browser cookies without printing values. It records only path-level network summaries with query strings removed, captures bounded small JSON/Next RSC response bodies for parsing only, summarizes localStorage/sessionStorage keys without values, and route-blocks non-GET/HEAD or destructive requests.

For custom SPA-backed platforms, the generic adapter starts from the configured contest path, parses `__NEXT_DATA__`, JSON script blocks, `self.__next_f.push` Flight chunks, and same-origin network JSON/RSC responses. It probes only a bounded same-origin read-only set such as `/contests/<id>/challenges`, `/contests/<id>/problems`, `/api/contests/<id>`, `/api/challenges`, `/api/problems`, `/api/tasks`, and `/trpc`. 404 and empty responses are normalized; submit/attempt/instance/start/deploy/reset/delete/logout/admin paths are filtered or blocked.

`sync-challenges` converts discovered generic challenges into queue entries. With `--ingest-text`, it fetches bounded read-only detail material for up to 20 challenges by default and creates text-only briefs when there are no attachments. In setup mode against a real platform, add `--allow-real-readonly` before using `--ingest-text`; rehearsal mode allows this read-only ingest by default. State rows become `ingest_ready` when a brief is generated and remain `new` when only metadata was discovered. Output is summary-only: it reports counts, IDs, names, brief paths, and whether detail text existed, but not raw statement bodies.

Storage-state rehearsal flow:

```bash
ctfctl auth storage-check \
  --path ~/.ctf-solver/secrets/<contest>.storage_state.json \
  --json

ctfctl platform profile-check \
  --mode setup \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --json

ctfctl platform sync-challenges \
  --mode setup \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --save-state \
  --ingest-text \
  --json

ctfctl platform browser-discover \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --json

ctfctl platform sync-challenges \
  --mode rehearsal \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --live \
  --save-state \
  --ingest-text \
  --json
```

The setup-mode sync command above is a safety check and should return `setup_requires_allow_real_readonly` unless `--allow-real-readonly` is intentionally added. Use rehearsal mode for read-only authenticated discovery and ingest after manual headed storage capture has produced a usable `storage_state_file`; keep the fallback `cookie_header_file` only as a secondary auth source. Neither command submits flags, starts instances, automates login, or sends non-read-only browser requests.

For an open real event, do not run a worker solve in setup mode or default rehearsal mode. A setup-mode or default rehearsal-mode worker that claims a real platform challenge is blocked before Codex is called. Rehearsal dry-run solving requires `ctfctl worker once --mode rehearsal --allow-real-solve-dry-run ...` and still cannot submit. Actual solve execution is a competition-mode action and requires an armed contest plus `--mode competition --confirm-competition`; live submission needs separate contest, submit, platform policy, and submit-policy gates.

Generic attachment download uses GET only, strips signed URL query strings from displayed metadata, sanitizes filenames, limits downloads per challenge to five by default, and requires `policy.allow_live_download: true`.

CTFd baseline API paths used by the read path:

- `GET /api/v1/challenges`
- `GET /api/v1/challenges/{id}`

The adapter stores only redacted summaries from discovery and detail lookups. It does not dump raw API responses.

Attachment handling notes:

- signed attachment URLs may contain tokens in the query string; displayed metadata strips the query entirely
- downloaded files land under `~/CTF/contests/<platform>/<challenge_id>/raw` by default, or under the configured `downloads.root`
- downloads are local-only artifacts and must stay ignored by git
- `ctfctl platform ingest --live` downloads first, then calls ingest on the local raw directory

Instancer behavior:

- CTFd instance lifecycle is deployment-specific
- Phase 7 rehearsal forbids real instance start

Submit behavior:

- Real submit is forbidden during live-readonly rehearsal.
- Use `policy.allow_submission: false` for read-only profiles and `policy.allow_submission: true` only for competition profiles that should auto-submit.
- Live submit requires all of: armed contest control state, `allow_live_submit` in that arm state, worker confirmation from `contest start-workers` or `--confirm` for manual `platform submit`, `policy.allow_submission: true`, and submit-policy approval.
- `ctfctl contest arm` enables the runner-side live-submit gate by default in competition. Use `--no-live-submit` to arm without automatic submissions; `--allow-live-submit` remains a compatibility spelling.
- Existing submit dry-runs and fake local submits remain test-only guardrails; do not use them against a real platform in this phase.

## Public Release Checks

Before publishing automation docs, run:

```bash
./scripts/ctfctl repo public-check --json
./scripts/release-check.sh
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
```

The public check expects only generic placeholder profile examples in this file. It fails if repo-local runtime directories, queue databases, auth files, storage-state files, cookie/token files, or non-generic real-event references are present.
