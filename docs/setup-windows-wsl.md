# Windows WSL Setup

Keep this repository on the WSL ext4 filesystem, for example `~/dding-ctf-runner`. Avoid `/mnt/c` because Windows filesystem mounts are slower for many small files, have different locking behavior, and can make Docker bind mounts and SQLite state less predictable.

Docker Desktop WSL integration is expected. For pwn/rev workloads, prefer persistent containers over one-shot `docker run`; startup overhead is high enough that a per-worker container pool should be the default.

Check Docker from the same WSL Ubuntu terminal that will run workers:

```bash
cd ~/dding-ctf-runner
docker info >/dev/null
./scripts/ctfctl preflight --deep --json
```

If Docker is reachable from a normal WSL terminal but reported unreachable inside Codex preflight, treat `codex_sandbox_docker_unreachable` as a sandbox-context warning and re-check in WSL before starting pwn/rev workers. Docker Desktop must have WSL integration enabled for this Ubuntu distro.

## Docker Desktop WSL Troubleshooting

When `docker` is missing or the daemon is unreachable in WSL:

1. Start Docker Desktop on Windows and wait until the engine is running.
2. Open Docker Desktop Settings -> Resources -> WSL Integration, enable integration for the Ubuntu distro that runs this repo, then Apply & restart.
3. In the WSL terminal, refresh shell command lookup and retry:

```bash
hash -r
docker --version
docker info --format '{{json .ServerVersion}}'
./scripts/ctfctl preflight --deep --json
```

If Docker Desktop's WSL CLI exists but is not on `PATH`, use a symlink fallback:

```bash
ls -l /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker
sudo ln -sf /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker /usr/local/bin/docker
hash -r
docker info --format '{{json .ServerVersion}}'
```

Use `sudo apt install docker.io` only as a last resort when you intentionally want the native Linux Docker engine instead of Docker Desktop. Mixing Docker Desktop and a distro-local daemon can make socket selection and image availability confusing during a contest.

Build or verify the default pwn/rev image before a contest:

```bash
docker image inspect ctf-pwn:latest >/dev/null
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id local-docker-smoke --json
```

`docker_image_missing` / `ctf_pwn_image_missing` means `ctf-pwn:latest` is not present in the daemon currently selected by the WSL Docker CLI.

The `benchmark` command records one-shot startup timing; `pool-smoke` verifies that persistent per-worker containers start, execute a safe command, and stop cleanly. Release rehearsal expects no active pool containers after cleanup.

Start one persistent container per worker for pwn/rev contests:

```bash
./scripts/ctfctl docker pool-start --contest-id <contest> --workers 5 --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-status --contest-id <contest> --json
./scripts/ctfctl docker pool-stop --contest-id <contest> --json
```

Pool workspaces are under `~/CTF/workspaces/<contest>/<worker>/` and are bind-mounted to `/workspace`. Keep them on WSL ext4, not `/mnt/c`, for performance and to avoid Windows file-lock semantics.

The existing `~/ctf-solver` stays as a library/tooling reference. This runner owns competition queueing, worker isolation, platform automation policy, and submit guards.

Secrets and auth state must stay outside the repo, under paths such as `~/.ctf-solver/secrets`. Do not commit cookies, browser storage, API tokens, flags, downloads, or writeups.

## Platform Auth Profiles

For CTFd or generic custom platforms, store browser cookie headers, API tokens, and Playwright storage state outside this repository:

```bash
mkdir -p ~/.ctf-solver/secrets ~/.ctf-solver/platforms
chmod 700 ~/.ctf-solver ~/.ctf-solver/secrets ~/.ctf-solver/platforms
printf '%s\n' '<cookie header>' > ~/.ctf-solver/secrets/ctfd.cookie
chmod 600 ~/.ctf-solver/secrets/ctfd.cookie
```

Never paste a real cookie, token, browser storage JSON, password, or auth header into chat, shell history snippets, git commits, public writeups, or issue trackers.

Generic custom-platform profile example:

```yaml
platform: generic
name: example_event
base_url: "https://ctf.example.com"
contest_url: "https://ctf.example.com/contests/<contest-id>"
auth:
  method: storage_state_file
  path: "~/.ctf-solver/secrets/<contest>.storage_state.json"
  fallback:
    - method: cookie_header_file
      path: "~/.ctf-solver/secrets/<contest>.cookie"
policy:
  allow_live_discovery: true
  allow_live_download: true
  allow_submission: false
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
```

Check profile metadata without printing raw auth material:

```bash
cd ~/dding-ctf-runner
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

For custom SPA platforms, prefer a per-contest storage state path such as:

```bash
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Capture is manual-login only:

```bash
./scripts/ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --output ~/.ctf-solver/secrets/<contest>.storage_state.json

./scripts/ctfctl auth capture-storage \
  --config ~/.ctf-solver/platforms/<contest>.yaml \
  --output ~/.ctf-solver/secrets/<contest>.storage_state.json \
  --live \
  --headed \
  --timeout-sec 300
```

If headed Chromium does not open under WSL, run `./scripts/ctfctl browser smoke --json` and review Playwright dependency output. WSLg or an X server must be available for manual login capture. Headless Playwright cannot complete a human login flow. When GUI capture is unavailable, use a manually exported browser storage state from a trusted workflow or fall back to `cookie_header_file`/`api_token_file`; keep the exported file under `~/.ctf-solver/secrets` with `chmod 600`.

## Codex Worker Isolation

Run competition workers from a WSL Ubuntu terminal, not from PowerShell.

Do not start competition workers with plain `codex`. On this machine, plain `codex` may start from `~/CTF` and load the long global `AGENTS.md` prompt. That global warning is acceptable only when competition workers are launched through the runner wrapper.

```bash
cd ~/dding-ctf-runner
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1
./scripts/ctf-worker-2
./scripts/ctf-worker-3
./scripts/ctf-worker-4
./scripts/ctf-worker-5
```

The shortcuts call `scripts/ctf-worker`, which calls `scripts/run-codex-worker.sh`. The wrapper always changes to `~/dding-ctf-runner`, sets `CODEX_HOME=~/.codex-workers/<worker-id>`, and uses the runner's slim `AGENTS.md`. Worker config is generated locally and does not copy `~/.codex/config.toml`, so global auto-cwd/profile behavior is avoided. Existing `~/CTF/AGENTS.md` and `~/.codex/AGENTS.md` are intentionally left unchanged.

Competition workers now default to no-prompt automation mode:

```bash
./scripts/ctf-worker-1
```

Default policy:

- `model=auto/unpinned`; the wrapper omits `--model` and follows the current default chosen by the Codex CLI
- `approval=never`
- `sandbox=danger-full-access`

Auto/unpinned does not guarantee the newest or strongest model; it means the runner does not hard-code a model and lets the installed Codex CLI choose. Set `CTF_CODEX_MODEL=<model>` only when you need a reproducible run against a concrete model or want to force a specific latest/strongest model. `CTF_CODEX_MODEL=`, an unset variable, and `CTF_CODEX_MODEL=auto` all omit the model flag and let Codex choose its current default.

On competition day, observe the actual CLI default before assigning workers:

```bash
./scripts/ctfctl codex default-model-smoke --worker-id worker-1 --json
```

To pin a worker launch explicitly:

```bash
CTF_CODEX_MODEL=<model> ./scripts/ctf-worker-1
```

For reproducibility, record the selected concrete model in the contest profile at the start of the event. To follow Codex updates/defaults instead, leave `CTF_CODEX_MODEL` unset or empty.

To opt down into a safer local mode:

```bash
CTF_CODEX_DANGER=0 CTF_CODEX_SANDBOX=workspace-write ./scripts/ctf-worker-1
```

If you need to diagnose Codex update or duplicate-install issues:

```bash
./scripts/ctfctl codex doctor --json
./scripts/ctfctl codex mcp-status --json
./scripts/ctfctl codex model-status --json
./scripts/ctfctl codex default-model-smoke --worker-id worker-1 --json
./scripts/ctfctl codex unset-model-all
./scripts/fix-codex-install.sh
./scripts/fix-codex-shell.sh
./scripts/fix-codex-shell.sh --apply
source ~/.bashrc
```

`scripts/fix-codex-install.sh` is dry-run by default. With `--apply`, it disables only confirmed older `@openai/codex` symlinks by renaming the symlink, leaves the package directory intact, and keeps the `.bashrc` runner block pointed at the preferred binary. It never deletes auth or config files.

If plain `codex` prints `MCP client for dreamhack_solver failed to start`, remove the legacy MCP entry from Codex config with the dry-run helper first:

```bash
./scripts/fix-codex-mcp.sh --remove-legacy-dreamhack
./scripts/fix-codex-mcp.sh --remove-legacy-dreamhack --apply
```

`dreamhack_solver` is a legacy MCP server name from an older workflow. The canonical runner path is shell-first through `ctfctl` and the `ctf-worker-*` wrappers, so `ctf_solver` MCP is not required unless you explicitly register it later. `ReVa` can remain configured for Ghidra/reverse-engineering workflows. The MCP helper prints server names only, creates `config.toml.bak.<timestamp>` backups before applying, and does not display command args, env values, auth content, cookies, tokens, or raw config.

If you hit `the argument '--ask-for-approval <APPROVAL_POLICY>' cannot be used multiple times`, check for old aliases or shell functions outside the runner:

1. Run the wrapper without `CTF_CODEX_APPROVAL` first.
2. Check `type -a codex` in your interactive shell for aliases or functions that already add `-a` or `-s`.
3. Check the wrapper shape with `./scripts/ctf-worker-1 --dry-run`.

Do not edit `~/.codex/config.toml` just to make competition workers launch. If you need stronger isolation from user config, use `CTF_CODEX_IGNORE_USER_CONFIG=1` on the wrapper; the runner will isolate through the worker home rather than rewriting global config.

Auth is not linked by default. If a worker needs Codex auth, initialize with `--link-auth`; this creates an `auth.json` symlink only and never reads or prints auth content.

Optional shell aliases can be prepared with `./scripts/fix-codex-shell.sh`. The script is dry-run by default and only edits `~/.bashrc` when `--apply` is passed after creating a backup.

The runner does not delete `models_cache.json` or other Codex product notice caches. If Codex shows model onboarding or selection UI after the runner removes hard pins, treat it as product-managed state; the wrapper stays unpinned so future Codex defaults and upgrades can take effect.

## Browser Readiness

Install Playwright into the repo-local virtualenv with:

```bash
./scripts/setup-browser.sh
```

The script creates `.venv`, installs `pytest` and `playwright`, downloads Chromium with `python -m playwright install chromium`, runs tests, and executes `ctfctl browser smoke --json`. It does not install system packages. If Chromium reports missing system dependencies, review the Playwright output and install the required Ubuntu packages manually, or run a reviewed command such as:

```bash
./scripts/fix-playwright-deps.sh --apply
```

That script runs `.venv/bin/python -m playwright install-deps chromium` only when `--apply` is passed. It may require sudo and changes the WSL system; do not run it from automated bootstrap.

On a minimal Ubuntu 24.04 WSL image, Chromium may fail with missing NSS/NSPR libraries. Manual package candidates to review are:

```bash
sudo apt-get update
sudo apt-get install -y libnss3 libnspr4
```

## Tunnel Readiness

Tunnel readiness detects tooling first. It never starts a public tunnel unless a later command is given `--allow-public`.

```bash
./scripts/setup-tunnel-tools.sh
./scripts/ctfctl tunnel check --json
```

Preferred Ubuntu/WSL install for `cloudflared`:

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update
sudo apt-get install -y cloudflared
```

Fallback install candidate for `bore`:

```bash
cargo install bore-cli
```

Provider notes:

- `cloudflared`: recommended for HTTP/browser callbacks.
- `bore`: simple TCP forwarding through `bore.pub`; HTTP smoke is skipped because the provider is TCP-forwarding first.
- `ngrok`: usable when account/token policy allows it; keep tokens in local secrets only, never in git.
- `lt` or `localtunnel`: manual HTTP fallback.

Public tunnels should be started only during a competition challenge with explicit approval and a challenge/run-specific listener. Never expose a dashboard, browser automation server, authenticated app, local CTF platform session, or any other secret-bearing local service. Do not log raw cookies, tokens, flags, secret-bearing callback URLs, or browser storage. Callback hits are stored as redacted summaries only under `~/.ctf-solver/runner-state/callbacks/<listener_id>/hits.jsonl`.

Cleanup commands:

```bash
./scripts/ctfctl tunnel stop --tunnel-id <id> --json
./scripts/ctfctl callback stop --listener-id <id> --json
./scripts/ctfctl tunnel logs --tunnel-id <id> --tail 80
```

Do not use `sudo apt install` from the runner bootstrap. Record missing tools in preflight and install manually when the competition setup requires them.

## Final Public Release Check

From the WSL repo directory, run the final local checks before publishing:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/ctfctl preflight --deep --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake --workers 5 --solver mock --json
./scripts/ctfctl contest full-rehearsal --contest-id final-fake-codex --workers 3 --max-parallel-codex 2 --solver codex --allow-codex-call --json
./scripts/release-check.sh
./scripts/fresh-clone-check.sh
./scripts/history-scan.sh
```

Public readiness means preflight has no High risk, the mock and Codex local fake rehearsals report `status: ok`, release/public checks pass, no active workers/tunnels/callback listeners/Docker pool containers remain, and `git status --short` contains only intended source/docs/scripts/tests before the final commit. Review `git log --stat` before the first GitHub push; if history is uncertain, publish from a clean branch or a fresh repository with a squashed initial commit.

## Optional Attachment Tools

Phase 3 ingest works with Python standard-library archive and manifest support first. The following tools are optional and should be installed manually only when needed for a competition workflow:

- `7z` / `p7zip`: optional `.7z` extraction support.
- `tshark`: packet capture inspection.
- `exiftool`: metadata inspection for media and documents.
- `binwalk`: firmware and embedded-file triage.
- `zsteg`: PNG/BMP steganography checks.
- `steghide`: JPEG/WAV steganography checks.
- `foremost`: file carving.
- `scapy`: Python packet parsing.

The runner does not auto-install these tools. Treat them as local offline helpers and keep generated artifacts outside git unless they are deliberate, safe fixtures.
