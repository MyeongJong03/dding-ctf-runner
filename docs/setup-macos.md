# macOS Setup

macOS is a secondary/mobile runner for the interactive swarm. Keep pwn/rev-heavy
work on the primary Windows WSL runner unless local Docker timing is known to be
acceptable.

## Boundaries

- Keep existing `~/CTF`, `~/CTF/AGENTS.md`, `~/CTF/CLAUDE.md`, `~/.codex/AGENTS.md`, `~/.agents`, and `~/ctf-solver` unchanged.
- Default live solving uses visible plain Codex sessions from `~/CTF`.
- Repo development Codex sessions belong in `~/dding-ctf-runner`; CTF solving Codex sessions belong in `~/CTF`.
- Use `scripts/ctf-worker-*` only for legacy worker/supervisor rehearsals.
- Keep platform profiles, cookies, browser storage, downloads, callback hits, operator state, postsolve output, and writeups outside the repo.

## Install

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner
python3 -m pip install -e . pytest
./scripts/ctfctl interactive toolchain doctor --json
```

Browser tooling is optional:

```bash
./scripts/setup-browser.sh
./scripts/ctfctl browser smoke --json
```

## Interactive Swarm

Prepare from the runner repo:

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml

./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 4 --json
./scripts/ctfctl interactive capabilities --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

Start up to four solver terminals:

```bash
cd ~/CTF
codex
```

Paste a different generated prompt into each terminal. Each terminal claims,
solves, submits through `ctfctl`, writes accepted-only ko/en writeups, cleans up,
and claims the next challenge.

## Toolchain Doctor

Run the doctor before a contest:

```bash
./scripts/ctfctl interactive toolchain doctor --json
./scripts/ctfctl interactive capabilities --contest-id "$CONTEST_ID" --category rev --refresh --json
./scripts/ctfctl interactive fallback --tool ncat --json
./scripts/ctfctl interactive fallback --tool cpio --json
```

Recommended macOS tools include `python3`, `pip`, `uv`, `git`, `curl`, `wget`,
`nc`/`ncat`, `openssl`, `socat`, `file`, `strings`, `lldb`, `qemu`, `cpio`,
`tshark`, `zsteg`, `steghide`, `foremost`, `yara`, `volatility3`, `sage`,
`z3`, `ROPgadget`, `one_gadget`, `patchelf`, and `pwninit`. Homebrew, pipx,
gem, or release-binary commands in the report are hints only; the runner never
runs sudo or installs packages automatically.

macOS uses BSD userland by default, so GNU ELF workflows may need Homebrew
binutils or the Docker `ctf-pwn:latest` fallback. For TLS remotes without
`ncat --ssl`, use `openssl s_client`; for initramfs/cpio work without `cpio`,
try `bsdtar`, a Python parser, or Docker.

## Docker On Apple Silicon

Docker Desktop on Apple Silicon can run the `ctf-pwn:latest` linux/amd64 image
through emulation. Treat this as acceptable for smoke checks and light work, not
as the preferred runtime for heavy pwn/rev debugging.

Keep Docker workspaces outside `~/CTF`:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"

./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
```

Always stop pool containers after smoke checks. Do not put secrets in Docker env
vars, command arguments, or mounted workspace files.

## Auth And Profiles

Use the same external profile layout as Windows:

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.storage_state.json
```

```bash
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Do not copy real cookies, tokens, storage state, auth headers, or raw flags into
repo files, prompts, public writeups, or issue trackers.

## Legacy Worker Isolation

Create worker homes only for legacy worker rehearsals:

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1 --dry-run
```

Expected legacy state:

- `~/.codex-workers/worker-N/AGENTS.md` is slim.
- `~/.codex-workers/worker-N/config.toml` does not copy global MCP entries.
- `~/.codex-workers/worker-N/auth.json` is a local symlink only when `--link-auth` is intentionally used.

## Tunnel And Callback

Provider readiness is safe to check:

```bash
./scripts/ctfctl tunnel check --json
./scripts/ctfctl callback smoke --json
```

Do not start a public tunnel during setup. Public callback smoke requires
`--allow-public` and should target only the local dummy listener.

## Local Verification

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/release-check.sh
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/fresh-clone-check.sh
```

Acceptable Mac warnings:

- `global_long_agents` when plain `codex` is reserved for the existing CTF workspace.
- `legacy_dreamhack_solver_mcp` when it exists only in global Codex config.
- linux/amd64 Docker image warnings on an arm64 host.

Fix high-risk preflight findings before running real interactive solvers.
