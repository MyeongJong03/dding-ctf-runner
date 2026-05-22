# macOS Setup

This guide is for adding `dding-ctf-runner` to a Mac that already has a separate
CTF/Codex setup. The Mac profile is intended as a secondary/mobile runner. Keep
pwn/rev-heavy work on the primary Windows WSL runner unless local Docker timing
is known to be acceptable.

## Boundaries

Do not rewrite existing global CTF settings during Mac setup:

- Keep `~/CTF`, `~/CTF/AGENTS.md`, `~/CTF/CLAUDE.md`, `~/.codex/AGENTS.md`,
  `~/.agents`, and `~/ctf-solver` unchanged.
- Leave plain `codex` for the existing CTF workspace.
- Run this project only through `scripts/ctf-worker-*` wrappers and worker-local
  `CODEX_HOME` directories.
- Keep real platform profiles, cookies, browser storage, downloads, callback
  hits, queue databases, postsolve output, and writeups outside the repository.

## Install

Use the public repo checkout as the runner workspace:

```bash
cd ~
git clone git@github.com:MyeongJong03/dding-ctf-runner.git dding-ctf-runner
cd ~/dding-ctf-runner
```

If `~/dding-ctf-runner` already exists, inspect it first. Move only an empty
placeholder checkout out of the way. Do not overwrite a non-empty directory.

## Python And Browser

macOS can use Homebrew Python, but browser tooling should stay repo-local:

```bash
python3 --version
./scripts/setup-browser.sh
./scripts/ctfctl browser smoke --json
```

If Python 3.14 or a future Python release breaks Playwright wheels, create a
Python 3.12 virtual environment with `uv` or another local Python manager. Do
not replace the system Python.

## Worker Isolation

Create worker homes under `~/.codex-workers`:

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1 --dry-run
./scripts/ctf-worker worker-1 exec "Reply with exactly: MAC_WORKER_OK"
```

Expected state:

- `~/.codex-workers/worker-N/AGENTS.md` exists and is slim.
- `~/.codex-workers/worker-N/config.toml` exists and does not copy global MCP
  entries.
- `~/.codex-workers/worker-N/auth.json` is a local symlink only when
  `--link-auth` is intentionally used.

Do not edit `~/.zshrc` automatically. If shortcuts are useful, add them manually:

```bash
alias ctf-runner='cd ~/dding-ctf-runner'
alias ctf-worker-1='~/dding-ctf-runner/scripts/ctf-worker-1'
alias ctf-worker-2='~/dding-ctf-runner/scripts/ctf-worker-2'
alias ctf-worker-3='~/dding-ctf-runner/scripts/ctf-worker-3'
alias ctf-worker-4='~/dding-ctf-runner/scripts/ctf-worker-4'
alias ctf-worker-5='~/dding-ctf-runner/scripts/ctf-worker-5'
```

## Docker

Docker Desktop on Apple Silicon can run the `ctf-pwn:latest` linux/amd64 image,
but it uses emulation. Treat that as acceptable for smoke checks and light local
work, not as the preferred runtime for heavy pwn/rev debugging.

The macOS default already keeps Docker pool workspaces outside the existing
`~/CTF` workspace. Set the variable explicitly when running smoke checks so the
operator shell shows that policy:

```bash
export CTF_DOCKER_WORKSPACE_ROOT="$HOME/.ctf-solver/runner-state/docker-workspaces"

./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id mac-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id mac-docker-smoke --json
```

Always stop the pool after smoke checks. Do not put secrets in Docker env vars,
command arguments, or mounted workspace files.

## Tunnel And Callback

Provider readiness is safe to check:

```bash
./scripts/ctfctl tunnel check --json
./scripts/ctfctl callback smoke --json
```

Do not start a public tunnel during setup. Public callback smoke requires an
explicit `--allow-public` flag and should only target the local dummy listener
when the operator intentionally validates that path. Prefer `cloudflared` for
HTTP/browser callbacks when it is installed.

## Local Verification

Run only local/fake validation before using the Mac in a contest:

```bash
python3 -m compileall -q ctf_runner
python3 -m pytest -q
./scripts/release-check.sh
./scripts/ctfctl fake-ctfd smoke --json
./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json
./scripts/fresh-clone-check.sh
```

Acceptable Mac warnings:

- `global_long_agents` when plain `codex` is reserved for an existing CTF
  workspace and workers use `scripts/ctf-worker-*`.
- `legacy_dreamhack_solver_mcp` when it exists only in global Codex config and
  worker configs do not inherit it.
- linux/amd64 Docker image warnings on an arm64 host.

High-risk preflight findings should be fixed before running real workers.
