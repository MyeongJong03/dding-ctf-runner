# Windows WSL Setup

Windows WSL is the preferred primary runner for heavy CTF work, especially
pwn/rev. Keep `dding-ctf-runner` on the WSL ext4 filesystem, for example
`~/dding-ctf-runner`. Avoid `/mnt/c` because filesystem locking, small-file
performance, Docker bind mounts, and SQLite state are less predictable there.

## Install

```bash
cd ~
git clone <repo-url> dding-ctf-runner
cd ~/dding-ctf-runner

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e . pytest
./scripts/ctfctl preflight --deep --json
```

Install browser support only when platform discovery or storage capture needs it:

```bash
./scripts/setup-browser.sh
./scripts/ctfctl browser smoke --json
```

## Interactive Codex Swarm

The default live workflow uses plain interactive Codex sessions from `~/CTF`.
These are CTF-solving terminals. Keep any Codex session used to edit this repo
separate in `~/dding-ctf-runner`.

Prepare from the runner repo:

```bash
cd ~/dding-ctf-runner
export CONTEST_ID=<contest>
export PROFILE=~/.ctf-solver/platforms/<contest>.yaml

./scripts/ctfctl interactive init --contest-id "$CONTEST_ID" --profile "$PROFILE" --agents 6 --json
./scripts/ctfctl interactive sync --contest-id "$CONTEST_ID" --profile "$PROFILE" --live --download --ingest --json
./scripts/ctfctl interactive board --contest-id "$CONTEST_ID" --json
./scripts/ctfctl interactive prompt --contest-id "$CONTEST_ID" --agent agent-1
```

Start up to six solver terminals when CPU/RAM and platform limits allow:

```bash
cd ~/CTF
codex
```

Paste a different generated prompt into each terminal. Every terminal is an
autonomous solver and should continue through claim, solve, verify, submit,
writeup, cleanup, and next claim.

Same-machine duplicate claims are blocked by default. Use
`ctfctl interactive claim --allow-duplicate` only when intentionally assigning
the same challenge to multiple local Codex sessions.

## Platform Auth Profiles

Store profiles and secrets outside the repo:

```text
~/.ctf-solver/platforms/<contest>.yaml
~/.ctf-solver/secrets/<contest>.cookie
~/.ctf-solver/secrets/<contest>.token
~/.ctf-solver/secrets/<contest>.storage_state.json
```

Example:

```yaml
platform: generic
name: example_event
base_url: "https://ctf.example.com"
contest_url: "https://ctf.example.com/contests/<contest-id>"
auth:
  method: storage_state_file
  path: "~/.ctf-solver/secrets/<contest>.storage_state.json"
policy:
  allow_live_discovery: true
  allow_live_download: true
  allow_submission: false
  allow_instance_start: false
downloads:
  root: "~/CTF/contests"
```

Check metadata without printing raw auth:

```bash
./scripts/ctfctl platform profile-check --config ~/.ctf-solver/platforms/<contest>.yaml --json
./scripts/ctfctl auth storage-check --path ~/.ctf-solver/secrets/<contest>.storage_state.json --json
```

Never paste real cookies, tokens, browser storage JSON, passwords, auth headers,
or raw flags into chat, shell history snippets, git commits, public writeups, or
issue trackers.

## Docker Desktop WSL

Docker Desktop WSL integration should be enabled for the Ubuntu distro running
this repo.

```bash
docker info >/dev/null
./scripts/ctfctl preflight --deep --json
```

If Docker is unreachable:

1. Start Docker Desktop and wait for the engine.
2. Enable Settings -> Resources -> WSL Integration for this Ubuntu distro.
3. Retry from WSL:

```bash
hash -r
docker --version
docker info --format '{{json .ServerVersion}}'
./scripts/ctfctl preflight --deep --json
```

Verify the pwn/rev image and pool:

```bash
docker image inspect ctf-pwn:latest >/dev/null
./scripts/ctfctl docker benchmark --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-smoke --contest-id local-docker-smoke --workers 2 --json
./scripts/ctfctl docker pool-stop --contest-id local-docker-smoke --json
```

Start contest pool containers only when needed:

```bash
./scripts/ctfctl docker pool-start --contest-id <contest> --workers 6 --image ctf-pwn:latest --json
./scripts/ctfctl docker pool-status --contest-id <contest> --json
./scripts/ctfctl docker pool-stop --contest-id <contest> --json
```

Pool workspaces live under `~/CTF/workspaces/<contest>/<worker>/` and are
mounted at `/workspace`. Keep them on WSL ext4.

## Legacy Worker Wrappers

`scripts/ctf-worker-*` wrappers are for legacy worker/supervisor rehearsals, not
the default interactive swarm.

```bash
./scripts/init-codex-workers.sh --count 5 --link-auth
./scripts/ctf-worker-1 --dry-run
```

Do not start legacy competition workers with plain `codex`. Use the emitted
wrapper commands only when intentionally running legacy/advanced automation.

## Safety

Do not modify `~/ctf-solver`, `~/CTF/AGENTS.md`, `~/CTF/CLAUDE.md`,
`~/.codex/AGENTS.md`, or global Codex config just to use this runner. Runtime
state, downloads, writeups, callback hits, and flags stay outside git.
