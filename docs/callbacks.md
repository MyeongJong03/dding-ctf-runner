# Callback Tunnels

Callback tooling is local-first. The listener binds only to `127.0.0.1` on an ephemeral port, stores redacted hit summaries under `~/.ctf-solver/runner-state`, and never records raw query strings, headers, or request bodies.

## Local Listener

```bash
./scripts/ctfctl callback start --json
./scripts/ctfctl callback start --contest-id <contest> --challenge-id <challenge> --worker-id worker-1 --json
./scripts/ctfctl callback status --listener-id <id> --json
./scripts/ctfctl callback hits --listener-id <id> --json
./scripts/ctfctl callback stop --listener-id <id> --json
```

Endpoints:

- `/`
- `/ping`
- `/hit/<token>`
- `/collect`

Hit logs are written to:

```text
~/.ctf-solver/runner-state/callbacks/<listener_id>/hits.jsonl
```

The stored hit format keeps method, endpoint kind, parameter names, header names, body length, and field names. Values are omitted or replaced with `[REDACTED]`; cookie, token, auth, bearer, session, CSRF, password, secret, key, and flag-like material must not be stored raw.

## Public Tunnel

Check providers first:

```bash
./scripts/ctfctl tunnel check --json
```

Start a tunnel only for a running listener and only with explicit public exposure approval:

```bash
./scripts/ctfctl tunnel start --listener-id <id> --contest-id <contest> --provider auto --allow-public --json
./scripts/ctfctl tunnel status --tunnel-id <id> --json
./scripts/ctfctl tunnel logs --tunnel-id <id> --tail 80
./scripts/ctfctl tunnel stop --tunnel-id <id> --json
```

Provider behavior:

- `cloudflared` runs `cloudflared tunnel --url http://127.0.0.1:<port>` and parses the `trycloudflare.com` HTTPS URL.
- `bore` runs `bore local <port> --to bore.pub`, reports a `tcp://bore.pub:<port>` endpoint, and marks the provider type as `tcp_forward`.
- `manual` records operator instructions only; it does not start a public process.

Public tunnel URLs are operationally sensitive. Default CLI JSON reports `public_url_display` as a redacted host summary and never includes query strings. Use `--show-public-url` only in a local terminal when the full query-stripped URL is needed for an active workflow.

## Contest Resource Tracking

When `--contest-id` is provided, callbacks and tunnels are tracked under:

```text
~/.ctf-solver/runner-state/contests/<contest>/resources/
```

The resource files are local-only:

- `callbacks.jsonl`
- `tunnels.jsonl`
- `resources.json`
- `cleanup_events.jsonl`

Resource records keep listener/tunnel IDs, provider, safe local URL, redacted public URL summary, PID/alive status, hit count, timestamps, and runtime paths. They do not store raw callback query strings, headers, bodies, cookies, auth material, passwords, private keys, or flags.

Inspect and clean contest resources:

```bash
./scripts/ctfctl contest resources --contest-id <contest> --json
./scripts/ctfctl contest cleanup-resources --contest-id <contest> --json
./scripts/ctfctl contest disarm --contest-id <contest> --stop-workers --cleanup-resources --json
```

## Safe Smoke

The smoke command starts a loopback dummy callback listener, starts a public tunnel only with `--allow-public`, sends one safe `GET /ping` through HTTP providers, then stops both the tunnel and listener.

```bash
./scripts/ctfctl callback public-smoke --provider auto --allow-public --json
./scripts/ctfctl callback public-smoke --contest-id local-tunnel-smoke --provider auto --allow-public --json
```

Do not point smoke traffic at an external CTF target. The only allowed target is the dummy loopback listener started by the command.

Release hardening uses this smoke only as a local callback/tunnel workflow check. It should leave zero active callback listeners and zero active tunnel processes in `ctfctl contest resources --contest-id <contest> --json` after cleanup. Do not include tunnel URLs, provider logs, callback hit files, or generated payloads in a public repository.

## Payload Helper

Generate inert callback snippets:

```bash
./scripts/ctfctl web payloads --callback-url https://<callback-host> --json
```

The helper emits plain URL, `img src`, `script src`, `fetch`, CSS `url()`, and SSRF URL forms with placeholders such as `{TOKEN_PLACEHOLDER}` and `{PROBE_ID}`. It does not add cookies, auth headers, browser storage, target URLs, or exploit-specific logic.

## Cleanup

After any manual workflow:

```bash
./scripts/ctfctl contest resources --contest-id <contest> --json
./scripts/ctfctl tunnel stop --tunnel-id <id> --json
./scripts/ctfctl callback stop --listener-id <id> --json
./scripts/ctfctl callback hits --listener-id <id> --json
./scripts/ctfctl contest cleanup-resources --contest-id <contest> --json
```

Treat callback URLs as sensitive operational details. Do not paste tunnel URLs, hit logs, or payload transcripts into public writeups or git commits.
