# Attachment Ingest

Phase 3 adds a local-only attachment ingestor for preparing CTF challenge files before a Codex worker starts analysis.

## Directory Layout

`ctfctl ingest run` and `ctfctl ingest text` write challenge material under:

```text
~/CTF/contests/<contest_id or manual>/<challenge_id>/
  raw/
  extracted/
  manifest/
    manifest.json
    scan.json
    ingest_summary.json
  brief.md
```

Raw attachment files are copied into `raw/` and are never deleted by ingest. Archive contents are extracted into `extracted/`. Directory inputs may be scanned in place instead of copied wholesale.

Text-only ingest is for custom platforms that expose challenge statements but no attachments:

```bash
ctfctl ingest text \
  --challenge-id <id> \
  --name "<title>" \
  --category "<category>" \
  --text-file /path/to/statement.md \
  --contest-id <contest>
```

It creates `raw/challenge.md`, `manifest/manifest.json`, `manifest/scan.json`, `manifest/ingest_summary.json`, and `brief.md`. The statement, hints, links, and connection info are redacted before writing. Flag-shaped values are replaced with redaction markers.

## Archive Policy

Supported archive types:

- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`
- single-file `.gz`
- `.7z` only when a local `7z` or `7za` command exists

Extraction is defensive:

- Absolute paths and path traversal entries are blocked.
- Symlink and hardlink entries are skipped by default and recorded in the summary.
- Default limits are 5000 files, 500 MB total uncompressed data, and 100 MB per extracted file.
- Nested archives are recorded in `nested_archives` but are not recursively extracted.
- Original archives remain preserved under `raw/`.

Attachment binaries are not executed during ingest. Binary handling is limited to non-executing metadata commands such as `file`, `strings`, and `checksec` when available.

## Manifest Policy

`manifest/manifest.json` records bounded metadata for every discovered non-`.git` file:

- relative path
- size
- extension
- detected file type
- sha256
- category
- text readability
- large-file marker
- interesting score and reasons

Categories include source, config, archive, binary, shared library, image, audio, video, pcap, document, text, and unknown.

Small text/source/config previews are allowed only up to 64 KB and are redacted. Binary and media previews are never included. Sensitive-looking paths such as auth files, local config, shell history, private keys, cookies, token files, and browser storage do not receive content previews. For those sensitive-name files, ingest also avoids content hashing and external type sniffing so raw content is not read for reporting.

`.git` directories are not traversed. The manifest records only whether a `.git` directory exists, whether `HEAD` exists, and whether commit object files appear to exist.

`node_modules/`, virtualenvs, `dist/`, and `build/` are still included in the manifest so file counts and size pressure are visible. The brief omits them by default unless package or version descriptors are interesting.

## Source Scan Policy

`manifest/scan.json` is a bounded quick-signal report. It does not prove exploitability and should be treated as triage input.

Signals include:

- Web: routes, framework hints, template rendering, eval/exec/subprocess sinks, SQL construction, JWT/session/cookie usage, upload/path usage, SSRF/open redirect hints, bot/admin/report hints, and runtime descriptors.
- Pwn/Rev: ELF/shared library candidates, checksec summaries, and redacted strings keyword hits.
- Crypto: RSA/ECC/AES/hash keywords, Sage/Python crypto helpers, public keys, and ciphertext-like files.
- Forensics/Misc: images, audio, video, pcaps, PDFs, office documents, and metadata-worthy artifacts.

All output is bounded and redacted. Flag-like values, cookies, tokens, bearer values, API keys, and password-like assignments are not printed raw.

## Brief Policy

`brief.md` is the compact context intended for Codex workers. It targets 12 KB or less and includes:

- challenge metadata
- challenge statement, hints, tags, links, and connection info when text-only material exists
- file summary
- likely category
- top interesting files
- archive extraction summary
- source scan signals
- recommended first actions
- warnings and unknowns

Workers should start from `brief.md`, `manifest/manifest.json`, `manifest/scan.json`, and manually selected files. They should not receive entire raw attachment trees as prompt context.

For Codex reliability, the worker prompt includes `brief.md`, the top interesting file list, and bounded selected text/source previews when they are safe to show. Selected previews stay under strict size limits and are redacted in public logs; raw challenge material remains local-only.

## Preservation Policy

Ingest preserves originals and generates manifests around them. It does not delete attachments, submit flags, log in to browsers, contact external CTF sites, expose public tunnels, or push generated outputs. Challenge outputs under `contests/` remain ignored by git by default.

Before a public release, run `ctfctl repo public-check --json` and remove any repo-local ingest output. The public repository should contain only generic fixture code and docs, not generated `brief.md`, `raw/`, `extracted/`, manifest files from an event, or local runner databases.
