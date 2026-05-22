# dding CTF Runner Rules

- Focus on live CTF solve-first execution: claim, solve, verify, submit, and compactly record the result.
- Use `ctfctl` as the shell-first control surface. Do not rely on hidden global state.
- Do not start workers with plain `codex`; use `scripts/ctf-worker-*` wrappers.
- Do not modify `~/ctf-solver`, `~/CTF/AGENTS.md`, `~/CTF/CLAUDE.md`, or `~/.codex/AGENTS.md`.
- Never print, commit, or copy raw cookies, tokens, auth files, browser storage, passwords, private keys, shell history, or real flags.
- Keep writeups, exploit transcripts, downloaded private files, browser artifacts, callback hits, and flags local-only.
- Do not push public git changes from this repo during CTF work.
- Live platform actions must go through `ctfctl` and require explicit `--live`, `--confirm` where destructive, and policy gates.
- Auto-submit is a goal, but only after confidence, rate-limit, duplicate-hash, and wrong-submission guards pass.
- Current-event writeup search is forbidden. Search official docs or CVEs only when local evidence such as version strings or errors justifies it.
- If a problem stalls, record a compact handoff with facts, attempted paths, blocker, and next action.
- After solving, create only a compact solve summary and `skill_candidate`; do not generate public writeups with secrets.
- Redact logs before display or telemetry. Store only hashes for submitted flags.
