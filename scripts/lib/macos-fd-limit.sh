#!/usr/bin/env bash

ctf_runner_raise_macos_fd_limit() {
  local min_limit="${CTF_RUNNER_MACOS_FD_LIMIT:-4096}"
  local current_limit

  if [[ "$(uname -s 2>/dev/null || true)" != "Darwin" ]]; then
    return 0
  fi

  current_limit="$(ulimit -n 2>/dev/null || true)"
  if [[ ! "$current_limit" =~ ^[0-9]+$ ]]; then
    echo "[ctf-runner] warning: unable to inspect file descriptor limit" >&2
    return 0
  fi

  if (( current_limit >= min_limit )); then
    return 0
  fi

  if ulimit -n "$min_limit" 2>/dev/null || ulimit -S -n "$min_limit" 2>/dev/null; then
    return 0
  fi

  echo "[ctf-runner] warning: unable to raise file descriptor limit from $current_limit to $min_limit" >&2
  return 0
}
