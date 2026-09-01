#!/bin/bash
set -euo pipefail

[[ "$#" -eq 0 ]] || { echo "offline verification accepts no arguments" >&2; exit 2; }
[[ "${HARNESS_OFFLINE_ENFORCED:-0}" == "1" ]] || { echo "external OS isolation is required" >&2; exit 2; }
[[ -n "${HARNESS_OFFLINE_BACKEND:-}" && -n "${HARNESS_OFFLINE_SESSION_ID:-}" ]] || { echo "trusted isolation identity is missing" >&2; exit 2; }
[[ -n "${HARNESS_TASK_PACKET:-}" && -f "$HARNESS_TASK_PACKET" && ! -L "$HARNESS_TASK_PACKET" ]] || { echo "hash-pinned packet is required" >&2; exit 2; }
[[ -z "${HARNESS_WARM_SOURCE_ROOTS:-}" ]] || { echo "warm-source roots must be hidden from repository code" >&2; exit 2; }
for setting in UV_OFFLINE UV_FROZEN UV_NO_SYNC; do
  [[ "${!setting:-}" == "1" ]] || { echo "$setting must be one" >&2; exit 2; }
done
ci_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH='' cd -- "${ci_dir}/.." && pwd -P)"
export PYTHONPATH="${repo_root}/src"
export SOURCE_DATE_EPOCH=946684800
cd "$repo_root"
exec python3 "${ci_dir}/run_packet_argv.py"
