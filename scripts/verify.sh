#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON=".venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  printf 'Error: required executable %s was not found.\n' "$PYTHON" >&2
  exit 127
fi

"$PYTHON" -m pytest -q
"$PYTHON" -m unittest discover -s tests -v
node --test tests/guarded_agent_bridge.test.js tests/near_testnet_preflight.test.js tests/local_ui.test.mjs tests/local_ui_server.test.js
npm run ui:build
"$PYTHON" -m compileall -q sentinel_guard tests
git diff --check HEAD

while IFS= read -r -d '' file; do
  # Skip binary data; empty files cannot contain whitespace errors.
  if [[ ! -s "$file" ]] || ! LC_ALL=C grep -Iq '' -- "$file"; then
    continue
  fi
  set +e
  check_output="$(git diff --no-index --check -- /dev/null "$file" 2>&1)"
  check_status=$?
  set -e
  if [[ -n "$check_output" ]]; then
    printf '%s\n' "$check_output" >&2
    exit 1
  fi
  if (( check_status > 1 )); then
    printf 'Error: whitespace check could not inspect untracked file %s.\n' "$file" >&2
    exit "$check_status"
  fi
done < <(git ls-files --others --exclude-standard -z)
