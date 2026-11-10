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
"$PYTHON" -m compileall -q sentinel_guard tests
git diff --check HEAD
