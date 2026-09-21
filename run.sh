#!/usr/bin/env bash
set -euo pipefail
export PYTHONUTF8=1
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v python3 >/dev/null 2>&1; then
    echo "Install Python 3.10+ with pip and venv, then run this file again." >&2
    exit 1
fi
exec python3 bootstrap.py "$@"
