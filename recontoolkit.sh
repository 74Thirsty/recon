#!/bin/bash
# Wrapper to launch the advanced Python-based Recon toolkit.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN=""

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo "[ERROR] Python 3 is required to run this application."
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/recon.py" "$@"
