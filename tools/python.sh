#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${VIBEGATE_PLAYGROUND_PYTHON_BIN:-"$ROOT/.venv/bin/python"}
if [ ! -x "$PYTHON" ]; then
    echo "Missing playground Python. Create .venv and install the documented dependencies." >&2
    exit 2
fi
export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON" "$@"
