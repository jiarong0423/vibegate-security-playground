#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${VIBEGATE_PLAYGROUND_PYTHON_BIN:-"$ROOT/.venv/bin/python"}
if [ ! -x "$PYTHON" ]; then
    echo "Missing playground Python. Create .venv and install the documented dependencies." >&2
    exit 2
fi
if [ -n "${AWS_ACCESS_KEY_ID-}${AWS_SECRET_ACCESS_KEY-}${AWS_SESSION_TOKEN-}${AWS_SECURITY_TOKEN-}${AWS_WEB_IDENTITY_TOKEN_FILE-}${AWS_CONTAINER_CREDENTIALS_FULL_URI-}${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI-}" ]; then
    echo "Direct AWS credential sources are not allowed. Use the project-local AWS login session." >&2
    exit 2
fi
export AWS_CONFIG_FILE="$ROOT/.aws/config"
export AWS_SHARED_CREDENTIALS_FILE="$ROOT/.aws/credentials"
export AWS_LOGIN_CACHE_DIRECTORY="$ROOT/.aws/login/cache"
export AWS_PROFILE="vibegate-dev"
export AWS_DEFAULT_PROFILE="vibegate-dev"
export AWS_REGION="ap-southeast-2"
export AWS_DEFAULT_REGION="ap-southeast-2"
export AWS_EC2_METADATA_DISABLED="true"
export PYTHONDONTWRITEBYTECODE=1
exec "$PYTHON" "$@"
