#!/usr/bin/env bash
set -euo pipefail

# Prompt for credentials
read -rp "IDA License ID: " IDA_LICENSE_ID
read -rsp "HCLI API Key: " HCLI_API_KEY
echo

export IDA_LICENSE_ID HCLI_API_KEY

python -m pip install uv

TMPDIR=$(readlink -f .) python -m uv run --with ida-hcli \
    hcli ida install \
    --download-id ida-pro:latest \
    --license-id "${IDA_LICENSE_ID}" \
    --set-default \
    --accept-eula \
    --yes

python -m uv pip install idapro ida-domain

unset IDA_LICENSE_ID HCLI_API_KEY
