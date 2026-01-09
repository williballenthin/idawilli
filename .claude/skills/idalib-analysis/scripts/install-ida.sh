#!/bin/bash
set -euo pipefail

# Install IDA Pro for idalib analysis
# This script is invoked by the /idalib-analysis skill

# Only run in Claude Code remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    echo "Not running in Claude Code web - assuming IDA Pro is already installed locally."

    # Verify idapro is importable
    if python3 -c "import idapro" 2>/dev/null; then
        echo "idapro is available."
        exit 0
    else
        echo "Warning: idapro not importable. Please ensure IDA Pro is installed and IDADIR is set."
        exit 1
    fi
fi

# Check if idapro is already working - if so, nothing to do
echo "Checking if idapro is already importable..."
if python3 -c "import idapro" 2>/dev/null; then
    echo "IDA Pro is already configured and ready."
    exit 0
fi

# Check for required environment variables
if [ -z "${HCLI_API_KEY:-}" ]; then
    echo "Error: HCLI_API_KEY environment variable is not set."
    echo "Please set HCLI_API_KEY in your Claude Code project secrets."
    exit 1
fi

if [ -z "${IDA_LICENSE_ID:-}" ]; then
    echo "Error: IDA_LICENSE_ID environment variable is not set."
    echo "Please set IDA_LICENSE_ID in your Claude Code project secrets."
    exit 1
fi

# Verify uv is available
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed."
    exit 1
fi

echo "Installing IDA Pro (this may take a few minutes)..."

# Install IDA Pro using HCLI via uv run
set +e
uv run --with ida-hcli hcli ida install \
    --download-id "release/9.2/ida-pro/ida-pro_92_x64linux.run" \
    --license-id "${IDA_LICENSE_ID}" \
    --set-default \
    --accept-eula \
    --yes
HCLI_EXIT_CODE=$?
set -e

if [ $HCLI_EXIT_CODE -ne 0 ]; then
    echo "Error: IDA Pro installation failed."
    exit $HCLI_EXIT_CODE
fi

echo "IDA Pro installed successfully."

# Install idapro and ida-domain Python packages
echo "Installing Python packages (idapro, ida-domain)..."
uv pip install --system idapro ida-domain

# Accept EULA and disable auto-update features for batch mode
echo "Configuring IDA settings..."

set +e
python3 -c "
import idapro
import ida_registry
ida_registry.reg_write_int('EULA 90', 1)
ida_registry.reg_write_int('AutoUseLumina', 0)
ida_registry.reg_write_int('AutoCheckUpdates', 0)
print('Registry settings configured')
"
REGISTRY_EXIT=$?
set -e

if [ $REGISTRY_EXIT -ne 0 ]; then
    echo "Warning: Failed to configure IDA registry settings."
fi

# Install this repository's package if available
if [ -f "${CLAUDE_PROJECT_DIR:-}/setup.py" ]; then
    echo "Installing idawilli package..."
    uv pip install --system -e "${CLAUDE_PROJECT_DIR}"
fi

# Verify final imports
echo "Verifying imports..."
if ! python3 -c "import idapro; from ida_domain import Database; print('imports successful')"; then
    echo "Error: Import verification failed after installation."
    exit 1
fi

echo "IDA Pro, idalib, and ida-domain are ready for use."
