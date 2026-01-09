#!/bin/bash
set -euo pipefail

# Session start hook for IDA Pro development environment
# This hook installs IDA Pro and idalib for Python development

# Only run in Claude Code remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    exit 0
fi

# Check for required environment variables
if [ -z "${HCLI_API_KEY:-}" ]; then
    echo "Warning: HCLI_API_KEY not set. IDA Pro installation will be skipped."
    exit 0
fi

if [ -z "${IDA_LICENSE_ID:-}" ]; then
    echo "Warning: IDA_LICENSE_ID not set. IDA Pro installation will be skipped."
    exit 0
fi

echo "Setting up IDA Pro development environment..."

# Set IDA installation directory
IDA_INSTALL_DIR="${HOME}/.local/ida"

# Export environment variables for the session
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "export HCLI_DISABLE_UPDATES=1" >> "$CLAUDE_ENV_FILE"
    echo "export IDADIR=\"${IDA_INSTALL_DIR}\"" >> "$CLAUDE_ENV_FILE"
fi

# Check if IDA is already installed (idempotent)
if [ -d "$IDA_INSTALL_DIR" ] && [ -f "$IDA_INSTALL_DIR/idat" ]; then
    echo "IDA Pro already installed at ${IDA_INSTALL_DIR}"
else
    echo "Installing HCLI..."

    # Install HCLI via pip
    uv pip install --system ida-hcli

    echo "Installing IDA Pro..."

    # Install IDA Pro using HCLI
    # Using ida-essential for x64 Linux - adjust download-id as needed for your license
    hcli ida install \
        --download-id "release/9.2/ida-pro/ida-pro_92_x64linux.run" \
        --license-id "${IDA_LICENSE_ID}" \
        --install-dir "${IDA_INSTALL_DIR}" \
        --set-default \
        --accept-eula \
        --yes

    echo "IDA Pro installed successfully."
fi

# Clear sensitive credentials after hcli is done
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    echo "export HCLI_API_KEY=" >> "$CLAUDE_ENV_FILE"
    echo "export IDA_LICENSE_ID=" >> "$CLAUDE_ENV_FILE"
fi

# Install idapro Python package if not already installed
if ! python3 -c "import idapro" 2>/dev/null; then
    echo "Installing idapro Python package..."

    # Install from PyPI (also installed as dependency of ida-hcli)
    uv pip install --system idapro

    # Activate idalib with the IDA installation
    if [ -f "${IDA_INSTALL_DIR}/py-activate-idalib.py" ]; then
        python3 "${IDA_INSTALL_DIR}/py-activate-idalib.py" -d "${IDA_INSTALL_DIR}"
    elif [ -f "${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py" ]; then
        python3 "${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py" -d "${IDA_INSTALL_DIR}"
    fi

    # Accept EULA and disable auto-update features for batch mode
    python3 -c "
import idapro
import ida_registry
ida_registry.reg_write_int('EULA 90', 1)
ida_registry.reg_write_int('AutoUseLumina', 0)
ida_registry.reg_write_int('AutoCheckUpdates', 0)
"

    echo "idapro Python package installed and activated."
else
    echo "idapro Python package already installed."
fi

# Install this repository's package
if [ -f "${CLAUDE_PROJECT_DIR:-}/setup.py" ]; then
    echo "Installing idawilli package..."
    uv pip install --system -e "${CLAUDE_PROJECT_DIR}"
fi

echo "IDA Pro development environment setup complete!"
