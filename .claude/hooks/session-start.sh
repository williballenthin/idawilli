#!/bin/bash
set -euo pipefail

# Session start hook for IDA Pro development environment
# This hook installs IDA Pro and idalib for Python development

LOG_FILE="/tmp/claude-idalib.log"

# Logging function with timestamps
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Run a command with full logging of stdout/stderr
run_logged() {
    log "EXEC: $*"
    set +e
    "$@" >> "$LOG_FILE" 2>&1
    local exit_code=$?
    set -e
    if [ $exit_code -ne 0 ]; then
        log "FAILED (exit code $exit_code): $*"
        return $exit_code
    fi
    log "SUCCESS: $*"
    return 0
}

# Initialize log file
echo "========================================" >> "$LOG_FILE"
log "Session start hook beginning"
log "Script: $0"
log "PWD: $(pwd)"
log "HOME: $HOME"
log "USER: ${USER:-unknown}"

# Log environment variables (redact sensitive values)
log "Environment variables:"
log "  CLAUDE_CODE_REMOTE=${CLAUDE_CODE_REMOTE:-<not set>}"
log "  CLAUDE_ENV_FILE=${CLAUDE_ENV_FILE:-<not set>}"
log "  CLAUDE_PROJECT_DIR=${CLAUDE_PROJECT_DIR:-<not set>}"
log "  HCLI_API_KEY=${HCLI_API_KEY:+<set, length ${#HCLI_API_KEY}>}"
log "  HCLI_API_KEY=${HCLI_API_KEY:-<not set>}"
log "  IDA_LICENSE_ID=${IDA_LICENSE_ID:+<set: ${IDA_LICENSE_ID}>}"
log "  IDA_LICENSE_ID=${IDA_LICENSE_ID:-<not set>}"
log "  IDADIR=${IDADIR:-<not set>}"

# Only run in Claude Code remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    log "CLAUDE_CODE_REMOTE is not 'true', exiting early (not a remote session)"
    exit 0
fi

# Check if idapro is already working - if so, nothing to do
log "Checking if idapro is already importable..."
set +e
python3 -c "import idapro" >> "$LOG_FILE" 2>&1
EARLY_IMPORT_EXIT=$?
set -e
log "Early idapro import check exit code: $EARLY_IMPORT_EXIT"

if [ $EARLY_IMPORT_EXIT -eq 0 ]; then
    log "idapro already works, nothing to do"
    echo "IDA Pro already configured."
    exit 0
fi
log "idapro not yet working, proceeding with installation"

# Check for required environment variables
if [ -z "${HCLI_API_KEY:-}" ]; then
    log "WARNING: HCLI_API_KEY not set. IDA Pro installation will be skipped."
    echo "Warning: HCLI_API_KEY not set. IDA Pro installation will be skipped."
    exit 0
fi

if [ -z "${IDA_LICENSE_ID:-}" ]; then
    log "WARNING: IDA_LICENSE_ID not set. IDA Pro installation will be skipped."
    echo "Warning: IDA_LICENSE_ID not set. IDA Pro installation will be skipped."
    exit 0
fi

log "All required environment variables are set, proceeding with setup"
echo "Setting up IDA Pro development environment..."

# Export environment variables for the session
log "About to write environment variables to CLAUDE_ENV_FILE"
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    log "Writing HCLI_DISABLE_UPDATES=1 to $CLAUDE_ENV_FILE"
    echo "export HCLI_DISABLE_UPDATES=1" >> "$CLAUDE_ENV_FILE"
    log "Environment file contents after write:"
    cat "$CLAUDE_ENV_FILE" >> "$LOG_FILE" 2>&1 || log "Could not read CLAUDE_ENV_FILE"
else
    log "CLAUDE_ENV_FILE not set, skipping environment variable export"
fi

# Install HCLI
log "About to install HCLI via uv pip"
echo "Installing HCLI..."
run_logged uv pip install --system ida-hcli

log "Verifying hcli installation"
run_logged which hcli
run_logged hcli --version || log "hcli --version not supported"

# Install IDA Pro
log "About to install IDA Pro via hcli"
echo "Installing IDA Pro..."

log "Running: hcli ida install --download-id release/9.2/ida-pro/ida-pro_92_x64linux.run --license-id <redacted> --set-default --accept-eula --yes"

# Install IDA Pro using HCLI (use default installation directory)
set +e
hcli ida install \
    --download-id "release/9.2/ida-pro/ida-pro_92_x64linux.run" \
    --license-id "${IDA_LICENSE_ID}" \
    --set-default \
    --accept-eula \
    --yes >> "$LOG_FILE" 2>&1
HCLI_EXIT_CODE=$?
set -e

log "hcli ida install exit code: $HCLI_EXIT_CODE"

if [ $HCLI_EXIT_CODE -ne 0 ]; then
    log "ERROR: hcli ida install failed with exit code $HCLI_EXIT_CODE"
    log "Last 50 lines of log:"
    tail -50 "$LOG_FILE" >> "$LOG_FILE" 2>&1 || true
    exit $HCLI_EXIT_CODE
fi

log "hcli ida install completed successfully"
echo "IDA Pro installed successfully."

# Get the installation directory from hcli
log "Querying hcli for installation directory"
IDA_INSTALL_DIR=$(hcli ida set-default 2>/dev/null || echo "${HOME}/.local/ida")
log "IDA installation directory: $IDA_INSTALL_DIR"

log "Listing IDA directory contents after installation:"
ls -la "$IDA_INSTALL_DIR" >> "$LOG_FILE" 2>&1 || log "Could not list IDA directory"

# Clear sensitive credentials after hcli is done
log "About to clear sensitive credentials from CLAUDE_ENV_FILE"
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    log "Clearing HCLI_API_KEY and IDA_LICENSE_ID in $CLAUDE_ENV_FILE"
    echo "export HCLI_API_KEY=" >> "$CLAUDE_ENV_FILE"
    echo "export IDA_LICENSE_ID=" >> "$CLAUDE_ENV_FILE"
    log "Credentials cleared"
else
    log "CLAUDE_ENV_FILE not set, skipping credential clearing"
fi

# Install idapro Python package
log "About to install idapro via uv pip"
echo "Installing idapro Python package..."
run_logged uv pip install --system idapro

# Activate idalib with the IDA installation
log "About to activate idalib"
log "Looking for py-activate-idalib.py script..."

if [ -f "${IDA_INSTALL_DIR}/py-activate-idalib.py" ]; then
    log "Found activation script at ${IDA_INSTALL_DIR}/py-activate-idalib.py"
    log "Running: python3 ${IDA_INSTALL_DIR}/py-activate-idalib.py -d ${IDA_INSTALL_DIR}"
    run_logged python3 "${IDA_INSTALL_DIR}/py-activate-idalib.py" -d "${IDA_INSTALL_DIR}"
elif [ -f "${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py" ]; then
    log "Found activation script at ${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py"
    log "Running: python3 ${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py -d ${IDA_INSTALL_DIR}"
    run_logged python3 "${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py" -d "${IDA_INSTALL_DIR}"
else
    log "WARNING: Could not find py-activate-idalib.py script"
    log "Searched locations:"
    log "  - ${IDA_INSTALL_DIR}/py-activate-idalib.py"
    log "  - ${IDA_INSTALL_DIR}/idalib/python/py-activate-idalib.py"
    log "Listing IDA directory to help debug:"
    find "$IDA_INSTALL_DIR" -name "*.py" -type f >> "$LOG_FILE" 2>&1 || log "Could not search IDA directory"
fi

# Accept EULA and disable auto-update features for batch mode
log "About to configure IDA registry settings (EULA, AutoUseLumina, AutoCheckUpdates)"
log "Running Python registry configuration..."

set +e
python3 -c "
import idapro
import ida_registry
ida_registry.reg_write_int('EULA 90', 1)
ida_registry.reg_write_int('AutoUseLumina', 0)
ida_registry.reg_write_int('AutoCheckUpdates', 0)
print('Registry settings configured')
" >> "$LOG_FILE" 2>&1
REGISTRY_EXIT=$?
set -e

log "Registry configuration exit code: $REGISTRY_EXIT"

if [ $REGISTRY_EXIT -ne 0 ]; then
    log "WARNING: Failed to configure IDA registry settings"
else
    log "IDA registry settings configured successfully"
fi

log "idapro Python package installation and activation complete"
echo "idapro Python package installed and activated."

# Verify final idapro import
log "About to verify final idapro import"
set +e
python3 -c "import idapro; print('idapro import successful')" >> "$LOG_FILE" 2>&1
FINAL_IMPORT_EXIT=$?
set -e
log "Final idapro import verification exit code: $FINAL_IMPORT_EXIT"

# Install this repository's package
log "About to check for idawilli package installation"
if [ -f "${CLAUDE_PROJECT_DIR:-}/setup.py" ]; then
    log "Found setup.py at ${CLAUDE_PROJECT_DIR}/setup.py"
    log "About to install idawilli package in editable mode"
    echo "Installing idawilli package..."
    run_logged uv pip install --system -e "${CLAUDE_PROJECT_DIR}"
    log "idawilli package installed"
else
    log "No setup.py found at ${CLAUDE_PROJECT_DIR:-<not set>}/setup.py, skipping idawilli installation"
fi

log "Session start hook completed successfully"
log "========================================"
echo "IDA Pro development environment setup complete!"
