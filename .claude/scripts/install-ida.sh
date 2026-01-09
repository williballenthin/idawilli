#!/bin/bash
set -euo pipefail

# Install IDA Pro for idalib analysis
# This script is invoked by the /idalib-analysis skill

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

echo "========================================" >> "$LOG_FILE"
log "install-ida.sh script beginning"

# Only run in Claude Code remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    log "CLAUDE_CODE_REMOTE is not 'true', assuming IDA is already available locally"
    echo "Not running in Claude Code web - assuming IDA Pro is already installed locally."

    # Verify idapro is importable
    if python3 -c "import idapro" 2>/dev/null; then
        log "idapro import successful in local environment"
        echo "idapro is available."
        exit 0
    else
        log "WARNING: idapro not importable in local environment"
        echo "Warning: idapro not importable. Please ensure IDA Pro is installed and IDADIR is set."
        exit 1
    fi
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
    echo "IDA Pro is already configured and ready."
    exit 0
fi
log "idapro not yet working, proceeding with installation"

# Check for required environment variables
if [ -z "${HCLI_API_KEY:-}" ]; then
    log "ERROR: HCLI_API_KEY not set"
    echo "Error: HCLI_API_KEY environment variable is not set."
    echo "Please set HCLI_API_KEY in your Claude Code project secrets."
    exit 1
fi

if [ -z "${IDA_LICENSE_ID:-}" ]; then
    log "ERROR: IDA_LICENSE_ID not set"
    echo "Error: IDA_LICENSE_ID environment variable is not set."
    echo "Please set IDA_LICENSE_ID in your Claude Code project secrets."
    exit 1
fi

# Verify uv is available
if ! command -v uv &> /dev/null; then
    log "ERROR: uv not found"
    echo "Error: uv is not installed."
    exit 1
fi

log "All required environment variables are set, proceeding with IDA installation"
echo "Installing IDA Pro (this may take a few minutes)..."

# Install IDA Pro using HCLI via uv run
log "Running: uv run --with ida-hcli hcli ida install --download-id release/9.2/ida-pro/ida-pro_92_x64linux.run --license-id <redacted> --set-default --accept-eula --yes"

set +e
uv run --with ida-hcli hcli ida install \
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
    echo "Error: IDA Pro installation failed. Check /tmp/claude-idalib.log for details."
    exit $HCLI_EXIT_CODE
fi

log "hcli ida install completed successfully"
echo "IDA Pro installed successfully."

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

# Accept EULA and disable auto-update features for batch mode
log "About to configure IDA registry settings (EULA, AutoUseLumina, AutoCheckUpdates)"
echo "Configuring IDA settings..."

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
    echo "Warning: Failed to configure IDA registry settings."
else
    log "IDA registry settings configured successfully"
fi

# Install this repository's package if available
log "About to check for idawilli package installation"
if [ -f "${CLAUDE_PROJECT_DIR:-}/setup.py" ]; then
    log "Found setup.py at ${CLAUDE_PROJECT_DIR}/setup.py"
    echo "Installing idawilli package..."
    run_logged uv pip install --system -e "${CLAUDE_PROJECT_DIR}"
    log "idawilli package installed"
fi

# Verify final idapro import
log "About to verify final idapro import"
set +e
python3 -c "import idapro; print('idapro import successful')" >> "$LOG_FILE" 2>&1
FINAL_IMPORT_EXIT=$?
set -e
log "Final idapro import verification exit code: $FINAL_IMPORT_EXIT"

if [ $FINAL_IMPORT_EXIT -ne 0 ]; then
    log "ERROR: Final idapro import failed"
    echo "Error: idapro import failed after installation. Check /tmp/claude-idalib.log for details."
    exit 1
fi

log "install-ida.sh completed successfully"
echo "IDA Pro and idalib are ready for use."
