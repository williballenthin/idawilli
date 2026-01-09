#!/bin/bash
set -euo pipefail

# Session start hook for IDA Pro development environment
# This hook ensures uv is available for later IDA Pro installation
# The actual IDA Pro installation is done by the /idalib-analysis skill

LOG_FILE="/tmp/claude-idalib.log"

# Logging function with timestamps
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
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
log "  IDA_LICENSE_ID=${IDA_LICENSE_ID:+<set>}"
log "  IDADIR=${IDADIR:-<not set>}"

# Only run in Claude Code remote (web) environment
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    log "CLAUDE_CODE_REMOTE is not 'true', exiting early (not a remote session)"
    exit 0
fi

# Verify uv is available
if command -v uv &> /dev/null; then
    log "uv is available: $(uv --version)"
    echo "uv is available. Use /idalib-analysis skill to install IDA Pro when needed."
else
    log "WARNING: uv not found"
    echo "Warning: uv not found. IDA Pro installation may not work."
fi

log "Session start hook completed"
