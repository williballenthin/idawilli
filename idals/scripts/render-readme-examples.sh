#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT_DIR="$ROOT/tests/snapshots"
OUTPUT_DIR="$ROOT/docs/readme"
FREEZE_BIN="${FREEZE_BIN:-freeze}"
SAMPLE_BINARY="../tests/data/Practical Malware Analysis Lab 01-01.exe_"

if ! command -v "$FREEZE_BIN" >/dev/null 2>&1; then
    echo "error: freeze not found on PATH. Install it with:" >&2
    echo "  go install github.com/charmbracelet/freeze@v0.2.2" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

render_snapshot() {
    local snapshot_name="$1"
    local output_name="$2"
    local prompt="$3"
    local temp_file

    temp_file="$(mktemp)"
    trap 'rm -f "$temp_file"' RETURN
    printf "%s\n" "$prompt" >"$temp_file"
    cat "$SNAPSHOT_DIR/$snapshot_name" >>"$temp_file"

    "$FREEZE_BIN" \
        --config full \
        --output "$OUTPUT_DIR/$output_name" \
        --execute "cat '$temp_file'"
}

render_snapshot \
    "overview.stdout" \
    "overview.svg" \
    "\$ idals '$SAMPLE_BINARY'"

render_snapshot \
    "disasm_import.stdout" \
    "disasm-import.svg" \
    "\$ idals '$SAMPLE_BINARY' CreateFileA --after 64 --before 16"

render_snapshot \
    "error_symbol.stderr" \
    "error-symbol.svg" \
    "\$ idals '$SAMPLE_BINARY' CreateFlie"
