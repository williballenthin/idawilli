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

render_execute() {
    local output_name="$1"
    local temp_file="$2"

    "$FREEZE_BIN" \
        --config full \
        --output "$OUTPUT_DIR/$output_name" \
        --execute "bash '$temp_file'"
}

render_snapshot() {
    local output_name="$1"
    local prompt="$2"
    local mode="$3"
    local snapshot_name="$4"
    local temp_file

    temp_file="$(mktemp)"
    trap 'rm -f "$temp_file"' RETURN
    cat >"$temp_file" <<EOF
#!/usr/bin/env bash
set -euo pipefail
python3 - "$mode" "$prompt" "$SNAPSHOT_DIR/$snapshot_name" <<'PY'
from pathlib import Path
import re
import sys

mode, prompt, source = sys.argv[1:4]
text = Path(source).read_text()

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[38;5;42m"
YELLOW = "\033[38;5;228m"
BLUE = "\033[38;5;81m"
MAGENTA = "\033[38;5;213m"
CYAN = "\033[38;5;87m"
RED = "\033[38;5;203m"


def highlight_addresses(line: str) -> str:
    return re.sub(r"(0x[0-9A-Fa-f]+)", lambda m: f"{BLUE}{m.group(1)}{RESET}", line)


def style_overview(line: str) -> str:
    line = highlight_addresses(line)
    if line.startswith("---"):
        return f"{BOLD}{CYAN}{line}{RESET}"
    if line.startswith("[") and line.endswith("]"):
        return f"{BOLD}{MAGENTA}{line}{RESET}"
    if line.startswith("•"):
        return f"{YELLOW}{line}{RESET}"
    if line.startswith("    $"):
        return f"{GREEN}{line}{RESET}"
    return line


def style_disasm(line: str) -> str:
    line = highlight_addresses(line)
    if "<-- target" in line:
        line = line.replace("<-- target", f"{BOLD}{RED}<-- target{RESET}")
    if line.lstrip().startswith(";"):
        return f"{DIM}{YELLOW}{line}{RESET}"
    match = re.match(r"^(\s*)(0x[0-9A-Fa-f]+)(\s+)(\S+)(.*)$", line)
    if match:
        indent, addr, gap, mnemonic, rest = match.groups()
        return f"{indent}{BLUE}{addr}{RESET}{gap}{CYAN}{mnemonic}{RESET}{rest}"
    return line


def style_error(line: str) -> str:
    line = highlight_addresses(line)
    if line.startswith("Error:"):
        return f"{BOLD}{RED}{line}{RESET}"
    if line.startswith("Did you mean:"):
        return f"{YELLOW}{line}{RESET}"
    if line.startswith("  "):
        return f"{CYAN}{line}{RESET}"
    if line.startswith("Tip:"):
        return f"{MAGENTA}{line}{RESET}"
    return line


if mode == "import-short":
    lines = text.rstrip("\n").splitlines()
    target = next(i for i, line in enumerate(lines) if "<-- target" in line)
    text = "\n".join(lines[max(0, target - 1):min(len(lines), target + 2)]) + "\n"
    mode = "disasm"

styler = {
    "overview": style_overview,
    "disasm": style_disasm,
    "error": style_error,
}[mode]

print(f"{BOLD}{GREEN}{prompt}{RESET}")
for line in text.rstrip("\n").splitlines():
    print(styler(line))
PY
EOF
    chmod +x "$temp_file"
    render_execute "$output_name" "$temp_file"
    rm -f "$temp_file"
}

render_snapshot \
    "overview.svg" \
    "\$ idals '$SAMPLE_BINARY'" \
    "overview" \
    "overview.stdout"

render_snapshot \
    "disasm-start.svg" \
    "\$ idals '$SAMPLE_BINARY' 0x401820 --decompile" \
    "disasm" \
    "disasm_start.stdout"

render_snapshot \
    "disasm-import.svg" \
    "\$ idals '$SAMPLE_BINARY' CreateFileA --after 1 --before 1" \
    "import-short" \
    "disasm_import.stdout"

render_snapshot \
    "error-symbol.svg" \
    "\$ idals '$SAMPLE_BINARY' CreateFlie" \
    "error" \
    "error_symbol.stderr"
