#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# If any command in a pipeline fails, the pipeline's return status is the value of the last command to exit with a non-zero status.
set -o pipefail

# Check if exactly one argument (the file path) is provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <python_file_path>" >&2
  exit 1
fi

FILE_PATH="$1"

# Check if the provided path is a file
if [ ! -f "$FILE_PATH" ]; then
    echo -e "\033[31mError: File '$FILE_PATH' not found.\033[0m" >&2
    exit 1
fi

# Check if the file has a .py extension
if [[ ! "$FILE_PATH" =~ \.py$ ]]; then
    echo -e "\033[33mWarning: Skipping linting for non-Python file: '$FILE_PATH'.\033[0m" >&2
    exit 0
fi

eval "$(direnv export bash)"

echo -e "\033[34mLinting $FILE_PATH...\033[0m" >&2

echo -e "\033[34mRunning ruff...\033[0m" >&2
uvx ruff check --line-length 120 "$FILE_PATH"

echo -e "\033[34mRunning ty check...\033[0m" >&2
uvx ty check --ignore unresolved-import "$FILE_PATH"

echo -e "\033[34mRunning mypy...\033[0m" >&2
uvx mypy --check-untyped-defs --ignore-missing-imports "$FILE_PATH"

echo -e "\033[32mLinting completed successfully for $FILE_PATH.\033[0m" >&2
exit 0
