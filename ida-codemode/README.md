# ida-codemode workspace

This directory is a uv workspace that groups the codemode packages:

- `packages/ida-codemode-agent`
- `packages/ida-codemode-api`
- `packages/ida-codemode-sandbox`

Common workflows:

```bash
# sync all workspace members into one .venv
uv sync --all-packages

# run command in a specific package
uv run --package ida-codemode-agent pytest -q

# build one package
uv build --package ida-codemode-agent
```
