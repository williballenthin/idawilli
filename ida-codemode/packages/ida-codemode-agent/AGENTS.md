Use `just all` to lint and test after every change.
We're using `jj` for VCS for this project.
Use `gh` to fetch read-only information about the project/issues/etc.

## User test preferences
- Prefer a lean, high-signal test suite over broad/verbose test coverage.
- Prioritize behavior/integration tests that validate real runtime contracts.
- Prune low-value static/docs/meta/factory/helper tests first when simplifying.
- Keep API behavior coverage intact when pruning `ida-codemode-api` tests.
- Keep tests aligned with the current product contract (remove tests for deleted CLI/features).
- Do not proactively expand testing-strategy/gap coverage unless explicitly requested.
