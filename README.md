# Occulens

> Local-first privacy layer for AI agents.

Occulens removes, masks, tokenizes, or generalizes sensitive context before any external model or provider can receive it.

**Core Invariant:** Raw secrets and disallowed private data must never cross the trusted local boundary.

---

## Architecture & Pipeline

```text
Task + Context
      │
      ▼
Secret Detector (Deterministic rules: API keys, tokens, credentials -> LOCAL_ONLY)
      │
      ▼
PII / Entity Detector (Presidio, regex, NER, local dictionaries)
      │
      ▼
Privacy Decision Engine (ALLOW | DROP | TOKENIZE | ABSTRACT | LOCAL_ONLY)
      │
      ▼
Transformer (Deterministic text sanitization)
      │
      ▼
Sanitized Context
```

---

## Project Structure

```text
occulens/
├── .pre-commit-config.yaml   # Enforced pre-commit hooks (branch name, lint, types, gitleaks)
├── CONTRIBUTING.md           # Git workflow, branch naming, commit standards
├── LICENSE                   # MIT License
├── Makefile                  # Quality gate shortcuts (make check)
├── pyproject.toml            # PEP 621 metadata, dependencies, tool configs
├── scripts/                  # Pre-commit & build utility scripts
│   └── pre_commit_hooks.py
├── src/
│   └── occulens/
│       ├── __init__.py
│       ├── adapters/         # CLI / integration adapters
│       ├── detectors/        # Secret & entity detectors
│       ├── domain/           # Enums, models, contracts
│       ├── evaluation/       # Leakage and utility test suites
│       ├── local_model/      # Local model advisory hooks
│       ├── policy/           # Policy engine & precedence rules
│       └── transform/        # Deterministic text transformers
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── test_smoke.py
```

---

## Quick Start

### 1. Requirements

- Python >= 3.12
- Gitleaks (for secret scanning)

### 2. Setup Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. Install Pre-commit Hooks

```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

---

## Development & Git Workflow

Occulens follows **Trunk-Based Development** with short-lived branches and strict quality gates. See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

- **Branch Naming**: `feature/<name>`, `fix/<name>`, `chore/<name>`, `refactor/<name>`.
- **Commit Standards**: [Conventional Commits](https://www.conventionalcommits.org/) enforced by Commitizen.
- **The Save Point Pattern**: Implement thin slices, verify tests pass, commit atomically (~100 lines/commit).
- **Zero Secrets**: Gitleaks enforces zero-secret commits on staged changes.

### Quality Gate Shortcuts

All standard developer commands are available via `make`:

```bash
make lint         # Run ruff linter
make format       # Format code with ruff
make typecheck    # Run mypy strict type checker
make test         # Run pytest test suite
make check        # Run full quality gate (lint + format-check + typecheck + test)
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
