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
python -m spacy download en_core_web_sm
```

### 3. Install Pre-commit Hooks

```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

---

## Usage

### 1. Basic Sanitization

Occulens sanitizes raw context before transmission to any external model:

```python
from occulens import sanitize

result = sanitize(
    task="Debug the production deployment",
    context=(
        "Alice Smith deployed using AKIAIOSFODNN7EXAMPLE. "
        "Contact alice@company.com if issues persist."
    ),
)

print(result.sanitized_text)
# "PERSON_A deployed using [LOCAL_ONLY]. Contact [REMOVED] if issues persist."

print(f"Blocked secrets: {result.blocked_count}")  # 1
print(f"Entities sanitized: {len(result.entities)}")  # 3
```

### 2. Task-Aware Invariant Rules

Occulens evaluates task intent deterministically. When an entity is necessary to fulfill the task (e.g. navigation, maps), it is preserved; otherwise it is abstracted:

```python
from occulens import sanitize

# Task requires location -> Seattle is ALLOWED
nav_result = sanitize(
    task="Find restaurants near me in Seattle",
    context="Looking for dinner options in Seattle tonight.",
)
print(nav_result.sanitized_text)
# "Looking for dinner options in Seattle tonight."

# Generic task -> Seattle is ABSTRACTED
memo_result = sanitize(
    task="Draft internal project memo",
    context="Looking for dinner options in Seattle tonight.",
)
print(memo_result.sanitized_text)
# "Looking for dinner options in a city tonight."
```

### 3. Custom Policy Configuration

Default actions can be customized via `Policy` while hard security invariants (`SECRET -> LOCAL_ONLY`) remain strictly enforced:

```python
from occulens import EntityType, Policy, PrivacyAction, sanitize

custom_policy = Policy(
    rules={
        EntityType.ORGANIZATION: PrivacyAction.ALLOW,
    },
    abstractions={
        EntityType.LOCATION: "a regional datacenter",
    },
)

result = sanitize(
    task="Review cloud infrastructure",
    context="Acme Corp operates a cluster in Chicago with password = 'SecretPassword99!'.",
    policy=custom_policy,
)
print(result.sanitized_text)
# "Acme Corp operates a cluster in a regional datacenter with [LOCAL_ONLY]."
```

---

## Evaluation & Phase 1 Results

The supplied `occulens-v0.1.0-report.json` records **114/114 evaluation cases passed**:

- **Recorded secret leaks:** 0
- **Recorded PII leaks:** 0
- **Cases with diagnostic leaks:** 0
- **Required information retained:** 38/38 applicable cases; 0 incorrect removals
- **Measured latency:** average 19.61 ms; P95 12.45 ms

These results apply to this evaluation run, not every possible input. The first case took about 1.49 seconds and is included in the average; these are not warm-only latency figures.

See [v0.1.0 release notes](RELEASE_NOTES.md) for setup, release results, and alpha limitations.

Detailed metrics, distributions, and architecture decisions are documented in:
- [Phase 1 Results & Metrics Baseline](docs/phase1-results.md)
- [Architecture Decision Records (ADRs)](docs/decisions/)

---

## Development & Git Workflow

Occulens follows **Trunk-Based Development** with short-lived branches and strict quality gates. See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

- **Branch Naming**: `feature/<name>`, `fix/<name>`, `chore/<name>`, `refactor/<name>`.
- **Commit Standards**: [Conventional Commits](https://www.conventionalcommits.org/) enforced by Commitizen.
- **The Save Point Pattern**: Implement thin slices, verify tests pass, commit atomically (~100 lines/commit).
- **Zero Secrets**: Gitleaks enforces zero-secret commits on staged changes.

### Quality Gate Shortcuts & Commands

All developer workflows are accessible via `make`:

| Command | Purpose | Quality Gate Target |
| :--- | :--- | :--- |
| `make lint` | Run Ruff linter across `src/` and `tests/` | 0 errors |
| `make format` | Automatically format code with Ruff | Clean formatting |
| `make format-check` | Verify formatting compliance without modifying files | 0 diffs |
| `make typecheck` | Run mypy strict type checking on `src/` | 0 type errors |
| `make test` | Run full pytest test suite | All tests pass |
| `make evaluate` | Run the privacy evaluation benchmark (114 cases) | 100% pass, 0 leaks |
| `make check` | Run full pre-merge quality gate (`lint` + `format-check` + `typecheck` + `test`) | All gates green |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

