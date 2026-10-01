# Contributing to Occulens

Thank you for contributing to Occulens. As a local-first privacy layer for AI agents, our primary commitments are correctness, security, and disciplined engineering.

Every change in this repository adheres to our Git Workflow and Versioning standards.

---

## 1. Branching Strategy (Trunk-Based Development)

Occulens uses **Trunk-Based Development**. The `main` branch is always kept deployable and stable. All work is completed in short-lived branches (1–3 days) and merged via Pull Requests.

### Branch Naming Conventions

Branches must start with a standardized category followed by a concise, kebab-case descriptor:

| Category | Pattern | Example |
|---|---|---|
| Features | `feature/<short-description>` | `feature/secret-detector` |
| Bug Fixes | `fix/<short-description>` | `fix/jwt-regex-bounds` |
| Tooling & Setup | `chore/<short-description>` | `chore/project-scaffold` |
| Refactoring | `refactor/<short-description>` | `refactor/policy-engine` |

> [!NOTE]
> Pre-commit hooks automatically validate that your active branch name conforms to this naming convention.

---

## 2. Commit Discipline & The Save Point Pattern

Commits are save points, branches are sandboxes, and history is documentation.

### Core Principles

1. **Commit Early, Commit Often**:
   Implement a slice → Test → Verify → Commit → Next slice.
   Avoid accumulating large uncommitted changes.
2. **The Save Point Pattern**:
   - If tests pass: commit the slice.
   - If tests fail or an implementation dead-ends: revert to the last known-good commit and investigate.
3. **Atomic Commits**:
   Each commit must do one logical thing. Target ~100 lines per commit/PR (max ~300 for a cohesive slice; split changes > 1000 lines).
4. **Keep Concerns Separate**:
   - **Never mix formatting changes with behavior changes.**
   - **Never mix refactoring with feature work.** A refactoring change and a feature change are two distinct commits/PRs.

---

## 3. Commit Message Standard (Conventional Commits)

Occulens enforces the [Conventional Commits](https://www.conventionalcommits.org/) standard via `commitizen`.

### Format
```text
<type>(<scope>): <short description>

[optional body explaining WHY, not just what]

[optional footer(s)]
```

### Allowed Types
- `feat`: A new feature or capability
- `fix`: A bug fix or security patch
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests or correcting existing tests
- `docs`: Documentation updates only
- `chore`: Tooling, dependencies, or configuration changes
- `build`: Build system or packaging changes
- `ci`: CI pipeline changes
- `perf`: Performance improvements
- `style`: Whitespace, formatting (no functional change)

### Message Rules
- Use imperative, present tense ("add secret detector", not "added secret detector").
- Do not capitalize the first character of the description.
- No trailing period in the subject line.
- The body should explain the **why** and motivation behind the change.

---

## 4. Parallel Work with Git Worktrees

For concurrent streams or sub-agent development, prefer `git worktree` over switching branches:

```bash
# Create an isolated worktree for a branch
git worktree add ../occulens-feature-a feature/presidio-detector

# Inspect worktrees
git worktree list

# Clean up after merge
git worktree remove ../occulens-feature-a
```

---

## 5. Pre-Commit Hygiene & Quality Gates

All commits must pass automated quality gates before entering the tree.

### Install Git Hooks
```bash
pre-commit install
pre-commit install --hook-type commit-msg
```

### Automated Hook Checks
Every staged commit runs:
1. `check-branch-name`: Verifies compliance with branch naming conventions.
2. `trailing-whitespace`: Strips unwanted whitespace from tracked code files.
3. `end-of-file-fixer`: Enforces single newline endings.
4. `check-yaml` & `check-toml`: Syntax validation for configuration files.
5. `ruff`: Linting and formatting enforcement.
6. `mypy`: Strict static type checking (`mypy src/ tests/`).
7. `gitleaks`: Detects leaked credentials, API keys, or private tokens in staged diffs.
8. `commitizen`: Validates commit message syntax on `commit-msg`.

### Full Quality Gate
Run the full gate locally before opening a PR:
```bash
make check
```

---

## 6. PR & Change Summary Requirements

Every Pull Request must include a structured Change Summary to make review unambiguous:

```markdown
### CHANGES MADE:
- src/occulens/detectors/secrets.py: Added deterministic regex detector for API keys
- tests/test_secrets.py: Added unit tests for AWS and GitHub key detection

### THINGS I DIDN'T TOUCH (intentionally):
- Presidio NER adapters: Out of scope for this secret detector slice
- Tokenizer mapping: Will be addressed in Phase 1 transformer task

### POTENTIAL CONCERNS:
- High entropy strings may match false positives; test thresholds require review.
```

---

## 7. Release & Semantic Versioning

Occulens strictly follows [Semantic Versioning 2.0.0](https://semver.org/):

- `MAJOR` (`X.0.0`): Incompatible breaking API or policy behavior changes.
- `MINOR` (`0.X.0`): Backward-compatible new features.
- `PATCH` (`0.0.X`): Backward-compatible bug fixes and security patches.

### Releases & Tags
Releases are marked with annotated Git tags derived from the version:
```bash
cz bump --changelog
git push origin main --tags
```

### Human-Curated Changelog
[CHANGELOG.md](file:///Users/murtazalightwala/Projects/Personal/01-Products/occulens/CHANGELOG.md) follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format with categories: `Added`, `Changed`, `Fixed`, `Deprecated`, `Removed`, `Security`. Write changelog entries alongside code changes rather than reconstructing them at release time.

---

## 8. Privacy & Security Non-Negotiables

- **Never Commit Secrets**: Real secrets, tokens, credentials, or private values must never be committed, tested with, or logged.
- **Fail Closed**: In privacy and secret detection logic, always fail closed.
- **Strict Repository Safety**: Git is read-only by default. Never run unauthorized state-changing operations or delete user files.
