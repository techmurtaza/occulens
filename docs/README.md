# Occulens Technical Documentation

This directory contains technical documentation, architecture decision records (ADRs), engineering invariants, and evaluation benchmark reports for Occulens.

Governing specification: [AGENTS.md](../AGENTS.md).

---

## Mission & Core Invariant

Occulens is a local-first privacy layer for AI agents. It removes, masks, tokenizes, or generalizes sensitive context before any external model or provider can receive it.

> **Core Invariant:** Raw secrets and disallowed private data must never cross the trusted local boundary.

---

## Phase 1 Scope & Boundary

Phase 1 is deliberately small and deterministic:

```text
task + context -> detect -> decide -> transform -> sanitized context
```

### In Scope
1. **Deterministic secret detection**: Regular expressions and keyword heuristics for API keys, credentials, tokens, authorization headers, and private keys.
2. **PII and entity detection**: Presidio and spaCy for names, emails, phone numbers, locations, and organizations.
3. **Privacy decision engine**: Policy evaluation with deterministic precedence and task-aware routing.
4. **Deterministic transformer**: Safe tokenization, abstraction, removal, and local-only redaction.
5. **Evaluation suite & regression benchmarks**: Comprehensive leakage verification and utility retention tests.

### Explicitly Out of Scope
To avoid premature complexity, Phase 1 strictly excludes:
- Vector databases and semantic retrieval
- 1M-token retrieval caching
- Provider-specific routing / proxy layers
- Model Context Protocol (MCP) servers
- Web dashboards and UI admin panels
- Encryption vaults
- Fine-tuned classifier models
- Multi-agent orchestration architectures

---

## Privacy Actions

Occulens enforces only five canonical privacy actions:

| Action | Description | Behavior |
| :--- | :--- | :--- |
| `ALLOW` | Preserve entity intact | Allowed only when explicitly justified (e.g. task requires location) |
| `DROP` | Remove entity completely | Removed from text (`[REMOVED]` or silent drop) |
| `TOKENIZE` | Consistent session alias | Replaced with session-scoped pseudonym (e.g. `PERSON_A`) |
| `ABSTRACT` | Generalized placeholder | Replaced with category descriptor (e.g. `a city`, `an organization`) |
| `LOCAL_ONLY` | Hard boundary quarantine | Never forwarded externally; replaced with `[LOCAL_ONLY]` |

---

## Privacy Rules & Security Invariants

1. **Zero Secret Leakage**: `SECRET`, credentials, passwords, private keys, bearer tokens, and API keys are strictly assigned `LOCAL_ONLY`.
2. **Rule Precedence**: Hard security rules outrank any policy configuration, task-aware heuristic, or local model advice.
3. **No Raw Secrets in Artifacts**: Never log raw context, secrets, credentials, tokens, replacement maps, or private values in logs, telemetry, error messages, or diagnostics.
4. **Total Diagnostic Boundary Seal**: Diagnostic result structures (`SanitizeResult.entities`, `SanitizeResult.decisions`) redact entity values to `"[REDACTED]"` for all actions other than `ALLOW` ([ADR-006](decisions/ADR-006-no-raw-values-in-diagnostics.md), [ADR-007](decisions/ADR-007-hardening-boundary-seal.md)).
5. **Fail-Closed Default**: If an unhandled exception or ambiguous high-risk classification occurs, fail closed to `LOCAL_ONLY`.
6. **Preserve Utility Without Identity**: Retain task-critical structure and non-sensitive information while sanitizing identifying details.

---

## Engineering Principles

- **KISS & YAGNI**: Build the smallest correct solution. No speculative abstractions.
- **DRY**: Do not invent unnecessary abstractions to eliminate two similar lines.
- **Single Responsibility & Pure Functions**: Separate detection, policy, transformation, and adapters into decoupled modules with explicit dependencies.
- **Deterministic Logic First**: Deterministic rules always beat an LLM for privacy guarantees. Local models may only advise on ambiguous decisions and cannot override hard rules.
- **Python 3.12+ Quality**: Full static typing (mypy strict), frozen immutable dataclasses for domain models, and specific exceptions (no silent swallowing).

---

## Architecture Decision Records (ADRs)

All architectural and technical design decisions are recorded in [docs/decisions/](decisions/):

| ADR | Title | Status | Date |
| :--- | :--- | :--- | :--- |
| [ADR-001](decisions/ADR-001-library-first.md) | Library-first, no HTTP yet | Accepted | 2026-10-02 |
| [ADR-002](decisions/ADR-002-dependency-direction.md) | Dependencies point toward domain | Accepted | 2026-10-02 |
| [ADR-003](decisions/ADR-003-presidio-and-regex-split.md) | Presidio + spaCy for PII, pure regex for secrets | Accepted | 2026-10-02 |
| [ADR-004](decisions/ADR-004-decision-precedence-invariant.md) | Decision precedence is a hard invariant | Accepted | 2026-10-02 |
| [ADR-005](decisions/ADR-005-session-scoped-aliases.md) | Session-scoped aliases for tokenization | Accepted | 2026-10-02 |
| [ADR-006](decisions/ADR-006-no-raw-values-in-diagnostics.md) | No raw values in diagnostics | Accepted | 2026-10-02 |
| [ADR-007](decisions/ADR-007-hardening-boundary-seal.md) | Phase 1 Hardening and Boundary Seal | Accepted | 2026-10-02 |
| [ADR-008](decisions/ADR-008-adversarial-completion-contract.md) | Adversarial Completion Contract and Phase 1 Defense-in-Depth | Accepted | 2026-10-03 |

---

## Benchmark & Evaluation Results

- [Phase 1 Results & Metrics Baseline](phase1-results.md): Full analysis across **114 test cases**, 0 secret leaks, 0 PII leaks, 0 diagnostic leaks, 18.60 ms average latency, and 20.13% character reduction.
- [Evaluation Baseline Report (JSON)](../evaluation/baseline_report.json): Machine-readable evaluation run output.
- [Release Report v0.1.0](../occulens-v0.1.0-report.json): Verified benchmark execution report artifact.


