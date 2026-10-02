# ADR-002: Dependencies point toward domain

## Status
Accepted

## Date
2026-10-02

## Context
A privacy pipeline contains distinct components: detection (regex, NER), decision-making (policy, rules), transformation (string editing), and evaluation. If components import each other directly, tight coupling and circular dependencies quickly emerge, preventing independent testing and substitution.

We need an architectural dependency rule that guarantees modularity, testability, and clarity of ownership.

## Decision
Enforce a Clean/Hexagonal dependency direction where all internal modules depend inward on `domain/`, and never on each other:

```text
domain/  <-- detectors/
domain/  <-- policy/
domain/  <-- transform/
domain/  <-- evaluation/
                ^
             pipeline orchestrator (composes them)
```

- `domain/` defines data contracts (`DetectedEntity`, `PrivacyDecision`, `SanitizeResult`, enums) with zero dependencies on other Occulens modules.
- `detectors/` produces `DetectedEntity` objects; it does not know about privacy policies or transformations.
- `policy/` consumes `DetectedEntity` and returns `PrivacyDecision`; it does not run detectors or edit text.
- `transform/` consumes `PrivacyDecision` and raw text to produce sanitized strings; it does not make policy decisions.
- The pipeline orchestrator wires these pure components together.

## Alternatives Considered

### 1. Flat package structure with direct cross-module calls
- **Pros:** Fewer directories.
- **Cons:** High coupling; detectors calling policy directly creates spaghetti logic and makes unit testing individual stages difficult.
- **Rejected:** Fails the modularity and separation-of-concerns standard in AGENTS.md.

### 2. Generic plugin/service-locator registry
- **Pros:** Highly dynamic.
- **Cons:** Over-engineering; introduces hidden runtime state and indirection when Phase 1 only requires a deterministic composition.
- **Rejected:** Premature abstraction violating YAGNI.

## Consequences
- Every stage of the pipeline can be tested in isolation using hand-crafted domain objects.
- Adding a new detector or modifying replacement behavior does not touch policy rules.
- Circular imports are structurally impossible.
