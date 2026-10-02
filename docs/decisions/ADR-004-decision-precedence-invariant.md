# ADR-004: Decision precedence is a hard invariant

## Status
Accepted

## Date
2026-10-02

## Context
In a privacy layer that supports customizable policies, task heuristics, and (in future phases) local model suggestions, conflicting decisions can arise. For example, a user task might ask to "inspect the API key", or a policy might mistakenly attempt to set `SECRET -> ALLOW`.

Without a strict hierarchy, softer layers or adversarial prompts could compromise hard security boundaries.

## Decision
Establish and enforce a non-negotiable decision precedence chain:

```text
hard security rule (SECRET -> LOCAL_ONLY)
  > explicit deny policy
  > deterministic task-aware rule
  > default entity-type rule (EMAIL -> DROP, PERSON -> TOKENIZE)
  > conservative fallback (TOKENIZE)
```

**Non-Negotiable Rule:** A lower layer may never weaken a higher layer. Specifically:
- `SECRET`, credentials, passwords, private keys, bearer tokens, and API keys are permanently locked to `LOCAL_ONLY`.
- If a custom policy attempts to override a `SECRET` to `ALLOW` or `TOKENIZE`, the decision engine will reject the configuration or force it to `LOCAL_ONLY`.
- The local model (in Phase 2) will act solely as an adviser for ambiguous entities; it will possess zero authority to override hard rules or explicit policies.

## Alternatives Considered

### 1. Flat priority with last-write-wins
- **Pros:** Simple to implement.
- **Cons:** Catastrophic risk where a task prompt or model heuristic overrides a secret detection and leaks credentials.
- **Rejected:** Completely violates the core invariant of Occulens.

### 2. Weighted scoring algorithm
- **Pros:** Mathematical arbitration.
- **Cons:** Unpredictable edge cases where scores barely tip the balance; difficult to audit and reason about.
- **Rejected:** Security decisions must be unambiguous, auditable, and deterministic.

## Consequences
- Guaranteed mathematical floor for security: credentials never cross the boundary under any circumstances.
- Clear mental model for developers configuring custom policies.
- Test suites can explicitly test precedence chains to prove security invariance.
