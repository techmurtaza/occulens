# ADR-006: No raw values in diagnostics

## Status
Accepted

## Date
2026-10-02

## Context
When `sanitize(task, context)` executes, it returns a `SanitizeResult` containing the sanitized text along with diagnostic metadata: detected entities, decision traces, and timing metrics.

If `SanitizeResult.entities` or `SanitizeResult.decisions` includes the original raw string of a credential (e.g. an API key) or dropped PII, then any downstream logging, error tracking, or telemetry that captures `SanitizeResult` would inadvertently re-leak the very secrets Occulens was tasked to protect.

AGENTS.md explicitly states:
> "Never log raw context, secrets, credentials, tokens, replacement maps, or private values."
> "Raw secrets and disallowed private data must never cross the trusted local boundary."

## Decision
Enforce a structural invariant in `SanitizeResult`:
1. `SanitizeResult` **never** retains raw text values for entities assigned `LOCAL_ONLY` or `DROP`, nor for any entity of type `SECRET`.
2. Any `DetectedEntity` or `PrivacyDecision` retained inside `SanitizeResult.entities` or `SanitizeResult.decisions` has its `value` field unconditionally replaced with `"[REDACTED]"`.
3. Only the `sanitized_text` and safe replacement tokens (e.g., `PERSON_A`, generalized locations) appear in the result object.
4. This guarantee is enforced immutably at `SanitizeResult` initialization.

## Alternatives Considered

### 1. Separate "DebugMode" returning raw values
- **Pros:** Convenient for local unit test assertions.
- **Cons:** Extremely dangerous; debug flags frequently leak into staging and production logs, causing silent secret exposure.
- **Rejected:** Fails the principle of safe-by-default architecture. Unit tests can inspect intermediate detector output directly without compromising `SanitizeResult`.

### 2. Trusting caller not to log `SanitizeResult`
- **Pros:** No redacting logic needed in `SanitizeResult`.
- **Cons:** Fragile; places the burden of secret defense on the caller rather than the privacy boundary.
- **Rejected:** Occulens is the trusted privacy boundary; it must fail closed and guard against caller negligence.

## Consequences
- `SanitizeResult` objects can be safely inspected, logged, serialized, or returned without risk of leaking credentials.
- Test suites must assert that raw secrets are never present in any field of `SanitizeResult`.
- Intermediate detectors can still be tested in isolation, but final output boundaries are locked.
