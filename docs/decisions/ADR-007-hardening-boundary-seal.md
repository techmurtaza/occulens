# ADR-007: Phase 1 Hardening and Boundary Seal

## Status
Accepted

## Date
2026-10-02

## Context
During QA review and adversarial probing following the initial Phase 1 release, four security, privacy, and observability gaps were identified:
1. **Secret Detector Blind Spots:** The credential detector required a minimum of 8 characters for unquoted variable assignments (`_ASSIGNED_SECRET_RE`), missing common passwords (e.g. `password = abc123`). Additionally, `_BEARER_TOKEN_RE` only matched `Bearer` tokens, missing `Authorization: Basic <base64>` and `Authorization: Token <token>` credential headers.
2. **Diagnostic Redaction Leakage:** ADR-006 mandated redaction of `LOCAL_ONLY`, `DROP`, and `SECRET` values, but allowed raw PII values to persist in `SanitizeResult.entities` and `SanitizeResult.decisions` for `TOKENIZE` and `ABSTRACT` actions. Serializing or printing `repr(result)` risked leaking original names, locations, or identifiers.
3. **Missing Safe Transmission DTO:** Callers forwarding sanitized outputs to external APIs needed an unambiguous, transmission-safe data structure containing only safe text and metadata without diagnostic entity spans.
4. **Silent Exception Swallowing in Fail-Closed Guard:** The fail-closed `except Exception:` block in `pipeline.py` safely returned `[LOCAL_ONLY]` but discarded the exception without structured logging or stack traces, violating production observability requirements.

## Decision
1. **Detection Hardening:**
   - Lowered the minimum unquoted assignment length in `_ASSIGNED_SECRET_RE` from `{8,}` to `{4,}`. The boolean and keyword exclusion set (`true`, `false`, `null`, `none`, `undefined`) prevents false positives on boolean flags.
   - Introduced `_AUTH_HEADER_RE` to detect case-insensitive `Bearer`, `Basic`, and `Token` authorization headers with or without JSON quotes.
2. **Total Diagnostic Boundary Seal:**
   - Redacted `entity.value` to `"[REDACTED]"` in both `SanitizeResult.entities` and `SanitizeResult.decisions` for **all** actions except `PrivacyAction.ALLOW`.
   - Guaranteed that `repr(result)` contains zero raw sensitive values for all redacted entities.
3. **SafeExternalPayload DTO:**
   - Created the immutable, frozen dataclass `SafeExternalPayload` containing `sanitized_text`, `token_map`, `action_counts`, `blocked_count`, and `processing_ms`.
   - Added `result.to_safe_payload()` to `SanitizeResult` for external transmission.
4. **Structured Observability in Fail-Closed Guard:**
   - Added `_logger = logging.getLogger("occulens.pipeline")`.
   - Logged `_logger.warning(..., exc_info=True)` upon unexpected detector crashes, preserving stack traces while strictly excluding raw context strings.

## Alternatives Considered

### 1. Allowing raw PII in diagnostics for TOKENIZE/ABSTRACT
- **Pros:** Allowed callers to view both raw and tokenized values in the same diagnostic object.
- **Cons:** Defeated the local privacy boundary; external logging of `SanitizeResult` would leak PII.
- **Rejected:** Raw values must never escape the trusted boundary. Callers requiring token mappings receive them via `token_map` without raw source strings.

### 2. Returning raw dicts instead of SafeExternalPayload DTO
- **Pros:** No new DTO definition required.
- **Cons:** Lacked type safety, immutability, and attribute autocompletion.
- **Rejected:** Domain contracts must be typed, frozen, and explicit.

### 3. Logging raw context strings in exception handlers
- **Pros:** Trivial debugging of crashed inputs.
- **Cons:** Direct violation of AGENTS.md rule: *"Never log raw context, secrets, credentials, tokens, replacement maps, or private values."*
- **Rejected:** Stack traces provide sufficient diagnostics without logging raw secrets.

## Consequences
- Zero secret or PII leakage occurs across diagnostic surfaces or external payloads.
- All 114 evaluation fixtures pass with 0 secret leaks and 0 diagnostic leaks.
- Production detector failures emit searchable warnings with full tracebacks.
- Library consumers have a typed `SafeExternalPayload` interface ready for agent transport.
