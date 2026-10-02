# ADR-003: Presidio + spaCy for PII, pure deterministic regex for secrets

## Status
Accepted

## Date
2026-10-02

## Context
Sensitive context contains two fundamentally different classes of data:
1. **Secrets:** Hard credentials (API keys, private keys, bearer tokens, JWTs, database URLs, passwords).
2. **PII and Named Entities:** Contextual human identifiers (person names, locations, organizations, phone numbers, email addresses).

We evaluated what technology should power the detection of each category.

## Decision
Split detector technologies strictly by risk profile and determinism:
- **Secrets:** Use **pure deterministic regex scanners only**. Never use an LLM or statistical model to decide if a credential is safe. If a secret pattern matches, its confidence is 1.0 and its action is unconditionally `LOCAL_ONLY`.
- **PII and Entities:** Use **Microsoft Presidio** (for structured PII like emails, phones, URLs) combined with **spaCy NER** (`en_core_web_md` for persons, organizations, locations). Presidio encapsulates spaCy internally, enabling clean deduplication and entity normalization into `DetectedEntity`.

## Alternatives Considered

### 1. All-regex detection
- **Pros:** Zero model dependencies, ultra-fast.
- **Cons:** Regex is notoriously brittle for natural language person names, locations, and organizations across diverse sentence structures.
- **Rejected:** Insufficient recall on natural language PII.

### 2. LLM-based detection (local SLM or cloud)
- **Pros:** Context-aware entity extraction.
- **Cons:** Non-deterministic, high latency, potential hallucination, and sends sensitive credentials into model weights.
- **Rejected:** Directly violates AGENTS.md rule: "Deterministic logic beats an LLM whenever deterministic logic can solve the problem."

### 3. Custom fine-tuned NER model
- **Pros:** Tailored dataset.
- **Cons:** High training and maintenance burden; violates Phase 1 scope.
- **Rejected:** Presidio + spaCy provides established, production-tested recognizers off-the-shelf.

## Consequences
- Requires ~100MB download for spaCy `en_core_web_sm` model.
- Secret scanning is instant, zero-dependency, and deterministic.
- PII detection leverages established Microsoft Presidio patterns with structured confidence scores.
