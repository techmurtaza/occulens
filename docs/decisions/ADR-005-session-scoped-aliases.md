# ADR-005: Session-scoped aliases for tokenization

## Status
Accepted

## Date
2026-10-02

## Context
When entities are masked via `TOKENIZE`, replacing them with stable aliases (e.g., `PERSON_A`, `ORG_B`) preserves semantic relationships across sentences so that an external LLM can reason about relationships without knowing identities.

However, we must decide how aliases are generated, how long they live, and whether mappings are stored persistently.

Key privacy threats:
- **Cross-session correlation:** If "John Doe" is always `PERSON_4819` across every conversation for months, an adversary observing external model outputs can build a behavioral profile linking sessions together.
- **Persistent mapping leakage:** Storing raw-to-token mappings in persistent databases creates an attractive target for attackers.

## Decision
1. Tokenization uses **session-scoped, ephemeral aliases**:
   - Within a single `sanitize()` call (or within a single explicit session context), identical entity values receive identical aliases (`Alice` -> `PERSON_A` throughout the context).
   - Across different sessions or independent calls, aliases are not linked.
2. No long-term persistent database or disk vault is used for mappings in Phase 1.
3. Token mappings are held in memory only for the duration required to complete the task.

## Alternatives Considered

### 1. Global persistent token vault
- **Pros:** Global entity consistency across all historic sessions.
- **Cons:** High security liability (a centralized database mapping real identities to tokens); enables cross-session de-anonymization attacks; requires encryption vault infrastructure.
- **Rejected:** Violates Phase 1 scope ("Do not add encryption vaults, vector DBs...").

### 2. Random per-occurrence replacement (e.g., random UUID per word)
- **Pros:** Zero correlation.
- **Cons:** Destroys model intelligence. If "Alice told Bob that Alice agreed" becomes "User_1 told User_2 that User_3 agreed", the LLM cannot understand that the speaker is referring to herself.
- **Rejected:** Degrades agent reasoning capabilities unnecessarily.

## Consequences
- Maintains high utility and coherent coreference resolution within a context.
- Zero correlation risk across independent sessions.
- Zero persistence overhead; in-memory data structures are garbage collected immediately.
