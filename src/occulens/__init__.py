"""Occulens: Local-first privacy layer for AI agents.

Occulens removes, masks, tokenizes, or generalizes sensitive context before any external
model or provider can receive it. It establishes a trusted local boundary guaranteeing that
raw credentials, API keys, and unauthorized private data never escape to external providers.

Public API:
    - sanitize: Primary entry point to sanitize raw context before external transmission.
    - Policy: Configuration model for overriding default actions and abstractions.
    - SanitizeResult: Immutable result container carrying sanitized text and redacted diagnostics.
    - EntityType: Enumeration of recognized sensitive entity categories.
    - PrivacyAction: Enumeration of permitted privacy transformations
      (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY).
    - DetectedEntity: Immutable span descriptor for detected sensitive entities.
    - PrivacyDecision: Immutable policy decision mapping an entity to an action.
    - DEFAULT_MAX_INPUT_LENGTH: Standard input character limit (100,000 chars).

Explicit Non-Responsibilities:
    - Does NOT route queries to external LLM providers (handled by application/agent).
    - Does NOT persist raw context or replacement maps to persistent databases.
    - Does NOT perform vector retrieval or embeddings (out of scope for Phase 1).
    - Does NOT allow external models to weaken or override hard security rules.

Example Usage:
    >>> from occulens import sanitize
    >>> result = sanitize(
    ...     task="Analyze cloud infrastructure",
    ...     context="Alice deployed using AKIAIOSFODNN7EXAMPLE. Contact: alice@acme.com",
    ... )
    >>> result.sanitized_text
    'PERSON_A deployed using [LOCAL_ONLY]. Contact: [REMOVED]'
    >>> result.blocked_count
    1

Architecture Decision Records:
    See `docs/decisions/` for ADRs 001-006 governing design invariants.
"""

from occulens.domain.models import (
    DetectedEntity,
    EntityType,
    PrivacyAction,
    PrivacyDecision,
    SanitizeResult,
)
from occulens.pipeline import DEFAULT_MAX_INPUT_LENGTH, sanitize
from occulens.policy.rules import Policy

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_MAX_INPUT_LENGTH",
    "DetectedEntity",
    "EntityType",
    "Policy",
    "PrivacyAction",
    "PrivacyDecision",
    "SanitizeResult",
    "__version__",
    "sanitize",
]
