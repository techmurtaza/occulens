"""Occulens Domain Module.

This module defines the foundational domain vocabulary for the Occulens privacy
sanitization pipeline. It specifies entity classifications, permitted privacy
actions, detected entity spans, policy decisions, and sanitized result structures.

Public API:
    - EntityType: Supported entity categories (SECRET, PERSON, EMAIL, etc.).
    - PrivacyAction: Permitted privacy actions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY).
    - DetectedEntity: Immutable span representation of an entity identified in text.
    - PrivacyDecision: Immutable policy decision mapping an entity to an action.
    - SanitizeResult: Immutable result container with redacted diagnostic metadata.

Explicit Non-Responsibilities:
    - Does NOT perform regex matching or NLP (handled by detectors/ module).
    - Does NOT compute policy rules or precedence (handled by policy/ module).
    - Does NOT perform string replacements (handled by transform/ module).
    - Does NOT handle HTTP or CLI transport (handled by adapters/ module).

Example Usage:
    >>> from occulens.domain import DetectedEntity, EntityType, PrivacyAction, PrivacyDecision
    >>> entity = DetectedEntity(
    ...     entity_type=EntityType.PERSON,
    ...     value="Alice",
    ...     start=0,
    ...     end=5,
    ...     confidence=0.95,
    ...     source="spacy",
    ... )
    >>> decision = PrivacyDecision(
    ...     entity=entity,
    ...     action=PrivacyAction.TOKENIZE,
    ...     replacement="PERSON_A",
    ...     reason="default tokenize policy for person",
    ... )

Architecture Decision Records:
    - ADR-002: Dependencies point toward domain.
    - ADR-006: Diagnostic representations strictly suppress raw secrets and PII.
"""

from occulens.domain.models import (
    DetectedEntity,
    EntityType,
    PrivacyAction,
    PrivacyDecision,
    SanitizeResult,
)

__all__ = [
    "DetectedEntity",
    "EntityType",
    "PrivacyAction",
    "PrivacyDecision",
    "SanitizeResult",
]
