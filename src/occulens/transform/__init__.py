"""Occulens Transform Module.

This module provides deterministic text transformation primitives that execute
privacy decisions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY) against source text.

Public API:
    - transform: Applies privacy decisions to raw context via reverse-offset substitution.

Action-to-Transformation Mapping:
    - ALLOW: Leaves original entity text untouched.
    - DROP: Replaces entity text with `[REMOVED]` placeholder.
    - TOKENIZE: Replaces entity with consistent session alias (e.g. `PERSON_A`, `ORG_A`).
    - ABSTRACT: Replaces entity with generalized category descriptor (e.g. `a city`).
    - LOCAL_ONLY: Replaces entity with `[LOCAL_ONLY]` placeholder indicating blocked data.

Span Handling & Output Guarantees:
    - Reverse-offset substitution: Replacements occur from the highest character offset
      to the lowest (right to left), guaranteeing earlier offsets remain stable.
    - Collision arbitration: Overlapping spans are resolved strictly by action severity
      (`LOCAL_ONLY > DROP > TOKENIZE > ABSTRACT > ALLOW`).
    - Length boundary validation: Enforces that entity offsets do not exceed input text length.

Explicit Non-Responsibilities:
    - Does NOT detect entities or credentials (handled by detectors/ module).
    - Does NOT evaluate policy or determine privacy actions (handled by policy/ module).
    - Does NOT store persistent replacement maps or session state (ephemeral per call).

Example Usage:
    >>> from occulens.domain import DetectedEntity, EntityType, PrivacyAction, PrivacyDecision
    >>> from occulens.transform import transform
    >>> text = "Alice deployed the service."
    >>> entity = DetectedEntity(EntityType.PERSON, "Alice", 0, 5, 1.0, "ner")
    >>> decision = PrivacyDecision(entity, PrivacyAction.TOKENIZE, replacement="PERSON_A")
    >>> transform(text, [decision])
    'PERSON_A deployed the service.'

Architecture Decision Records:
    - ADR-004: Reverse-offset string replacement and collision arbitration.
"""

from occulens.transform.transformer import transform

__all__ = ["transform"]
