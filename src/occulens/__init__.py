"""Occulens: Local-first privacy layer for AI agents.

Removes, masks, tokenizes, or generalizes sensitive context before any external
model or provider can receive it.

Public API:
    - sanitize: Primary entry point to sanitize raw context before external transmission.
    - Policy: Configuration model for overriding default actions and abstractions.
    - SanitizeResult: Immutable result container carrying sanitized text and redacted diagnostics.
    - EntityType: Enumeration of recognized sensitive entity categories.
    - PrivacyAction: Enumeration of permitted privacy transformations
      (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY).
    - DetectedEntity: Immutable span descriptor for detected sensitive entities.
    - PrivacyDecision: Immutable policy decision mapping an entity to an action.
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
