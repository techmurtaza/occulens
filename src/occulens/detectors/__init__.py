"""Occulens Detectors Module.

This module provides detection capabilities for identifying sensitive data
in raw input context, including credentials, secrets, and PII.

Public API:
    - detect_secrets: Scans text for credentials, keys, and tokens using deterministic regex.
    - detect_pii: Scans text for PII and named entities using Presidio and spaCy NER.

Detection & Confidence Semantics:
    - detect_secrets: Scans for AWS access keys, GitHub tokens, JWTs, SSH private keys,
      database/network connection URIs, bearer tokens, and generic credential assignments.
      Always returns confidence=1.0. Hard security invariant: secrets are unconditionally
      LOCAL_ONLY.
    - detect_pii: Scans for persons, emails, phone numbers, locations (GPE/LOC), organizations,
      URLs, and identifiers. Returns confidence between 0.50 and 1.00. Overlapping spans are
      arbitrated using half-open interval collision logic.

Adding New Patterns:
    - Secret patterns: Add regular expressions with boundary tags to `secret_detector.py`.
    - PII patterns: Register custom Presidio `PatternRecognizer` instances in `pii_detector.py`.

Explicit Non-Responsibilities:
    - Does NOT decide policy or assign privacy actions (handled by policy/ module).
    - Does NOT perform string masking or replacements (handled by transform/ module).
    - Does NOT manage session state or storage (ephemeral per call).

Example Usage:
    >>> from occulens.detectors import detect_secrets, detect_pii
    >>> text = "Alice deployed using AKIAIOSFODNN7EXAMPLE."
    >>> secrets = detect_secrets(text)
    >>> len(secrets)
    1
    >>> secrets[0].entity_type.value
    'SECRET'
    >>> pii = detect_pii(text)
    >>> pii[0].value
    'Alice'

Architecture Decision Records:
    - ADR-003: Presidio + spaCy for PII, pure regex for secrets.
"""

from occulens.detectors.pii_detector import detect_pii
from occulens.detectors.secret_detector import detect_secrets

__all__ = ["detect_pii", "detect_secrets"]
