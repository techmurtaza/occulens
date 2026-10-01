"""Occulens Detectors Module.

This module provides detection capabilities for identifying sensitive data
in raw input context, including credentials, secrets, and PII.

Public API:
    - detect_secrets: Scans text for credentials, keys, and tokens using deterministic regex.

Explicit Non-Responsibilities:
    - Does NOT decide policy or assign privacy actions (handled by policy/ module).
    - Does NOT perform string masking or replacements (handled by transform/ module).
    - Does NOT manage session state or storage (ephemeral per call).
"""

from occulens.detectors.secret_detector import detect_secrets

__all__ = ["detect_secrets"]
