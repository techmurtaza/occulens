"""Pipeline orchestrator for the Occulens privacy sanitization layer.

Coordinates the end-to-end execution:
    raw context -> secret detector -> PII detector -> entity merger
    -> decision engine -> transformer -> SanitizeResult
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from occulens.detectors import detect_pii, detect_secrets
from occulens.domain.models import (
    DetectedEntity,
    PrivacyAction,
    SanitizeResult,
)
from occulens.policy import Policy, decide
from occulens.transform import transform


def _merge_detector_entities(
    secrets: Sequence[DetectedEntity],
    pii_entities: Sequence[DetectedEntity],
) -> list[DetectedEntity]:
    """Merge detected secrets and PII entities, prioritizing secrets on collision.

    Hard security boundary rule: if any PII detection overlaps with a detected
    secret, the secret takes strict precedence and the PII detection is discarded.
    """
    merged: list[DetectedEntity] = list(secrets)

    for pii in pii_entities:
        overlaps_secret = any(max(pii.start, sec.start) < min(pii.end, sec.end) for sec in secrets)
        if not overlaps_secret:
            merged.append(pii)

    return sorted(merged, key=lambda e: (e.start, e.end))


def sanitize(
    task: str,
    context: str,
    policy: Policy | None = None,
) -> SanitizeResult:
    """Sanitize raw context before transmission to external AI agents or models.

    Executes the deterministic Phase 1 privacy pipeline:
    1. Detects hard credentials and secrets (AWS keys, tokens, passwords, etc.).
    2. Detects PII and named entities (persons, emails, phones, locations, orgs, URLs).
    3. Merges entities, enforcing secret precedence on overlapping spans.
    4. Evaluates privacy policy to assign actions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY).
    5. Transforms context by applying replacements in reverse offset order.
    6. Returns a SanitizeResult with diagnostic redaction invariants guaranteed.

    Args:
        task: The task prompt or goal for which context is being prepared.
        context: Raw text context potentially containing secrets or sensitive PII.
        policy: Optional custom Policy overriding default actions or abstractions.

    Returns:
        A SanitizeResult containing the sanitized text, diagnostics, and metrics.
    """
    start_time = time.perf_counter()

    if not context:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        return SanitizeResult(
            sanitized_text="",
            entities=(),
            decisions=(),
            blocked_count=0,
            local_only_count=0,
            processing_ms=elapsed_ms,
        )

    # 1. Deterministic secret detection
    secrets = detect_secrets(context)

    # 2. PII / named entity detection
    pii_entities = detect_pii(context)

    # 3. Merge entities, prioritizing secrets on collision
    entities = _merge_detector_entities(secrets, pii_entities)

    # 4. Privacy policy decision engine
    decisions = decide(entities=entities, task=task, policy=policy)

    # 5. Deterministic transformer
    sanitized_text = transform(text=context, decisions=decisions)

    # 6. Metrics & diagnostics
    local_only_count = sum(1 for d in decisions if d.action == PrivacyAction.LOCAL_ONLY)
    blocked_count = local_only_count
    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

    return SanitizeResult(
        sanitized_text=sanitized_text,
        entities=entities,
        decisions=decisions,
        blocked_count=blocked_count,
        local_only_count=local_only_count,
        processing_ms=elapsed_ms,
    )
