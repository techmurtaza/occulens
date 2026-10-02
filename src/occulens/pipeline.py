"""Pipeline orchestrator for the Occulens privacy sanitization layer.

Coordinates the end-to-end execution:
    raw context -> secret detector -> PII detector -> entity merger
    -> decision engine -> transformer -> SanitizeResult
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence

from occulens.detectors import detect_pii, detect_secrets
from occulens.domain.models import (
    DetectedEntity,
    EntityType,
    PrivacyAction,
    PrivacyDecision,
    SanitizeResult,
)
from occulens.policy import Policy, decide
from occulens.transform import transform

_logger = logging.getLogger("occulens.pipeline")


def _merge_detector_entities(
    secrets: Sequence[DetectedEntity],
    pii_entities: Sequence[DetectedEntity],
) -> list[DetectedEntity]:
    """Merge detected secrets and PII entities, prioritizing secrets on collision.

    Hard security boundary rule: if any PII detection overlaps with a detected
    secret (e.g. secret credentials inside a URL), the secret takes strict precedence
    and expands to protect the entire union of the overlapping spans (O01).
    """
    merged_secrets: list[DetectedEntity] = []

    for sec in secrets:
        cur_start, cur_end = sec.start, sec.end
        for pii in pii_entities:
            if pii.entity_type == EntityType.URL and max(cur_start, pii.start) < min(
                cur_end, pii.end
            ):
                cur_start = min(cur_start, pii.start)
                cur_end = max(cur_end, pii.end)
        if cur_start != sec.start or cur_end != sec.end:
            merged_secrets.append(
                DetectedEntity(
                    entity_type=EntityType.SECRET,
                    start=cur_start,
                    end=cur_end,
                    confidence=1.0,
                    source=sec.source,
                    value="",
                )
            )
        else:
            merged_secrets.append(sec)

    # Consolidate any overlapping secret spans
    merged_secrets = sorted(merged_secrets, key=lambda s: (s.start, s.end))
    consolidated_secrets: list[DetectedEntity] = []
    for sec in merged_secrets:
        if consolidated_secrets and sec.start <= consolidated_secrets[-1].end:
            last = consolidated_secrets[-1]
            consolidated_secrets[-1] = DetectedEntity(
                entity_type=EntityType.SECRET,
                start=last.start,
                end=max(last.end, sec.end),
                confidence=1.0,
                source=last.source,
                value="",
            )
        else:
            consolidated_secrets.append(sec)

    non_overlapping_pii: list[DetectedEntity] = []
    for pii in pii_entities:
        overlaps = any(
            max(pii.start, sec.start) < min(pii.end, sec.end) for sec in consolidated_secrets
        )
        if not overlaps:
            non_overlapping_pii.append(pii)

    return sorted(consolidated_secrets + non_overlapping_pii, key=lambda e: (e.start, e.end))


DEFAULT_MAX_INPUT_LENGTH: int = 100_000


def sanitize(
    task: str,
    context: str,
    policy: Policy | None = None,
    max_input_length: int = DEFAULT_MAX_INPUT_LENGTH,
) -> SanitizeResult:
    """Sanitize raw context before transmission to external AI agents or models.

    Executes the deterministic Phase 1 privacy pipeline:
    1. Validates inputs against type and size limits (default 100KB).
    2. Detects hard credentials and secrets (AWS keys, tokens, passwords, etc.).
    3. Detects PII and named entities (persons, emails, phones, locations, orgs, URLs).
    4. Merges entities, enforcing secret precedence on overlapping spans.
    5. Evaluates privacy policy to assign actions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY).
    6. Transforms context by applying replacements in reverse offset order.
    7. Returns a SanitizeResult with diagnostic redaction invariants guaranteed.
    8. Fails closed (replaces context with [LOCAL_ONLY]) if detector fails unexpectedly.

    Args:
        task: The task prompt or goal for which context is being prepared.
        context: Raw text context potentially containing secrets or sensitive PII.
        policy: Optional custom Policy overriding default actions or abstractions.
        max_input_length: Maximum allowed context length in characters (default: 100,000).

    Returns:
        A SanitizeResult containing the sanitized text, diagnostics, and metrics.

    Raises:
        TypeError: If task or context is not a string.
        ValueError: If context length exceeds max_input_length.
    """
    start_time = time.perf_counter()

    if task is None:
        raise TypeError("task cannot be None; expected str")
    if context is None:
        raise TypeError("context cannot be None; expected str")
    if not isinstance(task, str):
        raise TypeError(f"task must be a string, got {type(task).__name__}")
    if not isinstance(context, str):
        raise TypeError(f"context must be a string, got {type(context).__name__}")

    if len(context) > max_input_length:
        raise ValueError(
            f"context length ({len(context)}) exceeds maximum allowed limit ({max_input_length})"
        )

    if not context or not context.strip():
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        return SanitizeResult(
            sanitized_text=context,
            entities=(),
            decisions=(),
            blocked_count=0,
            local_only_count=0,
            processing_ms=elapsed_ms,
        )

    try:
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
    except Exception as err:
        # Hard security invariant: fail closed if any pipeline stage crashes unexpectedly.
        # Raw context must NEVER cross boundary when inspection, policy, or transformation fails.
        # Log exception type only to prevent canary/credential leakage from exception messages.
        error_type = type(err).__name__
        _logger.warning(
            "Pipeline encountered unexpected %s; invoking fail-closed fallback to [LOCAL_ONLY]",
            error_type,
        )
        fallback_entity = DetectedEntity(
            entity_type=EntityType.SECRET,
            start=0,
            end=len(context),
            confidence=1.0,
            source="fail_closed_guard",
            value="[REDACTED_DUE_TO_PIPELINE_ERROR]",
        )
        fallback_decision = PrivacyDecision(
            entity=fallback_entity,
            action=PrivacyAction.LOCAL_ONLY,
            replacement="[LOCAL_ONLY]",
            reason="pipeline failure fallback (fail-closed)",
        )
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        return SanitizeResult(
            sanitized_text="[LOCAL_ONLY]",
            entities=(fallback_entity,),
            decisions=(fallback_decision,),
            blocked_count=1,
            local_only_count=1,
            processing_ms=elapsed_ms,
        )

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
