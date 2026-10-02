"""Deterministic text transformation engine for Occulens.

Applies privacy decisions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY) to source
text in reverse offset order to prevent index drift, resolving any overlapping
span conflicts by action severity.
"""

from __future__ import annotations

from collections.abc import Sequence

from occulens.domain.models import PrivacyAction, PrivacyDecision

# Precedence for resolving conflicting overlapping decisions:
# Harder safety boundaries always outrank softer actions.
_ACTION_SEVERITY: dict[PrivacyAction, int] = {
    PrivacyAction.LOCAL_ONLY: 5,
    PrivacyAction.DROP: 4,
    PrivacyAction.TOKENIZE: 3,
    PrivacyAction.ABSTRACT: 2,
    PrivacyAction.ALLOW: 1,
}

_DROP_DEFAULT_PLACEHOLDER = "[REMOVED]"
_LOCAL_ONLY_DEFAULT_PLACEHOLDER = "[LOCAL_ONLY]"


def _resolve_replacement(decision: PrivacyDecision, text: str) -> str:
    """Resolve the replacement string for a privacy decision.

    Args:
        decision: The decision containing the target action and optional replacement.
        text: The source text being transformed.

    Returns:
        The string to substitute in place of the entity span.
    """
    match decision.action:
        case PrivacyAction.ALLOW:
            return text[decision.entity.start : decision.entity.end]
        case PrivacyAction.DROP:
            return (
                decision.replacement
                if decision.replacement is not None
                else _DROP_DEFAULT_PLACEHOLDER
            )
        case PrivacyAction.TOKENIZE | PrivacyAction.ABSTRACT:
            return (
                decision.replacement
                if decision.replacement is not None
                else f"[{decision.entity.entity_type.value}]"
            )
        case PrivacyAction.LOCAL_ONLY:
            return _LOCAL_ONLY_DEFAULT_PLACEHOLDER


def _filter_non_overlapping_decisions(
    decisions: Sequence[PrivacyDecision], text_len: int
) -> list[PrivacyDecision]:
    """Filter and arbitrate overlapping decisions by action severity and confidence.

    Args:
        decisions: Sequence of input decisions.
        text_len: Length of the source text for bounds validation.

    Returns:
        A list of non-overlapping decisions sorted in reverse order of starting offset.

    Raises:
        ValueError: If any entity offset exceeds text boundaries.
    """
    for d in decisions:
        if d.entity.end > text_len:
            raise ValueError(
                f"Entity end offset ({d.entity.end}) exceeds text length ({text_len})"
            )

    # Sort candidates by action severity descending, confidence descending,
    # span length descending, and earlier start offset.
    def priority_key(d: PrivacyDecision) -> tuple[int, float, int, int]:
        span_len = d.entity.end - d.entity.start
        return (
            _ACTION_SEVERITY[d.action],
            d.entity.confidence,
            span_len,
            -d.entity.start,
        )

    sorted_by_priority = sorted(decisions, key=priority_key, reverse=True)
    selected: list[PrivacyDecision] = []

    for cand in sorted_by_priority:
        # Two half-open intervals [a, b) and [c, d) overlap if max(a, c) < min(b, d)
        overlaps = any(
            max(cand.entity.start, s.entity.start) < min(cand.entity.end, s.entity.end)
            for s in selected
        )
        if not overlaps:
            selected.append(cand)

    # Return selected decisions ordered in reverse of starting position (right to left)
    return sorted(selected, key=lambda d: d.entity.start, reverse=True)


def transform(text: str, decisions: Sequence[PrivacyDecision]) -> str:
    """Apply privacy decisions to source text deterministically.

    Transformations are applied in reverse character offset order so that
    modifications near the end of the text do not displace or invalidate earlier
    offsets. Overlapping span conflicts are arbitrated by action severity.

    Args:
        text: The original context string.
        decisions: Sequence of privacy decisions to apply.

    Returns:
        The transformed, sanitized context string.

    Raises:
        ValueError: If any decision entity span extends beyond the input text.
    """
    if not text or not decisions:
        return text

    ordered_decisions = _filter_non_overlapping_decisions(decisions, len(text))
    result = text

    for decision in ordered_decisions:
        replacement = _resolve_replacement(decision, text)
        result = result[: decision.entity.start] + replacement + result[decision.entity.end :]

    return result
