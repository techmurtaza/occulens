"""Core domain models, enumerations, and immutable value objects for Occulens.

All types in this module are immutable, strictly typed, and define the core
vocabulary for the privacy sanitization pipeline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class EntityType(StrEnum):
    """Supported entity categories recognized by Occulens detectors."""

    SECRET = "SECRET"  # noqa: S105
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    LOCATION = "LOCATION"
    ORGANIZATION = "ORGANIZATION"
    PROJECT = "PROJECT"
    URL = "URL"
    ACCOUNT_ID = "ACCOUNT_ID"


class PrivacyAction(StrEnum):
    """Permitted privacy transformations.

    Defined in AGENTS.md: ALLOW | DROP | TOKENIZE | ABSTRACT | LOCAL_ONLY.
    No other actions exist without an explicit change to the product contract.
    """

    ALLOW = "ALLOW"
    DROP = "DROP"
    TOKENIZE = "TOKENIZE"
    ABSTRACT = "ABSTRACT"
    LOCAL_ONLY = "LOCAL_ONLY"


@dataclass(frozen=True, slots=True)
class DetectedEntity:
    """An entity span identified in raw context by a detector.

    Attributes:
        entity_type: Category of the detected entity.
        start: Zero-based starting character index in the source text.
        end: Zero-based ending character index (exclusive) in source text.
        confidence: Detector confidence score between 0.0 and 1.0.
        source: Identifier of the detector that matched this entity.
        value: The matched text span.
    """

    entity_type: EntityType
    start: int
    end: int
    confidence: float
    source: str
    value: str

    def __post_init__(self) -> None:
        """Validate span offsets and confidence boundaries."""
        if self.start < 0:
            raise ValueError(f"start offset cannot be negative: {self.start}")
        if self.end < self.start:
            raise ValueError(f"end offset ({self.end}) cannot precede start ({self.start})")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in range [0.0, 1.0]: {self.confidence}")

    def with_redacted_value(self, redacted_marker: str = "[REDACTED]") -> DetectedEntity:
        """Return a copy of this entity with its raw text value redacted.

        Used to prevent raw secret leakage in diagnostics and results.
        """
        return DetectedEntity(
            entity_type=self.entity_type,
            start=self.start,
            end=self.end,
            confidence=self.confidence,
            source=self.source,
            value=redacted_marker,
        )


@dataclass(frozen=True, slots=True)
class PrivacyDecision:
    """A policy decision applied to a detected entity.

    Attributes:
        entity: The target entity detected in the text.
        action: The privacy action assigned to this entity.
        replacement: The replacement text (required for TOKENIZE/ABSTRACT).
        reason: Human-readable explanation of why this policy action applied.
    """

    entity: DetectedEntity
    action: PrivacyAction
    replacement: str | None = None
    reason: str = ""

    def with_redacted_entity(self, redacted_marker: str = "[REDACTED]") -> PrivacyDecision:
        """Return a copy of this decision with the entity's raw value redacted."""
        return PrivacyDecision(
            entity=self.entity.with_redacted_value(redacted_marker),
            action=self.action,
            replacement=self.replacement,
            reason=self.reason,
        )


@dataclass(frozen=True, slots=True)
class SafeExternalPayload:
    """Transmission-safe payload for external consumption.

    Guaranteed to contain zero raw PII, credentials, or secrets.

    Attributes:
        sanitized_text: Context string with sensitive data transformed.
        token_map: Mapping of anonymized replacement tokens to their entity type.
        action_counts: Distribution of privacy actions executed.
        blocked_count: Total count of blocked entities.
        processing_ms: Pipeline processing duration in milliseconds.
    """

    sanitized_text: str
    token_map: Mapping[str, str]
    action_counts: Mapping[str, int]
    blocked_count: int
    processing_ms: float

    def __post_init__(self) -> None:
        """Freeze dictionary mappings into immutable MappingProxyType."""
        object.__setattr__(self, "token_map", MappingProxyType(dict(self.token_map)))
        object.__setattr__(self, "action_counts", MappingProxyType(dict(self.action_counts)))


@dataclass(frozen=True, slots=True)
class SanitizeResult:
    """Result of running context through the privacy pipeline.

    Invariant (AD-H1 / AGENTS.md):
        Raw secrets and disallowed private data must never cross the trusted
        boundary. In diagnostics (entities and decisions), any entity whose
        action is not ALLOW has its raw value strictly redacted to [REDACTED].

    Attributes:
        sanitized_text: Safe output context with sensitive data transformed.
        entities: Diagnosed entities (with non-ALLOW raw values redacted).
        decisions: Decisions applied (with non-ALLOW raw values redacted).
        blocked_count: Total count of blocked entities (LOCAL_ONLY).
        local_only_count: Total count of LOCAL_ONLY decisions.
        processing_ms: Time taken to process in milliseconds.
    """

    sanitized_text: str
    entities: tuple[DetectedEntity, ...]
    decisions: tuple[PrivacyDecision, ...]
    blocked_count: int
    local_only_count: int
    processing_ms: float

    def __init__(
        self,
        sanitized_text: str,
        entities: Sequence[DetectedEntity],
        decisions: Sequence[PrivacyDecision],
        blocked_count: int,
        local_only_count: int,
        processing_ms: float,
    ) -> None:
        """Initialize and enforce redaction invariant on diagnostics."""
        redacted_entities: list[DetectedEntity] = []
        redacted_decisions: list[PrivacyDecision] = []

        # Map decisions by entity identity to inspect actions
        decision_map: dict[tuple[EntityType, int, int], PrivacyAction] = {
            (d.entity.entity_type, d.entity.start, d.entity.end): d.action for d in decisions
        }

        for dec in decisions:
            if dec.action == PrivacyAction.ALLOW and dec.entity.entity_type != EntityType.SECRET:
                redacted_decisions.append(dec)
            else:
                redacted_decisions.append(dec.with_redacted_entity())

        for ent in entities:
            action = decision_map.get((ent.entity_type, ent.start, ent.end))
            if action == PrivacyAction.ALLOW and ent.entity_type != EntityType.SECRET:
                redacted_entities.append(ent)
            else:
                redacted_entities.append(ent.with_redacted_value())

        object.__setattr__(self, "sanitized_text", sanitized_text)
        object.__setattr__(self, "entities", tuple(redacted_entities))
        object.__setattr__(self, "decisions", tuple(redacted_decisions))
        object.__setattr__(self, "blocked_count", blocked_count)
        object.__setattr__(self, "local_only_count", local_only_count)
        object.__setattr__(self, "processing_ms", processing_ms)

    def to_safe_payload(self) -> SafeExternalPayload:
        """Export a transmission-safe DTO containing zero raw sensitive values.

        Returns:
            A SafeExternalPayload containing sanitized text, token alias mappings,
            action counts, blocked count, and processing duration.
        """
        token_map: dict[str, str] = {}
        action_counts: dict[str, int] = {}

        for dec in self.decisions:
            action_name = dec.action.value
            action_counts[action_name] = action_counts.get(action_name, 0) + 1
            if dec.action == PrivacyAction.TOKENIZE and dec.replacement:
                token_map[dec.replacement] = dec.entity.entity_type.value

        return SafeExternalPayload(
            sanitized_text=self.sanitized_text,
            token_map=token_map,
            action_counts=action_counts,
            blocked_count=self.blocked_count,
            processing_ms=self.processing_ms,
        )
