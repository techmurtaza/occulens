"""Unit tests for domain models, enums, and immutability guarantees."""

from dataclasses import FrozenInstanceError

import pytest

from occulens.domain import (
    DetectedEntity,
    EntityType,
    PrivacyAction,
    PrivacyDecision,
    SafeExternalPayload,
    SanitizeResult,
)


def test_privacy_action_values() -> None:
    """Ensure exact alignment with AGENTS.md permitted privacy actions."""
    expected_actions = {"ALLOW", "DROP", "TOKENIZE", "ABSTRACT", "LOCAL_ONLY"}
    actual_actions = {action.value for action in PrivacyAction}
    assert actual_actions == expected_actions
    assert len(PrivacyAction) == 5


def test_entity_type_coverage() -> None:
    """Ensure all required entity categories exist in EntityType."""
    required_types = {
        "SECRET",
        "PERSON",
        "EMAIL",
        "PHONE",
        "LOCATION",
        "ORGANIZATION",
        "PROJECT",
        "URL",
        "ACCOUNT_ID",
    }
    actual_types = {entity_type.value for entity_type in EntityType}
    assert required_types.issubset(actual_types)


def test_detected_entity_valid_construction() -> None:
    """Verify standard construction of DetectedEntity."""
    entity = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=0,
        end=4,
        confidence=0.95,
        source="test_detector",
        value="Alice",
    )
    assert entity.entity_type == EntityType.PERSON
    assert entity.start == 0
    assert entity.end == 4
    assert entity.confidence == 0.95
    assert entity.source == "test_detector"
    assert entity.value == "Alice"


def test_detected_entity_immutability() -> None:
    """Verify DetectedEntity is frozen and rejects mutation."""
    entity = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=0,
        end=4,
        confidence=0.95,
        source="test_detector",
        value="Alice",
    )
    with pytest.raises(FrozenInstanceError):
        entity.start = 5  # type: ignore[misc]


def test_detected_entity_validation_negative_start() -> None:
    """Negative start offsets must be rejected."""
    with pytest.raises(ValueError, match="start offset cannot be negative"):
        DetectedEntity(
            entity_type=EntityType.EMAIL,
            start=-1,
            end=5,
            confidence=1.0,
            source="test",
            value="a@b.co",
        )


def test_detected_entity_validation_end_before_start() -> None:
    """End offset preceding start offset must be rejected."""
    with pytest.raises(ValueError, match=r"end offset .* cannot precede start"):
        DetectedEntity(
            entity_type=EntityType.EMAIL,
            start=10,
            end=5,
            confidence=1.0,
            source="test",
            value="a@b.co",
        )


def test_detected_entity_validation_confidence_bounds() -> None:
    """Confidence scores outside [0.0, 1.0] must be rejected."""
    with pytest.raises(ValueError, match="confidence must be in range"):
        DetectedEntity(
            entity_type=EntityType.EMAIL,
            start=0,
            end=5,
            confidence=1.5,
            source="test",
            value="a@b.co",
        )

    with pytest.raises(ValueError, match="confidence must be in range"):
        DetectedEntity(
            entity_type=EntityType.EMAIL,
            start=0,
            end=5,
            confidence=-0.1,
            source="test",
            value="a@b.co",
        )


def test_detected_entity_with_redacted_value() -> None:
    """Verifies that with_redacted_value preserves metadata but replaces value."""
    entity = DetectedEntity(
        entity_type=EntityType.SECRET,
        start=10,
        end=25,
        confidence=1.0,
        source="secret_detector",
        value="fake_secret_key_123",
    )
    redacted = entity.with_redacted_value()
    assert redacted.value == "[REDACTED]"
    assert redacted.entity_type == EntityType.SECRET
    assert redacted.start == 10
    assert redacted.end == 25
    assert redacted.confidence == 1.0
    assert redacted.source == "secret_detector"


def test_privacy_decision_immutability() -> None:
    """Verify PrivacyDecision is frozen and rejects attribute assignment."""
    entity = DetectedEntity(
        entity_type=EntityType.ORGANIZATION,
        start=0,
        end=5,
        confidence=0.8,
        source="ner",
        value="Acme",
    )
    decision = PrivacyDecision(
        entity=entity,
        action=PrivacyAction.TOKENIZE,
        replacement="ORG_A",
        reason="Default organization policy",
    )
    assert decision.action == PrivacyAction.TOKENIZE
    assert decision.replacement == "ORG_A"

    with pytest.raises(FrozenInstanceError):
        decision.action = PrivacyAction.ALLOW  # type: ignore[misc]


def test_sanitize_result_raw_secret_redaction_invariant() -> None:
    """SanitizeResult must never expose raw values of LOCAL_ONLY, DROP, or SECRET entities."""
    raw_secret_val = "secret_api_token_abc"
    secret_entity = DetectedEntity(
        entity_type=EntityType.SECRET,
        start=12,
        end=33,
        confidence=1.0,
        source="secret_detector",
        value=raw_secret_val,
    )
    secret_decision = PrivacyDecision(
        entity=secret_entity,
        action=PrivacyAction.LOCAL_ONLY,
        replacement=None,
        reason="Hard security rule: secret must stay local",
    )

    allowed_entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=40,
        end=46,
        confidence=0.9,
        source="ner",
        value="London",
    )
    allowed_decision = PrivacyDecision(
        entity=allowed_entity,
        action=PrivacyAction.ALLOW,
        replacement=None,
        reason="Task allows location",
    )

    result = SanitizeResult(
        sanitized_text="Redacted text with London",
        entities=[secret_entity, allowed_entity],
        decisions=[secret_decision, allowed_decision],
        blocked_count=1,
        local_only_count=1,
        processing_ms=1.2,
    )

    # Invariant checks:
    # 1. Secret entity in entities tuple must have value redacted
    assert result.entities[0].value == "[REDACTED]"
    assert raw_secret_val not in [e.value for e in result.entities]

    # 2. Secret entity in decisions tuple must also have value redacted
    assert result.decisions[0].entity.value == "[REDACTED]"
    assert raw_secret_val not in [d.entity.value for d in result.decisions]

    # 3. Allowed non-secret entity retains value
    assert result.entities[1].value == "London"
    assert result.decisions[1].entity.value == "London"

    # 4. Result is frozen
    with pytest.raises(FrozenInstanceError):
        result.blocked_count = 0  # type: ignore[misc]


def test_sanitize_result_redaction_for_all_non_allow_actions() -> None:
    """SanitizeResult must redact raw values for TOKENIZE, ABSTRACT, DROP, and LOCAL_ONLY."""
    ent_tokenize = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=0,
        end=12,
        confidence=0.95,
        source="ner",
        value="John F. Doe",
    )
    dec_tokenize = PrivacyDecision(
        entity=ent_tokenize,
        action=PrivacyAction.TOKENIZE,
        replacement="PERSON_A",
        reason="default tokenize person",
    )

    ent_abstract = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=20,
        end=25,
        confidence=0.9,
        source="ner",
        value="Paris",
    )
    dec_abstract = PrivacyDecision(
        entity=ent_abstract,
        action=PrivacyAction.ABSTRACT,
        replacement="[LOCATION]",
        reason="abstract location",
    )

    ent_drop = DetectedEntity(
        entity_type=EntityType.URL,
        start=30,
        end=50,
        confidence=0.99,
        source="regex",
        value="http://internal.site",
    )
    dec_drop = PrivacyDecision(
        entity=ent_drop,
        action=PrivacyAction.DROP,
        replacement="",
        reason="drop url",
    )

    ent_allow = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=60,
        end=66,
        confidence=0.85,
        source="ner",
        value="London",
    )
    dec_allow = PrivacyDecision(
        entity=ent_allow,
        action=PrivacyAction.ALLOW,
        replacement=None,
        reason="task requires location",
    )

    result = SanitizeResult(
        sanitized_text="PERSON_A in [LOCATION]. London",
        entities=[ent_tokenize, ent_abstract, ent_drop, ent_allow],
        decisions=[dec_tokenize, dec_abstract, dec_drop, dec_allow],
        blocked_count=0,
        local_only_count=0,
        processing_ms=1.5,
    )

    # 1. Non-ALLOW entities must be redacted in both entities and decisions
    assert result.entities[0].value == "[REDACTED]"
    assert result.decisions[0].entity.value == "[REDACTED]"

    assert result.entities[1].value == "[REDACTED]"
    assert result.decisions[1].entity.value == "[REDACTED]"

    assert result.entities[2].value == "[REDACTED]"
    assert result.decisions[2].entity.value == "[REDACTED]"

    # 2. ALLOW entity retains original value
    assert result.entities[3].value == "London"
    assert result.decisions[3].entity.value == "London"

    # 3. repr(result) contains NO raw values of redacted entities
    repr_str = repr(result)
    assert "John F. Doe" not in repr_str
    assert "Paris" not in repr_str
    assert "http://internal.site" not in repr_str
    assert "London" in repr_str


def test_safe_external_payload_dto_and_generation() -> None:
    """Verifies SafeExternalPayload contains only transmission-safe fields and is frozen."""
    ent_person = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=0,
        end=5,
        confidence=0.9,
        source="ner",
        value="Alice",
    )
    dec_person = PrivacyDecision(
        entity=ent_person,
        action=PrivacyAction.TOKENIZE,
        replacement="PERSON_A",
        reason="tokenize person",
    )

    ent_secret = DetectedEntity(
        entity_type=EntityType.SECRET,
        start=10,
        end=30,
        confidence=1.0,
        source="secret_detector",
        value="my_secret_token_1234",
    )
    dec_secret = PrivacyDecision(
        entity=ent_secret,
        action=PrivacyAction.LOCAL_ONLY,
        replacement="[LOCAL_ONLY]",
        reason="block secret",
    )

    result = SanitizeResult(
        sanitized_text="PERSON_A [LOCAL_ONLY]",
        entities=[ent_person, ent_secret],
        decisions=[dec_person, dec_secret],
        blocked_count=1,
        local_only_count=1,
        processing_ms=2.5,
    )

    payload = result.to_safe_payload()
    assert isinstance(payload, SafeExternalPayload)
    assert payload.sanitized_text == "PERSON_A [LOCAL_ONLY]"
    assert payload.token_map == {"PERSON_A": "PERSON"}
    assert payload.action_counts == {"TOKENIZE": 1, "LOCAL_ONLY": 1}
    assert payload.blocked_count == 1
    assert payload.processing_ms == 2.5

    # Safe payload repr contains zero raw sensitive values
    repr_payload = repr(payload)
    assert "Alice" not in repr_payload
    assert "my_secret_token_1234" not in repr_payload

    # Payload is frozen
    with pytest.raises(FrozenInstanceError):
        payload.blocked_count = 0  # type: ignore[misc]
