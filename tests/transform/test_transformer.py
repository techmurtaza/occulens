"""Unit tests for the deterministic transformer module.

Verifies action mappings (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY),
reverse-offset substitution, span arbitration, boundary conditions, and immutability.
"""

from __future__ import annotations

import pytest

from occulens.domain.models import DetectedEntity, EntityType, PrivacyAction, PrivacyDecision
from occulens.transform import transform


def test_transform_allow_action() -> None:
    text = "Welcome to Chicago for the summit."
    entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=11,
        end=18,
        confidence=0.85,
        source="spacy",
        value="Chicago",
    )
    decision = PrivacyDecision(entity=entity, action=PrivacyAction.ALLOW)

    result = transform(text, [decision])
    assert result == text


def test_transform_drop_action_default_and_custom() -> None:
    text = "Call me at 555-123-4567 or email me."
    entity = DetectedEntity(
        entity_type=EntityType.PHONE,
        start=11,
        end=23,
        confidence=0.9,
        source="presidio",
        value="555-123-4567",
    )

    # Default DROP replacement
    decision_default = PrivacyDecision(entity=entity, action=PrivacyAction.DROP)
    assert transform(text, [decision_default]) == "Call me at [REMOVED] or email me."

    # Custom DROP replacement
    decision_custom = PrivacyDecision(
        entity=entity,
        action=PrivacyAction.DROP,
        replacement="<REDACTED_PHONE>",
    )
    assert transform(text, [decision_custom]) == "Call me at <REDACTED_PHONE> or email me."


def test_transform_tokenize_action_with_alias_and_fallback() -> None:
    text = "Reviewed by Alice Smith today."
    entity = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=12,
        end=23,
        confidence=0.95,
        source="spacy",
        value="Alice Smith",
    )

    # Provided alias
    decision_alias = PrivacyDecision(
        entity=entity,
        action=PrivacyAction.TOKENIZE,
        replacement="PERSON_1",
    )
    assert transform(text, [decision_alias]) == "Reviewed by PERSON_1 today."

    # Fallback when replacement is None
    decision_fallback = PrivacyDecision(
        entity=entity,
        action=PrivacyAction.TOKENIZE,
        replacement=None,
    )
    assert transform(text, [decision_fallback]) == "Reviewed by [PERSON] today."


def test_transform_abstract_action() -> None:
    text = "The team is located in Indore."
    entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=23,
        end=29,
        confidence=0.85,
        source="spacy",
        value="Indore",
    )
    decision = PrivacyDecision(
        entity=entity,
        action=PrivacyAction.ABSTRACT,
        replacement="a tier-2 city in central India",
    )

    result = transform(text, [decision])
    assert result == "The team is located in a tier-2 city in central India."


def test_transform_local_only_action() -> None:
    text = "The password is secretPassword123! and must not leak."
    entity = DetectedEntity(
        entity_type=EntityType.SECRET,
        start=16,
        end=34,
        confidence=1.0,
        source="secret_detector",
        value="secretPassword123!",
    )
    decision = PrivacyDecision(entity=entity, action=PrivacyAction.LOCAL_ONLY)

    result = transform(text, [decision])
    assert result == "The password is [LOCAL_ONLY] and must not leak."
    assert "secretPassword123!" not in result


def test_multiple_non_overlapping_entities_with_varying_lengths() -> None:
    text = "Contact Alice at alice@acme.org in New York with AKIA1234567890123456."
    e_person = DetectedEntity(EntityType.PERSON, 8, 13, 0.85, "spacy", "Alice")
    e_email = DetectedEntity(EntityType.EMAIL, 17, 31, 1.0, "presidio", "alice@acme.org")
    e_loc = DetectedEntity(EntityType.LOCATION, 35, 43, 0.85, "spacy", "New York")
    e_secret = DetectedEntity(
        EntityType.SECRET, 49, 69, 1.0, "secret_detector", "AKIA1234567890123456"
    )

    decisions = [
        PrivacyDecision(e_person, PrivacyAction.TOKENIZE, replacement="PERSON_A"),
        PrivacyDecision(e_email, PrivacyAction.DROP),
        PrivacyDecision(e_loc, PrivacyAction.ABSTRACT, replacement="an eastern city"),
        PrivacyDecision(e_secret, PrivacyAction.LOCAL_ONLY),
    ]

    result = transform(text, decisions)
    assert result == "Contact PERSON_A at [REMOVED] in an eastern city with [LOCAL_ONLY]."


def test_entity_at_string_start_and_end() -> None:
    text = "Alice meets Bob"
    e_start = DetectedEntity(EntityType.PERSON, 0, 5, 0.9, "spacy", "Alice")
    e_end = DetectedEntity(EntityType.PERSON, 12, 15, 0.9, "spacy", "Bob")

    decisions = [
        PrivacyDecision(e_start, PrivacyAction.TOKENIZE, replacement="PERSON_1"),
        PrivacyDecision(e_end, PrivacyAction.TOKENIZE, replacement="PERSON_2"),
    ]

    result = transform(text, decisions)
    assert result == "PERSON_1 meets PERSON_2"


def test_adjacent_entities_with_no_gap() -> None:
    text = "PrefixFooBarSuffix"
    e_foo = DetectedEntity(EntityType.PERSON, 6, 9, 0.8, "test", "Foo")
    e_bar = DetectedEntity(EntityType.ORGANIZATION, 9, 12, 0.8, "test", "Bar")

    decisions = [
        PrivacyDecision(e_foo, PrivacyAction.TOKENIZE, replacement="[FOO]"),
        PrivacyDecision(e_bar, PrivacyAction.TOKENIZE, replacement="[BAR]"),
    ]

    result = transform(text, decisions)
    assert result == "Prefix[FOO][BAR]Suffix"


def test_overlapping_decisions_arbitrated_by_severity() -> None:
    # Overlapping span: a secret spans [0..15], an inner entity spans [0..5]
    text = "AKIA12345678901 is sensitive."
    e_inner = DetectedEntity(EntityType.PERSON, 0, 5, 0.7, "spacy", "AKIA1")
    e_outer = DetectedEntity(EntityType.SECRET, 0, 15, 1.0, "secret_detector", "AKIA12345678901")

    # LOCAL_ONLY (severity 5) should suppress TOKENIZE (severity 3)
    decisions = [
        PrivacyDecision(e_inner, PrivacyAction.TOKENIZE, replacement="PERSON_1"),
        PrivacyDecision(e_outer, PrivacyAction.LOCAL_ONLY),
    ]

    result = transform(text, decisions)
    assert result == "[LOCAL_ONLY] is sensitive."
    assert "AKIA" not in result
    assert "PERSON_1" not in result


def test_decisions_passed_out_of_order() -> None:
    text = "Alpha Beta Gamma Delta"
    e1 = DetectedEntity(EntityType.PERSON, 0, 5, 0.8, "test", "Alpha")
    e2 = DetectedEntity(EntityType.PERSON, 6, 10, 0.8, "test", "Beta")
    e3 = DetectedEntity(EntityType.PERSON, 11, 16, 0.8, "test", "Gamma")
    e4 = DetectedEntity(EntityType.PERSON, 17, 22, 0.8, "test", "Delta")

    # Pass in shuffled order: e3, e1, e4, e2
    decisions = [
        PrivacyDecision(e3, PrivacyAction.TOKENIZE, replacement="3"),
        PrivacyDecision(e1, PrivacyAction.TOKENIZE, replacement="1"),
        PrivacyDecision(e4, PrivacyAction.TOKENIZE, replacement="4"),
        PrivacyDecision(e2, PrivacyAction.TOKENIZE, replacement="2"),
    ]

    result = transform(text, decisions)
    assert result == "1 2 3 4"


def test_empty_input_and_no_decisions() -> None:
    assert transform("", []) == ""
    assert (
        transform(
            "",
            [
                PrivacyDecision(
                    DetectedEntity(EntityType.PERSON, 0, 0, 1.0, "test", ""),
                    PrivacyAction.ALLOW,
                )
            ],
        )
        == ""
    )
    assert transform("Hello world", []) == "Hello world"


def test_out_of_bounds_entity_raises_value_error() -> None:
    text = "Short text."
    e_invalid = DetectedEntity(EntityType.PERSON, 0, 50, 0.8, "test", "Out of bounds")
    decision = PrivacyDecision(e_invalid, PrivacyAction.TOKENIZE, replacement="P")

    with pytest.raises(ValueError, match="exceeds text length"):
        transform(text, [decision])


def test_pure_function_idempotency() -> None:
    text = "Engineer Dave works on Occulens."
    e = DetectedEntity(EntityType.PERSON, 9, 13, 0.9, "spacy", "Dave")
    decision = PrivacyDecision(e, PrivacyAction.TOKENIZE, replacement="PERSON_1")

    run_1 = transform(text, [decision])
    run_2 = transform(text, [decision])

    assert run_1 == run_2 == "Engineer PERSON_1 works on Occulens."
    # Source text and decision object must be unmodified
    assert text == "Engineer Dave works on Occulens."
    assert decision.entity.value == "Dave"


def test_module_exports() -> None:
    import occulens.transform as transform_module

    assert hasattr(transform_module, "transform")
    assert callable(transform_module.transform)
