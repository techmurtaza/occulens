"""Unit tests for the policy rules and privacy decision engine.

Verifies precedence chain (hard rule > explicit policy > deterministic default > fallback),
alias generation, abstraction lookups, immutability, and error handling.
"""

from __future__ import annotations

import pytest

from occulens.domain.models import DetectedEntity, EntityType, PrivacyAction
from occulens.policy import Policy, decide
from occulens.policy.rules import index_to_letters


def test_default_actions_for_all_entity_types() -> None:
    entities = [
        DetectedEntity(EntityType.SECRET, 0, 10, 1.0, "test", "my-secret-key"),
        DetectedEntity(EntityType.EMAIL, 11, 26, 1.0, "test", "user@domain.com"),
        DetectedEntity(EntityType.PHONE, 27, 39, 1.0, "test", "555-123-4567"),
        DetectedEntity(EntityType.PERSON, 40, 50, 0.9, "test", "John Smith"),
        DetectedEntity(EntityType.PROJECT, 51, 59, 0.9, "test", "Occulens"),
        DetectedEntity(EntityType.ORGANIZATION, 60, 69, 0.9, "test", "Acme Corp"),
        DetectedEntity(EntityType.LOCATION, 70, 78, 0.9, "test", "New York"),
        DetectedEntity(EntityType.URL, 79, 98, 0.9, "test", "https://example.com"),
        DetectedEntity(EntityType.ACCOUNT_ID, 99, 111, 0.9, "test", "192.168.1.1"),
    ]

    decisions = decide(entities)
    action_map = {d.entity.entity_type: d.action for d in decisions}

    assert action_map[EntityType.SECRET] == PrivacyAction.LOCAL_ONLY
    assert action_map[EntityType.EMAIL] == PrivacyAction.DROP
    assert action_map[EntityType.PHONE] == PrivacyAction.DROP
    assert action_map[EntityType.PERSON] == PrivacyAction.TOKENIZE
    assert action_map[EntityType.PROJECT] == PrivacyAction.TOKENIZE
    assert action_map[EntityType.ORGANIZATION] == PrivacyAction.TOKENIZE
    assert action_map[EntityType.LOCATION] == PrivacyAction.ABSTRACT
    assert action_map[EntityType.URL] == PrivacyAction.DROP
    assert action_map[EntityType.ACCOUNT_ID] == PrivacyAction.DROP


def test_hard_security_rule_cannot_be_weakened_in_policy() -> None:
    # Attempting to map SECRET to ALLOW or any non-LOCAL_ONLY action must fail
    with pytest.raises(ValueError, match="Hard security rule violation"):
        Policy(actions={EntityType.SECRET: PrivacyAction.ALLOW})

    with pytest.raises(ValueError, match="Hard security rule violation"):
        Policy(actions={EntityType.SECRET: PrivacyAction.TOKENIZE})

    # Permitting SECRET explicitly as LOCAL_ONLY is valid
    policy = Policy(actions={EntityType.SECRET: PrivacyAction.LOCAL_ONLY})
    assert policy.actions[EntityType.SECRET] == PrivacyAction.LOCAL_ONLY


def test_hard_security_rule_precedence_in_decision_engine() -> None:
    entity = DetectedEntity(EntityType.SECRET, 0, 20, 1.0, "test", "secret-token-here")
    decisions = decide([entity], task="general query", policy=None)

    assert len(decisions) == 1
    assert decisions[0].action == PrivacyAction.LOCAL_ONLY
    assert decisions[0].replacement is None
    assert "hard security rule" in decisions[0].reason


def test_explicit_policy_override() -> None:
    entities = [
        DetectedEntity(EntityType.EMAIL, 0, 15, 1.0, "test", "alice@corp.com"),
        DetectedEntity(EntityType.LOCATION, 20, 26, 0.9, "test", "London"),
    ]

    # Override: Allow EMAIL (default is DROP), Tokenize LOCATION (default is ABSTRACT)
    policy = Policy(
        actions={
            EntityType.EMAIL: PrivacyAction.ALLOW,
            EntityType.LOCATION: PrivacyAction.TOKENIZE,
        }
    )

    decisions = decide(entities, policy=policy)
    assert decisions[0].action == PrivacyAction.ALLOW
    assert "explicit policy override" in decisions[0].reason

    assert decisions[1].action == PrivacyAction.TOKENIZE
    assert decisions[1].replacement == "LOCATION_A"
    assert "explicit policy override" in decisions[1].reason


def test_custom_abstractions_in_policy() -> None:
    entity = DetectedEntity(EntityType.LOCATION, 0, 6, 0.9, "test", "Boston")
    policy = Policy(abstractions={EntityType.LOCATION: "a coastal city in Massachusetts"})

    decisions = decide([entity], policy=policy)
    assert decisions[0].action == PrivacyAction.ABSTRACT
    assert decisions[0].replacement == "a coastal city in Massachusetts"


def test_alias_generation_stability_and_case_normalization() -> None:
    entities = [
        DetectedEntity(EntityType.PERSON, 0, 5, 0.9, "test", "Alice"),
        DetectedEntity(EntityType.PERSON, 10, 13, 0.9, "test", "Bob"),
        DetectedEntity(EntityType.PERSON, 20, 25, 0.9, "test", "alice"),  # lowercase duplicate
        DetectedEntity(EntityType.ORGANIZATION, 30, 39, 0.9, "test", "Acme Corp"),
        DetectedEntity(EntityType.ORGANIZATION, 40, 49, 0.9, "test", "Beta Corp"),
    ]

    decisions = decide(entities)
    replacements = [d.replacement for d in decisions]

    # Alice and lowercase alice must share the exact same alias
    assert replacements[0] == "PERSON_A"
    assert replacements[1] == "PERSON_B"
    assert replacements[2] == "PERSON_A"

    # Organizations get independent sequential letters
    assert replacements[3] == "ORG_A"
    assert replacements[4] == "ORG_B"


def test_index_to_letters_multi_alphabet_wrap() -> None:
    assert index_to_letters(0) == "A"
    assert index_to_letters(1) == "B"
    assert index_to_letters(25) == "Z"
    assert index_to_letters(26) == "AA"
    assert index_to_letters(27) == "AB"
    assert index_to_letters(51) == "AZ"
    assert index_to_letters(52) == "BA"


def test_empty_entities_returns_empty_list() -> None:
    assert decide([]) == []


def test_policy_immutability() -> None:
    policy = Policy(actions={EntityType.EMAIL: PrivacyAction.ALLOW})
    with pytest.raises(TypeError):
        policy.actions[EntityType.EMAIL] = PrivacyAction.DROP  # type: ignore[index]


def test_module_exports() -> None:
    import occulens.policy as policy_module

    assert hasattr(policy_module, "Policy")
    assert hasattr(policy_module, "decide")
    assert callable(policy_module.decide)
