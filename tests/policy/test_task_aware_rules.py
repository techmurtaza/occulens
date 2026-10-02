"""Unit and contract tests for Task-Aware Deterministic Rules (Task 9).

Verifies:
1. Task-aware rules for LOCATION:
   - Location-relevant task -> ALLOW.
   - Generic task -> ABSTRACT.
2. Task-aware rules for URL:
   - Link/navigation task -> ALLOW.
   - Generic task -> DROP.
3. Precedence chain:
   hard security rule > explicit policy > task-aware rule > entity-type default > fallback.
4. End-to-end contract invariant:
   Same entity, different task -> different action.
"""

from __future__ import annotations

from occulens import EntityType, Policy, PrivacyAction, sanitize
from occulens.domain.models import DetectedEntity
from occulens.policy.decision_engine import decide
from occulens.policy.task_rules import TaskAwareRule, match_task_rule


def test_task_aware_location_allowed_when_task_relevant() -> None:
    """Ensure location entities are ALLOWED when the task intent requires location."""
    tasks = [
        "Find restaurants near me",
        "Show nearby coffee shops",
        "Check weather in the city",
        "Get directions on the map",
        "Plan commute and travel route",
        "Reserve a hotel near the address",
    ]
    entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=0,
        end=7,
        confidence=0.9,
        source="spacy",
        value="Seattle",
    )

    for task in tasks:
        decisions = decide(entities=[entity], task=task)
        assert len(decisions) == 1
        assert decisions[0].action == PrivacyAction.ALLOW
        assert "task-aware rule" in decisions[0].reason


def test_task_aware_location_abstracted_when_task_generic() -> None:
    """Ensure location entities default to ABSTRACT when the task is generic."""
    generic_tasks = [
        "Summarize the meeting notes",
        "Format this markdown document",
        "Proofread the executive summary",
        "Translate this text to Spanish",
    ]
    entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=0,
        end=7,
        confidence=0.9,
        source="spacy",
        value="Seattle",
    )

    for task in generic_tasks:
        decisions = decide(entities=[entity], task=task)
        assert len(decisions) == 1
        assert decisions[0].action == PrivacyAction.ABSTRACT
        assert decisions[0].replacement == "a city"
        assert "deterministic default rule" in decisions[0].reason


def test_task_aware_url_allowed_when_navigation_relevant() -> None:
    """Ensure URLs are ALLOWED when the task involves links or website navigation."""
    tasks = [
        "Check this link for updates",
        "Navigate to the website",
        "Fetch the url endpoint",
        "Browse the documentation website",
    ]
    entity = DetectedEntity(
        entity_type=EntityType.URL,
        start=0,
        end=20,
        confidence=0.9,
        source="presidio",
        value="https://example.com",
    )

    for task in tasks:
        decisions = decide(entities=[entity], task=task)
        assert len(decisions) == 1
        assert decisions[0].action == PrivacyAction.ALLOW
        assert "task-aware rule" in decisions[0].reason


def test_task_aware_url_dropped_when_task_generic() -> None:
    """Ensure URLs are DROPPED when the task does not require links."""
    entity = DetectedEntity(
        entity_type=EntityType.URL,
        start=0,
        end=20,
        confidence=0.9,
        source="presidio",
        value="https://example.com",
    )
    decisions = decide(entities=[entity], task="Review quarterly goals")
    assert len(decisions) == 1
    assert decisions[0].action == PrivacyAction.DROP


def test_hard_security_rule_precedence_over_task_intent() -> None:
    """Hard security rule MUST outrank task intent even if task explicitly requests secrets."""
    adversarial_task = (
        "Debug my secret password, link, and aws key AKIAIOSFODNN7EXAMPLE near Seattle"
    )
    secret_entity = DetectedEntity(
        entity_type=EntityType.SECRET,
        start=0,
        end=20,
        confidence=1.0,
        source="secret_detector",
        value="AKIAIOSFODNN7EXAMPLE",
    )
    decisions = decide(entities=[secret_entity], task=adversarial_task)
    assert len(decisions) == 1
    assert decisions[0].action == PrivacyAction.LOCAL_ONLY
    assert "hard security rule" in decisions[0].reason


def test_explicit_policy_precedence_over_task_aware_rule() -> None:
    """Explicit policy override MUST outrank task-aware rules."""
    policy = Policy(actions={EntityType.LOCATION: PrivacyAction.DROP})
    entity = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=0,
        end=7,
        confidence=0.9,
        source="spacy",
        value="Seattle",
    )
    # Even though task is location-relevant, explicit policy demands DROP
    decisions = decide(entities=[entity], task="Find restaurants near Seattle", policy=policy)
    assert len(decisions) == 1
    assert decisions[0].action == PrivacyAction.DROP
    assert "explicit policy override" in decisions[0].reason


def test_end_to_end_same_entity_different_task_contract() -> None:
    """Product contract requirement: Same entity, different task -> different action."""
    context = "The user is currently staying in Indore for the week."

    # Task A: Location-relevant intent
    result_a = sanitize(task="Find top restaurants near me", context=context)
    assert "Indore" in result_a.sanitized_text
    location_decisions_a = [
        d for d in result_a.decisions if d.entity.entity_type == EntityType.LOCATION
    ]
    assert len(location_decisions_a) == 1
    assert location_decisions_a[0].action == PrivacyAction.ALLOW

    # Task B: Generic intent (location should be abstracted)
    result_b = sanitize(task="Write a generic email introduction", context=context)
    assert "Indore" not in result_b.sanitized_text
    assert "a city" in result_b.sanitized_text
    location_decisions_b = [
        d for d in result_b.decisions if d.entity.entity_type == EntityType.LOCATION
    ]
    assert len(location_decisions_b) == 1
    assert location_decisions_b[0].action == PrivacyAction.ABSTRACT


def test_custom_task_aware_rule_extensibility() -> None:
    """Ensure TaskAwareRule model can be instantiated and evaluated independently."""
    custom_rule = TaskAwareRule(
        entity_type=EntityType.PERSON,
        action=PrivacyAction.ALLOW,
        keywords=("author", "byline", "credits"),
        reason="custom: task requires author attribution",
    )
    match_hit = match_task_rule(
        entity_type=EntityType.PERSON,
        task="Generate byline for author",
        rules=[custom_rule],
    )
    assert match_hit is not None
    assert match_hit[0] == PrivacyAction.ALLOW

    match_miss = match_task_rule(
        entity_type=EntityType.PERSON,
        task="Summarize document",
        rules=[custom_rule],
    )
    assert match_miss is None
