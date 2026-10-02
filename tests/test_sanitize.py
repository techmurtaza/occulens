"""End-to-end integration tests for the public sanitize() API and pipeline orchestrator."""

from __future__ import annotations

from occulens import (
    EntityType,
    Policy,
    PrivacyAction,
    SanitizeResult,
    sanitize,
)


def test_sanitize_realistic_mixed_context() -> None:
    context = (
        "Project update from John Doe at Acme Corp: "
        "Contact me at john.doe@acme.com or +1 (415) 555-2671. "
        "The deployment server in Chicago uses AWS key AKIA1234567890123456."
    )
    task = "Summarize the project update"

    result: SanitizeResult = sanitize(task=task, context=context)

    # 1. Output text correctness
    assert "AKIA1234567890123456" not in result.sanitized_text
    assert "[LOCAL_ONLY]" in result.sanitized_text
    assert "john.doe@acme.com" not in result.sanitized_text
    assert "[REMOVED]" in result.sanitized_text
    assert "PERSON_A" in result.sanitized_text
    assert "ORG_A" in result.sanitized_text
    assert "a city" in result.sanitized_text

    # 2. Diagnostic redaction invariant
    assert result.blocked_count == 1
    assert result.local_only_count == 1
    assert result.processing_ms >= 0.0

    # Ensure raw secret is strictly purged from diagnostics
    for entity in result.entities:
        if entity.entity_type == EntityType.SECRET:
            assert entity.value == "[REDACTED]"
        if entity.entity_type == EntityType.EMAIL:
            assert entity.value == "[REDACTED]"

    for dec in result.decisions:
        if dec.action in (PrivacyAction.LOCAL_ONLY, PrivacyAction.DROP):
            assert dec.entity.value == "[REDACTED]"


def test_sanitize_empty_context() -> None:
    result = sanitize(task="Any task", context="")
    assert result.sanitized_text == ""
    assert result.entities == ()
    assert result.decisions == ()
    assert result.blocked_count == 0
    assert result.local_only_count == 0
    assert result.processing_ms >= 0.0


def test_sanitize_with_custom_policy_override() -> None:
    context = "Send logs to support@example.com for client in Seattle."
    task = "Support routing"

    # Allow email, customize location abstraction
    policy = Policy(
        actions={EntityType.EMAIL: PrivacyAction.ALLOW},
        abstractions={EntityType.LOCATION: "the Pacific Northwest office"},
    )

    result = sanitize(task=task, context=context, policy=policy)

    # Email was allowed per policy
    assert "support@example.com" in result.sanitized_text
    # Location was abstracted with custom phrase
    assert "the Pacific Northwest office" in result.sanitized_text
    assert result.blocked_count == 0


def test_sanitize_secret_precedence_over_overlapping_pii() -> None:
    # A database connection URI contains credentials and hostname that might match URL
    context = "Connect to postgresql://admin:superSecretPassword123!@db.internal.net:5432/prod"
    task = "Inspect database connection"

    result = sanitize(task=task, context=context)

    assert "superSecretPassword123!" not in result.sanitized_text
    assert "[LOCAL_ONLY]" in result.sanitized_text
    assert result.blocked_count >= 1

    # Secret takes priority; ensure no secret credentials remain
    secret_entities = [e for e in result.entities if e.entity_type == EntityType.SECRET]
    assert len(secret_entities) >= 1
    for s in secret_entities:
        assert s.value == "[REDACTED]"


def test_sanitize_timing_and_metrics() -> None:
    context = "Alice met Bob in Tokyo."
    result = sanitize(task="Notes", context=context)

    assert isinstance(result.processing_ms, float)
    assert result.processing_ms > 0.0
    assert len(result.entities) >= 3
    assert len(result.decisions) == len(result.entities)


def test_root_package_exports() -> None:
    import occulens

    assert hasattr(occulens, "sanitize")
    assert hasattr(occulens, "Policy")
    assert hasattr(occulens, "SanitizeResult")
    assert hasattr(occulens, "EntityType")
    assert hasattr(occulens, "PrivacyAction")
    assert hasattr(occulens, "DetectedEntity")
    assert hasattr(occulens, "PrivacyDecision")
    assert hasattr(occulens, "SafeExternalPayload")
    assert callable(occulens.sanitize)
