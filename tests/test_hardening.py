"""Edge cases and hardening tests for Occulens (Task 8).

Verifies:
1. Input validation: rejection of None, type mismatches, and exceeding max input size.
2. Empty and whitespace-only contexts.
3. Clean pass-through for contexts with no detectable entities.
4. Unicode handling (diacritics, CJK characters, accented names).
5. False-positive suppression (Git SHA hashes, boolean flags, keyword names).
6. Fail-closed error recovery when detectors fail internally.
7. Performance budget: 10KB payload sanitized in < 500ms.
8. JSON quoted key assignments and uppercase Bearer tokens.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from occulens import DEFAULT_MAX_INPUT_LENGTH, sanitize


def test_reject_none_inputs() -> None:
    """Ensure None values for task or context raise TypeError."""
    with pytest.raises(TypeError, match="task cannot be None"):
        sanitize(task=None, context="valid context")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="context cannot be None"):
        sanitize(task="valid task", context=None)  # type: ignore[arg-type]


def test_reject_non_string_types() -> None:
    """Ensure non-string types raise TypeError with descriptive messages."""
    with pytest.raises(TypeError, match="task must be a string"):
        sanitize(task=123, context="valid context")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="context must be a string"):
        sanitize(task="valid task", context=["invalid", "list"])  # type: ignore[arg-type]


def test_max_input_length_enforcement() -> None:
    """Ensure payloads exceeding max_input_length are rejected with ValueError."""
    oversized = "a" * (DEFAULT_MAX_INPUT_LENGTH + 1)
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        sanitize(task="Summarize text", context=oversized)

    # Custom threshold enforcement
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        sanitize(task="Summarize text", context="small context", max_input_length=5)


def test_empty_and_whitespace_only_context() -> None:
    """Ensure empty or whitespace-only strings return cleanly without error."""
    result_empty = sanitize(task="Task", context="")
    assert result_empty.sanitized_text == ""
    assert result_empty.blocked_count == 0
    assert len(result_empty.entities) == 0

    whitespace = "   \n\t   \n  "
    result_ws = sanitize(task="Task", context=whitespace)
    assert result_ws.sanitized_text == whitespace
    assert result_ws.blocked_count == 0
    assert len(result_ws.entities) == 0


def test_context_with_no_sensitive_entities_unchanged() -> None:
    """Ensure innocuous context without secrets or PII passes through unchanged."""
    innocuous = "The quick brown fox jumps over the lazy dog. Version 2.0 release is ready."
    result = sanitize(task="Grammar check", context=innocuous)
    assert result.sanitized_text == innocuous
    assert len(result.entities) == 0
    assert result.blocked_count == 0


def test_unicode_and_diacritic_handling() -> None:
    """Ensure non-ASCII names with diacritics are detected and sanitized."""
    text = (
        "Lead researcher François Müller collaborated with "
        "Dr. Sören Kierkegaard on quantum algorithms."
    )
    result = sanitize(task="Summarize research", context=text)
    assert "François Müller" not in result.sanitized_text
    assert "Sören Kierkegaard" not in result.sanitized_text
    assert "PERSON_A" in result.sanitized_text


def test_false_positive_suppression() -> None:
    """Ensure commit hashes, booleans, and enum names are not falsely flagged as secrets."""
    text = (
        "Commit dc6e60e4420c2794c489cf3d2da5a452ef72f1b8 was merged. "
        "password = false and api_key = null. "
        "The enum value is EntityType.SECRET."
    )
    result = sanitize(task="Review PR", context=text)
    assert "dc6e60e4420c2794c489cf3d2da5a452ef72f1b8" in result.sanitized_text
    assert "password = false" in result.sanitized_text
    assert "api_key = null" in result.sanitized_text
    assert result.local_only_count == 0


def test_json_quoted_keys_secret_redaction() -> None:
    """Ensure JSON-quoted keys like '\"password\":' and '\"api_key\":' are redacted."""
    json_payload = (
        "{\n"
        '  "user": "Alice",\n'
        '  "password": "MySuperSecretPassword99!",\n'
        '  "api_key": "apiKeySecretValue12345"\n'
        "}"
    )
    result = sanitize(task="Parse config", context=json_payload)
    assert "MySuperSecretPassword99!" not in result.sanitized_text
    assert "apiKeySecretValue12345" not in result.sanitized_text
    assert result.local_only_count == 2
    assert "[LOCAL_ONLY]" in result.sanitized_text


def test_case_insensitive_bearer_token() -> None:
    """Ensure uppercase BEARER and mixed-case Bearer tokens are redacted."""
    headers = "AUTHORIZATION: BEARER secret_token_abc123xyz\nAuth: Bearer secret_token_def456uvw"
    result = sanitize(task="Inspect headers", context=headers)
    assert "secret_token_abc123xyz" not in result.sanitized_text
    assert "secret_token_def456uvw" not in result.sanitized_text
    assert result.local_only_count == 2


def test_fail_closed_on_unexpected_detector_crash() -> None:
    """Ensure pipeline fails closed (returns [LOCAL_ONLY]) if a detector raises an exception."""
    with patch(
        "occulens.pipeline.detect_secrets",
        side_effect=RuntimeError("Simulated catastrophic regex failure"),
    ):
        sensitive_input = "Alice connected with password = 'CriticalSecret123!'."
        result = sanitize(task="Triage error", context=sensitive_input)

        # Invariant: raw text MUST NOT leak
        assert "CriticalSecret123!" not in result.sanitized_text
        assert "Alice" not in result.sanitized_text
        assert result.sanitized_text == "[LOCAL_ONLY]"
        assert result.local_only_count == 1
        assert result.blocked_count == 1


def test_performance_10kb_payload_budget() -> None:
    """Ensure a realistic 10KB text payload is sanitized in under 500ms."""
    # Build realistic 10KB context with mixed sentences and scattered credentials
    base_paragraph = (
        "Server node logs: CPU utilization nominal at 42%. "
        "Memory bandwidth 1.2GB/s across cluster in Seattle. "
        "Operator Sarah Connor acknowledged ticket INC-8821. "
        "Contact on-call at ops-support@platform.net or +1 415 555 0199. "
    )
    # ~218 chars per block; repeat 46 times for ~10KB (10,060 chars)
    large_context = (base_paragraph * 46) + "Final key: AKIAIOSFODNN7EXAMPLE."
    assert len(large_context) >= 10_000

    # Warmup
    sanitize(task="Warmup", context="Warmup text")

    start = time.perf_counter()
    result = sanitize(task="Performance benchmark", context=large_context)
    duration_ms = (time.perf_counter() - start) * 1000.0

    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "ops-support@platform.net" not in result.sanitized_text
    assert duration_ms < 500.0, f"Processing 10KB payload took {duration_ms:.2f}ms (budget: 500ms)"


def test_sanitize_short_passwords_and_auth_headers() -> None:
    """Ensure short unquoted passwords and auth headers are sanitized to [LOCAL_ONLY]."""
    text = (
        "Server config:\n"
        "password = abc123\n"
        "Authorization: Basic dXNlcjpwYXNzd29yZA==\n"
        "Authorization: Token ghp_abc123def456\n"
    )
    result = sanitize(task="Audit server config", context=text)

    # Invariant: raw secrets must never cross the boundary
    assert "abc123" not in result.sanitized_text
    assert "dXNlcjpwYXNzd29yZA==" not in result.sanitized_text
    assert "ghp_abc123def456" not in result.sanitized_text
    assert result.local_only_count == 3
    assert result.blocked_count == 3
    assert "Authorization: Basic [LOCAL_ONLY]" in result.sanitized_text
    assert "Authorization: Token [LOCAL_ONLY]" in result.sanitized_text
    assert "password = [LOCAL_ONLY]" in result.sanitized_text


def test_sanitize_conversational_basic_and_token_not_blocked() -> None:
    """Ensure conversational phrases with 'Basic' and 'Token' are not falsely blocked."""
    text = "Basic arithmetic is taught in grade school. The token ring network is historical."
    result = sanitize(task="Grammar review", context=text)
    assert result.sanitized_text == text
    assert result.local_only_count == 0
    assert result.blocked_count == 0
