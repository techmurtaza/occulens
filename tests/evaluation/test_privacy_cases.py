"""Comprehensive privacy evaluation test suite.

Verifies end-to-end sanitization behavior across 100+ privacy test cases:
1. Zero secret leakage across all cases.
2. DROP behavior for email/phone/urls.
3. TOKENIZE behavior for persons and organizations with consistent aliases.
4. ABSTRACT behavior for locations.
5. Task-aware rules (ALLOW for task-relevant locations and URLs).
6. Professional, SWE, HR/legal, customer support, memory, and adversarial scenarios.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from occulens import sanitize

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "privacy_cases.json"


def load_privacy_cases() -> list[dict[str, Any]]:
    """Load test cases from fixture JSON."""
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        cases: list[dict[str, Any]] = json.load(f)
    return cases


ALL_CASES = load_privacy_cases()


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: str(c["id"]))
def test_privacy_case_leakage_and_expectations(case: dict[str, Any]) -> None:
    """Test that each privacy case leaks no forbidden values and meets expected substrings."""
    task: str = case["task"]
    context: str = case["context"]
    forbidden_values: list[str] = case.get("forbidden_leaked_values", [])
    forbidden_diagnostic: list[str] = case.get("forbidden_diagnostic_values", [])
    expected_substrings: list[str] = case.get("expected_substrings", [])
    must_preserve: list[str] = case.get("must_preserve", [])

    result = sanitize(task=task, context=context)

    # Invariant 1: No forbidden values leak into sanitized output
    for forbidden in forbidden_values:
        assert forbidden not in result.sanitized_text, (
            f"Case {case['id']} leaked forbidden value: '{forbidden}' "
            f"in sanitized_text: '{result.sanitized_text}'"
        )

    # Invariant 2: Expected substrings must be present
    for expected in expected_substrings:
        assert expected in result.sanitized_text, (
            f"Case {case['id']} missing expected substring '{expected}' "
            f"in sanitized_text: '{result.sanitized_text}'"
        )

    # Invariant 3: SanitizeResult fields are populated and valid
    assert result.processing_ms >= 0.0
    if "[LOCAL_ONLY]" in result.sanitized_text:
        assert result.local_only_count > 0

    # Invariant 4: Forbidden diagnostic values must NOT appear in repr(result)
    result_repr = repr(result)
    for forbidden_diag in forbidden_diagnostic:
        assert forbidden_diag not in result_repr, (
            f"Case {case['id']} leaked forbidden diagnostic value: '{forbidden_diag}' "
            f"in repr(result): '{result_repr}'"
        )

    # Invariant 5: SafeExternalPayload must NOT leak forbidden values or diagnostic values
    safe_payload = result.to_safe_payload()
    payload_repr = repr(safe_payload)
    payload_dict = {
        "sanitized_text": safe_payload.sanitized_text,
        "token_map": dict(safe_payload.token_map),
        "action_counts": dict(safe_payload.action_counts),
        "blocked_count": safe_payload.blocked_count,
        "processing_ms": safe_payload.processing_ms,
    }
    payload_json = json.dumps(payload_dict)

    for forbidden in forbidden_values:
        assert forbidden not in safe_payload.sanitized_text, (
            f"Case {case['id']} leaked forbidden value '{forbidden}' "
            "in safe_payload.sanitized_text"
        )
    for forbidden_diag in forbidden_diagnostic:
        assert forbidden_diag not in payload_repr, (
            f"Case {case['id']} leaked forbidden diagnostic '{forbidden_diag}' "
            "in repr(safe_payload)"
        )
        assert forbidden_diag not in payload_json, (
            f"Case {case['id']} leaked forbidden diagnostic '{forbidden_diag}' "
            "in safe_payload JSON"
        )

    # Invariant 6: Preserved values must survive in sanitized_text
    for preserved in must_preserve:
        assert preserved in result.sanitized_text, (
            f"Case {case['id']} incorrectly removed preserved value '{preserved}' "
            f"from sanitized_text: '{result.sanitized_text}'"
        )


def test_zero_secret_leaks_across_suite() -> None:
    """Evaluate all 100+ cases and assert that total secret leaks is strictly 0."""
    secret_leaks = 0
    leaked_details: list[str] = []

    for case in ALL_CASES:
        result = sanitize(task=case["task"], context=case["context"])
        for forbidden in case.get("forbidden_leaked_values", []):
            if forbidden in result.sanitized_text:
                secret_leaks += 1
                leaked_details.append(f"{case['id']}: '{forbidden}' found in output")

    assert secret_leaks == 0, f"Detected {secret_leaks} leaks across suite: {leaked_details}"


def test_suite_case_count_target() -> None:
    """Ensure suite contains at least 100 test cases as required for Checkpoint C."""
    assert len(ALL_CASES) >= 100


def test_warm_pipeline_latency_budget() -> None:
    """Ensure warm average latency across evaluation suite is under 50ms."""
    # Warm up spaCy and Presidio engines
    sanitize(task="warmup", context="warmup context")

    latencies = [sanitize(task=c["task"], context=c["context"]).processing_ms for c in ALL_CASES]
    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 50.0, (
        f"Average pipeline latency ({avg_latency:.2f}ms) exceeded 50ms budget"
    )
