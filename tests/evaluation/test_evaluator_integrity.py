"""Evaluator self-test suite (E01-E07).

Proves that the evaluation harness detects:
- E01: No-op sanitizer that leaks original context
- E02: Drop-everything/marker-only sanitizer that removes utility
- E03: Sanitizer that cleans text but leaks canaries in diagnostics
- E04: Sanitizer that outputs markers but removes must_preserve phrases
- E05: Mixed cases classifying secret leaks and PII leaks separately
- E06: Malformed, duplicate, or empty-assertion fixture definitions
- E07: Secret leaks in exploratory probes
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from occulens.domain.models import (
    DetectedEntity,
    PrivacyDecision,
    SanitizeResult,
)
from occulens.evaluation.harness import evaluate, load_cases_from_json
from occulens.evaluation.models import PrivacyCase


def _make_dummy_result(
    sanitized_text: str,
    entities: list[DetectedEntity] | None = None,
    decisions: list[PrivacyDecision] | None = None,
) -> SanitizeResult:
    """Helper to build a SanitizeResult."""
    return SanitizeResult(
        sanitized_text=sanitized_text,
        entities=entities or [],
        decisions=decisions or [],
        blocked_count=1 if "[LOCAL_ONLY]" in sanitized_text else 0,
        local_only_count=1 if "[LOCAL_ONLY]" in sanitized_text else 0,
        processing_ms=1.5,
    )


def test_e01_noop_sanitizer_fails_leakage_checks() -> None:
    """E01: Mock returns original context -> leakage detected in evaluation report."""
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    case = PrivacyCase(
        id="e01-test",
        task="Summarize logs",
        context=f"Error with key {raw_secret} on server",
        category="secret",
        forbidden_leaked_values=(raw_secret,),
        expected_substrings=("[LOCAL_ONLY]",),
    )

    # Mutant returns original context unchanged
    def noop_sanitizer(task: str, context: str, policy: Any = None) -> SanitizeResult:
        return _make_dummy_result(sanitized_text=context)

    report = evaluate([case], sanitizer=noop_sanitizer)
    assert report.total_cases == 1
    assert report.passed == 0
    assert report.failed == 1
    assert report.secret_leaks == 1
    assert report.case_results[0].passed is False
    assert raw_secret in report.case_results[0].output_leaks


def test_e02_drop_everything_marker_only_mutant_fails_utility() -> None:
    """E02: Mock returns only markers -> useful-text assertions fail, utility is 0."""
    case = PrivacyCase(
        id="e02-test",
        task="Customer support triage",
        context="User John reported server timeout in cluster-us-east-1",
        category="person_org",
        forbidden_leaked_values=("John",),
        expected_substrings=("[REMOVED]",),
        must_preserve=("server timeout in cluster-us-east-1",),
    )

    # Mutant returns only marker, removing all useful context
    def marker_only_sanitizer(task: str, context: str, policy: Any = None) -> SanitizeResult:
        return _make_dummy_result(sanitized_text="[REMOVED]")

    report = evaluate([case], sanitizer=marker_only_sanitizer)
    assert report.total_cases == 1
    assert report.failed == 1
    assert report.applicable_utility_cases == 1
    assert report.required_info_retained == 0
    assert report.incorrect_removals == 1
    assert "server timeout in cluster-us-east-1" in report.case_results[0].missing_preserved


def test_e03_diagnostic_canary_leak_detected() -> None:
    """E03: Safe sanitized_text but diagnostics contain forbidden canary -> detected as leak."""
    canary = "diagnostic_canary_secret_123"
    case = PrivacyCase(
        id="e03-test",
        task="Process config",
        context="Database config setup",
        category="secret",
        expected_substrings=("[LOCAL_ONLY]",),
        forbidden_diagnostic_values=(canary,),
    )

    # Mutant returns safe text, but diagnostics repr contains the canary
    class LeakyDiagnosticResult:
        def __init__(self) -> None:
            self.sanitized_text = "[LOCAL_ONLY]"
            self.entities: tuple[Any, ...] = ()
            self.decisions: tuple[Any, ...] = ()
            self.blocked_count = 1
            self.local_only_count = 1
            self.processing_ms = 1.0

        def __repr__(self) -> str:
            return f"SanitizeResult(sanitized_text='[LOCAL_ONLY]', leak='{canary}')"

        def to_safe_payload(self) -> Any:
            return None

    def leaky_sanitizer(task: str, context: str, policy: Any = None) -> Any:
        return LeakyDiagnosticResult()

    report = evaluate([case], sanitizer=leaky_sanitizer)
    assert report.failed == 1
    assert canary in report.case_results[0].diagnostic_leaks
    assert report.secret_leaks == 1


def test_e04_missing_must_preserve_phrase_fails_case() -> None:
    """E04: Expected marker present but must_preserve phrase removed -> case fails."""
    case = PrivacyCase(
        id="e04-test",
        task="Incident review",
        context="Engineer Alice fixed outage in production db",
        category="person_org",
        expected_substrings=("PERSON_A",),
        must_preserve=("fixed outage in production db",),
    )

    # Mutant outputs the expected marker, but accidentally clips the must_preserve text
    def partial_clip_sanitizer(task: str, context: str, policy: Any = None) -> SanitizeResult:
        return _make_dummy_result(sanitized_text="Engineer PERSON_A resolved the issue")

    report = evaluate([case], sanitizer=partial_clip_sanitizer)
    assert report.failed == 1
    assert report.case_results[0].passed is False
    assert "fixed outage in production db" in report.case_results[0].missing_preserved


def test_e05_mixed_case_classifies_secret_and_pii_separately() -> None:
    """E05: Mixed case leaks secret + PII -> accurately split into secret/pii leaks."""
    secret_val = "AKIAIOSFODNN7EXAMPLE"
    pii_val = "john.doe@company.internal"
    case = PrivacyCase(
        id="e05-test",
        task="HR review",
        context=f"Contact {pii_val} with AWS key {secret_val}",
        category="mixed",
        forbidden_leaked_values=(secret_val, pii_val),
    )

    # Mutant leaks both values into sanitized output
    def leaky_mixed_sanitizer(task: str, context: str, policy: Any = None) -> SanitizeResult:
        return _make_dummy_result(sanitized_text=f"Contact {pii_val} with AWS key {secret_val}")

    report = evaluate([case], sanitizer=leaky_mixed_sanitizer)
    assert report.failed == 1
    assert report.secret_leaks == 1, f"Expected 1 secret leak, got {report.secret_leaks}"
    assert report.pii_leaks == 1, f"Expected 1 PII leak, got {report.pii_leaks}"


def test_e06_fixture_validation_rejects_malformed_and_duplicate_cases(tmp_path: Path) -> None:
    """E06: Duplicate case IDs, malformed fields, empty safety assertions are rejected."""
    # 1. Duplicate ID
    dup_file = tmp_path / "dup.json"
    dup_file.write_text(
        json.dumps(
            [
                {"id": "c1", "task": "t1", "context": "ctx", "forbidden_leaked_values": ["x"]},
                {"id": "c1", "task": "t2", "context": "ctx", "forbidden_leaked_values": ["y"]},
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate case id: 'c1'"):
        load_cases_from_json(dup_file)

    # 2. Missing id
    no_id_file = tmp_path / "no_id.json"
    no_id_file.write_text(
        json.dumps([{"task": "t1", "context": "ctx", "forbidden_leaked_values": ["x"]}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing required 'id'"):
        load_cases_from_json(no_id_file)

    # 3. Missing task
    no_task_file = tmp_path / "no_task.json"
    no_task_file.write_text(
        json.dumps([{"id": "c2", "context": "ctx", "forbidden_leaked_values": ["x"]}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing required non-empty 'task'"):
        load_cases_from_json(no_task_file)

    # 4. Missing context
    no_ctx_file = tmp_path / "no_ctx.json"
    no_ctx_file.write_text(
        json.dumps([{"id": "c3", "task": "t1", "forbidden_leaked_values": ["x"]}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing required 'context'"):
        load_cases_from_json(no_ctx_file)

    # 5. Non-probe case with empty assertions
    empty_assert_file = tmp_path / "empty_assert.json"
    empty_assert_file.write_text(
        json.dumps([{"id": "c4", "task": "t1", "context": "ctx", "is_probe": False}]),
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError, match="neither forbidden_leaked_values nor expected_substrings"
    ):
        load_cases_from_json(empty_assert_file)


def test_e07_probe_secret_leak_is_recorded_and_visible() -> None:
    """E07: Secret leak in exploratory probe is recorded and visible; cannot yield clean gate."""
    secret_val = "AKIAIOSFODNN7EXAMPLE"
    probe_case = PrivacyCase(
        id="e07-probe",
        task="Experimental format",
        context=f"Experimental token {secret_val}",
        category="secret",
        forbidden_leaked_values=(secret_val,),
        is_probe=True,
    )

    # Mutant leaks secret in probe
    def probe_leaky_sanitizer(task: str, context: str, policy: Any = None) -> SanitizeResult:
        return _make_dummy_result(sanitized_text=f"Experimental token {secret_val}")

    report = evaluate([probe_case], sanitizer=probe_leaky_sanitizer)
    assert report.total_cases == 1
    assert report.probes == 1
    assert report.secret_leaks == 1
    assert report.case_results[0].passed is False
    assert secret_val in report.case_results[0].output_leaks
