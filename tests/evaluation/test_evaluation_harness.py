"""Unit and integration tests for the Occulens evaluation framework."""

from __future__ import annotations

import json
from pathlib import Path

from occulens.evaluation.harness import evaluate, load_cases_from_json
from occulens.evaluation.models import PrivacyCase

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "privacy_cases.json"


def test_load_cases_from_json() -> None:
    """Ensure load_cases_from_json loads and parses PrivacyCase objects."""
    cases = load_cases_from_json(FIXTURE_PATH)
    assert len(cases) >= 50
    first = cases[0]
    assert isinstance(first, PrivacyCase)
    assert first.id == "sec-01"
    assert first.task != ""
    assert first.context != ""


def test_evaluate_clean_suite() -> None:
    """Ensure evaluate computes correct metrics on fixture cases."""
    cases = load_cases_from_json(FIXTURE_PATH)
    report = evaluate(cases)

    assert report.total_cases == len(cases)
    assert report.passed == len(cases)
    assert report.failed == 0
    assert report.secret_leaks == 0
    assert report.pii_leaks == 0
    assert report.entities_detected > 0
    assert report.avg_processing_ms > 0
    assert len(report.actions_by_type) > 0


def test_evaluate_detects_deliberate_leakage() -> None:
    """Ensure evaluate flags cases that leak forbidden values."""
    leaking_case = PrivacyCase(
        id="test-fail-01",
        task="Summarize text",
        context="Innocuous context without entities.",
        forbidden_leaked_values=("without",),  # 'without' is present in context and not redacted
    )
    report = evaluate([leaking_case])
    assert report.total_cases == 1
    assert report.failed == 1
    assert report.passed == 0
    assert report.pii_leaks == 1


def test_evaluate_empty_cases() -> None:
    """Ensure evaluate handles an empty case list gracefully."""
    report = evaluate([])
    assert report.total_cases == 0
    assert report.passed == 0
    assert report.failed == 0
    assert report.avg_processing_ms == 0.0


def test_report_formatting_and_serialization() -> None:
    """Ensure report can format markdown table and serialize to valid JSON."""
    cases = load_cases_from_json(FIXTURE_PATH)[:3]
    report = evaluate(cases)

    # Markdown table formatting
    table = report.format_table()
    assert "# Occulens Privacy Evaluation Report" in table
    assert "| **Total Cases** | 3 |" in table
    assert "### Actions Distribution" in table

    # JSON serialization
    json_str = report.to_json()
    parsed = json.loads(json_str)
    assert parsed["total_cases"] == 3
    assert "actions_by_type" in parsed
    assert "entities_by_type" in parsed
