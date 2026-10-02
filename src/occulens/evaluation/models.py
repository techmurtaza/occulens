"""Evaluation models and reporting containers for Occulens."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class PrivacyCase:
    """A test case for evaluating privacy and sanitization behavior.

    Attributes:
        id: Unique identifier for the case (e.g. sec-01, mix-02).
        task: User task intent.
        context: Raw text context potentially containing sensitive entities.
        category: Category grouping (secret, email_phone, person_org, location, etc.).
        name: Human-readable test name.
        forbidden_leaked_values: Strings that must NEVER appear in sanitized output.
        forbidden_diagnostic_values: Strings that must NEVER appear in diagnostic representation.
        expected_substrings: Strings expected in sanitized output (e.g. placeholders, aliases).
        must_preserve: Safe strings that must NOT be removed or redacted.
        is_probe: If True, indicates exploratory evaluation rather than hard pass/fail.
    """

    id: str
    task: str
    context: str
    category: str = "general"
    name: str = ""
    forbidden_leaked_values: tuple[str, ...] = ()
    forbidden_diagnostic_values: tuple[str, ...] = ()
    expected_substrings: tuple[str, ...] = ()
    must_preserve: tuple[str, ...] = ()
    is_probe: bool = False


@dataclass(frozen=True, slots=True)
class CaseResult:
    """Individual execution outcome of a PrivacyCase."""

    case_id: str
    category: str
    passed: bool
    is_probe: bool
    output_leaks: tuple[str, ...] = ()
    diagnostic_leaks: tuple[str, ...] = ()
    missing_preserved: tuple[str, ...] = ()
    missing_expected: tuple[str, ...] = ()
    actions: Mapping[str, int] = field(default_factory=dict)
    entities_count: int = 0
    processing_ms: float = 0.0

    def __post_init__(self) -> None:
        """Freeze dictionary mappings."""
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Aggregated evaluation and benchmark metrics across test suites."""

    total_cases: int
    passed: int
    failed: int
    probes: int
    secret_leaks: int
    pii_leaks: int
    entities_detected: int
    entities_by_type: Mapping[str, int]
    actions_by_type: Mapping[str, int]
    required_info_retained: int
    incorrect_removals: int
    avg_processing_ms: float
    p95_processing_ms: float
    case_results: tuple[CaseResult, ...] = ()

    def __post_init__(self) -> None:
        """Freeze dictionary mappings."""
        object.__setattr__(self, "entities_by_type", MappingProxyType(dict(self.entities_by_type)))
        object.__setattr__(self, "actions_by_type", MappingProxyType(dict(self.actions_by_type)))

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "total_cases": self.total_cases,
            "passed": self.passed,
            "failed": self.failed,
            "probes": self.probes,
            "secret_leaks": self.secret_leaks,
            "pii_leaks": self.pii_leaks,
            "entities_detected": self.entities_detected,
            "entities_by_type": dict(self.entities_by_type),
            "actions_by_type": dict(self.actions_by_type),
            "required_info_retained": self.required_info_retained,
            "incorrect_removals": self.incorrect_removals,
            "avg_processing_ms": self.avg_processing_ms,
            "p95_processing_ms": self.p95_processing_ms,
            "case_results": [
                {
                    "case_id": r.case_id,
                    "category": r.category,
                    "passed": r.passed,
                    "is_probe": r.is_probe,
                    "output_leaks": list(r.output_leaks),
                    "diagnostic_leaks": list(r.diagnostic_leaks),
                    "missing_preserved": list(r.missing_preserved),
                    "missing_expected": list(r.missing_expected),
                    "actions": dict(r.actions),
                    "entities_count": r.entities_count,
                    "processing_ms": r.processing_ms,
                }
                for r in self.case_results
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to indented JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def format_table(self) -> str:
        """Format report summary as a readable markdown table."""
        pass_rate = (self.passed / self.total_cases * 100) if self.total_cases > 0 else 0.0
        lines = [
            "# Occulens Privacy Evaluation Report",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Total Cases** | {self.total_cases} |",
            f"| **Passed** | {self.passed} ({pass_rate:.1f}%) |",
            f"| **Failed** | {self.failed} |",
            f"| **Probes** | {self.probes} |",
            f"| **Secret Leaks** | {self.secret_leaks} |",
            f"| **PII Leaks** | {self.pii_leaks} |",
            f"| **Entities Detected** | {self.entities_detected} |",
            f"| **Required Info Retained** | {self.required_info_retained} |",
            f"| **Incorrect Removals** | {self.incorrect_removals} |",
            f"| **Average Latency** | {self.avg_processing_ms:.2f} ms |",
            f"| **P95 Latency** | {self.p95_processing_ms:.2f} ms |",
            "",
            "### Actions Distribution",
            "",
            "| Action | Count |",
            "| :--- | :--- |",
        ]
        for action, count in sorted(self.actions_by_type.items()):
            lines.append(f"| {action} | {count} |")

        lines.extend(
            [
                "",
                "### Entities by Type",
                "",
                "| Entity Type | Count |",
                "| :--- | :--- |",
            ]
        )
        for ent_type, count in sorted(self.entities_by_type.items()):
            lines.append(f"| {ent_type} | {count} |")

        return "\n".join(lines)
