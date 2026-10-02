"""Evaluation harness for running privacy benchmark suites."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from occulens.evaluation.models import CaseResult, EvaluationReport, PrivacyCase
from occulens.pipeline import sanitize
from occulens.policy.rules import Policy


def load_cases_from_json(path: Path | str) -> list[PrivacyCase]:
    """Load PrivacyCase objects from a JSON fixture file.

    Args:
        path: Filepath to the JSON fixture.

    Returns:
        List of parsed and validated PrivacyCase instances.
    """
    file_path = Path(path)
    with open(file_path, encoding="utf-8") as f:
        data: list[dict[str, Any]] = json.load(f)

    cases: list[PrivacyCase] = []
    for item in data:
        cases.append(
            PrivacyCase(
                id=str(item.get("id", "")),
                task=str(item.get("task", "")),
                context=str(item.get("context", "")),
                category=str(item.get("category", "general")),
                name=str(item.get("name", "")),
                forbidden_leaked_values=tuple(item.get("forbidden_leaked_values", ())),
                forbidden_diagnostic_values=tuple(item.get("forbidden_diagnostic_values", ())),
                expected_substrings=tuple(item.get("expected_substrings", ())),
                must_preserve=tuple(item.get("must_preserve", ())),
                is_probe=bool(item.get("is_probe", False)),
            )
        )
    return cases


def evaluate(
    cases: Sequence[PrivacyCase],
    policy: Policy | None = None,
) -> EvaluationReport:
    """Execute evaluation across a sequence of PrivacyCases and compute metrics.

    Args:
        cases: The test cases to execute against the sanitize pipeline.
        policy: Optional custom Policy configuration.

    Returns:
        An immutable EvaluationReport summarizing pass/fail counts, leakages,
        action distributions, entity frequencies, and latency statistics.
    """
    if not cases:
        return EvaluationReport(
            total_cases=0,
            passed=0,
            failed=0,
            probes=0,
            secret_leaks=0,
            pii_leaks=0,
            entities_detected=0,
            entities_by_type={},
            actions_by_type={},
            required_info_retained=0,
            incorrect_removals=0,
            avg_processing_ms=0.0,
            p95_processing_ms=0.0,
            case_results=(),
        )

    results: list[CaseResult] = []
    latencies: list[float] = []
    entities_by_type_counter: Counter[str] = Counter()
    actions_by_type_counter: Counter[str] = Counter()
    total_secret_leaks = 0
    total_pii_leaks = 0
    required_info_retained_count = 0
    incorrect_removals_count = 0

    for case in cases:
        res = sanitize(task=case.task, context=case.context, policy=policy)
        sanitized = res.sanitized_text
        res_repr = repr(res)
        latencies.append(res.processing_ms)

        # Check leaks
        output_leaks = tuple(val for val in case.forbidden_leaked_values if val in sanitized)
        diag_leaks = tuple(val for val in case.forbidden_diagnostic_values if val in res_repr)
        missing_expected = tuple(exp for exp in case.expected_substrings if exp not in sanitized)
        missing_preserved = tuple(pres for pres in case.must_preserve if pres not in sanitized)

        # Count leak categories
        is_secret_case = case.category == "secret" or "[LOCAL_ONLY]" in case.expected_substrings
        if output_leaks or diag_leaks:
            if is_secret_case:
                total_secret_leaks += len(output_leaks) + len(diag_leaks)
            else:
                total_pii_leaks += len(output_leaks) + len(diag_leaks)

        # Utility tracking
        if not missing_expected:
            required_info_retained_count += 1
        if missing_preserved:
            incorrect_removals_count += len(missing_preserved)

        # Entity and action tallies
        case_actions: Counter[str] = Counter()
        for d in res.decisions:
            act_name = d.action.value
            case_actions[act_name] += 1
            actions_by_type_counter[act_name] += 1

        for e in res.entities:
            entities_by_type_counter[e.entity_type.value] += 1

        passed = not bool(output_leaks or diag_leaks or missing_expected or missing_preserved)

        results.append(
            CaseResult(
                case_id=case.id,
                category=case.category,
                passed=passed,
                is_probe=case.is_probe,
                output_leaks=output_leaks,
                diagnostic_leaks=diag_leaks,
                missing_preserved=missing_preserved,
                missing_expected=missing_expected,
                actions=dict(case_actions),
                entities_count=len(res.entities),
                processing_ms=res.processing_ms,
            )
        )

    # Compute aggregate stats
    total_cases = len(cases)
    probes_count = sum(1 for c in cases if c.is_probe)
    failed_count = sum(1 for r in results if not r.passed and not r.is_probe)
    passed_count = sum(1 for r in results if r.passed and not r.is_probe)

    avg_ms = round(sum(latencies) / total_cases, 2)
    sorted_latencies = sorted(latencies)
    p95_index = min(int(len(sorted_latencies) * 0.95), len(sorted_latencies) - 1)
    p95_ms = round(sorted_latencies[p95_index], 2)

    return EvaluationReport(
        total_cases=total_cases,
        passed=passed_count,
        failed=failed_count,
        probes=probes_count,
        secret_leaks=total_secret_leaks,
        pii_leaks=total_pii_leaks,
        entities_detected=sum(entities_by_type_counter.values()),
        entities_by_type=dict(entities_by_type_counter),
        actions_by_type=dict(actions_by_type_counter),
        required_info_retained=required_info_retained_count,
        incorrect_removals=incorrect_removals_count,
        avg_processing_ms=avg_ms,
        p95_processing_ms=p95_ms,
        case_results=tuple(results),
    )
