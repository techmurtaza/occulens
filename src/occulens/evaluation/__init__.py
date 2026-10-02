"""Occulens Evaluation and Benchmarking Framework.

Provides structured evaluation runners, report models, and CLI tools
to verify privacy preservation, leakage rates, and performance across test suites.

Public API:
    - evaluate: Executes a sequence of PrivacyCase fixtures against the pipeline.
    - load_cases_from_json: Loads and validates PrivacyCase objects from JSON files.
    - PrivacyCase: Immutable container describing task, context, and expected invariants.
    - CaseResult: Execution outcome for an individual test case.
    - EvaluationReport: Comprehensive metrics summary container with JSON and Markdown
      table outputs.

How to Run the Evaluation Harness:
    - CLI runner: `python -m occulens.evaluation`
    - Output to file: `python -m occulens.evaluation --output evaluation/baseline_report.json`
    - Makefile shortcut: `make evaluate`

How to Add Test Cases:
    Add a case object to `tests/evaluation/fixtures/privacy_cases.json`:
    ```json
    {
      "id": "sec-99",
      "category": "secret",
      "task": "Review deployment",
      "context": "API key AKIAIOSFODNN7EXAMPLE used.",
      "forbidden_leaked_values": ["AKIAIOSFODNN7EXAMPLE"],
      "expected_substrings": ["[LOCAL_ONLY]"]
    }
    ```

Metrics Definitions:
    - secret_leaks: Count of forbidden secrets appearing in sanitized output (Target: strictly 0).
    - pii_leaks: Count of forbidden PII appearing in sanitized output (Target: strictly 0).
    - required_info_retained: Cases where preserved/allowed information survived intact.
    - processing_ms: Warm pipeline execution time per case in milliseconds.

Explicit Non-Responsibilities:
    - Does NOT mutate or update baseline reports automatically without explicit user flags.
    - Does NOT mock pipeline components; runs strictly end-to-end against real models.

Example Usage:
    >>> from occulens.evaluation import load_cases_from_json, evaluate
    >>> cases = load_cases_from_json("tests/evaluation/fixtures/privacy_cases.json")
    >>> report = evaluate(cases)
    >>> report.secret_leaks
    0
    >>> report.passed
    110
"""

from occulens.evaluation.harness import evaluate, load_cases_from_json
from occulens.evaluation.models import CaseResult, EvaluationReport, PrivacyCase

__all__ = [
    "CaseResult",
    "EvaluationReport",
    "PrivacyCase",
    "evaluate",
    "load_cases_from_json",
]
