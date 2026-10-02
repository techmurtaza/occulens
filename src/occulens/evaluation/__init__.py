"""Occulens Evaluation and Benchmarking Framework.

Provides structured evaluation runners, report models, and CLI tools
to verify privacy preservation, leakage rates, and performance across test suites.
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
