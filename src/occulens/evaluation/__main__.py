"""CLI runner for Occulens evaluation suite.

Executes all evaluation cases, generates a structured markdown summary report,
and exits with code 0 on success or 1 if any critical failures / secret leaks occur.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from occulens.evaluation.harness import evaluate, load_cases_from_json


def main() -> int:
    """CLI entrypoint for running evaluation cases."""
    parser = argparse.ArgumentParser(description="Occulens Privacy Evaluation Runner")
    parser.add_argument(
        "--fixtures",
        type=str,
        default="tests/evaluation/fixtures/privacy_cases.json",
        help="Path to privacy cases JSON fixture file",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON report instead of markdown table",
    )
    args = parser.parse_args()

    fixture_path = Path(args.fixtures)
    if not fixture_path.exists():
        print(f"Error: Fixture file not found: {fixture_path}", file=sys.stderr)
        return 1

    cases = load_cases_from_json(fixture_path)
    report = evaluate(cases)

    if args.json:
        print(report.to_json())
    else:
        print(report.format_table())

    if report.secret_leaks > 0 or report.failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
