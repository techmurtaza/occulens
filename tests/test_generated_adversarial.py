"""Adversarial evaluation over 1000+ generated credential variants (Task G1).

Verifies that across all partitions (lengths, character classes, containers,
delimiters, auth schemes, casing):
1. Canary heads and tails are strictly absent from output and diagnostics.
2. Useful contextual text is preserved.
3. Pipeline maintains complete secret containment.
"""

from __future__ import annotations

from occulens import sanitize
from tests.generators.credential_generator import (
    generate_credential_variants,
)

GENERATED_CASES = generate_credential_variants(count=1000, seed=42)


def test_generated_variant_count_and_partitions() -> None:
    """Verify that at least 1000 variants are generated and all partitions are represented."""
    assert len(GENERATED_CASES) >= 1000
    partitions = {c.partition for c in GENERATED_CASES}
    expected_partitions = {
        "quoted_assigned",
        "unquoted_assigned",
        "auth_headers",
        "database_uris",
        "structural_containers",
    }
    assert expected_partitions.issubset(partitions)


def test_all_1000_generated_adversarial_variants_pass() -> None:
    """Execute all 1000 variants and verify zero leakages and useful text retention."""
    failing_seeds: list[dict[str, object]] = []

    for case in GENERATED_CASES:
        result = sanitize(task=case.task, context=case.context)
        sanitized = result.sanitized_text
        result_repr = repr(result)

        head_leaked = case.canary_head in sanitized or case.canary_head in result_repr
        tail_leaked = case.canary_tail in sanitized or case.canary_tail in result_repr
        useful_preserved = case.useful_text in sanitized

        if head_leaked or tail_leaked or not useful_preserved:
            failing_seeds.append(
                {
                    "seed": case.seed,
                    "partition": case.partition,
                    "head_leaked": head_leaked,
                    "tail_leaked": tail_leaked,
                    "useful_preserved": useful_preserved,
                    "context": case.context,
                    "output": sanitized,
                }
            )

    assert not failing_seeds, (
        f"{len(failing_seeds)} generated variants failed! First 5 failures: {failing_seeds[:5]}"
    )
