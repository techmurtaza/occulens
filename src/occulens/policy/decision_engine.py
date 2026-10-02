"""Privacy decision engine for assigning actions to detected entities.

Enforces strict policy precedence:
    hard security rule > explicit policy > deterministic default > conservative fallback
"""

from __future__ import annotations

from collections.abc import Sequence

from occulens.domain.models import DetectedEntity, EntityType, PrivacyAction, PrivacyDecision
from occulens.policy.rules import (
    _ALIAS_PREFIXES,
    _DEFAULT_ABSTRACTIONS,
    _DEFAULT_ACTIONS,
    Policy,
    index_to_letters,
)
from occulens.policy.task_rules import match_task_rule


def decide(
    entities: Sequence[DetectedEntity],
    task: str = "",
    policy: Policy | None = None,
) -> list[PrivacyDecision]:
    """Evaluate detected entities and produce deterministic privacy decisions.

    Precedence chain:
    1. Hard security rules: EntityType.SECRET is unconditionally LOCAL_ONLY.
    2. Explicit policy overrides: custom actions configured on the Policy object.
    3. Task-aware deterministic rules: contextually relevant entities allowed per task intent.
    4. Deterministic default rules: standard baseline actions per EntityType.
    5. Conservative fallback: any unmapped entity type defaults to TOKENIZE.

    Args:
        entities: Sequence of entities detected in the source context.
        task: Description of the task being performed (triggers task-aware rules).
        policy: Optional configuration policy overriding default actions/abstractions.

    Returns:
        A list of PrivacyDecision objects corresponding to the input entities.
    """
    if not entities:
        return []

    # Map of (EntityType, normalized_value) -> assigned alias token
    assigned_aliases: dict[tuple[EntityType, str], str] = {}
    decisions: list[PrivacyDecision] = []

    for entity in entities:
        action, reason = _determine_action_and_reason(entity=entity, task=task, policy=policy)
        replacement = _determine_replacement(
            entity=entity,
            action=action,
            policy=policy,
            assigned_aliases=assigned_aliases,
        )

        decisions.append(
            PrivacyDecision(
                entity=entity,
                action=action,
                replacement=replacement,
                reason=reason,
            )
        )

    return decisions


def _determine_action_and_reason(
    entity: DetectedEntity,
    task: str,
    policy: Policy | None,
) -> tuple[PrivacyAction, str]:
    """Determine the PrivacyAction and explanation reason based on strict precedence."""
    # 1. Hard Security Rule (Non-overridable invariant)
    if entity.entity_type == EntityType.SECRET:
        return (
            PrivacyAction.LOCAL_ONLY,
            "hard security rule: credentials/secrets are strictly LOCAL_ONLY",
        )

    # 2. Explicit Policy Override
    if policy is not None and entity.entity_type in policy.actions:
        override_action = policy.actions[entity.entity_type]
        return (
            override_action,
            f"explicit policy override for {entity.entity_type.value}",
        )

    # 3. Task-Aware Deterministic Rule (heuristic based on task intent)
    task_match = match_task_rule(entity.entity_type, task)
    if task_match is not None:
        action, reason = task_match
        return action, reason

    # 4. Deterministic Default Rule
    if entity.entity_type in _DEFAULT_ACTIONS:
        default_action = _DEFAULT_ACTIONS[entity.entity_type]
        return (
            default_action,
            f"deterministic default rule for {entity.entity_type.value}",
        )

    # 5. Conservative Fallback
    return (
        PrivacyAction.TOKENIZE,
        f"conservative fallback rule for unmapped entity type {entity.entity_type.value}",
    )


def _determine_replacement(
    entity: DetectedEntity,
    action: PrivacyAction,
    policy: Policy | None,
    assigned_aliases: dict[tuple[EntityType, str], str],
) -> str | None:
    """Generate or retrieve the replacement string for the chosen privacy action."""
    match action:
        case PrivacyAction.TOKENIZE:
            key = (entity.entity_type, entity.value.strip().lower())
            if key not in assigned_aliases:
                prefix = _ALIAS_PREFIXES.get(entity.entity_type, f"{entity.entity_type.value}_")
                count = sum(1 for k in assigned_aliases if k[0] == entity.entity_type)
                assigned_aliases[key] = f"{prefix}{index_to_letters(count)}"
            return assigned_aliases[key]

        case PrivacyAction.ABSTRACT:
            if policy is not None and entity.entity_type in policy.abstractions:
                return policy.abstractions[entity.entity_type]
            return _DEFAULT_ABSTRACTIONS.get(entity.entity_type, "an entity")

        case PrivacyAction.ALLOW | PrivacyAction.DROP | PrivacyAction.LOCAL_ONLY:
            return None
