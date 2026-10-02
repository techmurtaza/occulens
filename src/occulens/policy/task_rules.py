"""Task-aware deterministic privacy policy rules for Occulens.

Evaluates task intent to determine whether specific entities are necessary
for completing the requested user task, adjusting privacy actions deterministically.

Precedence placement:
    hard security rule > explicit policy > task-aware rule > entity-type default > fallback
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from occulens.domain.models import EntityType, PrivacyAction


@dataclass(frozen=True, slots=True)
class TaskAwareRule:
    """A deterministic heuristic rule triggered by keywords in the task description.

    Attributes:
        entity_type: The target EntityType this rule applies to.
        action: The PrivacyAction to assign when triggered.
        keywords: Keywords or phrases in the task prompt that activate this rule.
        reason: Explanatory audit trail reason for this decision.
    """

    entity_type: EntityType
    action: PrivacyAction
    keywords: tuple[str, ...]
    reason: str

    def matches(self, task: str) -> bool:
        """Check if any keyword is present in the task description as a whole word."""
        if not task:
            return False
        task_lower = task.lower()
        for kw in self.keywords:
            pattern = rf"\b{re.escape(kw.lower())}\b"
            if re.search(pattern, task_lower):
                return True
        return False


# Default built-in task-aware deterministic heuristics
_DEFAULT_TASK_AWARE_RULES: tuple[TaskAwareRule, ...] = (
    # 1. Location-relevant tasks retain local geographic context
    TaskAwareRule(
        entity_type=EntityType.LOCATION,
        action=PrivacyAction.ALLOW,
        keywords=(
            "near",
            "nearby",
            "restaurant",
            "restaurants",
            "direction",
            "directions",
            "map",
            "maps",
            "route",
            "routes",
            "weather",
            "commute",
        ),
        reason="task-aware rule: task intent requires local geographic context",
    ),
    # 2. URL/link navigation tasks retain web links
    TaskAwareRule(
        entity_type=EntityType.URL,
        action=PrivacyAction.ALLOW,
        keywords=(
            "link",
            "links",
            "url",
            "urls",
            "website",
            "websites",
            "browse",
            "navigate",
        ),
        reason="task-aware rule: task intent requires link/URL navigation",
    ),
)


def match_task_rule(
    entity_type: EntityType,
    task: str,
    rules: Sequence[TaskAwareRule] = _DEFAULT_TASK_AWARE_RULES,
) -> tuple[PrivacyAction, str] | None:
    """Evaluate task against task-aware rules for a given entity type.

    Args:
        entity_type: The EntityType being evaluated.
        task: The task prompt or intent string.
        rules: Optional sequence of rules (defaults to _DEFAULT_TASK_AWARE_RULES).

    Returns:
        (PrivacyAction, reason) if a rule matches; None if no rule applies.
    """
    if not task:
        return None

    for rule in rules:
        if rule.entity_type == entity_type and rule.matches(task):
            return rule.action, rule.reason

    return None
