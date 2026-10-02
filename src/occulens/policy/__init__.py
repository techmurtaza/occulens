"""Occulens Policy Module.

This module provides privacy policy rules, configuration models, and the
deterministic decision engine that assigns privacy actions to detected entities.

Public API:
    - Policy: Configuration dataclass defining action and abstraction overrides.
    - decide: Evaluates detected entities and assigns actions following precedence rules.

Explicit Non-Responsibilities:
    - Does NOT scan raw text for entities or credentials (handled by detectors/ module).
    - Does NOT execute text string replacements (handled by transform/ module).
    - Does NOT route context across external networks (strictly local-only).
"""

from occulens.policy.decision_engine import decide
from occulens.policy.rules import Policy
from occulens.policy.task_rules import TaskAwareRule, match_task_rule

__all__ = ["Policy", "TaskAwareRule", "decide", "match_task_rule"]
