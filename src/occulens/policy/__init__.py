"""Occulens Policy Module.

This module provides privacy policy rules, configuration models, and the
deterministic decision engine that assigns privacy actions to detected entities.

Public API:
    - Policy: Configuration dataclass defining action and abstraction overrides.
    - TaskAwareRule: Dataclass specifying task keyword matchers and action mappings.
    - decide: Evaluates detected entities and assigns actions following precedence rules.
    - match_task_rule: Matches a task string against registered keyword rules.

Policy Precedence Chain:
    1. Hard security rules: EntityType.SECRET is unconditionally LOCAL_ONLY
       (cannot be overridden).
    2. Explicit policy overrides: custom rules configured on Policy.rules.
    3. Task-aware deterministic rules: task keywords (e.g. "near me", "navigate to link")
       allow task-relevant entities.
    4. Deterministic default rules: standard baseline actions per EntityType.
    5. Conservative fallback: unmapped entity types default to TOKENIZE.

Hard Rules vs Soft Rules:
    - Hard Rules: `SECRET -> LOCAL_ONLY`. Any attempt to override in Policy raises ValueError.
    - Soft Rules: Defaults for PII (EMAIL/PHONE -> DROP, PERSON/ORG -> TOKENIZE,
      LOCATION -> ABSTRACT).

Explicit Non-Responsibilities:
    - Does NOT scan raw text for entities or credentials (handled by detectors/ module).
    - Does NOT execute text string replacements (handled by transform/ module).
    - Does NOT route context across external networks (strictly local-only).

Example Usage:
    >>> from occulens.domain import DetectedEntity, EntityType
    >>> from occulens.policy import Policy, decide
    >>> entity = DetectedEntity(
    ...     entity_type=EntityType.PERSON,
    ...     value="Alice",
    ...     start=0,
    ...     end=5,
    ...     confidence=0.9,
    ...     source="spacy",
    ... )
    >>> decisions = decide([entity], task="General summary")
    >>> decisions[0].replacement
    'PERSON_A'

Architecture Decision Records:
    - ADR-004: Decision precedence is a hard invariant.
    - ADR-005: Session-scoped aliases for tokenization.
"""

from occulens.policy.decision_engine import decide
from occulens.policy.rules import Policy
from occulens.policy.task_rules import TaskAwareRule, match_task_rule

__all__ = ["Policy", "TaskAwareRule", "decide", "match_task_rule"]
