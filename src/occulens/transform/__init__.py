"""Occulens Transform Module.

This module provides deterministic text transformation primitives that execute
privacy decisions (ALLOW, DROP, TOKENIZE, ABSTRACT, LOCAL_ONLY) against source text.

Public API:
    - transform: Applies privacy decisions to raw context via reverse-offset substitution.

Explicit Non-Responsibilities:
    - Does NOT detect entities or credentials (handled by detectors/ module).
    - Does NOT evaluate policy or determine privacy actions (handled by policy/ module).
    - Does NOT store persistent replacement maps or session state (ephemeral per call).
"""

from occulens.transform.transformer import transform

__all__ = ["transform"]
