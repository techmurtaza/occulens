"""Deterministic secret scanner for Occulens.

This module detects credentials, API keys, tokens, passwords, and private keys
using deterministic regular expressions. Any matched secret is classified as
EntityType.SECRET with confidence 1.0 and defaults to LOCAL_ONLY.
"""

from __future__ import annotations

import re

from occulens.domain.models import DetectedEntity, EntityType

_DETECTOR_SOURCE = "secret_detector"

# 1. AWS Access Key IDs (AKIA, ABIA, ACCA, ASIA followed by 16 alphanumeric characters)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")

# 2. GitHub Personal Access Tokens and Fine-Grained Tokens
_GITHUB_TOKEN_RE = re.compile(
    r"\b(?:ghp|gho|ghs|ghr|ghu)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"
)

# 3. JSON Web Tokens (three dot-separated base64 segments starting with eyJ)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b")

# 4. SSH, RSA, and OpenSSL Private Keys
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+)?PRIVATE KEY-----"
)

# 5. Database and network service connection URIs containing username:password credentials
_DATABASE_URI_RE = re.compile(
    r"\b(?:https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|cockroachdb|amqp(?:s)?)"
    r":\/\/[^\s:@\/]+:[^\s@\/]+@[^\s\/]+(?::\d+)?\/?[^\s\"'<>]*"
)

# 6. Authorization Headers (Bearer, Basic, Token - case-insensitive)
# Bearer tokens may appear standalone ("Bearer <token>") or prefixed.
# Basic and Token auth schemes strictly require an explicit "Authorization" / "Auth"
# header prefix to prevent false positives on conversational English phrases.
_AUTH_HEADER_RE = re.compile(
    r"""(?:["']?(?:authorization|auth)["']?\s*:\s*["']?)?(?:Bearer)\s+["']?([A-Za-z0-9\-._~+/]+=*)["']?"""
    r"""|["']?(?:authorization|auth)["']?\s*:\s*["']?(?:Basic|Token)\s+["']?([A-Za-z0-9\-._~+/]+=*)["']?""",
    re.IGNORECASE,
)

# 7. Generic credential assignments (password, api_key, secret_key, client_secret)
# Supports raw identifiers (password = ...) and JSON/YAML quoted keys ("password": ...)
_SECRET_KEYWORD_PATTERN = (
    r"(?:aws_secret_access_key|api[_-]?key|secret[_-]?key|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|password|passwd|pwd|client[_-]?secret|"
    r"x[_-]?api[_-]?key)"
)
_ASSIGNED_SECRET_RE = re.compile(
    rf"""(?:(?P<quote>["']?)(?P<key>{_SECRET_KEYWORD_PATTERN})(?P=quote))\s*[:=]\s*"""
    r"""(?:"(?P<quoted_val>[^"\r\n\t]{4,})"|'(?P<single_val>[^'\r\n\t]{4,})'|(?P<raw_val>[A-Za-z0-9_\-\/+=!@#$%^&*]{4,}))""",
    re.IGNORECASE,
)

_BOOLEAN_OR_NULL_VALUES = frozenset({"true", "false", "null", "none", "undefined"})


def _extract_assigned_secrets(text: str) -> list[tuple[int, int]]:
    """Extract span boundaries for assigned secrets, excluding booleans and keywords."""
    spans: list[tuple[int, int]] = []
    for match in _ASSIGNED_SECRET_RE.finditer(text):
        quoted = match.group("quoted_val")
        single = match.group("single_val")
        raw = match.group("raw_val")

        value = quoted or single or raw
        if not value or value.strip().lower() in _BOOLEAN_OR_NULL_VALUES:
            continue

        # Target the sensitive value span rather than the key label
        if quoted is not None:
            start = match.start("quoted_val")
            end = match.end("quoted_val")
        elif single is not None:
            start = match.start("single_val")
            end = match.end("single_val")
        else:
            start = match.start("raw_val")
            end = match.end("raw_val")

        spans.append((start, end))
    return spans


def _extract_auth_tokens(text: str) -> list[tuple[int, int]]:
    """Extract token spans from Authorization headers (Bearer, Basic, Token)."""
    spans: list[tuple[int, int]] = []
    for match in _AUTH_HEADER_RE.finditer(text):
        start = match.start(1) if match.group(1) is not None else match.start(2)
        end = match.end(1) if match.group(1) is not None else match.end(2)
        while end > start and text[end - 1] in ".,;:!?\"'":
            end -= 1
        if end > start:
            spans.append((start, end))
    return spans


def _merge_overlapping_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping or contiguous character intervals."""
    if not spans:
        return []

    sorted_spans = sorted(spans, key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int]] = [sorted_spans[0]]

    for current_start, current_end in sorted_spans[1:]:
        last_start, last_end = merged[-1]
        if current_start <= last_end:
            # Overlapping or adjacent interval: expand the previous span
            merged[-1] = (last_start, max(last_end, current_end))
        else:
            merged.append((current_start, current_end))

    return merged


def detect_secrets(text: str) -> list[DetectedEntity]:
    """Scan text and return all detected credentials as EntityType.SECRET.

    This is a pure, deterministic function. Every match has confidence 1.0
    and spans are deduplicated and merged before returning.

    Args:
        text: The raw input string to inspect.

    Returns:
        A list of DetectedEntity objects with entity_type=EntityType.SECRET,
        ordered by character position.
    """
    if not text:
        return []

    candidate_spans: list[tuple[int, int]] = []

    # 1. AWS Access Keys
    for match in _AWS_ACCESS_KEY_RE.finditer(text):
        candidate_spans.append(match.span())

    # 2. GitHub Tokens
    for match in _GITHUB_TOKEN_RE.finditer(text):
        candidate_spans.append(match.span())

    # 3. JWTs
    for match in _JWT_RE.finditer(text):
        candidate_spans.append(match.span())

    # 4. Private Keys
    for match in _PRIVATE_KEY_RE.finditer(text):
        candidate_spans.append(match.span())

    # 5. Database URIs with credentials
    for match in _DATABASE_URI_RE.finditer(text):
        candidate_spans.append(match.span())

    # 6. Authorization Headers (Bearer, Basic, Token)
    candidate_spans.extend(_extract_auth_tokens(text))

    # 7. Explicit secret variable assignments
    candidate_spans.extend(_extract_assigned_secrets(text))

    # Merge overlaps so each character span is transformed cleanly once
    merged_spans = _merge_overlapping_spans(candidate_spans)

    return [
        DetectedEntity(
            entity_type=EntityType.SECRET,
            start=start,
            end=end,
            confidence=1.0,
            source=_DETECTOR_SOURCE,
            value=text[start:end],
        )
        for start, end in merged_spans
    ]
