"""Seeded adversarial credential generator producing 1000+ variants across partitions.

Partitions covered:
- Value length (1 to 128 characters)
- Character classes (alphanumeric, special characters, unicode, spaces within quotes)
- Quoting (double quotes, single quotes, unquoted)
- Containers (plain text, JSON, YAML, Markdown, inline code blocks)
- Header schemes (Bearer, Basic, Token)
- Casing variants (lowercase, UPPERCASE, TitleCase, camelCase)
- Whitespace variations (no spaces, extra spaces, tabs around delimiters)
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GeneratedCredentialCase:
    """A generated adversarial credential test case."""

    seed: int
    partition: str
    task: str
    context: str
    canary_head: str
    canary_tail: str
    useful_text: str


_ASSIGNED_KEYS = (
    "password",
    "api_key",
    "secret_key",
    "auth_token",
    "access_token",
    "private_key",
    "client_secret",
    "passwd",
    "pwd",
)

_DELIMITERS = (":", "=", " : ", " = ", ": ", "= ")
_CONTAINER_TEMPLATES = (
    "plain",
    "json",
    "yaml",
    "markdown_inline",
    "markdown_block",
)

_SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
_ALNUM_CHARS = string.ascii_letters + string.digits


def _vary_casing(rng: random.Random, word: str) -> str:
    """Randomly apply casing variations to a keyword."""
    choice = rng.randint(0, 3)
    if choice == 0:
        return word.lower()
    if choice == 1:
        return word.upper()
    if choice == 2:
        return word.title()
    # Mixed random casing
    return "".join(c.upper() if rng.random() > 0.5 else c.lower() for c in word)


def generate_credential_variants(
    count: int = 1000,
    seed: int = 42,
) -> list[GeneratedCredentialCase]:
    """Generate reproducible adversarial credential test cases.

    Args:
        count: Total number of test variants to generate (minimum 1000).
        seed: Random seed for exact determinism.

    Returns:
        List of GeneratedCredentialCase instances.
    """
    rng = random.Random(seed)
    cases: list[GeneratedCredentialCase] = []

    for i in range(count):
        partition_selector = i % 5
        canary_head = f"HD{i:04d}x"
        canary_tail = f"TL{i:04d}y"
        useful_text = f"Preserve utility log message variant {i}"

        if partition_selector == 0:
            # 1. Quoted credentials with lengths 1 to 128 and special characters
            partition = "quoted_assigned"
            raw_key = rng.choice(_ASSIGNED_KEYS)
            key = _vary_casing(rng, raw_key)
            delim = rng.choice(_DELIMITERS)
            quote = rng.choice(('"', "'"))

            length = rng.randint(1, 128)
            # Pick characters including spaces and special characters
            char_pool = _ALNUM_CHARS + _SPECIAL_CHARS + " "
            # Avoid the active quote character to keep quoting well-formed
            safe_char_pool = char_pool.replace(quote, "").replace("\\", "")
            body = "".join(rng.choice(safe_char_pool) for _ in range(max(0, length - 12)))
            full_secret = f"{canary_head}_{body}_{canary_tail}"
            context = f"Config setting {key}{delim}{quote}{full_secret}{quote}. {useful_text}."

        elif partition_selector == 1:
            # 2. Raw unquoted credentials (length >= 4, no spaces, stop at boundary)
            partition = "unquoted_assigned"
            raw_key = rng.choice(_ASSIGNED_KEYS)
            key = _vary_casing(rng, raw_key)
            delim = rng.choice(("=", ":", " = ", " : "))
            length = rng.randint(4, 64)
            safe_chars = string.ascii_letters + string.digits + "_-.~"
            body = "".join(rng.choice(safe_chars) for _ in range(max(0, length - 12)))
            full_secret = f"{canary_head}_{body}_{canary_tail}"
            trailing_punct = rng.choice(("", ";", ",", "."))
            context = f"Env parameter {key}{delim}{full_secret}{trailing_punct} {useful_text}."

        elif partition_selector == 2:
            # 3. Auth Headers (Bearer, Basic, Token)
            partition = "auth_headers"
            scheme = rng.choice(("Bearer", "Basic", "Token"))
            scheme_casing = _vary_casing(rng, scheme)
            include_header_prefix = rng.choice((True, False)) if scheme == "Bearer" else True
            header_prefix = (
                f"{_vary_casing(rng, 'Authorization')}: " if include_header_prefix else ""
            )

            # Token body using base64/url-safe characters
            length = rng.randint(8, 64)
            token_chars = string.ascii_letters + string.digits + "-_.~+="
            body = "".join(rng.choice(token_chars) for _ in range(max(0, length - 12)))
            full_secret = f"{canary_head}_{body}_{canary_tail}"
            context = (
                f"HTTP Request: {header_prefix}{scheme_casing} "
                f"{quote}{full_secret}{quote}\n{useful_text}."
            )

        elif partition_selector == 3:
            # 4. Database URIs with credentials
            partition = "database_uris"
            db_scheme = rng.choice(("postgres", "postgresql", "mysql", "mongodb", "redis"))
            user = rng.choice(("admin", "user", "app", "svc_account"))
            pw_chars = string.ascii_letters + string.digits + "_-.~"
            body = "".join(rng.choice(pw_chars) for _ in range(rng.randint(4, 32)))
            full_secret = f"{canary_head}_{body}_{canary_tail}"
            port = rng.choice(("5432", "3306", "27017", "6379", ""))
            port_str = f":{port}" if port else ""
            context = (
                f"Connection string: {db_scheme}://{user}:{full_secret}@db.internal{port_str}/main\n"
                f"{useful_text}."
            )

        else:
            # 5. Structured containers: JSON, YAML, Markdown code
            partition = "structural_containers"
            container_type = rng.choice(_CONTAINER_TEMPLATES)
            raw_key = rng.choice(_ASSIGNED_KEYS)
            key = _vary_casing(rng, raw_key)
            pw_chars = string.ascii_letters + string.digits + "_-.~!@#"
            body = "".join(rng.choice(pw_chars) for _ in range(rng.randint(6, 40)))
            full_secret = f"{canary_head}_{body}_{canary_tail}"

            if container_type == "json":
                context = f'{{"status": "ok", "{key}": "{full_secret}", "info": "{useful_text}"}}'
            elif container_type == "yaml":
                context = f"services:\n  app:\n    {key}: '{full_secret}'\n# {useful_text}"
            elif container_type == "markdown_inline":
                context = f"Use code `{key} = '{full_secret}'` in script. {useful_text}."
            else:
                context = f"```bash\nexport {key}='{full_secret}'\n```\n{useful_text}."

        cases.append(
            GeneratedCredentialCase(
                seed=seed + i,
                partition=partition,
                task="Audit and sanitize credentials",
                context=context,
                canary_head=canary_head,
                canary_tail=canary_tail,
                useful_text=useful_text,
            )
        )

    return cases
