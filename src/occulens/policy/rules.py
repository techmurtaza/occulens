"""Privacy policy definitions, default rule sets, and configuration models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from occulens.domain.models import EntityType, PrivacyAction

_DEFAULT_ACTIONS: dict[EntityType, PrivacyAction] = {
    EntityType.SECRET: PrivacyAction.LOCAL_ONLY,
    EntityType.EMAIL: PrivacyAction.DROP,
    EntityType.PHONE: PrivacyAction.DROP,
    EntityType.PERSON: PrivacyAction.TOKENIZE,
    EntityType.PROJECT: PrivacyAction.TOKENIZE,
    EntityType.ORGANIZATION: PrivacyAction.TOKENIZE,
    EntityType.LOCATION: PrivacyAction.ABSTRACT,
    EntityType.URL: PrivacyAction.DROP,
    EntityType.ACCOUNT_ID: PrivacyAction.DROP,
}

_DEFAULT_ABSTRACTIONS: dict[EntityType, str] = {
    EntityType.LOCATION: "a city",
    EntityType.ORGANIZATION: "a company",
    EntityType.PERSON: "an individual",
    EntityType.PROJECT: "a project",
    EntityType.EMAIL: "an email address",
    EntityType.PHONE: "a phone number",
    EntityType.URL: "a web link",
    EntityType.ACCOUNT_ID: "an account identifier",
}

_ALIAS_PREFIXES: dict[EntityType, str] = {
    EntityType.PERSON: "PERSON_",
    EntityType.ORGANIZATION: "ORG_",
    EntityType.PROJECT: "PROJECT_",
    EntityType.LOCATION: "LOCATION_",
    EntityType.URL: "URL_",
    EntityType.EMAIL: "EMAIL_",
    EntityType.PHONE: "PHONE_",
    EntityType.ACCOUNT_ID: "ACCOUNT_",
}


def index_to_letters(index: int) -> str:
    """Convert a zero-based index to spreadsheet-style column letters (A, B, ..., Z, AA, AB...)."""
    result: list[str] = []
    current = index
    while True:
        result.append(chr(ord("A") + (current % 26)))
        current = (current // 26) - 1
        if current < 0:
            break
    return "".join(reversed(result))


@dataclass(frozen=True, slots=True)
class Policy:
    """Configuration overrides for privacy actions and abstractions.

    Attributes:
        actions: Mapping of EntityType to desired PrivacyAction overrides.
        abstractions: Custom generalization phrases per EntityType.

    Raises:
        ValueError: If a caller attempts to weaken a hard security rule (e.g. mapping
            EntityType.SECRET to any action other than PrivacyAction.LOCAL_ONLY).
    """

    actions: Mapping[EntityType, PrivacyAction] = field(default_factory=dict)
    abstractions: Mapping[EntityType, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Enforce hard security invariants and freeze dictionary inputs."""
        if (
            EntityType.SECRET in self.actions
            and self.actions[EntityType.SECRET] != PrivacyAction.LOCAL_ONLY
        ):
            raise ValueError(
                f"Hard security rule violation: SECRET cannot be mapped to "
                f"{self.actions[EntityType.SECRET].value}; must be LOCAL_ONLY."
            )
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))
        object.__setattr__(self, "abstractions", MappingProxyType(dict(self.abstractions)))
