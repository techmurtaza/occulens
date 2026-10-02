"""Unit tests for deterministic secret detection.

All credentials tested are purely synthetic mock fixtures per AGENTS.md rules.
"""

from occulens.detectors import detect_secrets
from occulens.domain import EntityType


def test_detect_aws_access_key() -> None:
    """Detects standard AWS Access Key IDs (AKIA, ASIA, etc.)."""
    text = "Deploying with AWS key AKIAIOSFODNN7EXAMPLE in production."
    entities = detect_secrets(text)
    assert len(entities) == 1
    entity = entities[0]
    assert entity.entity_type == EntityType.SECRET
    assert entity.value == "AKIAIOSFODNN7EXAMPLE"
    assert entity.start == 23
    assert entity.end == 43
    assert text[entity.start : entity.end] == entity.value
    assert entity.confidence == 1.0
    assert entity.source == "secret_detector"


def test_detect_aws_secret_key_assignment() -> None:
    """Detects AWS secret access keys when assigned to known key names."""
    # Synthetic 40-character base64 mock
    mock_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    text = f'aws_secret_access_key = "{mock_secret}"'
    entities = detect_secrets(text)
    assert len(entities) == 1
    assert entities[0].value == mock_secret


def test_detect_github_tokens() -> None:
    """Detects GitHub classic and fine-grained personal access tokens."""
    classic_pat = "ghp_MockToken1234567890abcdefghijklmn"
    fine_grained = (
        "github_pat_11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    text = f"Using {classic_pat} and fine-grained {fine_grained} for cloning."

    entities = detect_secrets(text)
    assert len(entities) == 2
    assert entities[0].value == classic_pat
    assert entities[1].value == fine_grained


def test_detect_jwt() -> None:
    """Detects standard 3-part JSON Web Tokens starting with eyJ."""
    mock_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"Authorization token is {mock_jwt}"
    entities = detect_secrets(text)
    assert len(entities) == 1
    assert entities[0].value == mock_jwt
    assert text[entities[0].start : entities[0].end] == mock_jwt


def test_detect_private_key() -> None:
    """Detects multi-line RSA and generic private key blocks."""
    mock_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+MockKeyDataForTestingOnlyNotARealPrivateKey==\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"Server configuration:\n{mock_key}\nEnd of config."
    entities = detect_secrets(text)
    assert len(entities) == 1
    assert entities[0].value == mock_key


def test_detect_database_connection_uris() -> None:
    """Detects database and network service URIs containing embedded passwords and credentials."""
    pg_uri = "postgresql://app_user:mockSecretPass123@db.internal.net:5432/production"
    mongo_uri = "mongodb+srv://admin:clusterMockPass99@cluster0.example.com/analytics"
    http_uri = "https://admin:UltraPass999!@internal-api.cluster.local:8443/status"
    text = f"Connect to:\n{pg_uri}\nor fallback:\n{mongo_uri}\nor status:\n{http_uri}"

    entities = detect_secrets(text)
    assert len(entities) == 3
    assert entities[0].value == pg_uri
    assert entities[1].value == mongo_uri
    assert entities[2].value == http_uri


def test_detect_bearer_token() -> None:
    """Detects token values provided in Bearer headers."""
    mock_token = "mock_bearer_token_string_alpha_12345"
    text = f"Authorization: Bearer {mock_token}"
    entities = detect_secrets(text)
    assert len(entities) == 1
    assert entities[0].value == mock_token


def test_detect_password_assignments() -> None:
    """Detects password and passwd variable assignments."""
    text = "password = \"mockSuperSecretPassword123\" and passwd: 'anotherMockPass987'"
    entities = detect_secrets(text)
    assert len(entities) == 2
    assert entities[0].value == "mockSuperSecretPassword123"
    assert entities[1].value == "anotherMockPass987"


def test_detect_api_key_assignments() -> None:
    """Detects api_key and x-api-key assignments."""
    text = 'api_key: "mock_api_key_value_abcdef" and x-api-key = "mock_secret_token_12345"'
    entities = detect_secrets(text)
    assert len(entities) == 2
    assert entities[0].value == "mock_api_key_value_abcdef"
    assert entities[1].value == "mock_secret_token_12345"


def test_empty_and_whitespace_input() -> None:
    """Returns an empty list for empty or whitespace-only inputs without error."""
    assert detect_secrets("") == []
    assert detect_secrets("   \n\t  ") == []


def test_false_positive_suppression_git_commit_sha() -> None:
    """Git commit SHAs without secret keywords must NOT be flagged as secrets."""
    text = (
        "Commit hash dc6e60e4420c2794c489cf3d2da5a452ef72f1b8 was merged into develop. "
        "Short rev 002f9cf passed review."
    )
    entities = detect_secrets(text)
    assert len(entities) == 0


def test_false_positive_suppression_standard_urls() -> None:
    """Standard HTTP/HTTPS URLs without credentials must NOT be flagged."""
    text = "Visit https://api.github.com/users/octocat or http://localhost:8080/health"
    entities = detect_secrets(text)
    assert len(entities) == 0


def test_false_positive_suppression_conversational_words() -> None:
    """Conversational occurrences of 'password' or 'token' must NOT be flagged."""
    text = (
        "Please enter your password on the login screen. "
        "A verification token will be sent to your registered email address."
    )
    entities = detect_secrets(text)
    assert len(entities) == 0


def test_false_positive_suppression_boolean_flags() -> None:
    """Boolean and null config values assigned to secret keys must NOT be flagged."""
    text = "has_password = true\nis_secret: false\napi_key = null\ntoken = None"
    entities = detect_secrets(text)
    assert len(entities) == 0


def test_multiple_mixed_secrets_with_overlapping_spans() -> None:
    """Multiple secrets in complex text are detected, sorted, and merged without overlap."""
    text = (
        "Deploy config:\n"
        "AWS_KEY: AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE: postgresql://admin:p@ssword99@postgres.internal:5432/main\n"
        "AUTH: Bearer mock_session_token_xyz123\n"
        "GitHub: ghp_MockToken1234567890abcdefghijklmn"
    )

    entities = detect_secrets(text)
    assert len(entities) == 4

    # Verify order is strictly ascending by start offset
    for i in range(len(entities) - 1):
        assert entities[i].start < entities[i + 1].start
        assert entities[i].end <= entities[i + 1].start

    # Verify all substrings match exact text slicing
    for entity in entities:
        assert text[entity.start : entity.end] == entity.value
