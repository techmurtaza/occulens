"""Shared pytest fixtures for Occulens test suites."""

import pytest


@pytest.fixture
def package_version() -> str:
    """Return current package version for sanity checks."""
    import occulens

    return occulens.__version__
