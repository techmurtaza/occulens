"""Smoke test to verify environment and package imports."""

import occulens


def test_package_import_and_version() -> None:
    """Verify package imports correctly and exposes expected version string."""
    assert occulens.__version__ == "0.1.0"
