import pytest


@pytest.fixture(autouse=True)
def _permissive_defaults(monkeypatch):
    """Most tests exercise one sensor over an open API; hardening tests override this."""
    monkeypatch.setenv("OVERLORD_MIN_INDEPENDENT_SOURCES", "1")
    monkeypatch.setenv("OVERLORD_ALLOW_UNAUTHENTICATED", "1")
