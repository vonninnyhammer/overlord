import pytest


@pytest.fixture(autouse=True)
def _permissive_defaults(monkeypatch):
    """Most tests exercise one sensor over an open API; hardening tests override this."""
    monkeypatch.setenv("OVERLORD_MIN_INDEPENDENT_SOURCES", "1")
    monkeypatch.setenv("OVERLORD_ALLOW_UNAUTHENTICATED", "1")


@pytest.fixture(autouse=True)
def _isolated_runtime(monkeypatch):
    """Give each test its own in-memory throttle and breaker, so API tests never write to
    the real state folder or trip the breaker for each other."""
    from overlord import api
    from overlord.runtime import RuntimeState

    monkeypatch.setattr(api, "_RUNTIME", RuntimeState())
