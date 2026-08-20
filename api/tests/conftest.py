import pytest

from app import ratelimit
from tests import keys


@pytest.fixture(autouse=True)
def _test_signing_key(monkeypatch):
    """Verify against a local keypair instead of reaching Supabase.

    Tests must never depend on network access to a third-party service.
    """
    keys.install(monkeypatch)


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """Each test starts with an empty limiter.

    Limits stay enabled so the suite exercises the real configuration --
    resetting between tests keeps one test's traffic from failing the next.
    """
    ratelimit.reset_all()
    yield
    ratelimit.reset_all()
