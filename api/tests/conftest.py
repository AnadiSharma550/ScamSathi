import pytest

from app import ratelimit


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    """Each test starts with an empty limiter.

    Limits stay enabled so the suite exercises the real configuration --
    resetting between tests keeps one test's traffic from failing the next.
    """
    ratelimit.reset_all()
    yield
    ratelimit.reset_all()
