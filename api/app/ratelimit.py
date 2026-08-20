"""Fixed-window rate limiting.

ponytail: in-process counters, no slowapi and no Redis. The deployment is a
single container, so a shared store buys nothing today, and a fixed-window
counter is a few lines. Ceiling: limits are per-process and reset on
restart, so they do not hold across replicas. Swap in a Redis-backed limiter
the day the API runs more than one instance.

Client identity is `request.client.host`. X-Forwarded-For is deliberately
NOT trusted -- any client can set it, which would turn the limiter into a
one-header bypass. When a reverse proxy is added, configure its trusted
address explicitly here rather than believing the header.
"""

import os
import time
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

ENABLED = os.getenv("RATE_LIMIT_ENABLED", "1") != "0"

# (window seconds, max requests). Both must pass.
SCAN_LIMITS = [(60, 10), (86_400, 100)]
FEEDBACK_LIMITS = [(86_400, 20)]

# Stop the counter dict from growing without bound -- an unbounded store
# would make the limiter its own memory-exhaustion vector.
_MAX_KEYS = 50_000


@dataclass
class FixedWindow:
    limits: list[tuple[int, int]]
    _counts: dict[tuple[str, int, int], int] = field(default_factory=dict)

    def check(self, key: str) -> int | None:
        """Count one request. Returns seconds to wait if over a limit."""
        now = time.time()
        buckets = []
        for window, cap in self.limits:
            index = int(now // window)
            slot = (key, window, index)
            if self._counts.get(slot, 0) >= cap:
                return int((index + 1) * window - now) + 1
            buckets.append(slot)

        # Only count the request once every limit has room; a rejected
        # request must not push the caller further over.
        for slot in buckets:
            self._counts[slot] = self._counts.get(slot, 0) + 1

        if len(self._counts) > _MAX_KEYS:
            self._prune(now)
        return None

    def _prune(self, now: float) -> None:
        live = {
            slot
            for slot in self._counts
            if slot[2] >= int(now // slot[1])
        }
        self._counts = {k: v for k, v in self._counts.items() if k in live}

    def reset(self) -> None:
        self._counts.clear()


scan_limiter = FixedWindow(SCAN_LIMITS)
feedback_limiter = FixedWindow(FEEDBACK_LIMITS)


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _guard(limiter: FixedWindow, request: Request) -> None:
    if not ENABLED:
        return
    retry_after = limiter.check(_client(request))
    if retry_after is not None:
        raise HTTPException(
            429,
            "Too many scans from this address. Please wait and try again.",
            headers={"Retry-After": str(retry_after)},
        )


def limit_scan(request: Request) -> None:
    """FastAPI dependency for the scan endpoints."""
    _guard(scan_limiter, request)


def limit_feedback(request: Request) -> None:
    _guard(feedback_limiter, request)


def reset_all() -> None:
    scan_limiter.reset()
    feedback_limiter.reset()
