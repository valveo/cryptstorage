"""
throttle.py - Sliding-window failure counter for brute-force protection.

In-memory, like the rest of the API's session state (the API runs as a single
process). Counters are lost on restart; that is acceptable for throttling.
"""

import threading
import time
from collections import deque


class FailureTracker:
    """Allows `limit` failures per `window` seconds per key."""

    def __init__(self, limit: int, window: float, max_keys: int = 50_000, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._clock = clock
        self._failures: dict[str, deque] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque:
        q = self._failures.get(key)
        if q is None:
            return deque()
        while q and now - q[0] > self.window:
            q.popleft()
        if not q:
            self._failures.pop(key, None)
        return q

    def blocked(self, key: str) -> int:
        """Seconds until the key may try again; 0 if it is not blocked."""
        now = self._clock()
        with self._lock:
            q = self._prune(key, now)
            if len(q) < self.limit:
                return 0
            return max(1, int(q[0] + self.window - now) + 1)

    def record_failure(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            if key not in self._failures and len(self._failures) >= self.max_keys:
                # Drop the oldest key so an attacker cannot grow memory without bound
                self._failures.pop(next(iter(self._failures)))
            q = self._failures.setdefault(key, deque())
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
