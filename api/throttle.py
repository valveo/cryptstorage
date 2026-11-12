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


class EscalatingLockout:
    """`limit` failures within `window` seconds lock the key, each time for longer (`lockouts`).

    For the second factor: with a fixed 15-minute window, someone who has the password gets about
    500 guesses a day at a 6-digit code, for as long as it takes. Here the third lock in a row lasts a
    day, so the guesses drop to a handful a day, and the owner is told at the first lock
    (record_failure returns the lock's length so the caller can send that notice).

    A success clears the failure count but not the level: the owner signing in must not hand the
    guesser a fresh start. The level falls back once `calm` seconds pass without a new lock.
    """

    def __init__(self, limit: int = 5, window: float = 900, lockouts=(900, 3600, 86400),
                 calm: float = 86400, max_keys: int = 50_000, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self.lockouts = tuple(lockouts)
        self.calm = calm
        self.max_keys = max_keys
        self._clock = clock
        self._state: dict[str, dict] = {}     # key -> {"failures": deque, "level": int, "until": float}
        self._lock = threading.Lock()

    def _get(self, key: str, now: float):
        s = self._state.get(key)
        if s is None:
            return None
        while s["failures"] and now - s["failures"][0] > self.window:
            s["failures"].popleft()
        if s["level"] and now - s["until"] > self.calm:
            s["level"] = 0
        if not s["failures"] and not s["level"] and now >= s["until"]:
            del self._state[key]
            return None
        return s

    def blocked(self, key: str) -> int:
        """Seconds until the key may try again; 0 if it is not locked."""
        now = self._clock()
        with self._lock:
            s = self._get(key, now)
            if s is None or now >= s["until"]:
                return 0
            return max(1, int(s["until"] - now) + 1)

    def record_failure(self, key: str) -> int:
        """Count a failure. Returns the length in seconds of the lock it started, else 0."""
        now = self._clock()
        with self._lock:
            s = self._get(key, now)
            if s is None:
                if len(self._state) >= self.max_keys:
                    # Drop an entry that holds no lock, so an attacker cannot grow memory without bound
                    # nor push a locked account out of the table
                    for old, st in self._state.items():
                        if now >= st["until"] and not st["level"]:
                            del self._state[old]
                            break
                    else:
                        self._state.pop(next(iter(self._state)))
                s = self._state[key] = {"failures": deque(), "level": 0, "until": 0.0}
            s["failures"].append(now)
            if len(s["failures"]) < self.limit:
                return 0
            seconds = self.lockouts[min(s["level"], len(self.lockouts) - 1)]
            s["failures"].clear()
            s["level"] += 1
            s["until"] = now + seconds
            return seconds

    def reset(self, key: str) -> None:
        """After a success: forget the failures, keep the level (see the class comment)."""
        with self._lock:
            s = self._state.get(key)
            if s is not None:
                s["failures"].clear()
