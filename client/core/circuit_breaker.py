"""
Furun VPN - Circuit Breaker

Automatic learning: IPs that fail to connect are temporarily blocked
so subsequent retries fail instantly instead of waiting 15s.
Entries expire after a cooldown period and are persisted to disk.
"""

import json
import time
import sys
from pathlib import Path
from collections import defaultdict

from common.utils import get_logger

log = get_logger("client.circuit_breaker")

# --- Configuration ---

FAIL_THRESHOLD = 3       # number of failures before blocking
COOLDOWN_SECONDS = 120   # how long to block (2 minutes)
MAX_ENTRIES = 500        # max tracked entries


class CircuitBreaker:
    """Tracks connection failures and fast-fails known-bad IPs.

    When a CONNECT to an IP fails, it is recorded. After FAIL_THRESHOLD
    failures, that IP is blocked for COOLDOWN_SECONDS. Subsequent
    SOCKS requests to blocked IPs are immediately rejected.

    State is persisted to logs/circuit_breaker.json for crash survival.
    """

    def __init__(self, state_path: str | Path | None = None):
        # failure_counts: {ip: [timestamp, timestamp, ...]}
        self._failures: dict[str, list[float]] = defaultdict(list)
        # blocked_until: {ip: float (absolute time when unblocked)}
        self._blocked: dict[str, float] = {}
        # Running tally of inconclusive TLS results -- stat only, never blocks.
        self._tls_reject_total = 0

        if state_path is None:
            if getattr(sys, "frozen", False):
                base = Path(sys.executable).parent
            else:
                base = Path(__file__).parent.parent.parent  # project root
            state_path = base / "logs" / "circuit_breaker.json"
        self._path = Path(state_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load()
        self._last_save = 0.0
        self._save_dirty = False

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        now = time.time()
        self._maybe_save(now)
        # Clean expired entries on read
        unblocked = now > self._blocked.get(ip, 0)
        if not unblocked:
            remaining = int(self._blocked[ip] - now)
            log.debug("CB: %s BLOCKED (%ds remaining)", ip, remaining)
        else:
            # Expired -- remove
            self._blocked.pop(ip, None)
        return not unblocked

    def record_failure(self, ip: str):
        """Record a connection failure for an IP."""
        now = time.time()
        self._failures[ip].append(now)

        # Prune old failures outside the tracking window
        window = COOLDOWN_SECONDS * 3
        self._failures[ip] = [t for t in self._failures[ip] if now - t < window]

        count = len(self._failures[ip])
        log.info("CB: %s failure #%d/%d", ip, count, FAIL_THRESHOLD)

        if count >= FAIL_THRESHOLD:
            self._blocked[ip] = now + COOLDOWN_SECONDS
            log.warning("CB: %s BLOCKED for %ds (threshold reached)", ip, COOLDOWN_SECONDS)
            # Clear failures after blocking to avoid re-triggering
            self._failures.pop(ip, None)

        self._prune()
        self._schedule_save()

    def record_success(self, ip: str):
        """Record a successful connection -- resets failure count."""
        self._failures.pop(ip, None)
        self._blocked.pop(ip, None)
        log.debug("CB: %s cleared (successful connection)", ip)

    def record_tls_reject(self, ip: str):
        """Record an inconclusive TLS result for stats only.

        Deliberately does NOT block or feed the failure counter: CDN shared
        IPs cause too many false positives, so a 'reject' here just means the
        success heuristic was inconclusive. Tracked as a separate tally so the
        real connect-failure stats stay clean.
        """
        self._tls_reject_total += 1
        log.info("CB: %s TLS-reject detected (stat only, not blocking)", ip)

    def get_blocked_count(self) -> int:
        now = time.time()
        return sum(1 for until in self._blocked.values() if now <= until)

    def get_failure_count(self) -> int:
        return sum(len(v) for v in self._failures.values())

    def get_tls_reject_count(self) -> int:
        return self._tls_reject_total

    def _prune(self):
        """Remove oldest IPs by count (per-IP, not per-timestamp)."""
        if len(self._failures) > MAX_ENTRIES:
            newest = sorted(
                self._failures.items(),
                key=lambda kv: max(kv[1]) if kv[1] else 0,
                reverse=True,
            )[:MAX_ENTRIES]
            self._failures = dict(newest)

    def _schedule_save(self):
        """Mark state dirty; save happens on next prune/is_blocked call."""
        self._save_dirty = True
        now = time.time()
        if now - self._last_save > 2.0:
            self._maybe_save(now)

    def _maybe_save(self, now: float = None):
        if now is None:
            now = time.time()
        if self._save_dirty and now - self._last_save > 2.0:
            self.save()
            self._last_save = now
            self._save_dirty = False

    def _load(self):
        """Load persisted state from disk."""
        try:
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8-sig") as f:
                    data = json.load(f)
                now = time.time()
                # Load blocked IPs, expire stale ones
                for ip, until in data.get("blocked", {}).items():
                    if now < until:
                        self._blocked[ip] = until
                # Load recent failures
                for ip, times in data.get("failures", {}).items():
                    recent = [t for t in times if now - t < COOLDOWN_SECONDS * 3]
                    if recent:
                        self._failures[ip] = recent
                if self._blocked or self._failures:
                    log.info("CB: loaded %d blocked + %d tracked failures from disk",
                             len(self._blocked),
                             sum(len(v) for v in self._failures.values()))
        except (json.JSONDecodeError, OSError, KeyError) as e:
            log.debug("CB: no valid state file: %s", e)

    def save(self):
        """Persist current state to disk."""
        try:
            data = {
                "blocked": dict(self._blocked),
                "failures": {ip: times[-20:] for ip, times in self._failures.items() if times},
            }
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            log.debug("CB: saved %d blocked + %d failures to %s",
                      len(self._blocked),
                      sum(len(v) for v in self._failures.values()),
                      self._path.name)
        except OSError as e:
            log.warning("CB: failed to save state: %s", e)


