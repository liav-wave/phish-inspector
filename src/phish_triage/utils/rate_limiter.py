"""Simple in-memory token-bucket rate limiter for external API calls."""

import asyncio
import time


class RateLimiter:
    """Token-bucket rate limiter.

    Args:
        max_tokens: Maximum burst size.
        refill_rate: Tokens added per second.
        name: Human-readable name for error messages.
    """

    def __init__(self, max_tokens: int, refill_rate: float, name: str = "API"):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.name = name
        self._tokens = float(max_tokens)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.max_tokens, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now

    async def acquire(self) -> bool:
        """Try to consume one token. Returns True if allowed, False if rate limited."""
        async with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def wait_time(self) -> float:
        """Estimated seconds until a token is available."""
        if self._tokens >= 1.0:
            return 0.0
        return (1.0 - self._tokens) / self.refill_rate


# Pre-configured limiters for each external API
urlscan_limiter = RateLimiter(max_tokens=5, refill_rate=5 / 60, name="URLScan.io")
virustotal_limiter = RateLimiter(max_tokens=4, refill_rate=4 / 60, name="VirusTotal")
safe_browsing_limiter = RateLimiter(max_tokens=10, refill_rate=10 / 60, name="Google Safe Browsing")
abuseipdb_limiter = RateLimiter(max_tokens=10, refill_rate=10 / 60, name="AbuseIPDB")
