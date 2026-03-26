"""Tests for rate limiter."""

import asyncio

import pytest

from phish_triage.utils.rate_limiter import RateLimiter


async def test_initial_tokens_available():
    limiter = RateLimiter(max_tokens=3, refill_rate=1.0, name="test")
    assert await limiter.acquire() is True
    assert await limiter.acquire() is True
    assert await limiter.acquire() is True


async def test_exhausted_tokens():
    limiter = RateLimiter(max_tokens=1, refill_rate=0.1, name="test")
    assert await limiter.acquire() is True
    assert await limiter.acquire() is False


async def test_wait_time():
    limiter = RateLimiter(max_tokens=1, refill_rate=1.0, name="test")
    await limiter.acquire()  # consume the token
    wait = limiter.wait_time()
    assert wait > 0


async def test_refill():
    limiter = RateLimiter(max_tokens=1, refill_rate=100.0, name="test")
    await limiter.acquire()  # consume
    await asyncio.sleep(0.02)  # wait for refill (100/s = 1 token in 0.01s)
    assert await limiter.acquire() is True
