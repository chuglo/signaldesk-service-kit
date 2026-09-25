"""Bounded network client settings."""

from __future__ import annotations

import httpx


def bounded_timeout(
    *, connect: float, read: float, write: float, pool: float, maximum: float = 60.0
) -> httpx.Timeout:
    """Create an httpx timeout with every phase positive and bounded."""

    values = (connect, read, write, pool, maximum)
    if not all(value > 0 for value in values) or any(value > maximum for value in values[:4]):
        raise ValueError("timeout values must be positive and no greater than maximum")
    return httpx.Timeout(connect=connect, read=read, write=write, pool=pool)
