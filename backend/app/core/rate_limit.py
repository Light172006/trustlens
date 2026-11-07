"""Rate limiting controls using Redis with in-memory fallback."""

import time
from collections import defaultdict

from app.core.exceptions import RateLimitExceededException
from app.core.logging import logger
from app.database.session import get_redis_client

# In-memory sliding window fallback store: key -> list of timestamps
_memory_rate_limit_store: dict[str, list[float]] = defaultdict(list)


async def enforce_rate_limit(key: str, max_requests: int, window_seconds: int = 60) -> None:
    """Enforce request rate limiting for a specific identifier.

    Raises:
        RateLimitExceededException: If the threshold is exceeded.
    """
    now = time.time()
    try:
        redis_client = get_redis_client()
        redis_key = f"rate_limit:{key}"
        # Pipeline: remove older timestamps, add current, count remaining, set TTL
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
        pipe.zadd(redis_key, {str(now): now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, window_seconds)
        results = await pipe.execute()

        request_count = results[2]
        if request_count > max_requests:
            logger.warning(
                f"Rate limit exceeded for key: {key} (count: {request_count}/{max_requests})"
            )
            raise RateLimitExceededException(retry_after_seconds=window_seconds)

    except RateLimitExceededException:
        raise
    except Exception as exc:
        # Fallback to local in-memory sliding window if Redis fails or is unavailable
        logger.debug(f"Redis rate limit check failed, using in-memory fallback: {exc}")
        timestamps = _memory_rate_limit_store[key]
        # Evict timestamps outside the sliding window
        _memory_rate_limit_store[key] = [ts for ts in timestamps if ts > (now - window_seconds)]
        _memory_rate_limit_store[key].append(now)

        if len(_memory_rate_limit_store[key]) > max_requests:
            raise RateLimitExceededException(retry_after_seconds=window_seconds)
