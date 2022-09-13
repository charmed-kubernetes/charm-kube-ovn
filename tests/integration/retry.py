"""async implementation of a retry decorator algorithm with similar api to retry

   Perhaps one day this package will have retry for async methods
   https://github.com/invl/retry
"""

import asyncio
from functools import wraps
import random
import logging
import time


def async_retry(
    exceptions=Exception,
    tries=-1,
    delay=0,
    max_delay=None,
    backoff=1,
    jitter=0,
    logger=logging,
    max_seconds=None
):
    """Return a retry decorator for an async function

    :param exceptions: an exception or a tuple of exceptions to catch. default: Exception.
    :param tries: the maximum number of attempts. default: -1 (infinite).
    :param delay: initial delay between attempts. default: 0.
    :param max_delay: the maximum value of delay. default: None (no limit).
    :param backoff: multiplier applied to delay between attempts. default: 1 (no backoff).
    :param jitter: extra seconds added to delay between attempts. default: 0.
                   fixed if a number, random if a range tuple (min, max)
    :param logger: logger.warning(fmt, error, delay) will be called on failed attempts.
                   default: root logger. if None, logging is disabled.
    :param deadline: maxiumum time spent retrying
    """

    def decorator(f):
        @wraps(f)
        async def wrapped(*fargs, **fkwargs):
            _tries, _delay = tries, delay
            _deadline = None
            if max_seconds is not None:
                _deadline = time.time() + max_seconds
            while _tries:
                try:
                    return await f(*fargs, **fkwargs)
                except exceptions as e:
                    _tries -= 1
                    if not _tries:
                        raise
                    if _deadline and _deadline > time.time():
                        raise

                    if logger is not None:
                        logger.warning("%s, retrying in %s seconds...", e, _delay)

                    await asyncio.sleep(_delay)
                    _delay *= backoff

                    if isinstance(jitter, tuple):
                        _delay += random.uniform(*jitter)
                    else:
                        _delay += jitter

                    if max_delay is not None:
                        _delay = min(_delay, max_delay)

        return wrapped

    return decorator
