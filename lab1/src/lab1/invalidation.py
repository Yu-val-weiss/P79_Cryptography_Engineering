"""Define a mixin to ensure only one use of the class"""

from collections import defaultdict
from contextlib import contextmanager
from functools import wraps
from threading import local
from typing import Callable


class FunctionOveruseError(Exception):
    """Invalid function error"""

    def __init__(self, func_name: str, max_use: int) -> None:
        """Initialise"""
        msg = f"{func_name}, has already been called {max_use} times!"
        super().__init__(msg)


class CallLimiter:
    """Mixing class to allow for a function to only be called once"""

    _tl = local()

    def __init__(self, max_calls: int) -> None:
        """Initialise function usage limiter"""
        self.max_calls = max_calls
        # Initialize counters dict in thread local storage if it doesn't exist
        if not hasattr(self._tl, "counters"):
            self._tl.counters = defaultdict(int)
        if not hasattr(self._tl, "disabled_funcs"):
            self._tl.disabled_funcs = set()

    def wrap(self, func: Callable):
        """Invalidates the wrapped function after `self.max_uses`"""

        @wraps(func)
        def wrapper(*args, **kwargs):
            if func.__name__ in self._tl.disabled_funcs:
                return func(*args, **kwargs)

            self._tl.counters[func.__name__] += 1
            if self._tl.counters[func.__name__] > self.max_calls:
                raise FunctionOveruseError(func.__name__, self.max_calls)
            return func(*args, **kwargs)

        return wrapper

    @classmethod
    @contextmanager
    def disable_call_limit(cls, func: Callable):
        """Context manager to temporarily disable all usage limits."""
        name = func.__name__ if hasattr(func, "__name__") else func
        if not hasattr(cls._tl, "disabled_funcs"):
            cls._tl.disabled_funcs = set()

        cls._tl.disabled_funcs.add(name)
        try:
            yield
        finally:
            cls._tl.disabled_funcs.remove(name)
