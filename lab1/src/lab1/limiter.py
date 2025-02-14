from contextlib import contextmanager
from functools import wraps
from threading import Lock
from typing import Callable, Generator, ParamSpec, Protocol, TypeVar, cast

# Type variables for the function
R_co = TypeVar("R_co", covariant=True)  # Return type
P = ParamSpec("P")  # Parameters specification


class LimitedFunction(Protocol[P, R_co]):
    """Protocol defining the interface of a function wrapped by CallLimiter."""

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R_co: ...
    def reset_count(self) -> None: ...
    def get_remaining_calls(self) -> int: ...
    def disable_limit(self) -> Generator[None, None, None]: ...

    limiter: "CallLimiter"


class CallLimiter:
    """
    A decorator class that limits the number of times a function can be called.
    The limit can be temporarily disabled using the provided context manager.

    Usage:
        @CallLimiter(max_calls=3)
        def my_function():
            pass

        with my_function.disable_limit():
            my_function()  # This call won't count towards the limit
    """

    def __init__(self, max_calls: int) -> None:
        self.max_calls = max_calls
        self.calls = 0
        self.lock = Lock()
        self.limit_enabled = True

    def __call__(self, func: Callable[P, R_co]) -> LimitedFunction[P, R_co]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R_co:
            with self.lock:
                if self.limit_enabled:
                    if self.calls >= self.max_calls:
                        raise RuntimeError(
                            f"Function '{func.__name__}' has exceeded its call limit of {self.max_calls}"
                        )
                    self.calls += 1
            return func(*args, **kwargs)

        # Add reference to the CallLimiter instance
        wrapper.limiter = self  # type: ignore

        # Add convenience methods to the wrapped function
        wrapper.disable_limit = self.disable_limit  # type: ignore
        wrapper.reset_count = self.reset_count  # type: ignore
        wrapper.get_remaining_calls = self.get_remaining_calls  # type: ignore

        return cast(LimitedFunction[P, R_co], wrapper)

    @contextmanager
    def disable_limit(self):
        """Temporarily disable the call limit."""
        self.limit_enabled = False
        try:
            yield
        finally:
            self.limit_enabled = True

    def reset_count(self) -> None:
        """Reset the call counter back to zero."""
        with self.lock:
            self.calls = 0

    def get_remaining_calls(self) -> int:
        """Get the number of remaining calls allowed."""
        with self.lock:
            return max(0, self.max_calls - self.calls)
