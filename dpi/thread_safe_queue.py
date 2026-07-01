"""Thread-safe bounded queue for multi-threaded DPI."""

from __future__ import annotations

import queue
import threading
from typing import Generic, TypeVar

T = TypeVar("T")


class TSQueue(Generic[T]):
    def __init__(self, max_size: int = 10000) -> None:
        self._queue: queue.Queue[T | None] = queue.Queue(maxsize=max_size)
        self._shutdown = False
        self._lock = threading.Lock()

    def push(self, item: T) -> None:
        with self._lock:
            if self._shutdown:
                return
        self._queue.put(item)

    def pop(self, timeout: float = 0.1) -> T | None:
        with self._lock:
            if self._shutdown and self._queue.empty():
                return None
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True

    def size(self) -> int:
        return self._queue.qsize()

    def is_shutdown(self) -> bool:
        with self._lock:
            return self._shutdown
