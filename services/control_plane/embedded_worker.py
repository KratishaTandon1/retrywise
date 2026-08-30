"""Lifecycle boundary for running the durable worker beside one web process."""

from __future__ import annotations

import logging
from threading import Event, Lock, Thread

from .worker_runtime import WorkerRuntime

_LOGGER = logging.getLogger("retrywise.embedded_worker")


class EmbeddedWorkerLifecycle:
    """Start one composed worker and stop it gracefully with the web process."""

    def __init__(
        self,
        *,
        runtime: WorkerRuntime,
        join_timeout_seconds: float = 20.0,
    ) -> None:
        if not isinstance(runtime, WorkerRuntime):
            raise TypeError("runtime must be WorkerRuntime")
        if not 0 < join_timeout_seconds <= 30:
            raise ValueError("join_timeout_seconds must be between 0 and 30")
        self._runtime = runtime
        self._join_timeout_seconds = float(join_timeout_seconds)
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("embedded worker lifecycle cannot be started twice")
            self._stop.clear()
            thread = Thread(
                target=self._run,
                name="retrywise-outbox-worker",
                daemon=True,
            )
            self._thread = thread
            thread.start()

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
            if thread is None:
                return
            self._stop.set()
        thread.join(timeout=self._join_timeout_seconds)
        if thread.is_alive():
            _LOGGER.error("embedded worker did not stop before the shutdown deadline")

    def _run(self) -> None:
        try:
            self._runtime.run(stop=self._stop)
        except Exception:
            _LOGGER.exception("embedded worker exited unexpectedly")


__all__ = ["EmbeddedWorkerLifecycle"]
