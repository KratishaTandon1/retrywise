from __future__ import annotations

import unittest
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock, patch

from retrywise.services.control_plane import api as api_module
from retrywise.services.control_plane.embedded_worker import EmbeddedWorkerLifecycle
from retrywise.services.control_plane.settings import DeploymentProfile
from retrywise.services.control_plane.worker_runtime import WorkerRuntime

try:
    from fastapi.testclient import TestClient
except ImportError:  # pragma: no cover - the api extra owns this integration check.
    TestClient = None  # type: ignore[assignment,misc]


class EmbeddedWorkerLifecycleTests(unittest.TestCase):
    def test_starts_once_and_stops_the_composed_runtime(self) -> None:
        runtime = Mock(spec=WorkerRuntime)
        entered = Event()

        def run(*, stop: Event) -> None:
            entered.set()
            stop.wait(1)

        runtime.run.side_effect = run
        lifecycle = EmbeddedWorkerLifecycle(runtime=runtime, join_timeout_seconds=1)

        lifecycle.start()
        self.assertTrue(entered.wait(1))
        self.assertTrue(lifecycle.running)
        lifecycle.stop()

        runtime.run.assert_called_once()
        self.assertFalse(lifecycle.running)
        with self.assertRaisesRegex(RuntimeError, "started twice"):
            lifecycle.start()

    def test_stop_before_start_is_safe_and_constructor_is_strict(self) -> None:
        runtime = Mock(spec=WorkerRuntime)
        lifecycle = EmbeddedWorkerLifecycle(runtime=runtime)
        lifecycle.stop()
        runtime.run.assert_not_called()

        with self.assertRaises(TypeError):
            EmbeddedWorkerLifecycle(runtime=object())  # type: ignore[arg-type]
        for timeout in (0, 31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                EmbeddedWorkerLifecycle(runtime=runtime, join_timeout_seconds=timeout)


@unittest.skipIf(TestClient is None, "FastAPI api extra is not installed")
class EmbeddedWorkerApiLifespanTests(unittest.TestCase):
    def test_factory_composes_worker_once_and_binds_it_to_app_lifespan(self) -> None:
        settings = SimpleNamespace(
            embedded_worker_enabled=True,
            environment=DeploymentProfile.DEVELOPMENT,
            cors_allowed_origins=("http://127.0.0.1:3000",),
        )
        control_plane = SimpleNamespace(settings=settings)
        worker_runtime = Mock(spec=WorkerRuntime)
        lifecycle = Mock()

        with (
            patch.object(
                api_module.ControlPlaneRuntime,
                "from_mapping",
                return_value=control_plane,
            ),
            patch.object(api_module, "WorkerRuntime", return_value=worker_runtime) as compose,
            patch.object(
                api_module,
                "EmbeddedWorkerLifecycle",
                return_value=lifecycle,
            ) as lifecycle_type,
        ):
            app = api_module.create_app()
            with TestClient(app):
                lifecycle.start.assert_called_once_with()
                lifecycle.stop.assert_not_called()

        compose.assert_called_once()
        lifecycle_type.assert_called_once_with(runtime=worker_runtime)
        lifecycle.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
