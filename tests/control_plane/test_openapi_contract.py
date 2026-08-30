import os
from pathlib import Path
from unittest import TestCase

try:
    import yaml
except ImportError:  # pragma: no cover - dependency-free CI deliberately skips this module.
    yaml = None  # type: ignore[assignment]

from retrywise.services.control_plane.api import create_app

HTTP_METHODS = {"delete", "get", "patch", "post", "put"}


class OpenApiContractTests(TestCase):
    def test_every_implemented_operation_matches_a_runtime_route(self) -> None:
        if yaml is None:
            if os.environ.get("RETRYWISE_REQUIRE_API_TESTS") == "1":
                self.fail("PyYAML is required for the API contract suite")
            self.skipTest("PyYAML is not installed")
        app = create_app()
        runtime_operations = {
            (route.path, method.lower())
            for route in app.routes
            if route.path.startswith(("/api/", "/health/"))
            for method in getattr(route, "methods", set())
            if method.lower() in HTTP_METHODS
        }

        contract_path = Path(__file__).parents[2] / "contracts" / "openapi.yaml"
        contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        implemented_operations = {
            (path, method)
            for path, path_item in contract["paths"].items()
            for method, operation in path_item.items()
            if method in HTTP_METHODS
            and operation.get("x-retrywise-implementation-status") == "implemented"
        }

        self.assertEqual(runtime_operations, implemented_operations)
