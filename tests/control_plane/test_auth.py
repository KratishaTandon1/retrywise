from __future__ import annotations

import unittest

from retrywise.services.control_plane.auth import (
    DenyAllAuthorizer,
    StaticBearerAuthorizer,
)


class OperatorAuthorizerTests(unittest.TestCase):
    def test_deny_all_is_default_safe_behavior(self) -> None:
        self.assertIsNone(DenyAllAuthorizer().authorize("Bearer anything"))

    def test_static_bearer_requires_exact_token(self) -> None:
        token = b"a-local-token-with-at-least-32-bytes!!"
        authorizer = StaticBearerAuthorizer(
            token=token, subject="operator-1", merchant_id="merchant-1"
        )
        self.assertIsNone(authorizer.authorize(None))
        self.assertIsNone(authorizer.authorize("Basic abc"))
        self.assertIsNone(authorizer.authorize("Bearer wrong"))
        context = authorizer.authorize(f"Bearer {token.decode('utf-8')}")
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.merchant_id, "merchant-1")
        self.assertIn("operator", context.roles)

    def test_short_tokens_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            StaticBearerAuthorizer(token=b"short", subject="operator-1", merchant_id="merchant-1")


if __name__ == "__main__":
    unittest.main()
