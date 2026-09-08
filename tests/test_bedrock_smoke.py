import asyncio
import unittest
from unittest.mock import patch

from strands.models import BedrockModel
from vibegate_playground.bedrock_smoke import BoundedBedrockModel, redact_error


class BudgetTests(unittest.TestCase):
    def test_single_call_limit(self):
        attempts = []

        async def fake_stream(self, *args, **kwargs):
            attempts.append(True)
            yield {}

        async def exercise():
            model = object.__new__(BoundedBedrockModel)
            model.call_limit = 1
            async for _ in model.stream([]):
                pass
            with self.assertRaisesRegex(RuntimeError, "provider_call_limit"):
                async for _ in model.stream([]):
                    pass

        with patch.object(BedrockModel, "stream", fake_stream):
            asyncio.run(exercise())
        self.assertEqual(len(attempts), 1)

    def test_error_redaction(self):
        result = redact_error("Denied arn:aws:iam::123456789012:user/test user@example.test 123456789012")
        self.assertNotIn("123456789012", result)
        self.assertNotIn("user@example.test", result)
        self.assertIn("Denied", result)

    def test_third_request_never_reaches_provider(self):
        attempts = []

        async def fake_stream(self, *args, **kwargs):
            attempts.append(True)
            yield {"messageStop": {"stopReason": "end_turn"}}

        async def exercise():
            model = object.__new__(BoundedBedrockModel)
            for _ in range(2):
                async for _ in model.stream([]):
                    pass
            with self.assertRaisesRegex(RuntimeError, "provider_call_limit"):
                async for _ in model.stream([]):
                    pass
            self.assertEqual(model.calls, 2)

        with patch.object(BedrockModel, "stream", fake_stream):
            asyncio.run(exercise())
        self.assertEqual(len(attempts), 2)


if __name__ == "__main__":
    unittest.main()
