import asyncio
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch, MagicMock

from botocore.config import Config
from vibegate_playground import bedrock_smoke as smoke
from vibegate_playground.bedrock_smoke import BoundedBedrockModel, redact_error


class BudgetTests(unittest.TestCase):
    def model(self, limit):
        session = MagicMock()
        session.region_name = "ap-southeast-2"
        request = session.client.return_value.converse_stream
        request.return_value = {"stream": []}
        model = BoundedBedrockModel(call_limit=limit, boto_session=session,
            boto_client_config=Config(retries={"total_max_attempts": 1}),
            model_id="global.amazon.nova-2-lite-v1:0", max_tokens=256)
        return model, request

    def test_single_call_limit(self):
        model, request = self.model(1)

        async def exercise():
            async for _ in model.stream([]):
                pass
            with self.assertRaisesRegex(RuntimeError, "provider_call_limit"):
                async for _ in model.stream([]):
                    pass

        asyncio.run(exercise())
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.kwargs["inferenceConfig"]["maxTokens"], 256)

    def test_error_redaction(self):
        result = redact_error("Denied arn:aws:iam::123456789012:user/test user@example.test 123456789012")
        self.assertNotIn("123456789012", result)
        self.assertNotIn("user@example.test", result)
        self.assertNotIn("arn:", result)
        self.assertIn("Denied", result)

    def test_third_request_never_reaches_provider(self):
        model, request = self.model(2)

        async def exercise():
            for _ in range(2):
                async for _ in model.stream([]):
                    pass
            with self.assertRaisesRegex(RuntimeError, "provider_call_limit"):
                async for _ in model.stream([]):
                    pass
            self.assertEqual(model.calls, 2)

        asyncio.run(exercise())
        self.assertEqual(request.call_count, 2)

    def test_internal_resend_and_nonstream_share_budget(self):
        model, request = self.model(1)
        model.client.converse_stream()
        for method in (model.client.converse_stream, model.client.converse):
            with self.assertRaises(smoke.ProviderCallLimit):
                method()
        self.assertEqual(request.call_count, 1)

    def test_failed_request_consumes_budget(self):
        model, request = self.model(1)
        request.side_effect = RuntimeError("synthetic_failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic_failure"):
            model.client.converse_stream()
        with self.assertRaises(smoke.ProviderCallLimit):
            model.client.converse_stream()
        self.assertEqual(request.call_count, 1)

    def test_invalid_limit_before_client_creation(self):
        with patch.object(smoke.boto3, "Session") as session:
            for limit in (0, 3, True):
                with self.assertRaises(ValueError):
                    BoundedBedrockModel(call_limit=limit)
            session.assert_not_called()

    def test_entrypoint_rejections_make_zero_calls(self):
        with TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            for case in ("approval", "existing", "preflight"):
                with self.subTest(case=case):
                    if case == "existing":
                        report.write_text("preserve", encoding="utf-8")
                    args = ["smoke", "--report", str(report)]
                    if case != "approval":
                        args.append("--allow-paid-inference")
                    with patch("sys.argv", args), patch.object(smoke.boto3, "Session") as session, \
                            patch.object(smoke.VibeGateHook, "prepare", return_value=False), \
                            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        if case == "approval":
                            with self.assertRaises(SystemExit):
                                smoke.main()
                        elif case == "existing":
                            with self.assertRaises(FileExistsError):
                                smoke.main()
                            self.assertEqual(report.read_text(), "preserve")
                            report.unlink()
                        else:
                            self.assertEqual(smoke.main(), 1)
                            self.assertEqual(json.loads(report.read_text())["provider_calls_attempted"], 0)
                        session.assert_not_called()

    def test_entrypoint_retry_config_and_error_report(self):
        with TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            args = ["smoke", "--allow-paid-inference", "--max-calls", "1", "--report", str(report)]
            with patch("sys.argv", args), patch.object(smoke.boto3, "Session") as session, \
                    patch.object(smoke, "Agent") as agent, redirect_stdout(io.StringIO()):
                session.return_value.region_name = "ap-southeast-2"
                request = session.return_value.client.return_value.converse_stream
                request.return_value = {"stream": []}

                def attempt(prompt):
                    model = agent.call_args.kwargs["model"]
                    model.client.converse_stream()
                    model.client.converse_stream()

                agent.return_value.side_effect = attempt
                self.assertEqual(smoke.main(), 1)
                config = session.return_value.client.call_args.kwargs["config"]
                self.assertEqual(config.retries["total_max_attempts"], 1)
                self.assertEqual(config.connect_timeout, 10)
                self.assertEqual(config.read_timeout, 30)
                self.assertIn("retry_strategy", agent.call_args.kwargs)
                self.assertIsNone(agent.call_args.kwargs["retry_strategy"])
                self.assertEqual(request.call_count, 1)
            payload = json.loads(report.read_text())
            self.assertFalse(payload["passed"])
            self.assertEqual(payload["provider_calls_attempted"], 1)
            self.assertEqual(payload["error_reason"], "provider_call_limit")


if __name__ == "__main__":
    unittest.main()
