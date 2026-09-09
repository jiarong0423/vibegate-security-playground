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


class ProviderIntegrationTests(unittest.TestCase):
    def test_two_turn_capture_and_default_single_turn_boundary(self):
        for turns in (1, 2):
            session = MagicMock()
            session.region_name = "ap-southeast-2"
            first = self.response(names=("read_synthetic_sample",))
            second = self.response(names=("send_synthetic_sample",))
            second["stream"][1]["contentBlockStart"]["start"]["toolUse"]["toolUseId"] = "second"
            request = session.client.return_value.converse_stream
            request.side_effect = [first, second]
            model = smoke.CapturedBedrockModel(call_limit=2, capture_turn_limit=turns,
                boto_session=session, model_id="global.amazon.nova-2-lite-v1:0", max_tokens=256)
            async def exercise():
                async for _ in model.stream([]):
                    pass
                if turns == 1:
                    with self.assertRaises(smoke.CaptureError):
                        async for _ in model.stream([]):
                            pass
                else:
                    async for _ in model.stream([]):
                        pass
            asyncio.run(exercise())
            self.assertEqual(request.call_count, turns)
            self.assertEqual(len(model.captures), turns)
            self.assertEqual(len(model.captured_requests), turns)

    def response(self, names=("read_synthetic_sample", "send_synthetic_sample"), arguments="{}"):
        chunks = [{"messageStart": {"role": "assistant"}}]
        for index, name in enumerate(names):
            chunks.extend([
                {"contentBlockStart": {"contentBlockIndex": index, "start": {
                    "toolUse": {"toolUseId": f"synthetic-{index}", "name": name}}}},
                {"contentBlockDelta": {"contentBlockIndex": index, "delta": {"toolUse": {"input": arguments}}}},
                {"contentBlockStop": {"contentBlockIndex": index}},
            ])
        if not names:
            chunks.extend([
                {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "No action."}}},
                {"contentBlockStop": {"contentBlockIndex": 0}},
            ])
        chunks.extend([
            {"messageStop": {"stopReason": "tool_use" if names else "end_turn"}},
            {"metadata": {"usage": {"inputTokens": 10, "outputTokens": 20, "totalTokens": 30},
                          "metrics": {"latencyMs": 1}}},
        ])
        return {"ResponseMetadata": {"HTTPStatusCode": 200, "RequestId": "synthetic-request-id"},
                "stream": chunks}

    def execute(self, response):
        with patch.object(smoke.boto3, "Session") as session:
            session.return_value.region_name = "ap-southeast-2"
            request = session.return_value.client.return_value.converse_stream
            request.return_value = response
            result = smoke.verify_interception(1, allow_paid_inference=True)
            self.assertEqual(request.call_count, 1)
            return result

    def test_full_sdk_capture_cancel_stop_and_replay(self):
        result = self.execute(self.response())
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["live"]["followup_stopped"])
        self.assertEqual(result["live"]["provider_calls"], 1)
        self.assertEqual([row["status"] for row in result["live"]["requests"]], ["executed", "blocked"])
        self.assertEqual(result["live"]["observed"]["received_bytes"], 0)
        self.assertEqual(result["live"]["request_digest"], result["replay"]["control"]["request_digest"])
        self.assertTrue(result["transport"][0]["stream_complete"])
        self.assertNotIn("synthetic-request-id", json.dumps(result))

    def test_no_attempt_is_not_success(self):
        result = self.execute(self.response(names=()))
        self.assertFalse(result["passed"])
        self.assertEqual(result["live"]["status"], "unobserved_attempt")

    def test_invalid_arguments_never_reach_tool_dispatch(self):
        result = self.execute(self.response(arguments='{"path":"private"}'))
        self.assertFalse(result["passed"])
        self.assertEqual(result["live"]["status"], "capture_failure")
        self.assertEqual(result["live"]["requests"], [])

    def test_truncated_stream_never_dispatches_partial_requests(self):
        response = self.response()
        response["stream"] = response["stream"][:-2]
        result = self.execute(response)
        self.assertFalse(result["passed"])
        self.assertEqual(result["live"]["requests"], [])
        self.assertEqual(result["live"]["status"], "capture_failure")

    def test_missing_metadata_is_not_live_evidence(self):
        response = self.response()
        response.pop("ResponseMetadata")
        result = self.execute(response)
        self.assertFalse(result["passed"])
        self.assertEqual(result["live"]["status"], "capture_failure")

    def test_provider_exception_is_not_interception(self):
        with patch.object(smoke.boto3, "Session") as session:
            session.return_value.region_name = "ap-southeast-2"
            session.return_value.client.return_value.converse_stream.side_effect = OSError("private-error")
            result = smoke.verify_interception(1, allow_paid_inference=True)
        self.assertFalse(result["passed"])
        self.assertEqual(result["live"]["status"], "provider_failure")
        self.assertNotIn("private-error", json.dumps(result))

    def test_interception_requires_explicit_cli_approval(self):
        with TemporaryDirectory() as temp, patch.object(smoke.boto3, "Session") as session, \
                patch("sys.argv", ["smoke", "--interception", "--report", str(Path(temp) / "report.json")]), \
                redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                smoke.main()
            session.assert_not_called()

    def test_direct_interception_also_requires_approval(self):
        with patch.object(smoke.boto3, "Session") as session:
            with self.assertRaises(ValueError):
                smoke.verify_interception(1)
            session.assert_not_called()

    def test_initialization_failure_has_zero_provider_calls(self):
        with patch.object(smoke.boto3, "Session", side_effect=RuntimeError("private-path")):
            result = smoke.verify_interception(1, allow_paid_inference=True)
        self.assertEqual(result["live"]["status"], "provider_initialization_failure")
        self.assertEqual(result["live"]["provider_calls"], 0)
        self.assertNotIn("private-path", json.dumps(result))

    def test_existing_interception_report_blocks_before_client(self):
        with TemporaryDirectory() as temp:
            report = Path(temp) / "result.json"
            report.write_text("preserve", encoding="utf-8")
            with patch.object(smoke.boto3, "Session") as session, patch("sys.argv", [
                    "smoke", "--interception", "--allow-paid-inference", "--report", str(report)]):
                with self.assertRaises(FileExistsError):
                    smoke.main()
                session.assert_not_called()
            self.assertEqual(report.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
