import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from vibegate_playground import mcp_harness as harness
from vibegate_playground.mcp_fixture_server import INJECTION


class MCPHarnessTests(unittest.TestCase):
    def test_l2_injection_is_explicit_but_has_no_external_target(self):
        self.assertIn("send_synthetic_sample", INJECTION)
        self.assertIn("no arguments", INJECTION)
        self.assertIn("fixed synthetic marker", INJECTION)
        self.assertNotIn("http://", INJECTION)
        self.assertNotIn("https://", INJECTION)
        self.assertNotIn("/Users/", INJECTION)

    def test_real_stdio_suite_counts_transport_and_server(self):
        with patch("boto3.Session", side_effect=AssertionError("AWS forbidden")), \
                patch.dict("os.environ", {"AWS_PROFILE": "synthetic-forbidden", "VIBEGATE_PARENT_SENTINEL": "synthetic"}):
            report = harness.run_mcp_suite()
        json.dumps(report, allow_nan=False)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["source_mode"], "offline_real_mcp")
        self.assertEqual(report["provider_calls"], 0)
        self.assertEqual([case["case"] for case in report["cases"]], list(harness.CASES))
        for case in report["cases"]:
            off, on = case["control"], case["protected"]
            self.assertEqual(off["request_digest"], on["request_digest"])
            for leg in (off, on):
                self.assertTrue(leg["health_before"] and leg["health_after"])
                self.assertEqual(leg["client_dispatch"], leg["server_entry"])
                self.assertEqual(leg["subprocess_environment"], {
                    "aws_variables_absent": True, "only_allowlisted_keys": True,
                    "home_empty": True, "user_site_disabled": True})
                self.assertLessEqual(leg["transport_messages"], harness.MAX_MESSAGES)
            if case["case"] == "safe":
                self.assertEqual(on["server_entry"]["read"], 1)
                self.assertEqual(on["sdk_cancelled"], 0)
            else:
                self.assertEqual(off["server_entry"]["send"], 1)
                self.assertGreater(off["received_bytes"], 0)
                self.assertEqual(on["client_dispatch"]["send"], 0)
                self.assertEqual(on["server_entry"]["send"], 0)
                self.assertEqual(on["received_bytes"], 0)
                self.assertEqual(on["sdk_cancelled"], 1)
            if "injection" in case["case"]:
                self.assertTrue(off["injection_observed"] and on["injection_observed"])
                self.assertEqual(on["injection_mode"], "offline_scripted")

    def test_server_command_and_environment_are_fixed(self):
        with TemporaryDirectory() as temporary, patch.dict("os.environ", {"AWS_PROFILE": "forbidden", "AWS_ACCESS_KEY_ID": "synthetic"}):
            params = harness.server_parameters(Path(temporary), "safe")
        self.assertEqual(params.command, sys.executable)
        self.assertEqual(params.args[:2], ["-m", "vibegate_playground.mcp_fixture_server"])
        self.assertFalse(any(key.startswith("AWS") for key in params.env))
        self.assertEqual(params.env["HOME"], "")

    def test_missing_sdk_completion_cannot_pass(self):
        with patch.object(harness.MCPAudit, "after_tool"):
            result = asyncio.run(harness.run_leg("direct", True))
        self.assertFalse(result["passed"])

    def test_missing_server_evidence_cannot_pass(self):
        with patch.object(harness, "read_entries", side_effect=OSError("synthetic")):
            result = asyncio.run(harness.run_leg("safe", True))
        self.assertFalse(result["passed"])
        self.assertIsNone(result["server_entry"])

    def test_bad_case_rejected_before_transport(self):
        with patch.object(harness, "stdio_client") as transport:
            result = asyncio.run(harness.run_leg("unknown", True))
        transport.assert_not_called()
        self.assertFalse(result["passed"])

    def test_model_request_arguments_are_rejected(self):
        with self.assertRaises(ValueError):
            harness.ScriptedMCPModel([{"toolUseId": "x", "name": "send_synthetic_sample",
                                       "input": {"path": "forbidden"}}], "direct")

    def test_stalled_transport_has_bounded_failure(self):
        @asynccontextmanager
        async def stalled(*args, **kwargs):
            await asyncio.sleep(10)
            yield None

        with patch.object(harness, "LEG_TIMEOUT", 0.02), patch.object(harness, "stdio_client", stalled):
            result = asyncio.run(harness.run_leg("direct", True))
        self.assertFalse(result["passed"])
        self.assertEqual(result["error_type"], "TimeoutError")
        self.assertIsNone(result["server_entry"])

    def test_failed_control_dispatch_cannot_pass(self):
        original = harness.DispatchStream.send

        async def broken_send(stream, message):
            data = message.message.model_dump(by_alias=True, exclude_none=True)
            if data.get("method") == "tools/call" and data["params"]["name"] == "send_synthetic_sample":
                raise OSError("synthetic_transport_failure")
            await original(stream, message)

        with patch.object(harness.DispatchStream, "send", broken_send):
            result = asyncio.run(harness.run_leg("direct", False))
        self.assertFalse(result["passed"])

    def test_unhealthy_receiver_cannot_pass(self):
        original = harness.result_text

        def unhealthy(result):
            text = original(result)
            if '"healthy"' in text:
                data = json.loads(text)
                data["healthy"] = False
                return json.dumps(data)
            return text

        with patch.object(harness, "result_text", unhealthy):
            result = asyncio.run(harness.run_leg("direct", True))
        self.assertFalse(result["passed"])
        self.assertFalse(result["health_before"])

    def test_stderr_is_bounded_and_excluded_from_public_report(self):
        marker = "SYNTHETIC-LOCAL-DIAGNOSTIC"

        @asynccontextmanager
        async def failed(*args, errlog, **kwargs):
            errlog.write("x" * (harness.STDERR_LIMIT * 3) + marker)
            errlog.flush()
            raise OSError("synthetic")
            yield None

        with patch.object(harness, "stdio_client", failed):
            result = asyncio.run(harness.run_leg("safe", False))
        self.assertFalse(result["passed"])
        self.assertEqual(result["error_type"], "OSError")
        self.assertNotIn(marker, json.dumps(result))
        diagnostics = harness.local_diagnostics()
        self.assertLessEqual(len(diagnostics), 10)
        self.assertTrue(diagnostics[-1]["stderr_tail"].endswith(marker))
        self.assertLessEqual(len(diagnostics[-1]["stderr_tail"]), harness.STDERR_LIMIT)
