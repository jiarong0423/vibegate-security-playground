import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from strands import Agent, tool
from ai_security_rules.strands_gate import VibeGateHook, snapshot_digest
from vibegate_playground.demo import SCENARIOS, SyntheticSandbox, run_case, run_replay, replay_pair, ReplayAudit
from vibegate_playground.model import AttemptModel


class ReplayTests(unittest.TestCase):
    def requests(self):
        return [{"toolUseId": "safe-1", "name": "read_synthetic_sample", "input": {}},
                {"toolUseId": "danger-1", "name": "send_synthetic_sample", "input": {}},
                {"toolUseId": "danger-2", "name": "send_synthetic_sample", "input": {}}]

    def test_mixed_requests_correlate_actual_sdk_completion(self):
        with patch("boto3.Session", side_effect=AssertionError("no_cloud")):
            pair = replay_pair(self.requests())
        self.assertTrue(pair["passed"])
        self.assertEqual(pair["provider_calls"], 0)
        self.assertEqual([row["status"] for row in pair["protected"]["requests"]],
                         ["executed", "blocked", "blocked"])
        self.assertEqual([row["executions"] for row in pair["control"]["requests"]], [1, 1, 1])
        self.assertTrue(all(row["sdk_cancelled"] for row in pair["protected"]["requests"][1:]))
        self.assertEqual(pair["protected"]["observed"]["received_bytes"], 0)
        self.assertEqual(pair["protected"]["provenance"], "not_verified_as_live")

    def test_no_dangerous_attempt_is_not_interception_success(self):
        for requests in ([], self.requests()[:1]):
            pair = replay_pair(requests)
            self.assertFalse(pair["passed"])
            self.assertEqual(pair["protected"]["status"], "unobserved_attempt")

    def test_scanner_failure_is_cancelled_by_sdk(self):
        result = run_replay(self.requests(), True, scanner_failure=True)
        self.assertTrue(result["passed"])
        self.assertTrue(all(row["status"] == "blocked" and row["executions"] == 0
                            for row in result["requests"]))

    def test_bad_records_fail_before_receiver_or_tools(self):
        request = self.requests()[0]
        for records in ([request, request], [{**request, "input": {"path": "private"}}],
                        [{**request, "name": "unknown"}], self.requests() * 3):
            with patch("vibegate_playground.demo.receiver_health") as health:
                result = run_replay(records, True)
                self.assertEqual(result["status"], "harness_failure")
                self.assertFalse(result["passed"])
                health.assert_not_called()

    def test_receiver_health_failure_is_not_blocked(self):
        with patch("vibegate_playground.demo.receiver_health", return_value=False):
            result = run_replay(self.requests(), True)
        self.assertEqual(result["status"], "harness_failure")
        self.assertFalse(result["passed"])

    def test_broken_socket_is_not_zero_transfer_success(self):
        with patch("vibegate_playground.demo.socket.socketpair", side_effect=OSError("synthetic")):
            result = run_replay(self.requests(), True)
        self.assertEqual(result["status"], "harness_failure")

    def test_tool_failure_is_not_interception(self):
        with patch.object(SyntheticSandbox, "perform", side_effect=OSError("synthetic")):
            result = run_replay(self.requests(), False)
        self.assertEqual(result["status"], "tool_failure")
        self.assertFalse(result["passed"])

    def test_missing_after_event_is_not_interception(self):
        with patch.object(ReplayAudit, "after_tool"):
            result = run_replay(self.requests(), True)
        self.assertEqual(result["status"], "harness_failure")
        self.assertFalse(result["passed"])

    def test_hook_exception_is_not_interception(self):
        with patch.object(ReplayAudit, "before_tool", side_effect=RuntimeError("synthetic")):
            result = run_replay(self.requests(), True)
        self.assertEqual(result["status"], "harness_failure")
        self.assertFalse(result["passed"])


class InterceptionTests(unittest.TestCase):
    def test_all_scenarios_real_sdk_paired(self):
        for scenario in SCENARIOS:
            for guarded in (False, True):
                with self.subTest(case=scenario.name, guarded=guarded):
                    self.assertTrue(run_case(scenario, guarded)["passed"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vibegate-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "hello.txt").write_text("Synthetic data\n")
        self.hook = VibeGateHook(self.root, frozenset({"perform_demo_action"}), policy=lambda _: True)
        self.assertTrue(self.hook.prepare())

    def test_unknown_tool_denied(self):
        self.assertEqual(self.hook.decide("unknown", {}).reason, "tool_not_allowlisted")

    def test_model_cannot_select_target_or_decision(self):
        for args in ({"target": "/"}, {"allowed": True}, {"output_dir": "/forbidden-output"}, None, []):
            with self.subTest(args=args):
                self.assertFalse(self.hook.decide("perform_demo_action", args).allowed)

    def test_no_preflight_denied(self):
        self.hook.expected_digest = None
        self.assertFalse(self.hook.decide("perform_demo_action", {}).allowed)

    def test_change_during_scan_denied(self):
        from ai_security_rules.cli import scan_project

        def mutating_scan(root):
            result = scan_project(root)
            (root / "hello.txt").write_text("changed")
            return result

        self.hook.scanner = mutating_scan
        self.assertEqual(self.hook.decide("perform_demo_action", {}).reason,
                         "snapshot_changed_during_scan")

    def test_policy_exception_denied_without_exception_text(self):
        def bad_policy(_):
            raise RuntimeError("DO_NOT_EXPOSE_THIS_EXCEPTION")

        self.hook.policy = bad_policy
        decision = self.hook.decide("perform_demo_action", {})
        self.assertFalse(decision.allowed)
        self.assertNotIn("DO_NOT_EXPOSE", str(decision))

    def test_malformed_scan_denied(self):
        for result in (None, {}, (SimpleNamespace(high=False, critical=0), []),
                       (SimpleNamespace(high=-1, critical=0), [])):
            with self.subTest(result=result):
                self.hook.scanner = lambda _, result=result: result
                self.assertFalse(self.hook.decide("perform_demo_action", {}).allowed)

    def test_symlink_denied(self):
        (self.root / "alias.txt").symlink_to(self.root / "hello.txt")
        self.assertFalse(self.hook.prepare())

    def test_env_filename_denied_without_reading(self):
        (self.root / ".env").write_text("synthetic")
        self.assertFalse(self.hook.prepare())

    def test_snapshot_limit(self):
        (self.root / "big.txt").write_bytes(b"x" * 250_001)
        self.assertFalse(self.hook.prepare())

    def test_same_size_content_change_detected(self):
        old = snapshot_digest(self.root)
        (self.root / "hello.txt").write_text("Synthetic DATA\n")
        self.assertNotEqual(old, snapshot_digest(self.root))

    def test_existing_cancellation_preserved(self):
        event = SimpleNamespace(tool_use={"name": "perform_demo_action", "input": {}},
                                cancel_tool="Another policy denied")
        self.hook.before_tool(event)
        self.assertTrue(event.cancel_tool)
        self.assertFalse(self.hook.decisions[-1].allowed)

    def test_repeated_attempts_remain_blocked_real_sdk(self):
        calls = []

        @tool
        def perform_demo_action() -> str:
            """Count an attempted synthetic effect."""
            calls.append(True)
            return "executed"

        self.hook.policy = lambda _: False
        agent = Agent(model=AttemptModel(attempts=3), tools=[perform_demo_action],
                      hooks=[self.hook], callback_handler=None)
        agent("Try the operation")
        self.assertEqual(calls, [])
        self.assertEqual(len(self.hook.decisions), 3)
        self.assertTrue(all(not decision.allowed for decision in self.hook.decisions))

    def test_canary_does_not_trigger_denial(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SyntheticSandbox(Path(temporary), SCENARIOS[0])
            gate = VibeGateHook(fixture.root, frozenset({"perform_demo_action"}), policy=lambda _: True)
            self.assertTrue(gate.prepare())
            self.assertTrue(gate.decide("perform_demo_action", {}).allowed)


if __name__ == "__main__":
    unittest.main()
