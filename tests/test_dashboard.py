import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from vibegate_playground import dashboard as dashboard_module, server
from vibegate_playground.dashboard import Dashboard, present, make_handler


class DashboardTests(unittest.TestCase):
    def test_canonical_server_entrypoint_uses_dashboard_main(self):
        self.assertIs(server.main, dashboard_module.main)

    def test_ui_copy_preserves_cloud_warning_and_precise_privacy_control(self):
        from vibegate_playground.dashboard import WEB
        html = (WEB / "index.html").read_text()
        for text in ("錄影模式", "LOCAL ONLY", "假私人資料", "準備真實測試"):
            self.assertNotIn(text, html)
        for text in ("顯示設定", "隱藏時間與測試識別資訊", "將連線 AWS 並消耗額度", "不代表提示注入成功"):
            self.assertIn(text, html)

    def test_ui_separates_new_test_from_history_without_native_selects(self):
        from vibegate_playground.dashboard import WEB
        html = (WEB / "index.html").read_text()
        self.assertNotIn("<select", html)
        self.assertNotIn('id="record-list"', html)
        self.assertEqual(html.count('id="history"'), 1)
        self.assertEqual(html.count('id="connection"'), 1)
        self.assertIn("建立新測試", html)
        self.assertIn("新測試呼叫上限", html)
        self.assertIn("歷史測試結果", html)
        self.assertEqual(html.count('type="radio" name="scenario"'), 6)

    def test_ui_is_bilingual_and_reset_preserves_evidence(self):
        from vibegate_playground.dashboard import WEB
        html = (WEB / "index.html").read_text()
        for text in ('id="lang-zh"', 'id="lang-en"', "VibeGate Security Tests",
                     '<button id="reset"', "viewCleared=true", "歷史證據仍保留"):
            self.assertIn(text, html)
        self.assertIn("selectedScenario.parentElement.querySelector('span')", html)
        self.assertNotIn('input[name="scenario"]:checked span', html)
        self.assertNotIn("/api/reset", html)
        self.assertNotIn("method:'DELETE'", html)

    def test_source_and_mcp_are_not_cloud_authorizations(self):
        for kind in ("github_source", "offline_mcp"):
            with self.assertRaises(ValueError):
                self.app.authorize(kind, "RUN NOVA")
        with patch("vibegate_playground.dashboard.threading.Thread") as worker:
            with self.assertRaises(ValueError):
                self.app.start("github_source", commit="main")
            worker.assert_not_called()

    def test_github_result_excludes_raw_content_and_claims_only_source(self):
        fetched = {"repository": "jiarong0423/vibegate-security-playground", "commit": "a"*40,
                   "path": "README.md", "content_sha256": "b"*64, "acquisition": "network",
                   "text": "PRIVATE-MARKER-not-for-display"}
        record = {"id": "a"*32, "kind": "github_source", "commit": "a"*40,
                  "state": "running", "started": "2026-09-09T00:00:00+00:00"}
        with patch("vibegate_playground.github_source.GitHubSource.fetch_snapshot", return_value=fetched), patch("boto3.Session", side_effect=AssertionError("No AWS")):
            self.app.execute(record, io.StringIO())
        self.assertNotIn("PRIVATE-MARKER", json.dumps(record))
        result = present(record)
        self.assertTrue(result["passed"])
        self.assertEqual(result["status"], "來源驗證完成")
        self.assertEqual(result["calls"], 0)
        self.assertIn("不代表注入攔截", result["scope_note"])
        record["payload"]["source"]["acquisition"] = "fixture"
        self.assertFalse(present(record)["passed"])

    def test_incomplete_mcp_report_never_passes(self):
        record = {"id": "a"*32, "kind": "offline_mcp", "state": "complete",
                  "started": "2026-09-09T00:00:00+00:00", "payload": {"passed": True}}
        self.assertFalse(present(record)["passed"])

    def test_workflow_unknown_state_and_malformed_evidence_fail_closed(self):
        record = {"id": "a"*32, "kind": "github_source", "state": "pending",
                  "started": "2026-09-09T00:00:00+00:00", "payload": {"source_verified": True,
                  "source": {"repository": "jiarong0423/vibegate-security-playground", "commit": "a"*40,
                  "path": "README.md", "content_sha256": "b"*64, "acquisition": "network"}}}
        self.assertFalse(present(record)["passed"])
        for malformed in (None, [], {"source": []}):
            record["payload"] = malformed
            self.assertFalse(present(record)["passed"])

    def test_real_mcp_projection_requires_per_request_evidence(self):
        from copy import deepcopy
        from vibegate_playground.mcp_harness import run_mcp_suite
        with patch("boto3.Session", side_effect=AssertionError("AWS forbidden")):
            suite = run_mcp_suite()
        record = {"id": "a"*32, "kind": "offline_mcp", "state": "complete",
                  "started": "2026-09-09T00:00:00+00:00", "payload": suite}
        self.assertTrue(present(record)["passed"], present(record))
        tampered = deepcopy(suite)
        for case in tampered["cases"]:
            for key in ("control", "protected"):
                case[key]["requests"] = [{"completed": True} for row in case[key]["requests"]]
        record["payload"] = tampered
        self.assertFalse(present(record)["passed"])
        record["kind"] = "offline_mcp"
        for bad_cases in ([{"case": []}]*5, [{"case": n, "control": None} for n in
                ("safe", "direct", "description_injection", "result_injection", "scanner_failure")]):
            record["payload"] = {"source_mode": "offline_real_mcp", "provider_calls": 0,
                                 "injection_mode": "offline_scripted", "cases": bad_cases}
            self.assertFalse(present(record)["passed"])

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Dashboard(Path(self.temp.name))

    def test_cloud_requires_one_use_scenario_bound_confirmation(self):
        with self.assertRaises(ValueError):
            self.app.start("live_e2e")
        with self.assertRaises(ValueError):
            self.app.start("live_direct")
        with self.assertRaises(ValueError):
            self.app.authorize("live_direct", "yes")
        nonce = self.app.authorize("live_direct", "RUN NOVA")
        with self.assertRaises(ValueError):
            self.app.start("live_injection", nonce)
        with self.assertRaises(ValueError):
            self.app.start("live_direct", nonce)

    def test_live_workflow_missing_evidence_never_claims_pass(self):
        record = {"id": "a"*32, "kind": "live_e2e", "state": "complete", "started": "2026-09-09T00:00:00Z",
                  "payload": {"passed": True, "cases": [{"case": "safe"}]*4}}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "測試失敗或證據不完整")
        self.assertEqual(result["error"], "測試失敗或證據不完整")
        self.assertEqual(result["live_cases"], [])

    def test_live_normal_summary_cannot_replace_read_evidence(self):
        cases = []
        for name in ("github", "description_injection", "result_injection", "safe"):
            cases.append({"case": name, "passed": True, "status": "normal_completed", "provider_calls": 1,
                "transport": [{"http_status": 200, "stream_complete": True, "stream_sha256": "a"*64}],
                "live": {"passed": True, "health_before": True, "health_after": True,
                         "server_entry": {"read": 1, "send": 0}, "requests": []}})
        record = {"id": "a"*32, "kind": "live_e2e", "state": "complete", "started": "2026-09-09T00:00:00Z",
                  "payload": {"provider_mode": "live_bedrock", "cases": cases}}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertFalse(result["live_cases"][-1]["safe_completed"])

    def test_retention_full_blocks_before_any_worker_or_aws(self):
        with patch("vibegate_playground.dashboard.MAX_REPORTS", 1):
            report = Path(self.temp.name) / ("a"*32 + ".json")
            report.write_text("{}")
            with patch("vibegate_playground.dashboard.threading.Thread") as worker, patch("boto3.Session") as aws:
                with self.assertRaises(ValueError):
                    self.app.start("offline")
                worker.assert_not_called()
                aws.assert_not_called()
            self.assertEqual(report.read_text(), "{}")
            self.assertEqual(self.app.storage_status()["reason"], "retention_limit")

    def test_retention_rejects_symlink_without_deleting(self):
        link = Path(self.temp.name) / ("b"*32 + ".json")
        link.symlink_to(Path(self.temp.name) / "missing")
        self.assertFalse(self.app.storage_status()["ready"])
        self.assertTrue(link.is_symlink())

    def test_expired_confirmation_blocks(self):
        nonce = self.app.authorize("live_direct", "RUN NOVA")
        self.app.confirmations[nonce] = ("live_direct", 0)
        with self.assertRaises(ValueError):
            self.app.start("live_direct", nonce)

    def test_double_click_does_not_start_second_run(self):
        with patch("vibegate_playground.dashboard.threading.Thread") as thread:
            self.app.start("offline")
            with self.assertRaises(ValueError):
                self.app.start("offline")
            thread.call_args.kwargs["args"][1].close()

    def test_offline_dispatch_does_not_create_aws_session(self):
        record = {"id": "test", "kind": "offline", "state": "running", "started": "test"}
        with patch("boto3.Session", side_effect=AssertionError("No AWS")):
            self.app.execute(record, io.StringIO())
        self.assertTrue(record["payload"]["passed"])
        summary = present(record)
        self.assertEqual(summary["calls"], 0)
        self.assertEqual(summary["summary"]["tools"], 1)
        self.assertEqual(summary["summary"]["dangerous"], 0)
        self.assertEqual(summary["control"]["dangerous"], 2)
        self.assertEqual(summary["protected"]["blocked"], 2)
        self.assertEqual(summary["control"]["bytes"], 164)

    def test_failed_worker_start_restores_idle(self):
        with patch("vibegate_playground.dashboard.threading.Thread") as thread:
            thread.return_value.start.side_effect = RuntimeError("unavailable")
            with self.assertRaises(ValueError):
                self.app.start("offline")
        self.assertFalse(self.app.busy)

    def test_saved_runs_reappear_after_restart(self):
        record = {"id": "a" * 32, "kind": "offline", "state": "running", "started": "2026-09-09T00:00:00+00:00"}
        path = Path(self.temp.name) / (record["id"] + ".json")
        self.app.execute(record, path.open("x"))
        restored = Dashboard(Path(self.temp.name)).snapshot()["runs"]
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0]["summary"]["blocked"], 2)

    def test_cloud_dispatch_fixed_budget_and_scenario(self):
        record = {"id": "test", "kind": "live_direct", "state": "running", "started": "test"}
        with patch("vibegate_playground.bedrock_smoke.verify_interception", return_value={"passed": False}) as run:
            self.app.execute(record, io.StringIO())
        run.assert_called_once_with(1, allow_paid_inference=True, scenario="direct")

    def test_private_text_never_reaches_projection(self):
        marker = "private-person@example.invalid /Users/private-person/key arn:aws:iam::123456789012:user/private"
        record = {"id": marker, "kind": "offline", "state": "complete", "started": marker,
                  "finished": marker, "error": marker, "payload": {"passed": marker, "protected": {
                      "request_digest": marker, "fixture_digest": marker, "provider_calls": marker,
                      "observed": {"received_bytes": marker}, "requests": [{"completed": True,
                          "toolUseId": marker, "tool": marker, "decision": marker, "executions": marker}]}}}
        result = present(record)
        encoded = json.dumps(result)
        for forbidden in ("private-person", "arn:aws", "123456789012", "/Users/"):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(result["passed"])
        self.assertEqual(result["rows"][0]["tool"], "unknown_tool")
        self.assertIsNone(result["calls"])

    def test_missing_evidence_cannot_pass_or_become_zero(self):
        record = {"id": "a"*32, "kind": "offline", "state": "complete", "started": "test",
                  "payload": {"passed": True, "control": {}, "protected": {}}}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertFalse(result["replay_available"])
        self.assertEqual(result["status"], "證據不足")
        self.assertIsNone(result["summary"]["dangerous"])
        self.assertIsNone(result["summary"]["bytes"])

    def test_unfinished_request_cannot_count_as_confirmed_block(self):
        record = {"id": "a"*32, "kind": "offline", "state": "complete", "started": "test",
                  "payload": {"passed": True, "protected": {"status": "blocked", "requests": [
                      {"completed": False, "status": "blocked", "executions": 0, "dangerous": True}]}}}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "證據不足")
        self.assertEqual(result["rows"][0]["status"], "未完成")
        self.assertIsNone(result["summary"]["blocked"])

    def test_in_progress_record_cannot_pass(self):
        record = {"id": "a"*32, "kind": "offline", "state": "running", "started": "test"}
        self.app.execute(record, io.StringIO())
        self.assertTrue(present(record)["passed"])
        record["state"] = "running"
        self.assertFalse(present(record)["passed"])

    def test_unobserved_is_not_safe_verdict(self):
        from vibegate_playground.demo import replay_pair
        record = {"id": "a"*32, "kind": "offline", "state": "complete", "started": "test",
                  "payload": replay_pair([])}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "未觀察到危險要求")

    def test_live_cannot_fall_back_to_offline_evidence(self):
        from vibegate_playground.demo import replay_pair
        pair = replay_pair([{"toolUseId": "danger-1", "name": "send_synthetic_sample", "input": {}}])
        record = {"id": "a"*32, "kind": "live_direct", "state": "complete", "started": "test",
                  "payload": {"passed": True, "replay": pair,
                              "transport": [{"http_status": 200, "stream_complete": True}]}}
        result = present(record)
        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "證據不足")

    def test_empty_control_or_changed_requests_cannot_pass(self):
        from copy import deepcopy
        from vibegate_playground.demo import replay_pair
        pair = replay_pair([{"toolUseId": "danger-1", "name": "send_synthetic_sample", "input": {}}])
        for mutation in ("empty", "id", "safe", "status"):
            candidate = deepcopy(pair)
            if mutation == "empty":
                candidate["control"]["requests"] = []
            elif mutation == "id":
                candidate["control"]["requests"][0]["toolUseId"] = "different"
            elif mutation == "safe":
                candidate["protected"]["requests"][0]["dangerous"] = False
            else:
                candidate["control"].pop("status")
            with self.subTest(mutation=mutation):
                result = present({"id": "a"*32, "kind": "offline", "state": "complete", "started": "test", "payload": candidate})
                self.assertFalse(result["passed"])

    def test_bad_origin_or_token_never_starts(self):
        handler = object.__new__(make_handler(self.app))
        handler.server = type("Server", (), {"server_port": 1234})()
        handler.rfile = io.BytesIO(b'{}')
        for headers in ({"Host": "evil.test:1234"},
                        {"Host": "127.0.0.1:1234", "Origin": "https://evil.test"},
                        {"Host": "127.0.0.1:1234", "Origin": "http://127.0.0.1:1234"}):
            handler.headers = headers
            with patch.object(handler, "send") as send, patch.object(self.app, "start") as start:
                handler.do_POST()
                self.assertEqual(send.call_args.args[0], 403)
                start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
