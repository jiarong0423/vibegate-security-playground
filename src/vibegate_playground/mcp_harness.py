"""Offline scripted Agent requests crossing a real, bounded MCP stdio transport.

Injection cases demonstrate host interception, not model induction. The scanner
checks the host-owned fixture; the fixed host policy forbids synthetic sends.
"""

import asyncio
from collections import deque
from contextlib import contextmanager
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import sys
import threading
from tempfile import TemporaryDirectory

import anyio
from mcp import ClientSession
from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS, StdioServerParameters, stdio_client
from strands import Agent, tool
from strands.tools.executors.sequential import SequentialToolExecutor

from .demo import ReplayAudit, unavailable_scanner
from .model import ReplayModel, validate_requests
from .mcp_fixture_server import CASES, INJECTION, PAYLOAD


LOG = logging.getLogger(__name__)
NAMES = {"read_synthetic_sample": "read", "send_synthetic_sample": "send",
         "fixture_health": "health"}
LEG_TIMEOUT = 15
MAX_MESSAGES = 16
STDERR_LIMIT = 4096
_LOCAL_DIAGNOSTICS = deque(maxlen=10)


def local_diagnostics():
    """Bounded process-local debugging only. Never include this in UI reports."""
    return [dict(item) for item in _LOCAL_DIAGNOSTICS]


@contextmanager
def bounded_stderr(case, guarded):
    """Drain the child pipe continuously; retain only a bounded diagnostic tail."""
    reader, writer = os.pipe()
    tail = bytearray()

    def drain():
        with os.fdopen(reader, "rb", buffering=0) as source:
            while block := source.read(STDERR_LIMIT):
                tail.extend(block)
                del tail[:-STDERR_LIMIT]

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    try:
        with os.fdopen(writer, "w", encoding="utf-8") as sink:
            yield sink
    finally:
        thread.join(timeout=1)
        if tail:
            _LOCAL_DIAGNOSTICS.append({"case": case, "guarded": guarded,
                                       "stderr_tail": bytes(tail).decode("utf-8", errors="replace")})


def server_parameters(root, case, lifetime=20):
    if type(lifetime) is not int or lifetime not in (20, 120):
        raise ValueError("invalid_server_lifetime")
    # stdio_client merges these defaults; explicitly replace every inherited key.
    environment = {key: "" for key in DEFAULT_INHERITED_ENV_VARS}
    environment.update(PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1",
                       PYTHONNOUSERSITE="1", TMPDIR=str(root),
                       PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    return StdioServerParameters(command=sys.executable,
        args=["-m", "vibegate_playground.mcp_fixture_server", "--root", str(root), "--case", case,
              "--lifetime", str(lifetime)],
        env=environment, cwd=str(root))


class DispatchStream:
    """Count actual tools/call messages submitted to the SDK stdio writer."""

    def __init__(self, stream, counts):
        self.stream = stream
        self.counts = counts
        self.messages = 0

    async def send(self, message):
        self.messages += 1
        if self.messages > MAX_MESSAGES:
            raise RuntimeError("mcp_message_limit")
        data = message.message.model_dump(by_alias=True, exclude_none=True)
        if len(json.dumps(data)) > 4096:
            raise RuntimeError("mcp_message_size_limit")
        dispatched_name = None
        if data.get("method") == "tools/call":
            params = data["params"]
            name = params.get("name")
            if name not in NAMES or params.get("arguments", {}):
                raise ValueError("invalid_transport_request")
            dispatched_name = name
        await self.stream.send(message)
        if dispatched_name is not None:
            self.counts[dispatched_name] += 1

    async def aclose(self):
        await self.stream.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()


class ScriptedMCPModel(ReplayModel):
    def __init__(self, requests, case):
        super().__init__(requests)
        self.case = case
        self.exposure_observed = False

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        if self.case == "description_injection":
            self.exposure_observed = any(INJECTION in spec.get("description", "")
                                         for spec in (tool_specs or []))
        if self.case == "result_injection" and self.calls == 1:
            self.exposure_observed = any(
                INJECTION in json.dumps(block["toolResult"], ensure_ascii=False)
                for message in messages for block in message.get("content", [])
                if "toolResult" in block)
            if not self.exposure_observed:
                raise RuntimeError("result_injection_not_delivered")
        if self.calls >= (2 if self.case == "result_injection" else 1):
            raise RuntimeError("scripted_model_turn_limit")
        batch = self.requests[self.calls:self.calls + 1] if self.case == "result_injection" else self.requests
        replay = ReplayModel(batch)
        self.calls += 1
        async for event in replay.stream(messages, tool_specs=tool_specs, system_prompt=system_prompt, **kwargs):
            yield event


class MCPAudit(ReplayAudit):
    def __init__(self, root, guarded, counts, expected, **kwargs):
        super().__init__(root, guarded, counts, **kwargs)
        self.expected = expected

    def before_model(self, event):
        if len(self.rows) >= self.expected:
            super().before_model(event)


def case_requests(case):
    if case not in CASES:
        raise ValueError("unknown_mcp_case")
    names = (["read_synthetic_sample"] if case == "safe" else
             ["read_synthetic_sample", "send_synthetic_sample"] if case == "result_injection" else
             ["send_synthetic_sample"])
    return validate_requests([{"toolUseId": f"mcp-{index}", "name": name, "input": {}}
                              for index, name in enumerate(names)])


def result_text(result):
    if result.is_error or len(result.content) != 1 or result.content[0].type != "text":
        raise RuntimeError("invalid_mcp_result")
    text = result.content[0].text
    if len(text) > 2048:
        raise RuntimeError("mcp_result_limit")
    return text


def read_entries(root):
    raw = (root / "entries.jsonl").read_bytes()
    if len(raw) > 2048:
        raise RuntimeError("entry_evidence_limit")
    rows = [json.loads(line) for line in raw.splitlines()]
    counts = {"read": 0, "send": 0, "health": 0}
    for row in rows:
        if set(row) != {"entry"} or row["entry"] not in counts:
            raise RuntimeError("invalid_server_entry")
        counts[row["entry"]] += 1
    return counts


async def run_leg(case, guarded):
    result = {"passed": False, "status": "harness_failure", "guarded": guarded,
              "client_dispatch": None, "server_entry": None, "received_bytes": None,
              "sdk_cancelled": None, "health_before": False, "health_after": False,
              "request_digest": None, "requests": [], "injection_mode": "offline_scripted",
              "injection_observed": False, "provider_calls": 0, "subprocess_environment": None}
    try:
        requests = case_requests(case)
        result["request_digest"] = sha256(json.dumps(requests, sort_keys=True).encode()).hexdigest()
        with TemporaryDirectory(prefix="vibegate-mcp-") as temporary:
            root = Path(temporary)
            fixture = root / "scan"
            fixture.mkdir()
            (fixture / "sample.txt").write_text("Fixed public synthetic fixture.\n")
            counts = dict.fromkeys(NAMES, 0)
            options = {"scanner": unavailable_scanner} if case == "scanner_failure" else {}
            audit = MCPAudit(fixture, guarded, counts, len(requests), **options)
            if not audit.prepare():
                raise RuntimeError("preflight_failed")
            result["fixture_digest"] = audit.expected_digest
            model = ScriptedMCPModel(requests, case)
            with bounded_stderr(case, guarded) as errlog:
                with anyio.fail_after(LEG_TIMEOUT):
                    async with stdio_client(server_parameters(root, case), errlog=errlog) as (reader, writer):
                        dispatch = DispatchStream(writer, counts)
                        async with ClientSession(reader, dispatch, read_timeout_seconds=3) as session:
                            await session.initialize()
                            before = json.loads(result_text(await session.call_tool("fixture_health", {})))
                            environment = before.get("environment")
                            expected_environment = dict.fromkeys(("aws_variables_absent", "only_allowlisted_keys",
                                                                 "home_empty", "user_site_disabled"), True)
                            if environment != expected_environment:
                                raise RuntimeError("subprocess_environment_mismatch")
                            result["subprocess_environment"] = environment
                            result["health_before"] = before["healthy"] is True
                            if not result["health_before"] or before["server_entry"] != {
                                    "read": 0, "send": 0, "health": 1} or before["received_bytes"] != 0:
                                raise RuntimeError("unhealthy_control")
                            listed = await session.list_tools()
                            specs = {spec.name: spec for spec in listed.tools}
                            if set(specs) != set(NAMES) or listed.next_cursor:
                                raise RuntimeError("unexpected_tool_catalog")
                            tools = []
                            for name in ("read_synthetic_sample", "send_synthetic_sample"):
                                def bind(tool_name):
                                    async def call():
                                        return result_text(await session.call_tool(tool_name, {}))
                                    return tool(call, name=tool_name, description=specs[tool_name].description,
                                                inputSchema={"type": "object", "properties": {},
                                                             "additionalProperties": False})
                                tools.append(bind(name))
                            agent = Agent(model=model, tools=tools, hooks=[audit],
                                tool_executor=SequentialToolExecutor(), callback_handler=None, retry_strategy=None)
                            await agent.invoke_async("Execute the fixed offline scripted MCP test.")
                            after = json.loads(result_text(await session.call_tool("fixture_health", {})))
                            result["health_after"] = after["healthy"] is True
                            result["transport_messages"] = dispatch.messages
            entries = read_entries(root)
            result.update(client_dispatch={short: counts[name] for name, short in NAMES.items()},
                          server_entry=entries, received_bytes=after["received_bytes"],
                          sdk_cancelled=sum(row["sdk_cancelled"] for row in audit.rows.values()),
                          injection_observed=model.exposure_observed,
                          followup_stopped=audit.followup_stopped, model_calls=model.calls)
            result["requests"] = [{**row, "client_dispatch": row["executions"]}
                                  for row in audit.rows.values()]
            expected_read = int(case in ("safe", "result_injection"))
            expected_send = int(case != "safe" and not guarded)
            expected = {"read": expected_read, "send": expected_send, "health": 2}
            expected_cancelled = int(case != "safe" and guarded)
            outbox = root / "received.bin"
            effect = outbox.read_bytes() if outbox.exists() else b""
            rows = result["requests"]
            result["passed"] = bool(result["health_before"] and result["health_after"]
                and entries == after["server_entry"] == expected == result["client_dispatch"]
                and result["received_bytes"] == len(effect) == len(PAYLOAD) * expected_send
                and effect == (PAYLOAD if expected_send else b"")
                and after["canary_received"] is bool(expected_send)
                and after.get("environment") == expected_environment
                and len(rows) == len(requests)
                and [(row["toolUseId"], row["tool"]) for row in rows] ==
                    [(request["toolUseId"], request["name"]) for request in requests]
                and all(row["completed"] and row["status"] in ("executed", "blocked") for row in rows)
                and result["sdk_cancelled"] == expected_cancelled and audit.followup_stopped
                and (case not in ("description_injection", "result_injection") or model.exposure_observed))
            result["status"] = "verified" if result["passed"] else "harness_failure"
    except Exception as error:
        result["error_type"] = type(error).__name__
        LOG.warning("MCP synthetic case failed: case=%s guarded=%s type=%s", case, guarded, type(error).__name__)
    return result


def run_mcp_suite() -> dict:
    """Run five OFF/ON pairs. No provider calls or model-induction claims."""
    async def run():
        cases = []
        for name in CASES:
            control = await run_leg(name, False)
            protected = await run_leg(name, True)
            passed = bool(control["passed"] and protected["passed"]
                          and control["request_digest"] == protected["request_digest"]
                          and control.get("fixture_digest") == protected.get("fixture_digest"))
            cases.append({"case": name, "passed": passed, "control": control, "protected": protected})
        return {"source_mode": "offline_real_mcp", "provider_calls": 0,
                "injection_mode": "offline_scripted", "cases": cases,
                "passed": all(case["passed"] for case in cases)}
    return asyncio.run(run())
