"""Opt-in live Strands smoke test: at most two provider requests per run."""

import argparse
from datetime import datetime, timezone
import json
import logging
import re
from threading import Lock
from pathlib import Path
from tempfile import TemporaryDirectory

import boto3
from botocore.config import Config
from strands import Agent, tool
from strands.models import BedrockModel
from ai_security_rules.strands_gate import VibeGateHook


class ProviderCallLimit(RuntimeError):
    """The operator's client request allowance is exhausted."""


class BoundedBedrockModel(BedrockModel):
    def __init__(self, *, call_limit=2, **kwargs):
        if type(call_limit) is not int or call_limit not in (1, 2):
            raise ValueError("invalid_call_limit")
        self.calls = 0
        self.call_limit = call_limit
        self._budget_lock = Lock()
        super().__init__(**kwargs)
        # SDK-internal retries must cross the same budget as new agent turns.
        self.client.converse_stream = self._bounded(self.client.converse_stream)
        self.client.converse = self._bounded(self.client.converse)

    def _bounded(self, request):
        def invoke(*args, **kwargs):
            with self._budget_lock:
                if self.calls >= self.call_limit:
                    raise ProviderCallLimit("provider_call_limit")
                self.calls += 1
            return request(*args, **kwargs)
        return invoke


def redact_error(message):
    text = str(message)
    text = re.sub(r"arn:aws[^\s\"']*", "[ARN]", text)
    text = re.sub(r"https?://[^\s]+", "[URL]", text)
    text = re.sub(r"\b\d{12}\b", "[ACCOUNT]", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+", "[EMAIL]", text)
    text = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[ACCESS_KEY]", text)
    text = re.sub(r"[A-Za-z0-9/+=_-]{40,}", "[OPAQUE_VALUE]", text)
    return text[:2000]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-paid-inference", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--max-calls", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    if not args.allow_paid_inference:
        parser.error("Explicit paid-inference approval required")
    logging.basicConfig(level=logging.ERROR)
    # Reserve evidence before any network call; an existing report prevents reruns.
    with args.report.open("x", encoding="utf-8") as report:
        result = {"started_at": datetime.now(timezone.utc).isoformat(),
                  "model": "global.amazon.nova-2-lite-v1:0",
                  "region": "ap-southeast-2", "max_calls": args.max_calls,
                  "max_output_tokens_per_call": 256, "passed": False}
        model = None
        executions = []
        hook = None
        try:
            with TemporaryDirectory(prefix="vibegate-live-synthetic-") as temp:
                root = Path(temp)
                (root / "sample.txt").write_text("Synthetic public sample.\n", encoding="utf-8")
                hook = VibeGateHook(root, frozenset({"read_synthetic_sample"}),
                                    policy=lambda name: not executions)
                if not hook.prepare():
                    raise RuntimeError("preflight_failed")

                @tool
                def read_synthetic_sample() -> str:
                    """Read the fixed public synthetic sample; takes no arguments."""
                    executions.append(True)
                    return (root / "sample.txt").read_text(encoding="utf-8")

                session = boto3.Session(profile_name="vibegate-dev", region_name=result["region"])
                model = BoundedBedrockModel(
                    call_limit=args.max_calls,
                    boto_session=session,
                    boto_client_config=Config(connect_timeout=10, read_timeout=30,
                                              retries={"total_max_attempts": 1, "mode": "standard"}),
                    model_id=result["model"], max_tokens=256, temperature=0,
                )
                agent = Agent(model=model, tools=[read_synthetic_sample], hooks=[hook],
                              callback_handler=None, retry_strategy=None)
                agent("Call read_synthetic_sample exactly once with no arguments, then briefly report its result.")
                result["passed"] = (len(executions) == 1 and len(hook.decisions) == 1
                                     and hook.decisions[0].allowed)
        except Exception as error:
            result["error_type"] = type(error).__name__
            if isinstance(error, ProviderCallLimit):
                result["error_reason"] = "provider_call_limit"
            if hasattr(error, "response"):
                result["aws_error_code"] = error.response.get("Error", {}).get("Code", "unknown")
                result["aws_error_message_redacted"] = redact_error(
                    error.response.get("Error", {}).get("Message", ""))
        finally:
            result["provider_calls_attempted"] = model.calls if model else 0
            result["tool_executions"] = len(executions)
            result["decisions"] = hook.evidence() if hook else []
            result["finished_at"] = datetime.now(timezone.utc).isoformat()
            json.dump(result, report, indent=2)
            report.write("\n")
            print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
