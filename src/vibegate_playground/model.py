"""Scripted model output; real Strands loop/hooks/tools, no provider API calls."""

import json
import re

from strands.models.model import Model


def validate_requests(requests):
    """Accept only bounded, argument-free requests for the synthetic replay tools."""
    if not isinstance(requests, (list, tuple)) or len(requests) > 8:
        raise ValueError("invalid_request_batch")
    validated = []
    seen = set()
    for request in requests:
        if not isinstance(request, dict) or set(request) != {"toolUseId", "name", "input"}:
            raise ValueError("invalid_request_shape")
        identifier = request["toolUseId"]
        if (not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
                or identifier in seen):
            raise ValueError("invalid_request_id")
        if request["name"] not in ("read_synthetic_sample", "send_synthetic_sample"):
            raise ValueError("unknown_replay_tool")
        if not isinstance(request["input"], dict) or request["input"]:
            raise ValueError("replay_arguments_forbidden")
        seen.add(identifier)
        validated.append({"toolUseId": identifier, "name": request["name"], "input": {}})
    return tuple(validated)


class AttemptModel(Model):
    def __init__(self, attempts: int = 1):
        self.calls = 0
        self.attempts = attempts
        self.config = {"model_id": "scripted-adversarial-tool-attempt"}

    def update_config(self, **model_config):
        self.config.update(model_config)

    def get_config(self):
        return self.config

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        self.calls += 1
        yield {"messageStart": {"role": "assistant"}}
        if self.calls <= self.attempts:
            yield {"contentBlockStart": {"contentBlockIndex": 0, "start": {
                "toolUse": {"toolUseId": f"attempt-{self.calls}", "name": "perform_demo_action"}}}}
            yield {"contentBlockDelta": {"contentBlockIndex": 0,
                                         "delta": {"toolUse": {"input": "{}"}}}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"contentBlockIndex": 0,
                                         "delta": {"text": "Attempt complete. Inspect host evidence."}}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "end_turn"}}

    async def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):
        raise NotImplementedError("This test model only emits tool attempts")
        yield


class ReplayModel(AttemptModel):
    """Offline request replay. This class makes no claim of provider provenance."""

    def __init__(self, requests):
        super().__init__()
        self.requests = validate_requests(requests)
        self.config = {"model_id": "offline-request-replay"}

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs):
        self.calls += 1
        yield {"messageStart": {"role": "assistant"}}
        if self.calls == 1 and self.requests:
            for index, request in enumerate(self.requests):
                yield {"contentBlockStart": {"contentBlockIndex": index, "start": {
                    "toolUse": {"toolUseId": request["toolUseId"], "name": request["name"]}}}}
                yield {"contentBlockDelta": {"contentBlockIndex": index,
                    "delta": {"toolUse": {"input": json.dumps(request["input"])}}}}
                yield {"contentBlockStop": {"contentBlockIndex": index}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockDelta": {"contentBlockIndex": 0,
                "delta": {"text": "Offline replay complete."}}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "end_turn"}}
