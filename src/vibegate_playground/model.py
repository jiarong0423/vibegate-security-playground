"""Scripted model output; real Strands loop/hooks/tools, no provider API calls."""

from strands.models.model import Model


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
