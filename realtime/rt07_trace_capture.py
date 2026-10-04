"""rt07: the tracing system keeps the prompt the guardrail just cleaned.

Real-world shape: LLM observability. OpenTelemetry's generative-AI
conventions keep prompt and completion text out of spans by default, and
instrumentation libraries let you opt in (commonly with the environment
variable OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT). Teams turn it
on to debug, and the trace store becomes a copy of every prompt.

Gap it exposes: the series protects what goes *to the model*. Part 7
protects the audit log. Traces are a third copy that neither covers, and
the span is usually recorded *before* the guardrail runs, around the whole
agent turn.
"""
import json

from ai_data_security.detect import scan_record
from ai_data_security.output import scan_output

tool_result = {"customer": {"name": "John Smith", "ssn": "900-12-3456"}}
prompt_to_model, _ = scan_output(
    "Explain the failed payment for John Smith, SSN 900-12-3456.")

span = {  # what an agent-turn span looks like with content capture on
    "name": "invoke_agent support",
    "attributes": {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.input.messages": json.dumps(
            [{"role": "tool", "content": json.dumps(tool_result)}]),
        "gen_ai.output.messages": json.dumps(
            [{"role": "assistant", "content": "Card declined twice."}]),
        "gen_ai.usage.input_tokens": 412,
    },
}

print("prompt the model received:", prompt_to_model)
print("span holds the raw SSN:   ", "900-12-3456" in json.dumps(span))

CONTENT_KEYS = {"gen_ai.input.messages", "gen_ai.output.messages",
                "gen_ai.system_instructions"}


def scrub_span(span: dict, keep_content: bool = False) -> dict:
    """An exporter-side processor: drop content, or keep it scanned."""
    attrs = {}
    for key, value in span["attributes"].items():
        if key not in CONTENT_KEYS:
            attrs[key] = value
        elif keep_content:
            found = scan_record(json.loads(value))
            attrs[key] = f"<{len(found)} finding(s): " + ", ".join(
                sorted({f.entity_type for f in found})) + ">" \
                if found else value
    return {**span, "attributes": attrs}


for keep in (False, True):
    out = scrub_span(span, keep_content=keep)
    print(f"\nscrubbed (keep_content={keep}):")
    print(json.dumps(out["attributes"], indent=2))
    print("holds the raw SSN:", "900-12-3456" in json.dumps(out))
