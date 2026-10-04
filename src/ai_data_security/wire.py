"""Scanning tool calls in both directions (Part 5).

Part 5's decorator only reported. This one asks a policy function what to
do and then does it: pass, rewrite the payload, or raise ``Blocked`` so the
call never happens. The policy callback is where Part 7's ``decide()``
plugs in; this module never decides anything itself.
"""
from __future__ import annotations

from typing import Any, Callable

from .detect import Finding, scan_record

# on_findings(tool, direction, findings, payload) -> payload to use
Handler = Callable[[str, str, list[Finding], Any], Any]


class Blocked(Exception):
    """Raised when policy says a tool call must not happen."""

    def __init__(self, tool: str, direction: str, reason: str):
        super().__init__(f"{tool} [{direction}] blocked: {reason}")
        self.tool, self.direction, self.reason = tool, direction, reason


def guarded_tool(name: str, handler: Callable[..., Any],
                 on_findings: Handler, analyzer=None) -> Callable[..., Any]:
    """Wrap a tool so arguments and response both pass through policy."""
    def wrapper(**arguments):
        outbound = scan_record(arguments, analyzer)          # egress
        if outbound:
            arguments = on_findings(name, "egress", outbound, arguments)
        response = handler(**arguments)
        inbound = scan_record(response, analyzer)            # ingress
        if inbound:
            response = on_findings(name, "ingress", inbound, response)
        return response
    wrapper.__name__ = f"guarded_{name}"
    return wrapper


def report_only(tool: str, direction: str, findings: list[Finding],
                payload: Any) -> Any:
    """Part 5's stand-in: print what crossed, change nothing."""
    print(f"  [{direction}] {tool} carries")
    for f in findings:
        print(f"      {f.field:<15} {f.entity_type:<13} {f.score:.2f}")
    return payload
