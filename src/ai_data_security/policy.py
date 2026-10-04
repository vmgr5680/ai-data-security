"""decide(): context in, action and reason out (Part 7).

``decide`` is the function from Part 7, rule for rule. Two things the
article lists under "from this sketch to production" are added around it,
not inside it, so the rules stay readable:

* ``purpose_for`` binds purpose to the entry point. Whatever the agent
  claims is ignored.
* ``decide_strict`` fails closed on context it does not recognize: an
  unknown agent, destination or purpose gets BLOCK with a reason, never a
  crash and never ALLOW.
"""
from __future__ import annotations

from dataclasses import dataclass

POLICY_VERSION = "2026-09-01"


@dataclass(frozen=True)
class Context:
    user: str
    role: str
    agent: str
    tool: str
    entity_type: str
    purpose: str
    destination: str        # internal | contracted | external
    environment: str = "prod"


@dataclass(frozen=True)
class Decision:
    action: str             # allow | mask | tokenize | block
    reason: str


REGULATED = {"US_SSN", "CREDIT_CARD"}
NEEDS_IDENTITY = {"identity_verification", "fraud_check"}


def decide(c: Context) -> Decision:
    if c.destination == "external" and c.entity_type in REGULATED:
        return Decision(
            "block", "regulated data may not leave the trust boundary")

    if c.agent == "analytics" and c.purpose not in NEEDS_IDENTITY:
        return Decision(
            "block", "analytics agent has no need for identified data")

    if c.entity_type == "US_SSN" and c.purpose == "identity_verification":
        return Decision(
            "mask", "verification needs recognition, not the value")

    if c.destination == "contracted" and c.purpose == "fraud_check":
        return Decision(
            "allow", "contracted processor, purpose requires original")

    return Decision(
        "tokenize", "default: preserve linkage, withhold value")


# -- around the rules ---------------------------------------------------------
ENTRY_PURPOSE = {
    "/support/verify": "identity_verification",
    "/support/chat": "order_lookup",
    "/fraud/review": "fraud_check",
    "/analytics/run": "marketing_analysis",
}
KNOWN_AGENTS = {"support", "analytics", "fraud", "coding"}
KNOWN_DESTINATIONS = {"internal", "contracted", "external"}


def purpose_for(entry_point: str, claimed: str | None = None) -> str:
    """Purpose comes from where the request entered. ``claimed`` is ignored."""
    return ENTRY_PURPOSE.get(entry_point, "unknown")


def decide_strict(c: Context) -> Decision:
    if c.agent not in KNOWN_AGENTS:
        return Decision("block", f"unknown agent {c.agent!r}")
    if c.destination not in KNOWN_DESTINATIONS:
        return Decision("block", f"unknown destination {c.destination!r}")
    if c.purpose == "unknown":
        return Decision("block", "no purpose bound to this entry point")
    return decide(c)
