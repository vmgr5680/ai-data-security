"""decide(): context in, action and reason out (Part 7).

``decide`` is the function from Part 7, rule for rule, including its
context validation (missing fields, unknown destination or environment).
Two more things the article lists under "from this sketch to production"
are added around it:

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
VALID_DESTINATIONS = {"internal", "contracted", "external"}
VALID_ENVIRONMENTS = {"prod", "staging"}


def decide(c: Context) -> Decision:
    # Reject incomplete or unknown context before applying business rules.
    required = (c.user, c.role, c.agent, c.tool, c.entity_type,
                c.purpose, c.destination, c.environment)
    if not all(required):
        return Decision("block", "missing required decision context")
    if c.destination not in VALID_DESTINATIONS:
        return Decision("block", "unknown destination")
    if c.environment not in VALID_ENVIRONMENTS:
        return Decision("block", "unknown environment")

    if c.destination == "external" and c.entity_type in REGULATED:
        return Decision(
            "block", "regulated data may not leave the trust boundary")

    if c.agent == "analytics" and c.purpose not in NEEDS_IDENTITY:
        return Decision(
            "block", "analytics agent has no need for identified data")

    if c.entity_type == "US_SSN" and c.purpose == "identity_verification":
        return Decision(
            "mask", "verification needs recognition, not the value")

    if (c.destination == "contracted" and c.tool == "fraud_vendor"
            and c.agent == "fraud" and c.role == "fraud_analyst"
            and c.purpose == "fraud_check" and c.entity_type == "US_SSN"
            and c.environment == "prod"):
        return Decision(
            "allow", "explicit fraud workflow and approved vendor context")

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
