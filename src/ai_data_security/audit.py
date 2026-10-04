"""Audit records that prove what happened without holding the value (Part 7).

Three rules from the article, enforced in code:

* every decision is recorded, allows included;
* a record carries the entity *type* and a token as the subject reference,
  never the value — ``AuditLog.record`` refuses a record that contains any
  value it was told to protect;
* the store answers the two questions that arrive under pressure: by
  subject ("who obtained this person's SSN?") and by actor ("what did this
  agent touch?").

``summary`` is the MONITOR stage from Part 1's lifecycle in its smallest
form: counts per agent and action, so a spike in reveals is visible.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from .policy import POLICY_VERSION, Context, Decision


class ValueInAuditRecord(ValueError):
    pass


@dataclass
class AuditLog:
    records: list[dict] = field(default_factory=list)

    def record(self, ctx: Context, decision: Decision, subject_ref: str,
               protected_values: tuple[str, ...] = (),
               ts: str = "2026-09-20T10:32:04Z") -> dict:
        rec = {
            "ts": ts,
            "actor": {"user": ctx.user, "role": ctx.role, "agent": ctx.agent},
            "tool": ctx.tool,
            "entity_type": ctx.entity_type,
            "subject_ref": subject_ref,
            "purpose": ctx.purpose,
            "destination": ctx.destination,
            "action": decision.action,
            "reason": decision.reason,
            "policy_version": POLICY_VERSION,
        }
        blob = json.dumps(rec)
        leaked = [v for v in protected_values if v and v in blob]
        if leaked:
            raise ValueInAuditRecord(
                f"{len(leaked)} protected value(s) found in audit record")
        self.records.append(rec)
        return rec

    def by_subject(self, subject_ref: str, entity_type: str | None = None):
        return [r for r in self.records if r["subject_ref"] == subject_ref
                and (entity_type is None or r["entity_type"] == entity_type)]

    def by_actor(self, user: str | None = None, agent: str | None = None):
        return [r for r in self.records
                if (user is None or r["actor"]["user"] == user)
                and (agent is None or r["actor"]["agent"] == agent)]

    def summary(self) -> Counter:
        return Counter((r["actor"]["agent"], r["action"])
                       for r in self.records)
