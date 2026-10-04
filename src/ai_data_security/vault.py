"""Consistent tokens and a guarded way back (Parts 4 and 7).

Part 4's ``Tokenizer`` kept its map in a dictionary inside the application
and revealed with plain string replacement. This version fixes the three
defects the series found or implied, and one the series did not reach:

1. **Scope travels with the token.** Every mapping is keyed by a scope
   (tenant, and optionally session). A token minted in one tenant's scope
   cannot be revealed from another's. Part 4's per-request run gave two
   customers the same ``PERSON_001``; a shared, unscoped map is the
   cross-tenant version of the same bug.
2. **Whole-token reveal.** ``PERSON_1000`` no longer reveals as
   ``PERSON_100`` plus a stray zero.
3. **Reveal only what this request was given.** A model can write a token
   it never saw (``PERSON_002``). With a session-wide vault that token may
   be real, and a naive reveal prints a customer who was never part of this
   conversation. ``reveal(..., allowed=...)`` refuses tokens that were not
   in the request's own input.
4. **The ladder.** ``reveal_ladder`` answers with the least information that
   serves the purpose (Part 7's selective reveal).

Every reveal, allowed or refused, is handed to an audit callback. The
callback receives token and scope, never the value.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Callable, Iterable

from .detect import Finding, field_context, resolve_overlaps, scan_text

TOKEN_RE = re.compile(r"\b([A-Z][A-Z_]*?_\d{3,})\b")

AuditHook = Callable[[dict], None]


class Vault:
    def __init__(self, audit: AuditHook | None = None):
        self._to_token: dict[tuple, str] = {}
        self._to_value: dict[tuple, str] = {}
        self._counters: dict[tuple, int] = {}
        self._audit = audit or (lambda event: None)

    # -- tokenize -----------------------------------------------------------
    def token_for(self, scope: str, entity_type: str, value: str) -> str:
        key = (scope, entity_type, value)
        if key not in self._to_token:
            n = self._counters.get((scope, entity_type), 0) + 1
            self._counters[(scope, entity_type)] = n
            token = f"{entity_type}_{n:03d}"
            self._to_token[key] = token
            self._to_value[(scope, token)] = value
        return self._to_token[key]

    def tokenize(self, text: str, findings: Iterable[Finding],
                 scope: str) -> tuple[str, set[str]]:
        """Replace each finding with its token. Returns text and tokens used."""
        used = set()
        for f in reversed(resolve_overlaps(list(findings))):
            token = self.token_for(scope, f.entity_type, f.value)
            used.add(token)
            text = text[:f.start] + token + text[f.end:]
        return text, used

    def tokenize_record(self, obj, scope: str, analyzer=None,
                        field: str = "") -> tuple[object, set[str]]:
        """Tokenize every string value in a JSON-like object, in place of
        scanning its serialized form. Keys are never touched."""
        if isinstance(obj, dict):
            out, used = {}, set()
            for key, val in obj.items():
                out[key], u = self.tokenize_record(
                    val, scope, analyzer, f"{field}.{key}".lstrip("."))
                used |= u
            return out, used
        if isinstance(obj, list):
            pairs = [self.tokenize_record(v, scope, analyzer, field)
                     for v in obj]
            return [p[0] for p in pairs], set().union(*(p[1] for p in pairs))
        if not isinstance(obj, str):
            return obj, set()
        return self.tokenize(obj, scan_text(obj, analyzer,
                                            context=field_context(field)),
                             scope)

    # -- reveal -------------------------------------------------------------
    def reveal(self, text: str, scope: str, caller: str,
               allowed: set[str] | None = None) -> str:
        """Resolve whole tokens that belong to ``scope``.

        ``allowed``: the tokens this request actually handed the model.
        Anything else the model wrote stays as a token and is audited.
        """
        def swap(match: re.Match) -> str:
            token = match.group(1)
            value = self._to_value.get((scope, token))
            if value is None:
                self._audit({"event": "reveal", "token": token,
                             "scope": scope, "caller": caller,
                             "outcome": "unknown_in_scope"})
                return token
            if allowed is not None and token not in allowed:
                self._audit({"event": "reveal", "token": token,
                             "scope": scope, "caller": caller,
                             "outcome": "refused_not_in_request"})
                return token
            self._audit({"event": "reveal", "token": token, "scope": scope,
                         "caller": caller, "outcome": "revealed"})
            return value
        return TOKEN_RE.sub(swap, text)

    def forget(self, scope: str, value: str) -> int:
        """Right to erasure: destroy every original equal to ``value``.

        Tokens stay in logs and memory, but nothing resolves them any more.
        Returns how many mappings were removed.
        """
        doomed = [k for k, v in self._to_value.items()
                  if k[0] == scope and v == value]
        for key in doomed:
            del self._to_value[key]
        for key in [k for k in self._to_token if k[0] == scope
                    and k[2] == value]:
            del self._to_token[key]
        return len(doomed)


# -- the reveal ladder (Part 7) ---------------------------------------------
def reveal_ladder(dob: date, rung: str, today: date) -> str | None:
    """Answer a question about a birth date with the least it needs."""
    age = today.year - dob.year - ((today.month, today.day)
                                   < (dob.month, dob.day))
    low = age // 10 * 10 - (5 if age % 10 < 5 else -5)
    return {
        "full": dob.isoformat(),
        "partial": dob.strftime("%B %Y"),
        "derived": f"age {age}",
        "range": f"age {low}-{low + 9}",
        "boolean": f"is over 18: {'yes' if age >= 18 else 'no'}",
        "absent": None,
    }[rung]


LADDER = ["full", "partial", "derived", "range", "boolean", "absent"]
