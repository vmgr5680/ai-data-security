"""A tokenize-on-write gate for agent memory (Part 6).

Memory exists to keep continuity, and continuity is linkage, so the default
is to tokenize rather than redact. Two additions to Part 6's sketch:

* a **deny list of topics** the policy says never belong in memory, because
  the detector has no entity type for "a recent cardiac procedure";
* a **retention** field on every note, so "forever" is a choice rather than
  the absence of one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .detect import scan_text
from .vault import Vault

TOKENIZE = {"PERSON", "US_SSN", "US_BANK_NUMBER", "EMAIL_ADDRESS",
            "PHONE_NUMBER", "CUSTOMER_ID", "CREDIT_CARD"}

# Policy, not detection: meaning-level topics a detector cannot see.
NEVER_STORE = re.compile(
    r"\b(cardiac|diagnos\w*|surgery|procedure|pregnan\w*|hiv|"
    r"salary|disciplinary)\b", re.I)


@dataclass
class Note:
    text: str
    retention_days: int


@dataclass
class MemoryGate:
    vault: Vault
    scope: str
    retention_days: int = 30
    store: list[Note] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)   # reasons, not text

    def remember(self, note: str, analyzer=None) -> str | None:
        topic = NEVER_STORE.search(note)
        if topic:
            self.refused.append(f"topic:{topic.group(0).lower()}")
            return None
        hits = [f for f in scan_text(note, analyzer)
                if f.entity_type in TOKENIZE]
        safe, _ = self.vault.tokenize(note, hits, self.scope)
        self.store.append(Note(safe, self.retention_days))
        return safe
