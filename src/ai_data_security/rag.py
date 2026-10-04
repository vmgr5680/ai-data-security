"""Retrieval with the two controls in the right order (Part 6).

Control 1 answers *whether*: the entitlement filter runs inside the search,
so the retriever can never return a chunk the user may not have, and a chunk
with no label fails closed. Control 2 answers *how much*: whatever survives
is scanned and transformed before it reaches the model.

The "search" here is a keyword-overlap ranker over a Python list. A vector
database does the same job with a metadata filter; the order of the two
controls is the part that carries over.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Finding, scan_text


@dataclass(frozen=True)
class Chunk:
    id: str
    text: str
    label: str | None = None          # None: indexed before labels existed
    source: str = ""


@dataclass
class Retrieved:
    kept: list[Chunk] = field(default_factory=list)
    findings: dict[str, list[Finding]] = field(default_factory=dict)


def _score(query: str, text: str) -> int:
    words = {w.strip(".,?").lower() for w in query.split()}
    return sum(w.strip(".,?").lower() in words for w in text.split())


def search(query: str, chunks: list[Chunk], allowed: set[str],
           k: int = 5) -> list[Chunk]:
    """Filter *inside* the search: unentitled chunks are never ranked."""
    visible = [c for c in chunks if c.label in allowed]   # None -> excluded
    return sorted(visible, key=lambda c: -_score(query, c.text))[:k]


def search_then_filter(query: str, chunks: list[Chunk], allowed: set[str],
                       k: int = 5) -> list[Chunk]:
    """The tempting shortcut: rank everything, discard afterwards."""
    top = sorted(chunks, key=lambda c: -_score(query, c.text))[:k]
    return [c for c in top if c.label in allowed]


def retrieve(query: str, chunks: list[Chunk], allowed: set[str],
             k: int = 5, analyzer=None) -> Retrieved:
    out = Retrieved(kept=search(query, chunks, allowed, k))
    for c in out.kept:
        out.findings[c.id] = scan_text(c.text, analyzer)
    return out
