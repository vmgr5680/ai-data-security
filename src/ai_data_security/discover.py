"""DISCOVER: where does sensitive data already sit? (lifecycle stage 1)

Part 1's lifecycle starts with DISCOVER, and it is the stage the series has
no article for. The failure it names is a store nobody catalogued: an
export in a shared folder, a log with request bodies in it, a wiki page
somebody pasted a customer record into, all waiting to be indexed for RAG.

``inventory`` walks a folder and reports, per file, which entity types
appear and how often. It never prints the values. CSV columns and JSON keys
are passed to the detector as context, the Part 2 fix.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

from .detect import field_context, scan_record, scan_text


def _scan_file(path: Path, analyzer) -> Counter:
    counts: Counter = Counter()
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                for column, value in row.items():
                    for f in scan_text(value or "", analyzer,
                                       context=field_context(column)):
                        counts[f.entity_type] += 1
    elif suffix in {".jsonl", ".json"}:
        lines = path.read_text().splitlines() if suffix == ".jsonl" \
            else [path.read_text()]
        for line in filter(None, lines):
            counts.update(f.entity_type
                          for f in scan_record(json.loads(line), analyzer))
    else:
        for line in path.read_text().splitlines():
            counts.update(f.entity_type for f in scan_text(line, analyzer))
    return counts


def inventory(folder: str | Path, analyzer=None) -> dict[str, Counter]:
    root = Path(folder)
    return {str(p.relative_to(root)): _scan_file(p, analyzer)
            for p in sorted(root.rglob("*")) if p.is_file()}
