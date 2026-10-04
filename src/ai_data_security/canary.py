"""Canary values: prove which sinks a sensitive value actually reached.

Precision and recall (Part 2) measure the detector. They do not tell you
whether the *system* leaks, because a value can reach a sink the detector
was never placed in front of. A canary answers that directly: plant a
unique, fake value at the source, run the real pipeline, then search every
sink for it. A hit is a leak path, with its name on it.
"""
from __future__ import annotations

import json
from collections import defaultdict


class Sinks:
    """Everywhere a pipeline writes: model input, logs, memory, traces..."""

    def __init__(self):
        self._data: dict[str, list[str]] = defaultdict(list)

    def write(self, sink: str, payload) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload)
        self._data[sink].append(text)

    def names(self) -> list[str]:
        return sorted(self._data)

    def containing(self, value: str) -> list[str]:
        return [s for s in self.names()
                if any(value in item for item in self._data[s])]


# Fake by construction: 900-series SSN (never issued), reserved TLD.
CANARY_SSN = "900-99-0417"
CANARY_EMAIL = "canary-0417@example.invalid"
