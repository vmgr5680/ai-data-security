"""The door out: scanning what the model says (Part 6, plus two gaps).

``scan_output`` is Part 6's backstop. Two production problems it does not
handle on its own:

* **Streaming.** Models send answers in chunks. A value split across two
  chunks is invisible to a scanner that looks at each chunk alone.
  ``StreamScanner`` holds back a short tail until it is safe to release.
* **Links as a channel.** A model's answer can carry data *out* inside a
  URL, for example a Markdown image the client fetches automatically.
  That is the exfiltration path in the Slack AI (2024) and EchoLeak (2025)
  reports. ``guard_links`` removes links to hosts that are not allow-listed,
  because the value in the URL is often encoded and the detector cannot
  read it.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer import RecognizerResult

from .detect import THRESHOLD, house_analyzer

_anonymizer = AnonymizerEngine()


def scan_output(completion: str, analyzer=None,
                threshold: float = THRESHOLD) -> tuple[str, list[str]]:
    analyzer = analyzer or house_analyzer()
    hits = analyzer.analyze(completion, language="en",
                            score_threshold=threshold)
    if not hits:
        return completion, []
    safe = _anonymizer.anonymize(completion, hits).text
    return safe, sorted({h.entity_type for h in hits})


class StreamScanner:
    """Release streamed text only once no value can straddle the cut.

    Keeps the last ``holdback`` characters unreleased, cuts at whitespace,
    and scans each released segment together with a little already-released
    context, so a word like "SSN" before the cut still boosts the score.
    """

    def __init__(self, analyzer=None, holdback: int = 48,
                 context_chars: int = 40, threshold: float = THRESHOLD):
        self.analyzer = analyzer or house_analyzer()
        self.holdback, self.context_chars = holdback, context_chars
        self.threshold = threshold
        self._pending, self._released_raw = "", ""

    def _release(self, segment: str) -> str:
        ctx = self._released_raw[-self.context_chars:]
        text = ctx + segment
        hits = [h for h in self.analyzer.analyze(
                    text, language="en", score_threshold=self.threshold)
                if h.start >= len(ctx)]
        self._released_raw += segment
        if not hits:
            return segment
        shifted = [RecognizerResult(h.entity_type, h.start - len(ctx),
                                    h.end - len(ctx), h.score) for h in hits]
        return _anonymizer.anonymize(segment, shifted).text

    def feed(self, chunk: str) -> str:
        self._pending += chunk
        if len(self._pending) <= self.holdback:
            return ""
        cut = self._pending.rfind(" ", 0, len(self._pending) - self.holdback)
        if cut <= 0:
            return ""
        segment, self._pending = self._pending[:cut + 1], self._pending[cut + 1:]
        return self._release(segment)

    def close(self) -> str:
        segment, self._pending = self._pending, ""
        return self._release(segment) if segment else ""


_LINK = re.compile(r"(!?)\[([^\]]*)\]\((\S+?)\)|(https?://\S+)")


def guard_links(completion: str, allowed_hosts: set[str]) -> tuple[str, list[str]]:
    """Drop Markdown links, images and bare URLs to non-allow-listed hosts."""
    removed: list[str] = []

    def swap(m: re.Match) -> str:
        url = m.group(3) or m.group(4)
        host = urlparse(url).hostname or ""
        if host in allowed_hosts:
            return m.group(0)
        removed.append(host)
        if m.group(3):                      # [text](url) or ![alt](url)
            return "" if m.group(1) else m.group(2)
        return "[link removed]"
    return _LINK.sub(swap, completion), removed
