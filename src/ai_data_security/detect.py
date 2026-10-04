"""Finding sensitive values (Part 2).

The framework does this for you: patterns, checksums, NER and context words,
via Presidio. This module adds the pieces the series says are yours to build:

* one shared spaCy pipeline, so several analyzers do not each load the model;
* house recognizers for formats only your company uses (Part 1's CUST-88231,
  Part 2's EMP-100417) and for secrets, which no default recognizer covers;
* a JSON walker that scans each value with its field name as context,
  instead of scanning ``json.dumps(payload)`` (Part 2, "the fix");
* ``drop_nested``, the overlap rule from Part 2's precision run.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from presidio_analyzer import (AnalyzerEngine, Pattern, PatternRecognizer,
                               RecognizerResult)
from presidio_analyzer.nlp_engine import NlpEngineProvider

THRESHOLD = 0.4  # the cut-off the series has used since Part 2


@lru_cache(maxsize=1)
def _nlp():
    # Presidio's own default configuration (en_core_web_lg plus its NER
    # label mapping). A hand-written config silently changes the results:
    # without the mapping, ORGANIZATION findings appear everywhere.
    return NlpEngineProvider().create_engine()


@lru_cache(maxsize=1)
def default_analyzer() -> AnalyzerEngine:
    """Presidio exactly as the articles ran it: nothing customized."""
    return AnalyzerEngine(nlp_engine=_nlp())


def house_recognizers() -> list[PatternRecognizer]:
    """Formats no general-purpose detector ships knowing."""
    return [
        PatternRecognizer(
            supported_entity="CUSTOMER_ID",
            patterns=[Pattern("cust id", r"\bCUST-\d{5}\b", 0.9)],
            context=["customer", "cust", "account"]),
        PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            patterns=[Pattern("emp id", r"\bEMP-\d{6}\b", 0.9)],
            context=["employee", "emp", "staff", "reassign"]),
        # Presidio's email recognizer checks the top-level domain against the
        # public list, so ops@acme.internal or ops@acme.corp is not an email
        # to it. Internal domains are exactly what enterprise data carries.
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            patterns=[Pattern("email, any domain",
                              r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 0.6)]),
        # Secrets: the "confidential business information" group from
        # Part 1 that no default recognizer covers. Patterns follow the
        # vendors' published key formats.
        PatternRecognizer(
            supported_entity="SECRET",
            patterns=[
                Pattern("aws access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
                        0.95),
                Pattern("github token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
                        0.95),
                Pattern("private key block",
                        r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0.95),
                Pattern("password assignment",
                        r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+", 0.7),
            ]),
    ]


@lru_cache(maxsize=1)
def house_analyzer() -> AnalyzerEngine:
    """The default analyzer plus your own formats and secret patterns."""
    engine = AnalyzerEngine(nlp_engine=_nlp())
    for recognizer in house_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine


@dataclass(frozen=True)
class Finding:
    field: str          # dotted path inside a record; "" for plain text
    entity_type: str
    value: str
    score: float
    start: int
    end: int


def drop_nested(findings: list[RecognizerResult]) -> list[RecognizerResult]:
    """Drop a finding that sits inside a larger one (Part 2)."""
    return [f for f in findings
            if not any(g.start <= f.start and f.end <= g.end
                       and g.end - g.start > f.end - f.start
                       for g in findings)]


def resolve_overlaps(findings: list["Finding"]) -> list["Finding"]:
    """Keep one finding per region of text: highest score, then longest.

    Needed before any transformation. Two recognizers can report the
    *same* span (``900-77-3301`` is both a US_SSN at 0.85 and a US_ITIN at
    0.5); replacing it twice shifts the text and eats the next character.
    """
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda f: (-f.score, -(f.end - f.start))):
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def scan_text(text: str, analyzer: AnalyzerEngine | None = None,
              threshold: float = THRESHOLD, context: list[str] | None = None,
              field: str = "") -> list[Finding]:
    analyzer = analyzer or house_analyzer()
    results = analyzer.analyze(text=text, language="en", context=context,
                               score_threshold=threshold)
    results = drop_nested(results)
    return [Finding(field, r.entity_type, text[r.start:r.end], r.score,
                    r.start, r.end)
            for r in sorted(results, key=lambda r: r.start)]


def field_context(field: str) -> list[str]:
    """``customer.date_of_birth`` -> ["date_of_birth", "date", "of", "birth"]"""
    name = field.split(".")[-1].split("[")[0]
    return [name, *name.split("_")] if name else []


def scan_record(obj, analyzer: AnalyzerEngine | None = None,
                threshold: float = THRESHOLD, field: str = "") -> list[Finding]:
    """Scan every string value in a JSON-like object, field name as context.

    Field names are never submitted as data, so a key such as
    ``date_of_birth`` can no longer come back as a PERSON (Part 1).
    """
    if isinstance(obj, dict):
        return [hit for key, val in obj.items()
                for hit in scan_record(val, analyzer, threshold,
                                       f"{field}.{key}".lstrip("."))]
    if isinstance(obj, (list, tuple)):
        return [hit for i, val in enumerate(obj)
                for hit in scan_record(val, analyzer, threshold,
                                       f"{field}[{i}]")]
    if not isinstance(obj, str):
        return []
    return scan_text(obj, analyzer, threshold, field_context(field), field)
