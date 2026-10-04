"""Part 8: Choosing Your AI Data Security Architecture.

Step 1 of the one-week test (a candidate scorecard) and step 6 (search the
audit record for the value). Add a vendor by writing one function that
takes text and returns the set of values it flagged.
"""
import json
import re
import statistics
import time

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from ai_data_security.detect import default_analyzer, house_analyzer

engine = default_analyzer()


def presidio(text):
    return {text[r.start:r.end]
            for r in engine.analyze(text=text, language="en")
            if r.score >= 0.4}


def presidio_house(text):
    """Same library plus your own formats: the cheapest upgrade."""
    return {text[r.start:r.end]
            for r in house_analyzer().analyze(text=text, language="en")
            if r.score >= 0.4}


SSN = r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"
PHONE = r"\b\d{3}-\d{3}-\d{4}\b"
PATTERN = re.compile(f"{SSN}|{PHONE}")


def regex_only(text):
    return set(PATTERN.findall(text))


CORPUS = [
    ("SSN 900-12-3456 on file.", {"900-12-3456"}),
    ("SSN 900 12 3456 on file.", {"900 12 3456"}),
    ("SSN 900123456 on file.", {"900123456"}),
    ("Call Dana Reyes on 212-555-0147.", {"Dana Reyes", "212-555-0147"}),
    ('{"customer_name": "Dana Reyes"}', {"Dana Reyes"}),
    ("Ticket 100-20-3000 closed by support.", set()),
    ("Order ORD-12345 shipped to the depot.", set()),
]


def score(detect, runs=20):
    tp = fp = fn = 0
    times = []
    for text, truth in CORPUS:
        flagged = detect(text)
        tp += len(flagged & truth)
        fp += len(flagged - truth)
        fn += len(truth - flagged)
        for _ in range(runs):
            t0 = time.perf_counter()
            detect(text)
            times.append((time.perf_counter() - t0) * 1000)
    p95 = statistics.quantiles(times, n=20)[-1]
    return tp / (tp + fp), tp / (tp + fn), p95


print("== step 1: candidate scorecard (latency is machine-dependent) ==")
print(f"{'candidate':<16}{'precision':>10}{'recall':>8}{'p95 ms':>8}")
for name, fn_ in [("regex_only", regex_only), ("presidio", presidio),
                  ("presidio_house", presidio_house)]:
    p, r, ms = score(fn_)
    print(f"{name:<16}{p:>10.0%}{r:>8.0%}{ms:>8.3f}")

print("\n== step 6: search the audit record for the value ==")
text = "Customer Dana Reyes, SSN 900-12-3456, phone 212-555-0147."
values = ["Dana Reyes", "900-12-3456", "212-555-0147", "0147"]
ops = {
    "PERSON": OperatorConfig("keep"),
    "PHONE_NUMBER": OperatorConfig("mask", {
        "masking_char": "*", "chars_to_mask": 8, "from_end": False}),
    "US_SSN": OperatorConfig("replace", {"new_value": "<SSN>"}),
}
found = engine.analyze(text=text, language="en")
out = AnonymizerEngine().anonymize(text, found, operators=ops)
print(out.text)
naive = json.loads(out.to_json())
typed = {"entities": sorted(i.entity_type for i in out.items),
         "operators": sorted(i.operator for i in out.items)}
for name, record in [("naive", naive), ("typed", typed)]:
    blob = json.dumps(record)
    print(name, "leaks:", [v for v in values if v in blob])
