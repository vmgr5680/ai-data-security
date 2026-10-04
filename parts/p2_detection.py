"""Part 2: How Sensitive Data Detection Actually Works.

Every printed result in the article, in article order. The only change
from the article's snippets: one shared analyzer instead of a new
AnalyzerEngine() per snippet, so the spaCy model loads once.
"""
import json
import re
import statistics
import time

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import AnalyzerEngine

from ai_data_security.detect import _nlp, default_analyzer, drop_nested

analyzer = default_analyzer()


def section(title):
    print(f"\n== {title} ==")


section("four spellings, plus the canonical sample")
for ssn in ["900-12-3456", "900 12 3456", "900123456",
            "nine zero zero one two three four five six",
            "123-45-6789"]:
    text = f"My SSN is {ssn}"
    findings = analyzer.analyze(text=text, language="en")
    print(ssn)
    for f in findings:
        print(f"    {f.entity_type:<18} {f.score:.2f}")
    if not findings:
        print("    nothing")

section("the other two deny-listed samples")
for ssn in ["078-05-1120", "987-65-4320"]:
    text = f"My SSN is {ssn}"
    print(ssn, [(f.entity_type, round(f.score, 2))
                for f in analyzer.analyze(text=text, language="en")])

section("custom EMPLOYEE_ID recognizer")
emp_analyzer = AnalyzerEngine(nlp_engine=_nlp())   # its own registry
text = "Please reassign ticket T-55 from EMP-100417 to EMP-200932."


def show(label):
    print(label)
    for f in emp_analyzer.analyze(text=text, language="en"):
        value = text[f.start:f.end]
        print(f"    {f.entity_type:<18} {value:<11} {f.score:.2f}")


show("before:")
emp_analyzer.registry.add_recognizer(PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[Pattern(name="emp id", regex=r"\bEMP-\d{6}\b", score=0.9)],
    context=["employee", "emp", "staff", "reassign"],
))
show("after:")

section("checksums (Luhn)")
for card in ["4111 1111 1111 1111", "4111 1111 1111 1112",
             "1234 5678 9012 3456"]:
    print(card, [(card[f.start:f.end], f.entity_type, round(f.score, 2))
                 for f in analyzer.analyze(text=card, language="en")])

section("named-entity recognition")
for sentence in ["John Smith visited Dallas Children's Hospital.",
                 "John went to the hospital yesterday."]:
    print(sentence)
    for f in analyzer.analyze(text=sentence, language="en"):
        print(f"   ->  {f.entity_type:<9} {sentence[f.start:f.end]!r:<14} "
              f"{f.score:.2f}")

section("context words")
for text in ["The patient was born in 1985.",
             "The invoice number is 1985.",
             "Date of Birth: 04/12/1985",
             "Invoice: 04/12/1985",
             "Invoice date: 04/12/1985"]:
    for f in analyzer.analyze(text=text, language="en"):
        print(f"{text:<31} {f.entity_type}  {f.score:.2f}")

section("JSON: values alone vs values plus field names as context")
record = {"customer_name": "John Smith", "customer_id": "CUST-88231",
          "date_of_birth": "04/12/1985", "ssn": "900-12-3456"}
for field, value in record.items():
    words = [field, *field.split("_")]
    bare = analyzer.analyze(text=value, language="en")
    ctx = analyzer.analyze(text=value, language="en", context=words)
    for b, c in zip(bare, ctx):
        print(f"{field:<14} {b.entity_type:<10} "
              f"bare {b.score:.2f}   +field name {c.score:.2f}")

section("semantic gap: a medical tool response")
response = ("Customer ID: 45892\nName: Sarah Johnson\nDOB: 08/22/1991\n"
            "Medical condition: Asthma\nInsurance ID: XYZ12345")
for f in analyzer.analyze(text=response, language="en"):
    print(f"{f.entity_type:<10} {response[f.start:f.end]!r:<17} {f.score:.2f}")

section("precision and recall on ten hard lines")
THRESHOLD = 0.4
CORPUS = [
    ("My SSN is 900-12-3456.", {"900-12-3456"}),
    ("SSN 900 12 3456 is on file.", {"900 12 3456"}),
    ("Call Maria Lopez about the refund.", {"Maria Lopez"}),
    ("Card 4111 1111 1111 1111 was declined.", {"4111 1111 1111 1111"}),
    ("Email jane.doe@example.com for access.", {"jane.doe@example.com"}),
    ("Please reassign EMP-100417.", {"EMP-100417"}),
    ("SSN: nine zero zero one two three four five six",
     {"nine zero zero one two three four five six"}),
    ("Order ORD-12345 shipped Tuesday.", set()),
    ("Invoice 900123456 was paid.", set()),
    ("Ticket 4111 1111 1111 1112 is closed.", set()),
]


def measure(post=lambda fs: fs, verbose=True):
    tp = fp = fn = 0
    for text, truly_sensitive in CORPUS:
        found = post(analyzer.analyze(text=text, language="en"))
        flagged = {text[f.start:f.end] for f in found
                   if f.score >= THRESHOLD}
        tp += len(flagged & truly_sensitive)
        fn += len(truly_sensitive - flagged)
        fp += len(flagged - truly_sensitive)
        if verbose:
            for v in sorted(truly_sensitive - flagged):
                print("missed:     ", v)
            for v in sorted(flagged - truly_sensitive):
                print("false alarm:", v)
    print(f"TP={tp}  FP={fp}  FN={fn}")
    print(f"precision = {tp}/{tp + fp} = {tp / (tp + fp):.0%}")
    print(f"recall    = {tp}/{tp + fn} = {tp / (tp + fn):.0%}")


measure()
print("-- with drop_nested --")
measure(drop_nested, verbose=False)

section("latency, p95 over 40 runs (machine-dependent)")
record = {"customer_name": "John Smith", "ssn": "900-12-3456",
          "date_of_birth": "04/12/1985", "notes": "Called about a refund."}
sentence = "My SSN is 900-12-3456."
payload = json.dumps([record] * 50)
ssn_regex = re.compile(r"\b\d{3}[- .]\d{2}[- .]\d{4}\b")


def p95_ms(fn, runs=40):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.quantiles(times, n=20)[-1]


cases = [
    ("regex only, payload", lambda: ssn_regex.findall(payload)),
    ("analyzer, sentence", lambda: analyzer.analyze(sentence, "en")),
    ("analyzer, payload", lambda: analyzer.analyze(payload, "en")),
]
print(f"payload size        {len(payload):>7,} chars")
for name, fn in cases:
    print(f"{name:<19} {p95_ms(fn):7.2f} ms")
