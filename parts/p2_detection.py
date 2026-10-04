"""Part 2: How Sensitive Data Detection Actually Works.

Every printed result in the article, in article order, one function per
claim. The article names the function next to each result, so you can find
the code behind any number:

    four_spellings()          the four spellings, plus the canonical 123-45-6789
    deny_listed_samples()     the other two deny-listed sample numbers
    score_breakdown()         0.85 = pattern 0.50 + context 0.35 from "SSN"
    employee_id_recognizer()  a custom recognizer, and the wrong answer it leaves
    same_span_overlap()       900-77-3301 as US_SSN and US_ITIN; resolve_overlaps
    checksums()               Luhn: one valid test card, two that fail
    named_entities()          NER, and the ORG label Presidio drops by default
    context_words()           where context words help, and where they don't
    json_field_context()      JSON values alone vs values plus field names
    semantic_gap()            a medical tool response, fragment by fragment
    precision_recall()        ten hard lines, then the same with drop_nested
    handwritten_config()      the same ten lines, hand-written spaCy config
    latency()                 p95 timings, and the share spent in spaCy

The one change from the article's snippets: one shared analyzer instead of a
new AnalyzerEngine() per snippet, so the spaCy model loads once.
"""
import json
import re
import statistics
import time

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ai_data_security.detect import (Finding, _nlp, default_analyzer,
                                     drop_nested, resolve_overlaps)

analyzer = default_analyzer()


def section(title):
    print(f"\n== {title} ==")


def four_spellings():
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


def deny_listed_samples():
    section("the other two deny-listed samples")
    for ssn in ["078-05-1120", "987-65-4320"]:
        text = f"My SSN is {ssn}"
        print(ssn, [(f.entity_type, round(f.score, 2))
                    for f in analyzer.analyze(text=text, language="en")])


def explain(engine, text):
    """Print each finding's pattern score, final score and boosting word."""
    for f in engine.analyze(text=text, language="en",
                            return_decision_process=True):
        e = f.analysis_explanation
        print(f"    {f.entity_type:<18} {text[f.start:f.end]:<12} "
              f"pattern {e.original_score:.2f} -> {f.score:.2f}  "
              f"context word: {e.supportive_context_word or '-'}")


def score_breakdown():
    section("where 0.85 comes from")
    explain(analyzer, "My SSN is 900-12-3456")


def employee_id_recognizer():
    section("custom EMPLOYEE_ID recognizer")
    emp_analyzer = AnalyzerEngine(nlp_engine=_nlp())   # its own registry
    text = "Please reassign ticket T-55 from EMP-100417 to EMP-200932."

    def show(label):
        print(label)
        for f in emp_analyzer.analyze(text=text, language="en"):
            value = text[f.start:f.end]
            print(f"    {f.entity_type:<18} {value:<11} {f.score:.2f}")

    show("before:")
    employee_id = PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[Pattern(name="emp id", regex=r"\bEMP-\d{6}\b", score=0.9)],
        context=["employee", "emp", "staff", "reassign"],
    )
    emp_analyzer.registry.add_recognizer(employee_id)
    show("after:")
    print("which word boosted it:")
    explain(emp_analyzer, "Please reassign EMP-100417.")


def same_span_overlap():
    section("two recognizers, one span")
    text = "Chargeback opened for John Smith, SSN 900-77-3301."
    found = [Finding("", f.entity_type, text[f.start:f.end], f.score,
                     f.start, f.end)
             for f in analyzer.analyze(text=text, language="en")]
    for f in found:
        print(f"    found  {f.entity_type:<8} {f.value:<12} {f.score:.2f}")
    for f in resolve_overlaps(found):
        print(f"    kept   {f.entity_type:<8} {f.value:<12} {f.score:.2f}")


def checksums():
    section("checksums (Luhn)")
    for card in ["4111 1111 1111 1111", "4111 1111 1111 1112",
                 "1234 5678 9012 3456"]:
        print(card, [(card[f.start:f.end], f.entity_type, round(f.score, 2))
                     for f in analyzer.analyze(text=card, language="en")])


def named_entities():
    section("named-entity recognition")
    for sentence in ["John Smith visited Dallas Children's Hospital.",
                     "John went to the hospital yesterday."]:
        print(sentence)
        for f in analyzer.analyze(text=sentence, language="en"):
            print(f"   ->  {f.entity_type:<9} {sentence[f.start:f.end]!r:<14} "
                  f"{f.score:.2f}")
    section("what spaCy found, and what Presidio ignores by default")
    nlp_engine = analyzer.nlp_engine
    for sentence in ["John Smith visited Dallas Children's Hospital.",
                     "John went to the hospital yesterday."]:
        doc = nlp_engine.nlp["en"](sentence)
        print([(e.text, e.label_) for e in doc.ents])
    ignored = nlp_engine.ner_model_configuration.labels_to_ignore
    print("ORGANIZATION ignored by default:", "ORGANIZATION" in ignored)


def context_words():
    section("context words")
    for text in ["The patient was born in 1985.",
                 "The invoice number is 1985.",
                 "Date of Birth: 04/12/1985",
                 "Invoice: 04/12/1985",
                 "Invoice date: 04/12/1985"]:
        for f in analyzer.analyze(text=text, language="en"):
            print(f"{text:<31} {f.entity_type}  {f.score:.2f}")


def json_field_context():
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


def semantic_gap():
    section("semantic gap: a medical tool response")
    response = ("Customer ID: 45892\nName: Sarah Johnson\nDOB: 08/22/1991\n"
                "Medical condition: Asthma\nInsurance ID: XYZ12345")
    for f in analyzer.analyze(text=response, language="en"):
        print(f"{f.entity_type:<10} {response[f.start:f.end]!r:<17} "
              f"{f.score:.2f}")


THRESHOLD = 0.4
CORPUS = [  # (text, the values a human says are sensitive)
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


def measure(engine=None, post=lambda fs: fs, verbose=True):
    engine = engine or analyzer
    tp = fp = fn = 0
    for text, truly_sensitive in CORPUS:
        found = post(engine.analyze(text=text, language="en"))
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


def precision_recall():
    section("precision and recall on ten hard lines")
    measure()
    print("-- with drop_nested --")
    measure(post=drop_nested, verbose=False)


def handwritten_config():
    section("same ten lines, hand-written spaCy config")
    # Names the model but leaves out Presidio's NER label mapping, so spaCy's
    # ORG label comes through as ORGANIZATION instead of being ignored.
    config = {"nlp_engine_name": "spacy",
              "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]}
    engine = AnalyzerEngine(
        nlp_engine=NlpEngineProvider(nlp_configuration=config).create_engine())
    measure(engine, verbose=False)


def latency():
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

    def median_ms(fn, runs=20):
        fn()
        times = []
        for _ in range(runs):
            start = time.perf_counter()
            fn()
            times.append((time.perf_counter() - start) * 1000)
        return statistics.median(times)

    full = median_ms(lambda: analyzer.analyze(payload, "en"))
    spacy = median_ms(lambda: analyzer.nlp_engine.process_text(payload, "en"))
    print(f"share spent in the spaCy pipeline: {spacy / full:.0%}")


if __name__ == "__main__":
    four_spellings()
    deny_listed_samples()
    score_breakdown()
    employee_id_recognizer()
    same_span_overlap()
    checksums()
    named_entities()
    context_words()
    json_field_context()
    semantic_gap()
    precision_recall()
    handwritten_config()
    latency()
