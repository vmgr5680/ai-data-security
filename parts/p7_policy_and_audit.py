"""Part 7: Policy, Access Control, and Audit.

The five-case policy table, the purpose-binding test, detect-mask-audit
with the no-value check, the query by subject, and the reveal ladder
(whose code the article cut for length).
"""
import json
from datetime import date

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from ai_data_security.audit import AuditLog, ValueInAuditRecord
from ai_data_security.detect import default_analyzer
from ai_data_security.policy import (Context, Decision, POLICY_VERSION, decide,
                                     decide_strict, purpose_for)
from ai_data_security.vault import LADDER, reveal_ladder

CASES = [
    Context("u-481", "support_rep", "support", "customer_db",
            "US_SSN", "identity_verification", "internal"),
    Context("u-481", "support_rep", "analytics", "customer_db",
            "US_SSN", "marketing_analysis", "internal"),
    Context("u-481", "support_rep", "support", "shipping_api",
            "PERSON", "order_lookup", "external"),
    Context("u-207", "fraud_analyst", "fraud", "fraud_vendor",
            "US_SSN", "fraud_check", "contracted"),
    Context("u-481", "support_rep", "support", "case_notes",
            "PERSON", "case_summary", "internal"),
]

print("== five requests through decide() ==")
print(f"{'action':<10}{'role':<15}{'agent':<11}{'entity':<8}"
      f"{'purpose':<22}dest")
for c in CASES:
    d = decide(c)
    print(f"{d.action.upper():<10}{c.role:<15}{c.agent:<11}"
          f"{c.entity_type:<8}{c.purpose:<22}{c.destination}")

print("\n== who writes the purpose? ==")


def ask(purpose):
    c = Context("u-481", "support_rep", "analytics", "customer_db",
                "US_SSN", purpose, "internal")
    return decide(c).action.upper()


print("honest claim:  ", ask("marketing_analysis"))
print("helpful claim: ", ask("fraud_check"))
print("bound to entry:", ask(purpose_for("/analytics/run",
                                         claimed="fraud_check")))

print("\n== fail closed on context nobody anticipated ==")
odd = Context("u-481", "support_rep", "summarizer-v2", "customer_db",
              "US_SSN", purpose_for("/new/endpoint"), "internal")
print("decide():       ", decide(odd).action.upper(), "-", decide(odd).reason)
print("decide_strict():", decide_strict(odd).action.upper(), "-",
      decide_strict(odd).reason)

print("\n== detect, mask, audit, and check the record for the value ==")
analyzer = default_analyzer()
text = "Caller John Smith, SSN 900-12-3456, wants to update his address."
ssn = [r for r in analyzer.analyze(text, language="en")
       if r.entity_type == "US_SSN"][0]
original = text[ssn.start:ssn.end]
print("found", ssn.entity_type, "score", ssn.score)
ctx = CASES[0]
d = decide(ctx)
mask = OperatorConfig("mask", {"masking_char": "X",
                               "chars_to_mask": 7, "from_end": False})
shown = AnonymizerEngine().anonymize(text, [ssn], {"US_SSN": mask})
print(d.action, "->", shown.text)

log = AuditLog()
record = log.record(ctx, d, "PERSON_001", protected_values=(original,))
debug = {"redacted": original,
         "replacement": shown.text[ssn.start:ssn.end]}
for name, rec in [("audit record", record), ("debug line", debug)]:
    print(f"{name:<13} contains the SSN:", original in json.dumps(rec))

print("\n== the library refuses a record that carries the value ==")
bad = Decision(d.action, f"masked {original}")   # the reason quotes it
try:
    log.record(ctx, bad, "PERSON_001", protected_values=(original,))
except ValueInAuditRecord as e:
    print("refused:", e)

print("\n== who obtained PERSON_001's SSN? ==")
SUBJECT = ["PERSON_001", "PERSON_001", "PERSON_002",
           "PERSON_001", "PERSON_001"]
full = AuditLog()
for c, s in zip(CASES, SUBJECT):
    full.record(c, decide(c), s)
denials = [r for r in full.records if r["action"] == "block"]
print("denials-only log:", [(r["actor"]["user"], r["actor"]["agent"],
                             r["action"]) for r in denials
                            if r["subject_ref"] == "PERSON_001"
                            and r["entity_type"] == "US_SSN"])
print("full log:")
for r in full.by_subject("PERSON_001", "US_SSN"):
    print("  ", (r["actor"]["user"], r["actor"]["agent"], r["action"]))
print("monitor summary:", dict(full.summary()))
print("policy version in every record:",
      all(r["policy_version"] == POLICY_VERSION for r in full.records))

print("\n== the reveal ladder: one birth date, six rungs ==")
for rung in LADDER:
    print(f"{rung:<8} {reveal_ladder(date(1985, 4, 12), rung, date(2026, 9, 20))}")
