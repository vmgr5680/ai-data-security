"""Part 3: Detection Is Half the Problem.

Mask, redact next to replace, encrypt round trip, the hash operator with
and without a salt, and the unsalted SHA-256 search. The brute-force run
covers one million numbers (every SSN starting 900-) and extrapolates
to the full one billion from the measured rate.
"""
import hashlib
import time

from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig

from ai_data_security.detect import default_analyzer

analyzer = default_analyzer()
anonymizer = AnonymizerEngine()
text = "Patient John Smith, SSN 900-12-3456, has diabetes."
findings = analyzer.analyze(text=text, language="en")

print("== mask ==")
result = anonymizer.anonymize(
    text=text, analyzer_results=findings,
    operators={"US_SSN": OperatorConfig("mask", {
        "masking_char": "X", "chars_to_mask": 7, "from_end": False})})
print(result.text)

print("\n== redact vs replace ==")
for op, params in [("redact", {}), ("replace", {"new_value": "<SSN>"})]:
    result = anonymizer.anonymize(
        text=text, analyzer_results=findings,
        operators={"US_SSN": OperatorConfig(op, params)})
    print(f"{op:8} {result.text}")

print("\n== redaction destroys linkage ==")
history = ("John Smith purchased a laptop on the 3rd. "
           "John Smith returned the laptop on the 9th. "
           "John Smith contacted support about a refund.")
hits = analyzer.analyze(text=history, language="en")
print([(h.entity_type, history[h.start:h.end], h.score) for h in hits])
red = anonymizer.anonymize(
    text=history, analyzer_results=hits,
    operators={"DEFAULT": OperatorConfig("replace",
                                         {"new_value": "[REDACTED]"})})
print(red.text.replace(". ", ".\n"))

print("\n== encrypt, then decrypt ==")
key = "WmZq4t7w!z%C&F)J"  # demo only: a real key lives in a KMS
enc = anonymizer.anonymize(
    text=text, analyzer_results=findings,
    operators={"DEFAULT": OperatorConfig("encrypt", {"key": key})})
for item in sorted(enc.items, key=lambda i: i.start):
    print(f"{item.entity_type:7} {item.text}   (ciphertext differs per run)")
dec = DeanonymizeEngine().deanonymize(
    text=enc.text, entities=enc.items,
    operators={"DEFAULT": OperatorConfig("decrypt", {"key": key})})
print(dec.text)

print("\n== hash operator: default (random salt) vs fixed salt ==")
twice = "SSN 900-12-3456 on file; caller confirmed 900-12-3456."
ssn_hits = analyzer.analyze(text=twice, language="en", entities=["US_SSN"])
for params in [{}, {"salt": "a-fixed-16b-salt"}]:
    result = anonymizer.anonymize(
        text=twice, analyzer_results=ssn_hits,
        operators={"US_SSN": OperatorConfig("hash", params)})
    hashes = [i.text for i in sorted(result.items, key=lambda i: i.start)]
    print(params or "default", "-> same hash both times:",
          hashes[0] == hashes[1])

print("\n== unsalted SHA-256 of an SSN, attacked ==")


def h(ssn: str) -> str:
    return hashlib.sha256(ssn.encode()).hexdigest()


leaked = h("900-12-3456")
start = time.perf_counter()
for n in range(1_000_000):
    guess = f"900-{n // 10_000:02d}-{n % 10_000:04d}"
    if h(guess) == leaked:
        print("found:", guess)
elapsed = time.perf_counter() - start
rate = 1_000_000 / elapsed
print(f"rate: {rate:,.0f} hashes/sec")
print(f"all 1,000,000,000: {1e9 / rate / 60:.1f} minutes (extrapolated)")

print("\n== the fix: a keyed hash (HMAC) keeps linkage, needs the key ==")
import hmac  # noqa: E402

KEY = b"from-a-kms-in-production"
k1 = hmac.new(KEY, b"900-12-3456", hashlib.sha256).hexdigest()[:16]
k2 = hmac.new(KEY, b"900-12-3456", hashlib.sha256).hexdigest()[:16]
print("same value, same keyed hash:", k1 == k2, k1 + "...")
