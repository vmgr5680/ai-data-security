"""Part 3: Detection Is Half the Problem.

Every printed result in the article, in article order, one function per
claim. The article names the function next to each result, so you can find
the code behind any output:

    mask()                 mask the SSN, keep the last four
    redact_vs_replace()    redact deletes the value; replace leaves a marker
    redaction_linkage()    three support lines, one name, redacted
    encrypt_round_trip()   encrypt every finding, then decrypt with the key
    encrypt_linkage()      the same SSN encrypted twice: two ciphertexts
    misses_pass_through()  a missed SSN and a low-score SSN, at a 0.5 threshold
    hash_salts()           Presidio's hash: default (random salt) vs fixed salt
    unsalted_sha256()      the timed search against a plain SHA-256 of an SSN
    keyed_hash()           the fix: a keyed hash (HMAC) keeps linkage, needs a key

The brute-force run covers one million numbers (every SSN starting 900-) and
extrapolates to the full one billion from the measured rate.
"""
import hashlib
import hmac
import time

from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig

from ai_data_security.detect import default_analyzer

analyzer = default_analyzer()
anonymizer = AnonymizerEngine()
text = "Patient John Smith, SSN 900-12-3456, has diabetes."
findings = analyzer.analyze(text=text, language="en")
twice = "SSN 900-12-3456 on file; caller confirmed 900-12-3456."
ssn_hits = analyzer.analyze(text=twice, language="en", entities=["US_SSN"])
key = "WmZq4t7w!z%C&F)J"  # demo only: a real key lives in a KMS


def section(title):
    print(f"\n== {title} ==")


def mask():
    section("mask")
    result = anonymizer.anonymize(
        text=text, analyzer_results=findings,
        operators={"US_SSN": OperatorConfig("mask", {
            "masking_char": "X", "chars_to_mask": 7, "from_end": False})})
    print(result.text)


def redact_vs_replace():
    section("redact vs replace")
    for op, params in [("redact", {}), ("replace", {"new_value": "<SSN>"})]:
        result = anonymizer.anonymize(
            text=text, analyzer_results=findings,
            operators={"US_SSN": OperatorConfig(op, params)})
        print(f"{op:8} {result.text}")


def redaction_linkage():
    section("redaction destroys linkage")
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


def encrypt_round_trip():
    section("encrypt, then decrypt")
    enc = anonymizer.anonymize(
        text=text, analyzer_results=findings,
        operators={"DEFAULT": OperatorConfig("encrypt", {"key": key})})
    for item in sorted(enc.items, key=lambda i: i.start):
        print(f"{item.entity_type:7} {item.text}   (ciphertext differs per run)")
    dec = DeanonymizeEngine().deanonymize(
        text=enc.text, entities=enc.items,
        operators={"DEFAULT": OperatorConfig("decrypt", {"key": key})})
    print(dec.text)


def encrypt_linkage():
    section("encrypt the same SSN twice: no linkage")
    enc = anonymizer.anonymize(
        text=twice, analyzer_results=ssn_hits,
        operators={"US_SSN": OperatorConfig("encrypt", {"key": key})})
    ciphers = [i.text for i in sorted(enc.items, key=lambda i: i.start)]
    print("same ciphertext both times:", ciphers[0] == ciphers[1])


def misses_pass_through():
    section("what the detector misses, every operator allows")
    for line in ["My SSN is nine zero zero one two three four five six.",
                 "My SSN is 900123456."]:
        hits = analyzer.analyze(text=line, language="en")
        print([(x.entity_type, round(x.score, 2)) for x in hits])
        kept = [x for x in hits if x.score >= 0.5]   # a 0.5 threshold
        out = anonymizer.anonymize(text=line, analyzer_results=kept)
        print("  at 0.5:", out.text)


def hash_salts():
    section("hash operator: default (random salt) vs fixed salt")
    for params in [{}, {"salt": "a-fixed-16b-salt"}]:
        result = anonymizer.anonymize(
            text=twice, analyzer_results=ssn_hits,
            operators={"US_SSN": OperatorConfig("hash", params)})
        hashes = [i.text for i in sorted(result.items, key=lambda i: i.start)]
        print(params or "default", "-> same hash both times:",
              hashes[0] == hashes[1])


def h(ssn: str) -> str:
    return hashlib.sha256(ssn.encode()).hexdigest()


def unsalted_sha256():
    section("unsalted SHA-256 of an SSN, attacked")
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


def keyed_hash():
    section("the fix: a keyed hash (HMAC) keeps linkage, needs the key")
    k = b"from-a-kms-in-production"
    k1 = hmac.new(k, b"900-12-3456", hashlib.sha256).hexdigest()[:16]
    k2 = hmac.new(k, b"900-12-3456", hashlib.sha256).hexdigest()[:16]
    print("same value, same keyed hash:", k1 == k2, k1 + "...")


if __name__ == "__main__":
    mask()
    redact_vs_replace()
    redaction_linkage()
    encrypt_round_trip()
    encrypt_linkage()
    misses_pass_through()
    hash_salts()
    unsalted_sha256()
    keyed_hash()
