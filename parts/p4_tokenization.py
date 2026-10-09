"""Part 4: Tokenization and the Privacy Vault.

Every printed result in the article, in article order, one function per
claim. The article prints the Tokenizer class in full and names the
function next to each other result, so you can find the code behind any
output:

    consistent_tokens()    three sentences, one name, one tokenizer
    per_request_scope()    a fresh tokenizer per call: two people, one token
    format_preserving()    a naive same-shape token, and the Luhn check
    detector_on_tokens()   what the detector says about each kind of token
    lab_walk()             tokenize a lab record, reveal a hard-coded reply
    overlapping_findings() one number, five findings, corrupted output
    naive_reveal()         PERSON_1000 revealed by substring replacement
    library_vault()        the Vault that fixes them: whole-token, scoped,
                           one finding per span

The cross-tenant and invented-token runs are realtime/rt04_cross_tenant.py
and realtime/rt06_invented_token.py.
"""
import hashlib
import hmac

from ai_data_security.detect import default_analyzer, scan_text
from ai_data_security.vault import Vault

analyzer = default_analyzer()
record = ("Patient John Smith, DOB 04/12/1985, SSN 900-12-3456.\n"
          "Hemoglobin 12.4. Diagnosis: diabetes. Phone 555-0142.")
ambiguous = "Customer SSN 900773301 on file."


class Tokenizer:                                  # verbatim from the article
    def __init__(self):
        self._to_token, self._to_value = {}, {}
        self._counters = {}

    def _token_for(self, entity_type, value):
        key = (entity_type, value)
        if key not in self._to_token:
            n = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = n
            token = f"{entity_type}_{n:03d}"
            self._to_token[key] = token       # value -> token
            self._to_value[token] = value     # token -> value
        return self._to_token[key]

    def tokenize(self, text):
        found = analyzer.analyze(text=text, language="en")
        spans = sorted(found, key=lambda r: r.start)
        tokens = [(r.start, r.end, self._token_for(
            r.entity_type, text[r.start:r.end])) for r in spans]
        for start, end, token in reversed(tokens):
            text = text[:start] + token + text[end:]
        return text

    def reveal(self, text):
        for token, value in self._to_value.items():
            text = text.replace(token, value)
        return text


def section(title):
    print(f"\n== {title} ==")


def consistent_tokens():
    section("consistent tokens")
    t = Tokenizer()
    for line in ["John Smith purchased a laptop on the 3rd.",
                 "John Smith returned the laptop on the 9th.",
                 "John Smith contacted support about a refund."]:
        print(t.tokenize(line))


def per_request_scope():
    section("per-request scope: two customers, one token")
    print(Tokenizer().tokenize("John Smith purchased a laptop."))
    print(Tokenizer().tokenize("Maria Garcia returned a laptop."))


KEY = b"demo-only"  # a real key lives in a KMS, never in code


def fp_token(value):
    """Same shape: digits stay digits, separators stay put."""
    mac = hmac.new(KEY, value.encode(), hashlib.sha256).hexdigest()
    fake = iter(str(int(mac, 16)))
    return "".join(next(fake) if c.isdigit() else c for c in value)


def luhn_ok(number):
    digits = [int(c) for c in number if c.isdigit()][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def format_preserving():
    section("format-preserving tokens")
    card, ssn = "4111 1111 1111 1111", "900-12-3456"
    print(card, "->", fp_token(card))
    print(ssn, "->", fp_token(ssn))
    print("Luhn check:", luhn_ok(card), "->", luhn_ok(fp_token(card)))


def detector_on_tokens():
    section("what the detector thinks of each kind of token")
    for text in ["Customer SSN 274-76-1817 on file.",
                 "Customer SSN US_SSN_001 on file."]:
        found = analyzer.analyze(text=text, language="en")
        print(text, "->", [(r.entity_type, round(r.score, 2)) for r in found])


def lab_walk():
    section("the lab-record walk")
    t = Tokenizer()
    print(t.tokenize(record))
    # The model's reply, hard-coded so the run needs no API key:
    reply = "PERSON_001 has a hemoglobin of 12.4 and a diagnosis of diabetes."
    print(t.reveal(reply))
    print(t.tokenize("Follow up with John Smith next week."))


def overlapping_findings():
    section("five findings on one span")
    print([r.entity_type
           for r in analyzer.analyze(text=ambiguous, language="en")])
    print(Tokenizer().tokenize(ambiguous))


def naive_reveal():
    section("naive reveal with a thousand stored names")
    t = Tokenizer()
    for n in range(1, 1001):
        t._token_for("PERSON", f"Customer #{n}-A")
    print("PERSON_1000 ->", t.reveal("PERSON_1000"))


def library_vault():
    section("the library Vault: whole-token reveal, scoped")
    v = Vault()
    for n in range(1, 1001):
        v.token_for("tenant:acme", "PERSON", f"Customer #{n}-A")
    print("PERSON_1000 ->", v.reveal("PERSON_1000", "tenant:acme", "clinician"))
    print("from tenant:globex ->",
          v.reveal("PERSON_1000", "tenant:globex", "clinician"))
    safe, _ = v.tokenize(record, scan_text(record, analyzer),
                         "tenant:acme/session:7")
    print(safe)
    safe, _ = v.tokenize(ambiguous, scan_text(ambiguous, analyzer),
                         "tenant:acme")
    print(safe)


if __name__ == "__main__":
    consistent_tokens()
    per_request_scope()
    format_preserving()
    detector_on_tokens()
    lab_walk()
    overlapping_findings()
    naive_reveal()
    library_vault()
