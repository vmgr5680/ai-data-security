"""Part 4: Tokenization and the Privacy Vault.

The article's toy Tokenizer, run exactly as printed, then the defects it
names, then the library Vault that fixes them.
"""
import hashlib
import hmac

from ai_data_security.detect import default_analyzer, scan_text
from ai_data_security.vault import Vault

analyzer = default_analyzer()


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
            self._to_token[key] = token
            self._to_value[token] = value
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


print("== consistent tokens ==")
t = Tokenizer()
for line in ["John Smith purchased a laptop on the 3rd.",
             "John Smith returned the laptop on the 9th.",
             "John Smith contacted support about a refund."]:
    print(t.tokenize(line))

print("\n== per-request scope: two customers, one token ==")
print(Tokenizer().tokenize("John Smith purchased a laptop."))
print(Tokenizer().tokenize("Maria Garcia returned a laptop."))

print("\n== format-preserving tokens ==")
KEY = b"demo-only"


def fp_token(value):
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


card, ssn = "4111 1111 1111 1111", "900-12-3456"
print(card, "->", fp_token(card))
print(ssn, "->", fp_token(ssn))
print("Luhn check:", luhn_ok(card), "->", luhn_ok(fp_token(card)))

print("\n== what the detector thinks of each kind of token ==")
for text in ["Customer SSN 274-76-1817 on file.",
             "Customer SSN US_SSN_001 on file."]:
    found = analyzer.analyze(text=text, language="en")
    print(text, "->", [(r.entity_type, round(r.score, 2)) for r in found])

print("\n== the lab-record walk ==")
record = ("Patient John Smith, DOB 04/12/1985, SSN 900-12-3456.\n"
          "Hemoglobin 12.4. Diagnosis: diabetes. Phone 555-0142.")
t = Tokenizer()
print(t.tokenize(record))
reply = "PERSON_001 has a hemoglobin of 12.4 and a diagnosis of diabetes."
print(t.reveal(reply))
print(t.tokenize("Follow up with John Smith next week."))

print("\n== naive reveal with a thousand stored names ==")
t = Tokenizer()
for n in range(1, 1001):
    t._token_for("PERSON", f"Customer #{n}-A")
print("PERSON_1000 ->", t.reveal("PERSON_1000"))

print("\n== the library Vault: whole-token reveal, scoped ==")
v = Vault()
for n in range(1, 1001):
    v.token_for("tenant:acme", "PERSON", f"Customer #{n}-A")
print("PERSON_1000 ->", v.reveal("PERSON_1000", "tenant:acme", "clinician"))
print("from tenant:globex ->",
      v.reveal("PERSON_1000", "tenant:globex", "clinician"))
safe, used = v.tokenize(record, scan_text(record, analyzer),
                        "tenant:acme/session:7")
print(safe)
