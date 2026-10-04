"""Part 1: From PII Detection to AI Data Security.

Two runs over the tool response from the opening:
  1. the default detector over the serialized JSON (3 right, 1 missed,
     1 invented: the key "date_of_birth" as a PERSON);
  2. detect-then-replace, which silently renames that key.
Then the fix from Part 2, applied: scan values with field names as context.
Last, the article's harder shape: the misspelled name is still caught, the
spelled-out SSN is not.
"""
import json

from presidio_anonymizer import AnonymizerEngine

from ai_data_security.detect import default_analyzer, house_analyzer, scan_record

analyzer = default_analyzer()

tool_response = (
    '{"customer_name": "John Smith", "customer_id": "CUST-88231", '
    '"date_of_birth": "04/12/1985", "ssn": "900-12-3456", '
    '"account_balance": "$10,250", "payment_status": "Failed"}'
)

print("== 1. detector over the serialized tool response ==")
for finding in analyzer.analyze(text=tool_response, language="en"):
    value = tool_response[finding.start:finding.end]
    print(f"{finding.entity_type:<16} {value:<20} score={finding.score}")

print("\n== 2. detect, then replace everything flagged ==")
findings = analyzer.analyze(text=tool_response, language="en")
safe = AnonymizerEngine().anonymize(text=tool_response,
                                    analyzer_results=findings)
print(json.dumps(json.loads(safe.text), indent=2))

print("\n== 3. the fix: values only, field names as context, house formats ==")
for f in scan_record(json.loads(tool_response), house_analyzer()):
    print(f"{f.field:<16} {f.entity_type:<12} {f.value:<12} {f.score:.2f}")

print("\n== 4. same facts, harder shape: a misspelled name, a spelled-out SSN ==")
harder = ("Customer John Smiht's SSN is\n"
          "nine zero zero dash one two dash three four five six.")
found = analyzer.analyze(text=harder, language="en")
for finding in found:
    value = harder[finding.start:finding.end]
    print(f"{finding.entity_type:<16} {value:<20} score={finding.score}")
if not any(f.entity_type == "US_SSN" for f in found):
    print("US_SSN           (none found)")
