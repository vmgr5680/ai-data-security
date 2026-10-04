"""rt01: an engineer pastes code into an AI assistant.

Real-world shape: in April 2023, Samsung semiconductor engineers pasted
source code and a meeting transcript into ChatGPT on three occasions in
about three weeks; Samsung then restricted generative-AI tools on company
devices. (Forbes, 2 May 2023.)

Gap it exposes: the series' detectors look for *personal* data. Part 1
lists "confidential business information" as the fourth group of sensitive
data, but no default recognizer finds an access key, a token or a password.
The AWS key is the example from AWS's own documentation; the GitHub token
and password are made up in the published formats.
"""
from ai_data_security.detect import default_analyzer, house_analyzer

paste = '''Can you fix the retry bug in this?

import boto3
s3 = boto3.client("s3", aws_access_key_id="AKIAIOSFODNN7EXAMPLE")
DB_URL = "postgres://billing:password=Tr0ub4dor&3@db.internal/prod"
GH = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
# escalations: priya.shah@example.com
'''

for name, analyzer in [("default detector", default_analyzer()),
                       ("with house recognizers", house_analyzer())]:
    hits = analyzer.analyze(paste, language="en", score_threshold=0.4)
    print(f"== {name}: {len(hits)} finding(s) ==")
    for h in sorted(hits, key=lambda h: h.start):
        shown = paste[h.start:h.end]
        shown = shown[:6] + "..." if h.entity_type == "SECRET" else shown
        print(f"  {h.entity_type:<14} {shown:<24} {h.score:.2f}")

# The secrets are now caught. The code itself is not, and cannot be: the
# thing Samsung actually lost (source code, a meeting transcript) has no
# entity type. For that, the control is where the paste is allowed to go
# (an approved, contracted assistant), which is a policy decision, not a
# detection one.
print("\nsource code detected as sensitive:",
      any(h.entity_type == "SOURCE_CODE" for h in
          house_analyzer().analyze(paste, language="en")))
