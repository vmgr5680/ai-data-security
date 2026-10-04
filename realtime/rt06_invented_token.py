"""rt06: the model writes a token it was never given, and reveal obeys.

Real-world shape: the reveal step in every tokenize-then-reveal design
(Part 4's clinician walk-through). Models copy tokens well, and they also
produce plausible new ones: asked about "the other patient", or completing
a pattern, a model can write a token it was never shown.

Gap it exposes: with a session-wide or permanent vault (Part 4's
"usual pragmatic choice"), that token may be a real person from earlier in
the session. A reveal that resolves every token it finds then shows the
clinician a patient who was never part of this answer's evidence.
"""
from ai_data_security.detect import scan_text
from ai_data_security.vault import Vault

events = []
vault = Vault(audit=events.append)
scope = "tenant:clinic/session:ward-4"

# Earlier in the session: another patient was discussed.
earlier = "Patient Maria Garcia, bed 12, allergy to penicillin."
vault.tokenize(earlier, scan_text(earlier), scope)

# This request: only John Smith's record goes to the model.
record = "Patient John Smith, hemoglobin 12.4, diagnosis: diabetes."
safe, given = vault.tokenize(record, scan_text(record), scope)
print("model input:   ", safe, "   tokens given:", sorted(given))

# The model's answer invents a comparison with a token it never saw.
reply = ("PERSON_002 has a hemoglobin of 12.4. Compared with PERSON_001 "
         "from the last review, no change.")
print("model output:  ", reply)

print("\nnaive reveal:  ", vault.reveal(reply, scope, "clinician"))
print("guarded reveal:", vault.reveal(reply, scope, "clinician",
                                      allowed=given))
print("\naudit:", [(e["token"], e["outcome"]) for e in events])
