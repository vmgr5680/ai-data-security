"""rt10: the same customer record in four languages, one English model.

Real-world shape: a support assistant serving customers in Spain, Germany
and India, with the detector configured the way every example in this
series ran it: English pipeline, default recognizers.

Gap it exposes: Part 2 says "an English model is built for English text"
and that coverage is "weakest exactly where you have least visibility",
but never measures it. This does. It then shows the cheapest fix: Presidio
ships country recognizers (Spanish NIF, German tax ID, Indian Aadhaar)
that are not loaded by default.

Test numbers: 12345678Z is the standard Spanish test DNI (check letter
valid); 86095742719 is the example tax ID printed in the German tax
administration's own specification. The Aadhaar-shaped number is
deliberately checksum-invalid, so it cannot be anyone's real number, and a
validating recognizer correctly refuses it.
"""
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.predefined_recognizers import (DeTaxIdRecognizer,
                                                      EsNifRecognizer,
                                                      InAadhaarRecognizer)

from ai_data_security.detect import _nlp, default_analyzer

SENTENCES = {
    "en": "Customer Maria Lopez, phone +1 212 555 0147, email "
          "maria.lopez@example.com, SSN 900-12-3456, asked for a refund.",
    "es": "La clienta María López, teléfono +34 612 345 678, correo "
          "maria.lopez@example.com, DNI 12345678Z, pidió un reembolso.",
    "de": "Die Kundin Maria Lopez, Telefon +49 30 1234567, E-Mail "
          "maria.lopez@example.com, Steuer-ID 86095742719, bat um "
          "eine Erstattung.",
    "hi": "ग्राहक मारिया लोपेज़, फ़ोन +91 98765 43210, ईमेल "
          "maria.lopez@example.com, आधार 2345 6789 0123, ने रिफ़ंड माँगा।",
}


def show(analyzer, title):
    print(f"== {title} ==")
    for lang, text in SENTENCES.items():
        hits = analyzer.analyze(text, language="en", score_threshold=0.4)
        found = sorted({f"{h.entity_type} '{text[h.start:h.end]}'"
                        for h in hits if h.entity_type != "URL"})
        print(f"[{lang}] " + "; ".join(found))


show(default_analyzer(), "default English detector")

country = AnalyzerEngine(nlp_engine=_nlp())
for recognizer in (EsNifRecognizer(supported_language="en"),
                   DeTaxIdRecognizer(supported_language="en"),
                   InAadhaarRecognizer()):
    country.registry.add_recognizer(recognizer)
print()
show(country, "plus the country recognizers Presidio ships but does not load")
