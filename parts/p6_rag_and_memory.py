"""Part 6: Securing RAG and Agent Memory.

One function per result, in article order:

    retrieval_two_controls()   entitlement filter, then scan, for two roles
    inside_vs_after()          filter inside the search versus after it
    memory_gate_sketch()       the tokenize-on-write gate (token_for, remember)
    policy_aware_gate()        the library gate: refuses the cardiac note
    output_scanner()           the four answers through scan_output()
    salary_no_threshold()      the salary line with no score threshold

The streamed answer and the link channel are realtime/rt03_streaming_split.py
and realtime/rt02_link_exfiltration.py.
"""
from ai_data_security.detect import default_analyzer, scan_text
from ai_data_security.memory import MemoryGate
from ai_data_security.output import scan_output
from ai_data_security.rag import Chunk, search, search_then_filter
from ai_data_security.vault import Vault

analyzer = default_analyzer()

CHUNKS = [
    {"id": "c1", "label": "public",
     "text": "The dental plan covers two cleanings a year."},
    {"id": "c2", "label": "internal",
     "text": "Open enrollment closes on 30 November."},
    {"id": "c3", "label": "restricted",
     "text": "John Smith, band L6, base salary 184000, "
             "SSN 900-12-3456."},
    {"id": "c4", "label": "internal",
     "text": "Questions go to the benefits lead, Maria Lopez."},
    {"id": "c5",
     "text": "Draft: relocation bonus for Dev Patel."},
]
ENTITLED = {
    "employee": {"public", "internal"},
    "hr": {"public", "internal", "restricted"},
}
NOTES = ["Priya Shah prefers email contact.",
         "Priya Shah gave account number 900123456.",
         "Priya Shah mentioned a recent cardiac procedure.",
         "Priya Shah was annoyed about the September billing error."]


def retrieve(role, chunks):
    allowed = ENTITLED[role]
    kept = [c for c in chunks if c.get("label") in allowed]
    print(f"=== role={role} ===")
    print("  dropped:", [c["id"] for c in chunks if c not in kept])
    for c in kept:
        hits = analyzer.analyze(c["text"], language="en",
                                score_threshold=0.4)
        found = [f"{h.entity_type} '{c['text'][h.start:h.end]}'"
                 for h in sorted(hits, key=lambda h: h.start)]
        print(f"  {c['id']} {c['label']:<10}",
              ", ".join(found) or "no PII")


def retrieval_two_controls():
    print("== retrieval: entitlement filter, then scan ==")
    for role in ("employee", "hr"):
        retrieve(role, CHUNKS)


def inside_vs_after():
    print("\n== filter inside the search vs after it (library) ==")
    corpus = [Chunk(c["id"], c["text"], c.get("label")) for c in CHUNKS] + [
        Chunk("c6", "Salary bands and base salary review for 2026.",
              "restricted"),
        Chunk("c7", "Salary review timeline: managers submit in October.",
              "restricted"),
        Chunk("c8", "Salary questions go to your HR partner.", "internal"),
    ]
    q = "what is the base salary for band L6"
    inside = search(q, corpus, ENTITLED["employee"], k=3)
    after = search_then_filter(q, corpus, ENTITLED["employee"], k=3)
    print("inside:", [c.id for c in inside])
    print("after: ", [c.id for c in after],
          f"({3 - len(after)} of 3 slots lost to discarded chunks)")


TOKENIZE = ["PERSON", "US_SSN", "US_BANK_NUMBER",
            "EMAIL_ADDRESS", "PHONE_NUMBER"]
vault, memory = {}, []


def token_for(entity, value):
    for tok, original in vault.items():
        if original == value:
            return tok
    n = sum(t.startswith(f"<{entity}_") for t in vault) + 1
    vault[f"<{entity}_{n}>"] = value
    return f"<{entity}_{n}>"


def remember(note):
    hits = analyzer.analyze(note, language="en",
                            entities=TOKENIZE, score_threshold=0.4)
    for h in sorted(hits, key=lambda h: h.start, reverse=True):
        tok = token_for(h.entity_type, note[h.start:h.end])
        note = note[:h.start] + tok + note[h.end:]
    memory.append(note)


def memory_gate_sketch():
    print("\n== memory: Part 6's gate, then the policy-aware gate ==")
    for n in NOTES:
        remember(n)
    print("memory store:")
    for m in memory:
        print("  " + m)
    print("vault:", vault)


def policy_aware_gate():
    gate = MemoryGate(Vault(), scope="user:priya", retention_days=30)
    for n in NOTES:
        gate.remember(n, analyzer)
    print("policy-aware store:")
    for note in gate.store:
        print(f"  {note.text}   (keep {note.retention_days}d)")
    print("refused:", gate.refused)


def output_scanner():
    print("\n== output scanner: four answers ==")
    answers = {
        "verbatim": "The customer's SSN is 900-12-3456.",
        "spaced": "The customer's SSN is 900 12 3456.",
        "paraphrased": ("The customer's social security number starts with "
                        "nine hundred and ends in thirty-four fifty-six."),
        "inferred": ("That employee is in the top salary band for their "
                     "level."),
    }
    for name, text in answers.items():
        safe, found = scan_output(text, analyzer)
        if found:
            print(f"{name:<12} {found}\n             -> {safe}")
        else:
            print(f"{name:<12} NOTHING DETECTED")


def salary_no_threshold():
    print("\n== the salary, with no threshold ==")
    line = "John Smith, band L6, base salary 184000, SSN 900-12-3456."
    for h in sorted(analyzer.analyze(line, language="en"),
                    key=lambda h: h.start):
        print(f"{line[h.start:h.end]!r:<14} {h.entity_type:<18} "
              f"{h.score:.2f}")
    print("at 0.4:", [f.entity_type for f in scan_text(line, analyzer)])


if __name__ == "__main__":
    retrieval_two_controls()
    inside_vs_after()
    memory_gate_sketch()
    policy_aware_gate()
    output_scanner()
    salary_no_threshold()
