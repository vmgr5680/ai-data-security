"""The measured claims each article rests on.

If a detector upgrade changes one of these, the article needs re-checking
before it is republished. That is the point of pinning them.
"""
import contextlib
import io
import runpy
from pathlib import Path

import pytest

PARTS = Path(__file__).resolve().parent.parent / "parts"


def run(script: str) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        runpy.run_path(str(PARTS / script), run_name="__main__")
    return buf.getvalue()


@pytest.fixture(scope="module")
def out():
    return {name: run(name) for name in sorted(p.name for p in
                                               PARTS.glob("p*.py"))}


def test_part1_detector_invents_a_person_from_a_field_name(out):
    o = out["p1_leak_path.py"]
    assert "PERSON           date_of_birth        score=0.85" in o
    assert '"<PERSON>": "<DATE_TIME>"' in o          # the key was renamed
    assert '"customer_id": "CUST-88231"' in o        # the miss
    assert "PERSON           John Smiht's" in o       # misspelling still caught
    assert "US_SSN           (none found)" in o       # spelled-out SSN missed


def test_part2_deny_list_and_precision_recall(out):
    o = out["p2_detection.py"]
    assert "123-45-6789\n    nothing" in o
    assert "precision = 5/11 = 45%" in o
    assert "recall    = 5/7 = 71%" in o
    assert "precision = 5/9 = 56%" in o              # with drop_nested
    assert "ssn            US_SSN     bare 0.50   +field name 0.85" in o


def test_part2_explained_scores_overlaps_and_config(out):
    o = out["p2_detection.py"]
    assert "pattern 0.50 -> 0.85  context word: ssn" in o      # 0.85 = 0.50 + 0.35
    assert "pattern 0.90 -> 1.00  context word: emp" in o      # boost from the ID itself
    assert "found  US_ITIN  900-77-3301  0.50" in o            # same span twice
    assert "kept   US_ITIN" not in o                           # resolve_overlaps keeps one
    assert "(\"Dallas Children's Hospital\", 'ORG')" in o      # spaCy found it
    assert "ORGANIZATION ignored by default: True" in o         # Presidio dropped it
    assert "precision = 5/15 = 33%" in o                       # hand-written config


def test_part3_operators(out):
    o = out["p3_six_options.py"]
    assert "redact   Patient <PERSON>, SSN , has diabetes." in o
    assert "default -> same hash both times: False" in o
    assert "{'salt': 'a-fixed-16b-salt'} -> same hash both times: True" in o
    assert "found: 900-12-3456" in o


def test_part4_tokens(out):
    o = out["p4_tokenization.py"]
    assert "900-12-3456 -> 274-76-1817" in o
    assert "Customer SSN 274-76-1817 on file. -> [('US_SSN', 0.85)]" in o
    assert "Phone 555-0142." in o                     # not tokenized
    assert "PERSON_1000 -> Customer #100-A0" in o     # naive reveal bug
    assert "PERSON_1000 -> Customer #1000-A" in o     # vault fix


def test_part5_nine_words(out):
    o = out["p5_the_wire.py"]
    assert "(0 findings)" in o
    assert "customer.ssn    US_SSN        0.85" in o
    assert "after:   <PERSON> <PHONE_NUMBER> refund" in o


def test_part6_output_scanner_misses_meaning(out):
    o = out["p6_rag_and_memory.py"]
    assert "paraphrased  NOTHING DETECTED" in o
    assert "inferred     NOTHING DETECTED" in o
    assert "'184000'       US_DRIVER_LICENSE  0.01" in o
    assert "dropped: ['c3', 'c5']" in o


def test_part7_purpose_and_audit(out):
    o = out["p7_policy_and_audit.py"]
    assert "helpful claim:  TOKENIZE" in o
    assert "bound to entry: BLOCK" in o
    assert "audit record  contains the SSN: False" in o
    assert "range    age 35-44" in o


def test_part8_audit_record_search(out):
    o = out["p8_scorecard.py"]
    assert "naive leaks: ['Dana Reyes', '0147']" in o
    assert "typed leaks: []" in o
