"""rt08: plant a canary, run the pipeline, search every sink.

Real-world shape: the question in Part 7's opening, "who has seen this
customer's SSN?", asked of a whole system rather than an audit log. The
pipeline below is the support agent from Part 1: a tool returns a customer
record, the agent builds a prompt, and the turn is written to a
conversation log, agent memory, a trace and an audit log.

Gap it exposes: Part 2 measures the *detector* with precision and recall.
Nothing in the series measures the *system*: which stores a value actually
reached. A canary does: unique and fake by construction, so any hit is a
leak path with its name on it.

What the first run of this script found, in the *guarded* pipeline: the
canary email uses the reserved ``.invalid`` domain, Presidio's email
recognizer rejects domains not on the public list, and a URL fragment
(``example.in``) was tokenized instead. The address reached agent memory
whole, and reached the model as ``canary-0417@URL_001valid``: identifying
part intact, and invisible to an exact-string search. Internal domains
(``.internal``, ``.corp``) behave the same way. The house detector's
any-domain email pattern closes it. Search sinks for fragments of a canary
too, not only the whole value.
"""
import json

from ai_data_security.audit import AuditLog
from ai_data_security.canary import CANARY_EMAIL, CANARY_SSN, Sinks
from ai_data_security.detect import default_analyzer, house_analyzer
from ai_data_security.memory import MemoryGate
from ai_data_security.policy import Context, decide
from ai_data_security.vault import Vault

RECORD = {"customer_name": "Dana Reyes", "ssn": CANARY_SSN,
          "email": CANARY_EMAIL, "payment_status": "Failed"}
CTX = Context("u-481", "support_rep", "support", "billing_api",
              "US_SSN", "order_lookup", "internal")


def unguarded() -> Sinks:
    sinks = Sinks()
    prompt = f"Explain the failed payment. Record: {json.dumps(RECORD)}"
    sinks.write("model_input", prompt)
    sinks.write("conversation_log", {"turn": 1, "prompt": prompt})
    sinks.write("agent_memory", f"{RECORD['customer_name']} "
                f"({RECORD['email']}) had a failed payment.")
    sinks.write("trace", {"gen_ai.input.messages": prompt})
    sinks.write("audit_log", {"action": decide(CTX).action,
                              "redacted": RECORD["ssn"]})   # "for debugging"
    return sinks


def guarded(analyzer) -> Sinks:
    sinks, vault = Sinks(), Vault()
    scope = "tenant:acme/session:1"
    safe, _ = vault.tokenize_record(RECORD, scope, analyzer)  # ingress
    prompt = f"Explain the failed payment. Record: {json.dumps(safe)}"
    sinks.write("model_input", prompt)
    sinks.write("conversation_log", {"turn": 1, "prompt": prompt})
    gate = MemoryGate(vault, scope)
    gate.remember(f"{RECORD['customer_name']} ({RECORD['email']}) "
                  "had a failed payment.", analyzer)
    sinks.write("agent_memory", [n.text for n in gate.store])
    sinks.write("trace", {"gen_ai.input.messages": "<not captured>"})
    sinks.write("audit_log", AuditLog().record(
        CTX, decide(CTX), "PERSON_001",
        protected_values=(CANARY_SSN, CANARY_EMAIL)))
    return sinks


RUNS = [("unguarded", unguarded),
        ("guarded, default detector", lambda: guarded(default_analyzer())),
        ("guarded, house detector", lambda: guarded(house_analyzer()))]
for name, run in RUNS:
    sinks = run()
    print(f"== {name} ==")
    for canary in (CANARY_SSN, CANARY_EMAIL):
        print(f"  {canary:<28} reached: {sinks.containing(canary) or 'none'}")
    print("  model saw:", sinks._data["model_input"][0].split("Record: ")[1])
