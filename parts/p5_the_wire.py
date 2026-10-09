"""Part 5: Agents, MCP, and the Wire.

Every printed result in the article, in article order, one function per
claim. The article prints guarded_tool() (src/ai_data_security/wire.py)
and names the function next to each other result:

    nine_words_trace()    the prompt is clean; both tool calls are not
    proxy_view()          the same response as one flat body, as a proxy
                          that can decrypt it would scan it
    redact_vendor_query() the vendor query before and after redaction
    wrapper_cost()        what the wrapper costs per call (p95, varies by
                          machine)

The injected-instruction run (scanning cannot see a salary table) is
realtime/rt05_lethal_trifecta.py.
"""
import json
import statistics
import time

from presidio_anonymizer import AnonymizerEngine

from ai_data_security.detect import default_analyzer
from ai_data_security.wire import guarded_tool, report_only

analyzer = default_analyzer()


def lookup_order(order_id):             # the customer database tool
    return {"order": order_id, "status": "shipped",
            "customer": {"name": "John Smith",
                         "phone": "555-123-4567",
                         "ssn": "900-12-3456",
                         "address": "123 Main Street"}}


def search_vendor(query):               # a third-party search API
    return {"results": []}


def nine_words_trace():
    """Replay the agent's two steps through guarded tools; return the query."""
    lookup = guarded_tool("lookup_order", lookup_order, report_only, analyzer)
    search = guarded_tool("search_vendor", search_vendor, report_only,
                          analyzer)
    print("== the nine-words trace ==")
    prompt = "Show me the status of my order."
    hits = analyzer.analyze(text=prompt, language="en")
    print(f"USER PROMPT: {prompt!r}  ({len(hits)} findings)\n")
    print("agent calls lookup_order(order_id='ORD-12345')")
    customer = lookup(order_id="ORD-12345")["customer"]
    query = f"{customer['name']} {customer['phone']} refund"
    print(f"\nagent then calls search_vendor(query={query!r})")
    search(query=query)
    return query


def proxy_view():
    """Scan the lookup_order response as one flat body."""
    print("\n== the same response, as a network proxy sees it ==")
    body = json.dumps(lookup_order("ORD-12345"))
    for f in analyzer.analyze(text=body, language="en"):
        print(f"{f.entity_type:<13} {body[f.start:f.end]:<15} {f.score:.2f}")


def redact_vendor_query(query):
    """Replace each finding in the vendor query with its entity type."""
    print("\n== redacting the vendor query ==")
    found = analyzer.analyze(text=query, language="en")
    print("before: ", query)
    print("after:  ", AnonymizerEngine().anonymize(text=query,
                                                   analyzer_results=found).text)


def p95_ms(fn, runs=40):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.quantiles(times, n=20)[-1]


def wrapper_cost():
    """p95 latency of a bare tool call and the same call guarded."""
    print("\n== what the wrapper costs per call (p95, machine-dependent) ==")
    quiet = guarded_tool("lookup_order", lookup_order,
                         lambda t, d, f, p: p, analyzer)
    print(f"bare tool call     "
          f"{p95_ms(lambda: lookup_order('ORD-12345')):8.3f} ms")
    print(f"guarded tool call  "
          f"{p95_ms(lambda: quiet(order_id='ORD-12345')):8.3f} ms")


if __name__ == "__main__":
    query = nine_words_trace()
    proxy_view()
    redact_vendor_query(query)
    wrapper_cost()
