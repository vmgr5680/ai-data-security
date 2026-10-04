"""Part 5: Agents, MCP, and the Wire.

The nine-words trace, the proxy's view of the same response, and the
vendor-query redaction. Then the part the article did not measure: what
the wrapper costs per tool call.
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


lookup = guarded_tool("lookup_order", lookup_order, report_only, analyzer)
search = guarded_tool("search_vendor", search_vendor, report_only, analyzer)

print("== the nine-words trace ==")
prompt = "Show me the status of my order."
hits = analyzer.analyze(text=prompt, language="en")
print(f"USER PROMPT: {prompt!r}  ({len(hits)} findings)\n")
print("agent calls lookup_order(order_id='ORD-12345')")
customer = lookup(order_id="ORD-12345")["customer"]
query = f"{customer['name']} {customer['phone']} refund"
print(f"\nagent then calls search_vendor(query={query!r})")
search(query=query)

print("\n== the same response, as a network proxy sees it ==")
body = json.dumps(lookup_order("ORD-12345"))
for f in analyzer.analyze(text=body, language="en"):
    print(f"{f.entity_type:<13} {body[f.start:f.end]:<15} {f.score:.2f}")

print("\n== redacting the vendor query ==")
found = analyzer.analyze(text=query, language="en")
print("before: ", query)
print("after:  ", AnonymizerEngine().anonymize(text=query,
                                               analyzer_results=found).text)

print("\n== what the wrapper costs per call (p95, machine-dependent) ==")
quiet = guarded_tool("lookup_order", lookup_order,
                     lambda t, d, f, p: p, analyzer)


def p95_ms(fn, runs=40):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.quantiles(times, n=20)[-1]


print(f"bare tool call     {p95_ms(lambda: lookup_order('ORD-12345')):8.3f} ms")
print(f"guarded tool call  {p95_ms(lambda: quiet(order_id='ORD-12345')):8.3f} ms")
