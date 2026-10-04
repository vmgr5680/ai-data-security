"""rt04: two customers of your AI product share one token map.

Real-world shape: in June 2025 Asana took its MCP server offline for about
two weeks after finding a tenant-isolation flaw that could expose one
organization's data to MCP users in other organizations (roughly 1,000
customers notified). In March 2023 a bug in a Redis client library let
some ChatGPT users see other users' chat titles, and for about 1.2% of
Plus subscribers active in a nine-hour window, another user's name, email,
payment address and card's last four digits.

Gap it exposes: Part 4 discussed token scope per request, session and
forever, all inside one organization. A multi-tenant product has a wider
scope question: whose vault is this token in? The article's per-request
run already showed two different people getting PERSON_001.
"""
from ai_data_security.detect import scan_text
from ai_data_security.vault import Vault

acme_note = "Refund approved for Maria Garcia, SSN 900-45-1122."
globex_note = "Chargeback opened for John Smith, SSN 900-77-3301."

print("== one unscoped map shared by every tenant ==")
shared = Vault()
a, _ = shared.tokenize(acme_note, scan_text(acme_note), scope="global")
g, _ = shared.tokenize(globex_note, scan_text(globex_note), scope="global")
print("acme sees:  ", a)
print("globex sees:", g)
print("globex's agent reveals acme's token:",
      shared.reveal("PERSON_001 US_SSN_001", "global", "globex-agent"))

print("\n== scope = tenant ==")
events = []
v = Vault(audit=events.append)
a, _ = v.tokenize(acme_note, scan_text(acme_note), scope="tenant:acme")
g, _ = v.tokenize(globex_note, scan_text(globex_note), scope="tenant:globex")
print("acme sees:  ", a)
print("globex sees:", g, " <- same token text, different tenant")
print("globex reveals PERSON_001:",
      v.reveal("PERSON_001", "tenant:globex", "globex-agent"))
print("acme reveals PERSON_001:  ",
      v.reveal("PERSON_001", "tenant:acme", "acme-agent"))
print("audit:", [(e["scope"], e["outcome"]) for e in events])
print("\nNote: the token strings collide across tenants by design. Safety",
      "comes from the scope on every lookup, so a token copied into the",
      "wrong tenant's context resolves to that tenant's own record or to",
      "nothing. Never to the other tenant's.", sep="\n")
