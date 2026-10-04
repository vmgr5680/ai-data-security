"""rt03: the answer is streamed, and the SSN arrives in two pieces.

Real-world shape: every chat interface streams. Model APIs send an answer
as a sequence of small text deltas so the user sees words appear. An output
scanner bolted onto that stream usually scans each delta as it passes.

Gap it exposes: Part 6 tested the output scanner on whole answers. On a
stream, a value that straddles two deltas is two harmless fragments.
"""
from ai_data_security.output import StreamScanner, scan_output

answer = ("Thanks for waiting. I found the account. The customer's SSN is "
          "900-12-3456 and the card on file ends in 4242. Anything else?")

# Deltas cut where a tokenizer might cut them: mid-number.
cuts = [0, 20, 44, 66, 70, 80, 102, len(answer)]
deltas = [answer[a:b] for a, b in zip(cuts, cuts[1:])]
print("deltas:", deltas)

print("\n== scanning each delta on its own ==")
naive = "".join(scan_output(d)[0] for d in deltas)
print(naive)
print("SSN reached the user:", "900-12-3456" in naive)

print("\n== StreamScanner: hold back a short tail, cut at whitespace ==")
scanner = StreamScanner()
released = []
for d in deltas:
    out = scanner.feed(d)
    if out:
        released.append(out)
released.append(scanner.close())
guarded = "".join(released)
print(guarded)
print("SSN reached the user:", "900-12-3456" in guarded)
print("released in", len([r for r in released if r]), "pieces; the cost is",
      "up to", scanner.holdback, "characters of extra delay")
