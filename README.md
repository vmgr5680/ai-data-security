# ai-data-security

![tests](../../actions/workflows/tests.yml/badge.svg)

**Companion code for the eight-part Medium series *AI Data Security*.**
Every example in the articles, runnable, plus ten scenarios modelled on
real incidents that the articles don't cover.

A detection library finds sensitive data. Almost everything else an AI
application needs (deciding what happens to it, keeping it out of logs and
memory, proving afterwards who saw it) is yours to build. This repository is
a small, readable version of that "everything else", built on
[Presidio](https://presidio.dataprivacystack.org/) and tested against the
numbers printed in the articles.

> **Educational reference code.** The mechanisms are real and every output
> in the articles reproduces from here. The policy rules, thresholds and
> word lists are examples. They aren't recommendations. Nothing here is a
> production control until you've measured it on your own traffic.

No API key and no network calls after install. The "agents" are scripted, so
every run is repeatable.

---

## Quick start

You need Python 3.10 or newer (tested on 3.10, 3.12 and 3.14) and about
1 GB of disk, most of it spaCy's English model. Clone the repository, then:

```bash
make install      # venv + package + spaCy's large English model
make test         # 36 tests, about 20 seconds
make parts        # every article's examples, part by part
make realtime     # the ten real-world scenarios
```

`make install` uses `python3`. To pick another interpreter, run
`make install PYTHON=python3.12`.

To run one article's examples, run its script:

```bash
.venv/bin/python parts/p4_tokenization.py
```

### Without make (Windows, or by hand)

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate    Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m spacy download en_core_web_lg
python -m pytest
python parts/p1_leak_path.py
```

### Reproducing the printed outputs

Exact dependency versions are pinned in `pyproject.toml`. Detector scores
move between releases, so the pins are what make the printed outputs
reproduce. `runs/` holds the captured output of every script from the last
`make runs`, so you can diff after an upgrade.

A few lines will differ on every run and every machine. That's expected:
latency and hash-rate figures (Parts 2, 3, 5 and 8) and the encrypted
ciphertext in Part 3. The tests don't assert any of them.

If you skip the model step, Presidio downloads the model itself the first
time a script runs ("Model en_core_web_lg is not installed.
Downloading..."). That first run is slow, and it needs network access.

---

## The division of labour

| | The framework does this for you | This is yours to build |
|---|---|---|
| **Detect** | patterns, checksums, NER, context words | your own formats (`CUST-`, `EMP-`), secrets, internal email domains, overlap resolution, measuring precision and recall |
| **Transform** | mask, redact, replace, hash, encrypt, keep | choosing which one, per destination |
| **Tokenize** | nothing | consistent tokens, scope, the vault, whole-token reveal, deletion |
| **Wire** | nothing | wrapping every tool call in both directions |
| **RAG and memory** | metadata filters in your vector store | labels at ingestion, fail-closed defaults, a memory gate, retention |
| **Output** | nothing | output scanning, streaming, link control |
| **Policy and audit** | nothing | `decide()`, purpose binding, records that never hold the value |

---

## Where each part lives

One script per article reproduces its printed results. The reusable pieces
are in `src/ai_data_security/`.

| Part | Script | Library module |
|---|---|---|
| 1. From PII Detection to AI Data Security | `parts/p1_leak_path.py` | `detect.scan_record` |
| 2. How Sensitive Data Detection Actually Works | `parts/p2_detection.py` | `detect` |
| 3. Detection Is Half the Problem | `parts/p3_six_options.py` | (Presidio operators) |
| 4. Tokenization and the Privacy Vault | `parts/p4_tokenization.py` | `vault` |
| 5. Agents, MCP, and the Wire | `parts/p5_the_wire.py` | `wire` |
| 6. Securing RAG and Agent Memory | `parts/p6_rag_and_memory.py` | `rag`, `memory`, `output` |
| 7. Policy, Access Control, and Audit | `parts/p7_policy_and_audit.py` | `policy`, `audit`, `vault.reveal_ladder` |
| 8. Choosing Your AI Data Security Architecture | `parts/p8_scorecard.py` | (the scorecard) |

Part 2's script is split into one function per claim (`four_spellings()`,
`employee_id_recognizer()`, `precision_recall()` and so on, listed in its
docstring). The article names the function next to each result instead of
printing the full code.

The part scripts keep the articles' code as printed. The one change is that
they share a single analyzer, so the language model loads once per script,
not once per snippet.

Three things the articles mention without showing are here too: the reveal
ladder's code (Part 7), the cost of the tool-call wrapper (Part 5 says "I
have not measured it"; `p5` does, at about 20 ms per call on a laptop), and a
keyed hash as the fix for Part 3's unsalted one.

---

## Ten real-world scenarios

Each file in `realtime/` opens with the incident it's modelled on, the gap
in the series it exposes, and then runs it. The incidents are public and
cited in the file. The data is invented.

| Scenario | Modelled on | What the run shows |
|---|---|---|
| `rt01_pasted_secrets` | Samsung engineers pasting code into ChatGPT (2023) | The default detector finds none of three secrets. House recognizers find all three. The source code itself has no entity type. |
| `rt02_link_exfiltration` | Slack AI (2024), EchoLeak in Microsoft 365 Copilot (2025) | The output scanner lets 3 of the 4 link-carrying answers out. Its only URL hit is the fragment `p.pn`, and the attacker host survives. A host allow-list removes all four links. |
| `rt03_streaming_split` | Every streaming chat UI | An SSN split across two deltas passes a per-delta scanner. A 48-character hold-back catches it. |
| `rt04_cross_tenant` | Asana's MCP server (2025), ChatGPT's cache bug (2023) | One unscoped token map lets tenant B reveal tenant A's customer. Tenant scope on every lookup stops it. |
| `rt05_lethal_trifecta` | GitHub MCP prompt injection (2025) | The salary table being exfiltrated scores only `DATE_TIME`. A "no external write after untrusted content" rule stops it. |
| `rt06_invented_token` | Any tokenize-then-reveal design | The model writes a token it was never given, and a session-wide reveal prints a different patient's name. |
| `rt07_trace_capture` | LLM tracing with content capture on | The guardrail cleans the prompt, and the trace keeps the raw SSN anyway. |
| `rt08_canary_sinks` | "Who has seen this SSN?" | A planted canary shows which stores it reached. It caught a leak in the *guarded* pipeline (below). |
| `rt09_discover_share` | The folder about to be indexed for RAG | An inventory by file and entity type, with a suggested label. The salary still has no entity type. |
| `rt10_multilingual` | One English model, four languages | A Spanish DNI comes back as a date and German nouns come back as people. Country recognizers ship with Presidio but aren't loaded by default. |

### What surprised me

These came out of running the code, not planning it.

- **Configuration changes results silently.** My first shared-engine setup
  used a hand-written NLP config. Every sentence then grew an
  `ORGANIZATION` finding, and Part 2's precision fell from 45% to 33%. The
  fix was to use Presidio's own default config (`detect._nlp`).
- **Two recognizers can claim the same span.** `900-77-3301` is both a
  `US_SSN` (0.85) and a `US_ITIN` (0.5), because 77 is in the ITIN range.
  Replacing both shifted the text and ate the full stop after it. The fix is
  `detect.resolve_overlaps`. Part 4's toy tokenizer escapes only because
  `US_ITIN_001` happens to be 11 characters, the same length as the number.
- **Internal email domains aren't emails.** Presidio's email recognizer
  checks the domain against the public list, so `ops@acme.internal` isn't
  detected. Instead a URL fragment inside it gets replaced, which leaves the
  identifying half of the address readable. The canary found this in the
  guarded pipeline.
- **The naive reveal bug can look correct.** With values named
  `Customer 1` to `Customer 1000`, Part 4's substring bug turns
  `PERSON_1000` into `Customer 100` + `0`, which reads as "Customer 1000".
  The test fixtures use values that can't hide it.

---

## Layout

```text
src/ai_data_security/   detect, vault, wire, rag, memory, output,
                        policy, audit, discover, canary
parts/                  p1 … p8: each article's examples
realtime/               rt01 … rt10: real-world scenarios
data/unlabelled_share/  the folder rt09 inventories
tests/                  article claims, library, scenarios
runs/                   captured output of every script
.github/workflows/      runs the tests on Python 3.10, 3.12 and 3.14
```

All example identifiers are fake. SSNs use the 900 series, which the Social
Security Administration doesn't issue (and `123-45-6789` is on Presidio's
deny list, so it would test nothing). The AWS key is the example from AWS's
own documentation. The GitHub token is made up in the published format. The
German tax ID is the example printed in the tax administration's own
specification.

## License

MIT
