"""rt09: before anyone indexes a shared folder for RAG, look inside it.

Real-world shape: Part 6's salary spreadsheet, indexed "along with
everything else in the HR folder". In practice the folder also holds a CRM
export somebody saved for a migration, a debug log with request bodies,
and a wiki page with a pasted row from a restricted sheet.

Gap it exposes: DISCOVER is the first stage of Part 1's lifecycle, and no
part covers it. Part 8's checklist says "find the data, including indexes
and memory nobody catalogued" but never shows how. This inventory prints
entity types and counts per file, never values, and it is the input the
Part 6 entitlement label needs.
"""
from pathlib import Path

from ai_data_security.detect import house_analyzer
from ai_data_security.discover import inventory

share = Path(__file__).resolve().parent.parent / "data" / "unlabelled_share"
RESTRICTED = {"US_SSN", "CREDIT_CARD", "SECRET", "US_BANK_NUMBER"}

for name, counts in inventory(share, house_analyzer()).items():
    label = ("restricted" if RESTRICTED & counts.keys()
             else "internal" if counts else "public")
    found = ", ".join(f"{k}x{v}" for k, v in sorted(counts.items()))
    print(f"{name:<22} suggested label: {label:<11} {found}")

print("\nWhat the inventory cannot see: team_wiki.md holds a salary, and "
      "no entity type exists for it. The label for that file has to come "
      "from its source (the HR sheet), which is Part 6's point.")
