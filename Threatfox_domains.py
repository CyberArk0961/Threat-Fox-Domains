#!/usr/bin/env python3
"""
ThreatFox DOMAIN IOC Crawler (POSITIONAL – FINAL)

Source:
https://threatfox.abuse.ch/export/csv/domains/recent/

IMPORTANT:
- Feed has NO header row
- Rows are comma-separated
- Must be parsed positionally
"""

import requests
import csv
import os

# =====================
# CONFIG
# =====================
THREATFOX_DOMAIN_URL = "https://threatfox.abuse.ch/export/csv/domains/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_Domain.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

# Exact ThreatFox column order (same as IP & URL feeds)
FIELDNAMES = [
    "first_seen_utc",     # 0
    "ioc_id",             # 1
    "ioc_value",          # 2  (DOMAIN)
    "ioc_type",           # 3
    "threat_type",        # 4
    "fk_malware",         # 5
    "malware_alias",      # 6
    "malware_printable",  # 7
    "last_seen_utc",      # 8
    "confidence_level",   # 9
    "reference",          # 10
    "tags",               # 11
    "anonymous",          # 12
    "reporter"            # 13
]

# =====================
# FETCH
# =====================
def fetch_threatfox_csv():
    r = requests.get(THREATFOX_DOMAIN_URL, headers=HEADERS, timeout=60)
    r.raise_for_status()
    return r.text.lstrip("\ufeff")

# =====================
# PARSE (POSITIONAL)
# =====================
def parse_csv(raw_csv):
    records = []
    seen_ids = set()

    reader = csv.reader(
        (line for line in raw_csv.splitlines() if line and not line.startswith("#")),
        delimiter=",",
        quotechar='"'
    )

    for row in reader:
        if len(row) < 14:
            continue

        ioc_id = row[1].strip()
        if not ioc_id or ioc_id in seen_ids:
            continue
        seen_ids.add(ioc_id)

        record = dict(zip(FIELDNAMES, [c.strip() for c in row[:14]]))
        records.append(record)

    return records

# =====================
# SAVE CSV
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    if not data:
        print("[!] No domain IOCs collected")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES,
            quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} domain IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox DOMAIN IOCs...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing DOMAIN IOCs (positional)...")
    iocs = parse_csv(raw_csv)

    print("[*] Writing output...")
    save_csv(iocs)

if __name__ == "__main__":
    main()
