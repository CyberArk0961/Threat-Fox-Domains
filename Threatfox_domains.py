#!/usr/bin/env python3
"""
ThreatFox DOMAIN IOC Crawler (CSV)

Source:
https://threatfox.abuse.ch/export/csv/domains/recent/

- Fetches recent domain-based IOCs
- Handles ThreatFox CSV quirks (# comments)
- Produces stable CSV output for GitHub Actions
"""

import requests
import csv
import os
from datetime import datetime

# =====================
# CONFIG
# =====================
THREATFOX_CSV_URL = "https://threatfox.abuse.ch/export/csv/domains/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_Domain.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

FIELDNAMES = [
    "ioc",
    "ioc_type",
    "threat_type",
    "malware",
    "confidence_level",
    "reference",
    "first_seen",
    "last_seen",
    "source",
    "collection_date"
]

# =====================
# FETCH CSV
# =====================
def fetch_threatfox_csv():
    response = requests.get(THREATFOX_CSV_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text

# =====================
# PARSE CSV
# =====================
def parse_csv(raw_csv):
    records = []
    seen_iocs = set()
    collection_time = datetime.utcnow().isoformat()

    reader = csv.reader(
        line for line in raw_csv.splitlines()
        if line and not line.startswith("#")
    )

    header = next(reader, None)
    if not header:
        return records

    for row in reader:
        # Expected ThreatFox domain CSV format
        # ioc,ioc_type,threat_type,malware,confidence_level,reference,first_seen,last_seen
        if len(row) < 8:
            continue

        ioc = row[0].strip().lower()
        confidence = row[4].strip()

        if not ioc:
            continue

        # Deduplicate
        if ioc in seen_iocs:
            continue
        seen_iocs.add(ioc)

        records.append({
            "ioc": ioc,
            "ioc_type": row[1].strip(),
            "threat_type": row[2].strip(),
            "malware": row[3].strip(),
            "confidence_level": confidence,
            "reference": row[5].strip(),
            "first_seen": row[6].strip(),
            "last_seen": row[7].strip(),
            "source": "ThreatFox",
            "collection_date": collection_time
        })

    return records

# =====================
# SAVE CSV (ALWAYS)
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} domain IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox DOMAIN IOCs (CSV)...")
    raw_csv = fetch_threatfox_csv()

    print("[*] Parsing domain IOCs...")
    iocs = parse_csv(raw_csv)

    print("[*] Writing output...")
    save_csv(iocs)

if __name__ == "__main__":
    main()
