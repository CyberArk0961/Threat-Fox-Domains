#!/usr/bin/env python3
"""
ThreatFox DOMAIN IOC Crawler (JSON)

Source:
https://threatfox.abuse.ch/export/json/domains/recent/

- Fetches recent domain-based IOCs
- Parses ThreatFox JSON correctly
- Outputs clean CSV for automation / GitHub Actions
"""

import requests
import csv
import os
from datetime import datetime

# =====================
# CONFIG
# =====================
THREATFOX_JSON_URL = "https://threatfox.abuse.ch/export/json/domains/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_Domain.csv"

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

# =====================
# FETCH DATA
# =====================
def fetch_threatfox_json():
    response = requests.get(THREATFOX_JSON_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.json()


# =====================
# PARSE JSON
# =====================
def parse_json(raw_json):
    records = []

    # ThreatFox JSON stores data under "data"
    ioc_data = raw_json.get("data", {})

    if not ioc_data:
        return records

    for ioc_id, entry in ioc_data.items():
        records.append({
            "ioc": entry.get("ioc", "").strip(),
            "ioc_type": entry.get("ioc_type", "").strip(),
            "threat_type": entry.get("threat_type", "").strip(),
            "malware": entry.get("malware", "").strip(),
            "confidence_level": entry.get("confidence_level", ""),
            "reference": entry.get("reference", ""),
            "first_seen": entry.get("first_seen", ""),
            "last_seen": entry.get("last_seen", ""),
            "source": "ThreatFox",
            "collection_date": datetime.utcnow().isoformat()
        })

    return records


# =====================
# SAVE CSV
# =====================
def save_csv(data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    if not data:
        print("[!] No IOCs collected")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
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
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} domain IOCs → {output_path}")


# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox DOMAIN IOCs (JSON)...")
    raw_json = fetch_threatfox_json()

    print("[*] Parsing IOCs...")
    iocs = parse_json(raw_json)

    print("[*] Writing output...")
    save_csv(iocs)


if __name__ == "__main__":
    main()
