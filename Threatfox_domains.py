#!/usr/bin/env python3
"""
ThreatFox DOMAIN IOC Crawler (JSON)

Source:
https://threatfox.abuse.ch/export/json/domains/recent/

Improvements:
- Confidence filtering
- Deduplication
- Normalized output
- Always produces CSV (CI-safe)
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

CONFIDENCE_THRESHOLD = 75  # Only high-confidence IOCs

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
    seen_iocs = set()

    ioc_data = raw_json.get("data", {})
    collection_time = datetime.utcnow().isoformat()

    for _, entry in ioc_data.items():
        ioc = entry.get("ioc", "").strip().lower()
        ioc_type = entry.get("ioc_type", "").strip().lower()
        confidence = int(entry.get("confidence_level", 0))

        # Strict filtering
        if not ioc or ioc_type != "domain":
            continue
        if confidence < CONFIDENCE_THRESHOLD:
            continue
        if ioc in seen_iocs:
            continue

        seen_iocs.add(ioc)

        records.append({
            "ioc": ioc,
            "ioc_type": "domain",
            "threat_type": entry.get("threat_type", "").strip(),
            "malware": entry.get("malware", "").strip(),
            "confidence_level": confidence,
            "reference": entry.get("reference", "").strip(),
            "first_seen": entry.get("first_seen", "").strip(),
            "last_seen": entry.get("last_seen", "").strip(),
            "source": "ThreatFox",
            "collection_date": collection_time
        })

    # Sort newest first
    records.sort(key=lambda x: x["last_seen"], reverse=True)

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

    print(f"[+] Saved {len(data)} high-confidence domain IOCs → {output_path}")

# =====================
# MAIN
# =====================
def main():
    print("[*] Fetching ThreatFox DOMAIN IOCs...")
    raw_json = fetch_threatfox_json()

    print("[*] Processing & filtering IOCs...")
    iocs = parse_json(raw_json)

    print("[*] Writing output...")
    save_csv(iocs)

if __name__ == "__main__":
    main()
