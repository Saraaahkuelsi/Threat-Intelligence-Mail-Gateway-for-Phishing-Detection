"""
collect_feodotracker.py
Collecte le blocklist CSV Feodo Tracker et insère les IOC dans iocs.db.

Usage : python collect_feodotracker.py
(le chemin de la base est fixé ci-dessous, pas besoin d'argument)
"""

import csv
import io
import sqlite3
import sys
import requests
from dotenv import load_dotenv
load_dotenv()

from db import upsert_ioc
from normalize_new_sources import normalize_feodotracker

DB_PATH = "iocs.db"
FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


def fetch_feodotracker() -> list[dict]:
    resp = requests.get(FEED_URL, timeout=30)
    resp.raise_for_status()

    lines = resp.text.splitlines()
    header_idx = next(
        (i for i, l in enumerate(lines) if l.strip('#" ').startswith("first_seen_utc")),
        None,
    )
    if header_idx is None:
        raise ValueError("En-tête CSV introuvable dans le flux Feodo Tracker")

    csv_body = "\n".join(lines[header_idx:])
    reader = csv.DictReader(io.StringIO(csv_body))
    rows = [r for r in reader if r.get("dst_ip") and not r["dst_ip"].startswith("#")]
    return rows


def main():
    try:
        rows = fetch_feodotracker()
    except (requests.RequestException, ValueError) as e:
        print(f"[ERREUR] Échec de récupération/parsing Feodo Tracker : {e}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    try:
        inserted = 0
        for row in rows:
            ioc = normalize_feodotracker(row)
            upsert_ioc(conn, ioc)
            inserted += 1
    finally:
        conn.close()

    print(f"[OK] {inserted} IOC Feodo Tracker traités (insert/update) dans {DB_PATH}")


if __name__ == "__main__":
    main()
