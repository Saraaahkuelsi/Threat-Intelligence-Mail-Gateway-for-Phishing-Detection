"""
collect_openphish.py
Collecte le feed communautaire OpenPhish et insère les IOC dans iocs.db.

Usage : python collect_openphish.py
(le chemin de la base est fixé ci-dessous, pas besoin d'argument)
"""

import sqlite3
import sys
import requests
from dotenv import load_dotenv
load_dotenv()

from db import upsert_ioc
from normalize_new_sources import normalize_openphish

DB_PATH = "iocs.db"
FEED_URL = "https://openphish.com/feed.txt"


def fetch_openphish() -> list[str]:
    resp = requests.get(FEED_URL, timeout=30)
    resp.raise_for_status()
    lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
    return lines


def main():
    try:
        urls = fetch_openphish()
    except requests.RequestException as e:
        print(f"[ERREUR] Échec de récupération du feed OpenPhish : {e}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    try:
        inserted = 0
        for line in urls:
            ioc = normalize_openphish(line)
            upsert_ioc(conn, ioc)
            inserted += 1
    finally:
        conn.close()

    print(f"[OK] {inserted} IOC OpenPhish traités (insert/update) dans {DB_PATH}")


if __name__ == "__main__":
    main()
