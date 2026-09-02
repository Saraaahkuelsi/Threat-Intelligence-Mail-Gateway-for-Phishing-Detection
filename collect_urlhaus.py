import re
import sqlite3
import requests
import socket
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from db import normaliser_valeur, upsert_ioc
import os

_old_getaddrinfo = socket.getaddrinfo

def _ipv4_only_getaddrinfo(*args, **kwargs):
    responses = _old_getaddrinfo(*args, **kwargs)
    return [r for r in responses if r[0] == socket.AF_INET]

socket.getaddrinfo = _ipv4_only_getaddrinfo


AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY")


def convertir_date(date_str):
    if not date_str:
        return datetime.now().isoformat()
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S UTC")
        return dt.isoformat()
    except ValueError:
        return date_str


def extraire_cve(tags):
    if not tags:
        return []
    cves = []
    for tag in tags:
        cves += re.findall(r"CVE-\d{4}-\d{4,7}", tag, re.IGNORECASE)
    return list(set(cves))


def collecter_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {"Auth-Key": AUTH_KEY}
    print("Connexion à URLhaus...")
    response = requests.get(url, headers=headers, timeout=120)
    data = response.json()
    print(data.get("query_status"), "| clés reçues:", list(data.keys()))
    urls_brutes = data.get("urls", [])
    print(f"{len(urls_brutes)} URLs récupérées")
    conn = sqlite3.connect("iocs.db")
    total = 0
    for entry in urls_brutes:
        valeur_norm = normaliser_valeur(entry["url"])
        tags = entry.get("tags") or []
        ioc = {
            "type": "url",
            "value": valeur_norm,
            "port": None,
            "source": "URLhaus",
            "source_reference": entry.get("urlhaus_reference"),
            "tags": tags,
            "threat_type": entry.get("threat"),
            "malware_name": None,
            "mitre_techniques": [],
            "related_cves": extraire_cve(tags),
            "country": None,
            "confidence": 75 if entry.get("url_status") == "online" else 50,
            "first_seen": convertir_date(entry.get("date_added")),
            "expiration": None,
            "is_active": 1 if entry.get("url_status") == "online" else 0,
            "pulse_name": entry.get("reporter")
        }
        upsert_ioc(conn, ioc)
        total += 1
    conn.close()
    print(f"Terminé — {total} IOCs traités (insertion/mise à jour)")


if __name__ == "__main__":
    collecter_urlhaus()
