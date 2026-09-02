import requests
import re
import sqlite3
from datetime import datetime
from db import normaliser_valeur, upsert_ioc
from dotenv import load_dotenv
load_dotenv()
import os
AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY")

def normaliser_type_threatfox(ioc_type_brut):
    mapping = {
        "ip:port": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash",
        "sha1_hash": "hash",
        "sha256_hash": "hash",
    }
    return mapping.get(ioc_type_brut.lower(), ioc_type_brut.lower())

def separer_ip_port(valeur):
    """Retourne (ip, port) séparés si applicable, sinon (valeur, None)"""
    if ":" in valeur and valeur.count(":") == 1:
        ip, port = valeur.split(":")
        try:
            return ip, int(port)
        except ValueError:
            return valeur, None
    return valeur, None

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

def collecter_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": AUTH_KEY}
    payload = {"query": "get_iocs", "days": 7}

    print("Connexion à ThreatFox...")
    response = requests.post(url, headers=headers, json=payload, timeout=60)
    data = response.json()

    iocs_bruts = data.get("data", [])
    print(f"{len(iocs_bruts)} IOCs récupérés")

    conn = sqlite3.connect("iocs.db")
    total = 0

    for entry in iocs_bruts:
        type_norm = normaliser_type_threatfox(entry["ioc_type"])

        if type_norm == "ip":
            ip_extraite, port_extrait = separer_ip_port(entry["ioc"])
            valeur_norm = normaliser_valeur(ip_extraite)
        else:
            valeur_norm = normaliser_valeur(entry["ioc"])
            port_extrait = None

        tags = entry.get("tags") or []

        ioc = {
            "type": type_norm,
            "value": valeur_norm,
            "port": port_extrait,
            "source": "ThreatFox",
            "source_reference": entry.get("reference"),
            "tags": tags,
            "threat_type": entry.get("threat_type"),
            "malware_name": entry.get("malware_printable"),
            "mitre_techniques": [],
            "related_cves": extraire_cve(tags),
            "country": None,
            "confidence": entry.get("confidence_level", 50),
            "first_seen": convertir_date(entry.get("first_seen")),
            "expiration": None,
            "is_active": 1,
            "pulse_name": entry.get("reporter")
        }

        upsert_ioc(conn, ioc)
        total += 1

    conn.close()
    print(f"Terminé — {total} IOCs traités (insertion/mise à jour)")

if __name__ == "__main__":
    collecter_threatfox()
