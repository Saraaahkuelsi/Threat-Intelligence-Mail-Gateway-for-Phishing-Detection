import sqlite3
import re
from datetime import datetime
from OTXv2 import OTXv2
from dotenv import load_dotenv
load_dotenv()
from db import upsert_ioc, normaliser_type, normaliser_valeur
import os
AUTH_KEY = os.environ.get("OTX_API_KEY")


def extraire_pays(description):
    if not description:
        return None
    match = re.search(r"CC=([A-Z]{2})", description)
    return match.group(1) if match else None


def extraire_cve(texte):
    if not texte:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", texte, re.IGNORECASE)))


def collecter_otx():
    otx = OTXv2(API_KEY)
    conn = sqlite3.connect("iocs.db")

    print("Connexion à OTX...")
    pulses = otx.getsince("2026-07-01T00:00:00", limit=20)
    print(f"{len(pulses)} pulses récupérés")

    total_iocs = 0

    for pulse in pulses:

        tags = pulse.get("tags", [])
        pulse_name = pulse.get("name", "")
        pulse_id = pulse.get("id")

        # Extraction des CVE présentes dans le pulse
        cves_du_pulse = set()

        cves_du_pulse.update(extraire_cve(pulse_name))
        cves_du_pulse.update(extraire_cve(pulse.get("description", "")))

        for tag in tags:
            cves_du_pulse.update(extraire_cve(tag))

        for indicateur in pulse.get("indicators", []):
            if indicateur["type"].upper() == "CVE":
                cves_du_pulse.add(indicateur["indicator"].upper())

        cves_liste = list(cves_du_pulse)

        # Traitement des indicateurs
        for indicateur in pulse.get("indicators", []):

            if indicateur["type"].upper() == "CVE":
                continue

            type_norm = normaliser_type(indicateur["type"])
            valeur_norm = normaliser_valeur(indicateur["indicator"])

            ioc = {

                # IOC
                "type": type_norm,
                "value": valeur_norm,
                "port": None,

                # Source (sera stockée dans ioc_sources)
                "source": "OTX",
                "source_id": pulse_id,
                "source_reference": f"https://otx.alienvault.com/pulse/{pulse_id}",
                "pulse_name": pulse_name,

                # Contexte
                "tags": tags,
                "threat_type": tags[0] if tags else None,
                "malware_name": None,
                "mitre_techniques": pulse.get("attack_ids", []),
                "related_cves": cves_liste,
                "country": extraire_pays(indicateur.get("description", "")),

                # Scoring
                "confidence": 50,
                "severity": None,

                # Lifecycle
                "first_seen": indicateur.get("created", datetime.now().isoformat()),
                "expiration": indicateur.get("expiration"),
                "status": "active",
                "is_active": indicateur.get("is_active", 1)
            }

            upsert_ioc(conn, ioc)
            total_iocs += 1

    conn.close()
    print(f"Terminé — {total_iocs} IOCs traités (insertion/mise à jour)")


if __name__ == "__main__":
    collecter_otx()
