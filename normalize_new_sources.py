"""
Fonctions de normalisation pour OpenPhish et Feodo Tracker.
Retournent un dict compatible avec upsert_ioc(conn, ioc) de db.py réel
(schéma iocs / ioc_sources) — PAS une dataclass IOC.

Clés attendues par upsert_ioc :
  table iocs       : type, value, port, tags(list), threat_type,
                      malware_name, mitre_techniques(list),
                      related_cves(list), country, confidence,
                      severity, first_seen, expiration, status,
                      is_active
  table ioc_sources : source, source_id, source_reference, pulse_name
"""

from datetime import datetime, timezone


def normalize_openphish(line: str) -> dict:
    """
    OpenPhish (feed communautaire) : une URL brute par ligne, aucune
    métadonnée native. Pas de confidence natif -> absent du dict,
    db.py appliquera son défaut (50) via ioc.get("confidence", 50).
    """
    url = line.strip()
    now = datetime.now(timezone.utc).isoformat()

    return {
        "type": "url",
        "value": url,
        "source": "openphish",
        "source_id": None,
        "source_reference": None,
        "pulse_name": None,
        "tags": [],
        "threat_type": "phishing",
        "malware_name": None,
        "mitre_techniques": [],
        "related_cves": [],
        "country": None,
        "severity": None,
        "first_seen": now,
        "expiration": None,
        "status": "active",
        "is_active": 1,
        "port": None,
    }


def normalize_feodotracker(row: dict) -> dict:
    """
    Feodo Tracker (CSV) : colonnes attendues
    first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware

    c2_status ('online'/'offline') pilote is_active, même logique que
    url_status pour URLhaus -> point de vigilance déjà identifié
    (source vs decay), pas encore tranché globalement.

    last_online (info Feodo Tracker, pas un sighting côté collecte)
    est stocké dans tags, à part -> ne pilote PAS last_seen, qui reste
    entièrement géré par db.py (CURRENT_TIMESTAMP à l'upsert, approche A).
    """
    last_online = row.get("last_online", "")

    return {
        "type": "ip",
        "value": row["dst_ip"],
        "source": "feodotracker",
        "source_id": None,
        "source_reference": None,
        "pulse_name": None,
        "tags": [f"last_online_feodo:{last_online}"] if last_online else [],
        "threat_type": "botnet_c2",
        "malware_name": row.get("malware"),
        "mitre_techniques": [],
        "related_cves": [],
        "country": None,
        "severity": None,
        "first_seen": row["first_seen_utc"],
        "expiration": None,
        "status": "active",
        "is_active": 1 if row.get("c2_status") == "online" else 0,
        "port": int(row["dst_port"]) if row.get("dst_port") else None,
    }
