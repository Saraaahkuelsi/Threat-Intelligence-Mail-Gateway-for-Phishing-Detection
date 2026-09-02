import sqlite3
import json
from datetime import datetime


def normaliser_valeur(valeur):
    valeur = valeur.strip().lower()
    valeur = valeur.replace("http://", "").replace("https://", "")
    valeur = valeur.replace("www.", "")
    valeur = valeur.rstrip("/")
    return valeur


def normaliser_type(type_brut):
   mapping = {
    # IP
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",

    # Domaines
    "domain": "domain",
    "hostname": "domain",

    # URL
    "url": "url",

    # Hashes
    "md5_hash": "hash",
    "sha1_hash": "hash",
    "sha256_hash": "hash",

    "filehash-md5": "hash",
    "filehash-sha1": "hash",
    "filehash-sha256": "hash",

    # Autres
    "email": "email",
    "filename": "filename",
}

   return mapping.get(type_brut.lower(), type_brut.lower())


def upsert_ioc(conn, ioc):
    cursor = conn.cursor()

    # 1. Insérer/mettre à jour l'IOC lui-même dans `iocs`
    cursor.execute("""
        INSERT INTO iocs (
            type,
            value,
            port,
            tags,
            threat_type,
            malware_name,
            mitre_techniques,
            related_cves,
            country,
            confidence,
            severity,
            first_seen,
            last_seen,
            expiration,
            status,
            is_active
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(type, value)
        DO UPDATE SET
            last_seen = CURRENT_TIMESTAMP,
            confidence = MAX(confidence, excluded.confidence),
            severity = COALESCE(excluded.severity, severity),
            tags = excluded.tags,
            threat_type = COALESCE(excluded.threat_type, threat_type),
            malware_name = COALESCE(excluded.malware_name, malware_name),
            mitre_techniques = excluded.mitre_techniques,
            related_cves = excluded.related_cves,
            country = COALESCE(excluded.country, country),
            expiration = COALESCE(excluded.expiration, expiration),
            status = COALESCE(excluded.status, status),
            is_active = excluded.is_active,
            port = COALESCE(excluded.port, port)
    """, (
        ioc["type"],
        ioc["value"],
        ioc.get("port"),
        json.dumps(ioc.get("tags", [])),
        ioc.get("threat_type"),
        ioc.get("malware_name"),
        json.dumps(ioc.get("mitre_techniques", [])),
        json.dumps(ioc.get("related_cves", [])),
        ioc.get("country"),
        ioc.get("confidence", 50),
        ioc.get("severity"),
        ioc["first_seen"],
        datetime.utcnow().isoformat(),   # last_seen = maintenant dès l'INSERT (approche A)
        ioc.get("expiration"),
        ioc.get("status", "active"),
        ioc.get("is_active", 1)
    ))

    # 2. Récupérer l'id de l'IOC
    cursor.execute("""
        SELECT id
        FROM iocs
        WHERE type = ? AND value = ?
    """, (
        ioc["type"],
        ioc["value"]
    ))

    ioc_id = cursor.fetchone()[0]

    # 3. Ajouter/mettre à jour la source dans ioc_sources
    cursor.execute("""
        INSERT INTO ioc_sources (
            ioc_id,
            source,
            source_id,
            source_reference,
            pulse_name,
            collected_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(ioc_id, source)
        DO UPDATE SET
            source_reference = excluded.source_reference,
            pulse_name = excluded.pulse_name,
            collected_at = excluded.collected_at
    """, (
        ioc_id,
        ioc["source"],
        ioc.get("source_id"),
        ioc.get("source_reference"),
        ioc.get("pulse_name"),
        datetime.utcnow().isoformat()
    ))

    conn.commit()
