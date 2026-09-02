import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()
import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from db import normaliser_valeur

DB_PATH = "iocs.db"
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def build_consolidated_verdict(ioc_row, external_intel):
    """Fusionne le verdict interne et VirusTotal. Ne tranche jamais
    automatiquement en cas de désaccord -> signale le conflit pour
    qu'un analyste tranche, ne remplace pas son jugement."""

    vt_available = external_intel and external_intel.get("found_in_vt")
    vt_ratio = None
    vt_says_malicious = None
    if vt_available and external_intel.get("total_engines"):
        vt_ratio = external_intel["malicious_votes"] / external_intel["total_engines"]
        vt_says_malicious = vt_ratio > 0.3  # seuil provisoire

    # Cas 1 : IOC totalement absent en interne
    if ioc_row is None:
        if vt_available:
            return {
                "verdict": "malicious" if vt_says_malicious else "suspicious" if vt_ratio and vt_ratio > 0 else "clean",
                "confidence": "external_only",
                "reasoning": f"Aucune donnée interne (absent de nos 5 sources CTI). VirusTotal : {external_intel['detection_ratio']} moteurs positifs.",
            }
        return {
            "verdict": "unknown",
            "confidence": "none",
            "reasoning": "Aucune donnée interne ni externe disponible pour cet IOC.",
        }

    internal_says_malicious = bool(ioc_row["current_score"]) and ioc_row["current_score"] > 50
    internal_verdict = "malicious" if internal_says_malicious else "low_confidence"

    if not vt_available:
        return {
            "verdict": internal_verdict,
            "confidence": "internal_only",
            "reasoning": f"Score interne {ioc_row['current_score']}. Pas de vérification externe déclenchée ou disponible.",
        }

    if vt_says_malicious == internal_says_malicious:
        return {
            "verdict": internal_verdict,
            "confidence": "corroborated",
            "reasoning": f"Score interne {ioc_row['current_score']}, confirmé par VirusTotal ({external_intel['detection_ratio']}).",
        }

    # Désaccord -> signalé explicitement, aucune source ne l'emporte automatiquement
    return {
        "verdict": "conflicting",
        "confidence": "conflicting",
        "reasoning": (
            f"Désaccord entre sources : score interne {ioc_row['current_score']} "
            f"({'malveillant' if internal_says_malicious else 'faible confiance'}) vs "
            f"VirusTotal {external_intel['detection_ratio']} "
            f"({'malveillant' if vt_says_malicious else 'peu de détections'}). "
            f"Vérification manuelle recommandée."
        ),
    }


def compute_uncertainty(ioc_row, nb_sources, nb_related):
    """Score cumulé d'incertitude sur un IOC connu en base.
    >= 2 signaux -> justifie une vérification externe (VT).
    Un seul signal isolé ne suffit pas, pour préserver le quota."""
    score = 0
    if not ioc_row["malware_name"]:
        score += 1
    if not ioc_row["mitre_techniques"] or ioc_row["mitre_techniques"] in ("[]", ""):
        score += 1
    if nb_sources <= 1:
        score += 1
    if nb_related == 0:
        score += 1
    return score


def looks_like_hash(value):
    return bool(HASH_PATTERN.match(value.strip()))


def call_virustotal_hash(hash_value):
    """Interroge VT pour un hash : réputation multi-moteurs +
    techniques MITRE observées en sandbox (si disponibles).
    Retourne None si la clé n'est pas configurée ou en cas d'erreur,
    plutôt que de faire planter /check."""
    if not VT_API_KEY:
        return {"error": "Clé VirusTotal non configurée (variable d'environnement VT_API_KEY absente)"}

    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(f"{VT_BASE_URL}/files/{hash_value}", headers=headers, timeout=10)
        if resp.status_code == 404:
            return {"found_in_vt": False}
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total_engines = sum(stats.values()) if stats else 0

        result = {
            "found_in_vt": True,
            "detection_ratio": f"{malicious}/{total_engines}" if total_engines else None,
            "malicious_votes": malicious,
            "total_engines": total_engines,
            "popular_names": data.get("popular_threat_classification", {}).get("suggested_threat_label"),
            "first_submission": data.get("first_submission_date"),
            "last_analysis": data.get("last_analysis_date"),
            "type_description": data.get("type_description"),
        }

        # Techniques MITRE observées en sandbox, si dispo (endpoint séparé)
        try:
            mitre_resp = requests.get(
                f"{VT_BASE_URL}/files/{hash_value}/behaviour_mitre_trees",
                headers=headers, timeout=10
            )
            if mitre_resp.status_code == 200:
                mitre_data = mitre_resp.json().get("data", {})
                techniques = set()
                for sandbox_report in mitre_data.values():
                    for tactic in sandbox_report.get("tactics", []):
                        for technique in tactic.get("techniques", []):
                            if technique.get("id"):
                                techniques.add(technique["id"])
                result["mitre_techniques_observed"] = sorted(techniques)
        except requests.RequestException:
            pass  # pas bloquant, le reste de la réponse VT reste valide

        return result
    except requests.RequestException as e:
        return {"error": f"Erreur d'appel VirusTotal: {e}"}


app = FastAPI(title="CTI Platform API")

# Paramètres de decay par type, repris du modèle déjà défini (à garder
# synchronisé avec update_scores.py si ces valeurs changent là-bas)
DECAY_PARAMS = {
    "ip":      {"lifetime": 3,    "decay_speed": 2.3, "threshold": 30},
    "url":     {"lifetime": 5,    "decay_speed": 2.3, "threshold": 30},
    "domain":  {"lifetime": 30,   "decay_speed": 2.0, "threshold": 30},
    "hash":    {"lifetime": 3650, "decay_speed": 1.0, "threshold": 5},
    "generic": {"lifetime": 120,  "decay_speed": 2.0, "threshold": 30},
}


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # permet d'accéder aux colonnes par nom
    return conn


def parse_json_field(value):
    """Les colonnes tags/mitre_techniques/related_cves/aliases sont
    stockées en JSON -> reconvertit en liste Python, tolère les valeurs
    vides/None/mal formées sans planter."""
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def build_justification(ioc_row):
    """Génère une explication texte du score à partir des paramètres
    de decay et de l'ancienneté de last_seen."""
    ioc_type = ioc_row["type"]
    params = DECAY_PARAMS.get(ioc_type, DECAY_PARAMS["generic"])

    if not ioc_row["last_seen"]:
        return "Aucune date de dernière observation disponible, score non calculable précisément."

    try:
        last_seen_dt = datetime.fromisoformat(ioc_row["last_seen"].replace("Z", "+00:00"))
        if last_seen_dt.tzinfo is None:
            last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return "Date de dernière observation illisible, score non calculable précisément."

    now = datetime.now(timezone.utc)
    days_since = (now - last_seen_dt).total_seconds() / 86400

    score = ioc_row["current_score"]
    is_active = bool(ioc_row["is_active"])

    statut = "actif" if is_active else "expiré"
    return (
        f"IOC de type '{ioc_type}' : dernière observation il y a "
        f"{days_since:.1f} jour(s). Pour ce type, le modèle de decay "
        f"utilise une durée de vie de référence de {params['lifetime']} "
        f"jour(s) et un seuil d'expiration de {params['threshold']}. "
        f"Score actuel : {score if score is not None else 'non calculé'} "
        f"-> statut {statut}."
    )


def ioc_to_dict(conn, ioc_row, allow_external=True):
    """Construit la fiche complète d'un IOC : sources, profil malware,
    justification du score."""
    cur = conn.cursor()

    # Sources CTI ayant vu cet IOC
    cur.execute("""
        SELECT source, source_id, source_reference, pulse_name, collected_at
        FROM ioc_sources
        WHERE ioc_id = ?
        ORDER BY collected_at DESC
    """, (ioc_row["id"],))
    sources = [dict(r) for r in cur.fetchall()]

    # Détections vues par le Mail Gateway pour ce même IOC (type + valeur) :
    # mail_events est une table séparée de ioc_sources, donc on la
    # requête à part et on l'ajoute à la même liste "sources" pour que
    # l'analyste voie Mail Gateway comme une source à part entière.
    cur.execute("""
        SELECT message_id, sender, recipient, received_at
        FROM mail_events
        WHERE ioc_type = ? AND ioc_value = ?
        ORDER BY received_at DESC
    """, (ioc_row["type"], ioc_row["value"]))
    for h in cur.fetchall():
        sources.append({
            "source": "Mail Gateway",
            "source_id": h["message_id"],
            "source_reference": f"{h['sender'] or '?'} -> {h['recipient'] or '?'}",
            "pulse_name": None,
            "collected_at": h["received_at"],
        })

    # Profil malware associé, si connu
    malware_profile = None
    if ioc_row["malware_name"]:
        cur.execute("""
            SELECT malware_name, malware_type, description, aliases,
                   mitre_techniques, related_cves, references_docs
            FROM malware_profiles
            WHERE malware_name = ?
        """, (ioc_row["malware_name"],))
        row = cur.fetchone()
        if row:
            malware_profile = {
                "malware_name": row["malware_name"],
                "malware_type": row["malware_type"],
                "description": row["description"],
                "aliases": parse_json_field(row["aliases"]),
                "mitre_techniques": parse_json_field(row["mitre_techniques"]),
                "related_cves": parse_json_field(row["related_cves"]),
                "references": parse_json_field(row["references_docs"]),
            }

    # Nombre d'IOC liés (même logique de priorité que /related), pour
    # alimenter le score d'incertitude
    nb_related = 0
    if ioc_row["malware_name"]:
        cur.execute("SELECT COUNT(*) as n FROM iocs WHERE id != ? AND malware_name = ?",
                    (ioc_row["id"], ioc_row["malware_name"]))
        nb_related = cur.fetchone()["n"]

    uncertainty = compute_uncertainty(ioc_row, len(sources), nb_related)

    # Enrichissement externe (VirusTotal) : uniquement sur les hashes,
    # et seulement si au moins 2 signaux d'incertitude cumulés -> évite
    # de consommer le quota pour des IOC déjà bien contextualisés.
    # `allow_external` permet de désactiver complètement cet appel
    # (utilisé par /related pour éviter d'enchaîner N appels VT).
    external_intelligence = None
    if allow_external and ioc_row["type"] == "hash" and uncertainty >= 2:
        external_intelligence = call_virustotal_hash(ioc_row["value"])

    consolidated = build_consolidated_verdict(ioc_row, external_intelligence)

    return {
        "id": ioc_row["id"],
        "type": ioc_row["type"],
        "value": ioc_row["value"],
        "port": ioc_row["port"],
        "threat_type": ioc_row["threat_type"],
        "malware_name": ioc_row["malware_name"],
        "tags": parse_json_field(ioc_row["tags"]),
        "related_cves": parse_json_field(ioc_row["related_cves"]),
        "country": ioc_row["country"],
        "confidence": ioc_row["confidence"],
        "severity": ioc_row["severity"],
        "timeline": {
            "first_seen": ioc_row["first_seen"],
            "last_seen": ioc_row["last_seen"],
            "expiration": ioc_row["expiration"],
        },
        "score": {
            "current_score": ioc_row["current_score"],
            "score_updated_at": ioc_row["score_updated_at"],
            "is_active": bool(ioc_row["is_active"]),
            "status": ioc_row["status"],
        },
        "justification": build_justification(ioc_row),
        "sources": sources,
        "malware_profile": malware_profile,
        "uncertainty_score": uncertainty,
        "external_intelligence": external_intelligence,
        "consolidated_verdict": consolidated,
    }


@app.get("/check")
def check_ioc(
    value: str = Query(..., description="Valeur de l'IOC à vérifier (IP, domaine, URL, hash...)"),
    type: str | None = Query(None, description="Type d'IOC, optionnel si la valeur est suffisamment unique"),
):
    conn = get_conn()
    try:
        valeur_norm = normaliser_valeur(value)
        cur = conn.cursor()

        if type:
            cur.execute("SELECT * FROM iocs WHERE type = ? AND value = ?", (type, valeur_norm))
        else:
            cur.execute("SELECT * FROM iocs WHERE value = ?", (valeur_norm,))

        row = cur.fetchone()
        if not row:
            # Gap filling : IOC totalement absent de nos 5 sources.
            # Si ça ressemble à un hash, VT peut être la seule info
            # disponible -> on tente quand même.
            external_intelligence = None
            if looks_like_hash(valeur_norm):
                external_intelligence = call_virustotal_hash(valeur_norm)

            consolidated = build_consolidated_verdict(None, external_intelligence)

            return {
                "found": False,
                "value": valeur_norm,
                "message": "Aucun IOC correspondant trouvé dans nos sources CTI internes.",
                "external_intelligence": external_intelligence,
                "consolidated_verdict": consolidated,
            }

        return {"found": True, "ioc": ioc_to_dict(conn, row)}
    finally:
        conn.close()


@app.get("/related/{ioc_id}")
def related_iocs(ioc_id: int, limit: int = 20):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
        base_ioc = cur.fetchone()
        if not base_ioc:
            raise HTTPException(status_code=404, detail="IOC introuvable")

        # Chercher si cet IOC appartient à une campagne nommée (pulse_name),
        # info qui vit dans ioc_sources, pas dans iocs directement
        cur.execute("""
            SELECT DISTINCT pulse_name FROM ioc_sources
            WHERE ioc_id = ? AND pulse_name IS NOT NULL AND pulse_name != ''
        """, (ioc_id,))
        pulse_names = [r["pulse_name"] for r in cur.fetchall()]

        # Ordre de priorité du lien, du plus fiable au moins fiable :
        # 1. Même campagne nommée (pulse_name) -> lien le plus fort
        # 2. Même malware identifié -> lien correct mais générique si
        #    l'outil (ex: Cobalt Strike) est partagé par des acteurs
        #    non liés entre eux
        # 3. Même threat_type -> dernier recours, catégorie large
        if pulse_names:
            link_type = "pulse_name"
            placeholders = ",".join("?" for _ in pulse_names)
            where_clause = f"""
                id != ? AND id IN (
                    SELECT ioc_id FROM ioc_sources
                    WHERE pulse_name IN ({placeholders})
                )
            """
            params = [ioc_id] + pulse_names
        elif base_ioc["malware_name"]:
            link_type = "malware_name"
            where_clause = "id != ? AND malware_name = ?"
            params = [ioc_id, base_ioc["malware_name"]]
        elif base_ioc["threat_type"]:
            link_type = "threat_type"
            where_clause = "id != ? AND threat_type = ?"
            params = [ioc_id, base_ioc["threat_type"]]
        else:
            return {"ioc_id": ioc_id, "related": [], "message": "Pas assez de contexte sur cet IOC pour trouver des IOC liés."}

        # Total réel (sans limite), pour que l'analyste sache l'ampleur
        # du cluster même si on n'affiche qu'un extrait
        cur.execute(f"SELECT COUNT(*) as total FROM iocs WHERE {where_clause}", params)
        total_count = cur.fetchone()["total"]

        # Tri par pertinence pratique : actifs d'abord, puis les plus
        # récemment observés -> ce qu'un analyste veut voir en premier
        cur.execute(f"""
            SELECT * FROM iocs WHERE {where_clause}
            ORDER BY is_active DESC, last_seen DESC
            LIMIT ?
        """, params + [limit])

        related = [ioc_to_dict(conn, r, allow_external=False) for r in cur.fetchall()]
        return {
            "ioc_id": ioc_id,
            "link_type": link_type,
            "total_related": total_count,
            "returned_count": len(related),
            "related": related,
        }
    finally:
        conn.close()

class MailIOCResult(BaseModel):
    type: str
    value: str
    verdict: str
    malware_name: str | None = None
    threat_type: str | None = None


class MailEventLog(BaseModel):
    message_id: str
    sender: str | None = None
    recipient: str | None = None
    iocs: list[MailIOCResult]


@app.post("/mail/log")
def log_mail_event(event: MailEventLog):
    """Reçoit le résultat de vérification d'un email depuis le Mail
    Gateway (Haraka) et le journalise -> alimente ensuite /mail/stats
    et l'onglet dédié du dashboard."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        for ioc in event.iocs:
            cur.execute("""
                INSERT INTO mail_events
                (message_id, received_at, sender, recipient, ioc_type, ioc_value, verdict, malware_name, threat_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.message_id, now, event.sender, event.recipient,
                ioc.type, ioc.value, ioc.verdict, ioc.malware_name, ioc.threat_type,
            ))
        conn.commit()
        return {"logged": len(event.iocs)}
    finally:
        conn.close()


@app.get("/mail/stats")
def mail_stats(limit: int = 20):
    """Statistiques agrégées sur les emails traités par le Mail
    Gateway -> alimente l'onglet 'Mail Gateway' du dashboard.
    `limit` contrôle la taille de `recent_detections` (par défaut 20,
    utilisé par les onglets courts ; la page Historique demande une
    valeur plus grande pour afficher un vrai historique)."""
    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(DISTINCT message_id) as n FROM mail_events")
        total_emails = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(DISTINCT message_id) as n FROM mail_events WHERE verdict = 'malicious'")
        total_malicious = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(DISTINCT ioc_value || ':' || ioc_type) as n FROM mail_events")
        total_distinct_iocs = cur.fetchone()["n"]

        cur.execute("""
            SELECT malware_name, COUNT(*) as n FROM mail_events
            WHERE malware_name IS NOT NULL
            GROUP BY malware_name ORDER BY n DESC LIMIT 10
        """)
        top_malware = [{"malware_name": r["malware_name"], "count": r["n"]} for r in cur.fetchall()]

        cur.execute("""
            SELECT threat_type, COUNT(*) as n FROM mail_events
            WHERE threat_type IS NOT NULL
            GROUP BY threat_type ORDER BY n DESC LIMIT 10
        """)
        top_threat_types = [{"threat_type": r["threat_type"], "count": r["n"]} for r in cur.fetchall()]

        cur.execute("""
            SELECT substr(received_at, 1, 10) as day, COUNT(DISTINCT message_id) as n
            FROM mail_events GROUP BY day ORDER BY day
        """)
        timeline = [{"date": r["day"], "count": r["n"]} for r in cur.fetchall()]

        cur.execute("""
            SELECT message_id, received_at, sender, recipient, ioc_type, ioc_value, verdict, malware_name, threat_type
            FROM mail_events ORDER BY received_at DESC LIMIT ?
        """, (limit,))
        recent = [dict(r) for r in cur.fetchall()]

        return {
            "total_emails": total_emails,
            "total_malicious_emails": total_malicious,
            "total_distinct_iocs": total_distinct_iocs,
            "top_malware": top_malware,
            "top_threat_types": top_threat_types,
            "timeline": timeline,
            "recent_detections": recent,
        }
    finally:
        conn.close()


@app.get("/stats")
def get_stats():
    """Statistiques globales de la base, utilisées par le dashboard
    Streamlit (vue d'ensemble) -> tout passe par l'API, pas d'accès
    direct à iocs.db depuis le dashboard, pour rester cohérent avec
    l'architecture (une seule couche d'accès aux données)."""
    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as n FROM iocs")
        total_iocs = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) as n FROM ioc_sources")
        total_sources_liees = cur.fetchone()["n"]

        cur.execute("SELECT COUNT(*) as n FROM malware_profiles")
        total_malwares = cur.fetchone()["n"]

        cur.execute("SELECT type, COUNT(*) as n FROM iocs GROUP BY type ORDER BY n DESC")
        par_type = {r["type"]: r["n"] for r in cur.fetchall()}

        cur.execute("SELECT status, COUNT(*) as n FROM iocs GROUP BY status ORDER BY n DESC")
        par_statut = {r["status"]: r["n"] for r in cur.fetchall()}

        cur.execute("SELECT is_active, COUNT(*) as n FROM iocs GROUP BY is_active")
        actifs_vs_expires = {("actif" if r["is_active"] else "expiré"): r["n"] for r in cur.fetchall()}

        cur.execute("SELECT source, COUNT(*) as n FROM ioc_sources GROUP BY source ORDER BY n DESC")
        par_source = {r["source"]: r["n"] for r in cur.fetchall()}

        cur.execute("""
            SELECT malware_name, COUNT(*) as n FROM iocs
            WHERE malware_name IS NOT NULL
            GROUP BY malware_name ORDER BY n DESC LIMIT 10
        """)
        top_malwares = [{"malware_name": r["malware_name"], "count": r["n"]} for r in cur.fetchall()]

        cur.execute("SELECT MIN(first_seen) as min_d, MAX(last_seen) as max_d FROM iocs")
        row = cur.fetchone()

        return {
            "total_iocs": total_iocs,
            "total_sources_liees": total_sources_liees,
            "total_malwares_profiles": total_malwares,
            "par_type": par_type,
            "par_statut": par_statut,
            "actifs_vs_expires": actifs_vs_expires,
            "par_source": par_source,
            "top_malwares": top_malwares,
            "plage_temporelle": {"first_seen_min": row["min_d"], "last_seen_max": row["max_d"]},
        }
    finally:
        conn.close()
@app.get("/malware")
def list_malware():
    """Liste tous les profils malware connus (table malware_profiles),
    techniques MITRE incluses -> alimente la page 'Malware' du
    dashboard, sans page MITRE ATT&CK séparée puisque l'information
    est déjà rattachée à chaque famille."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT malware_name, malware_type, description, aliases,
                   mitre_techniques, related_cves, references_docs
            FROM malware_profiles ORDER BY malware_name
        """)
        result = []
        for r in cur.fetchall():
            result.append({
                "malware_name": r["malware_name"],
                "malware_type": r["malware_type"],
                "description": r["description"],
                "aliases": parse_json_field(r["aliases"]),
                "mitre_techniques": parse_json_field(r["mitre_techniques"]),
                "related_cves": parse_json_field(r["related_cves"]),
                "references": parse_json_field(r["references_docs"]),
            })
        return {"total": len(result), "malware_profiles": result}
    finally:
        conn.close()
@app.get("/")
def root():
    return {"message": "CTI Platform API — voir /docs pour la documentation interactive"}
