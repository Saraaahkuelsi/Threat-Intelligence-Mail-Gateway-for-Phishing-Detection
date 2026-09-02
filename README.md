# CTI Platform

Plateforme de Cyber Threat Intelligence (CTI) construite à partir de sources publiques, avec normalisation, scoring de fraîcheur (decay), et export des indicateurs de compromission (IOC).

## Objectifs

- Collecter des IOC depuis plusieurs sources CTI publiques
- Normaliser les données dans un schéma commun
- Gérer le cycle de vie des IOC via un système de score dégressif (inspiré de MISP / OpenCTI), plutôt qu'un TTL fixe
- Exporter les IOC actifs (STIX 2.1 / CSV) pour intégration dans d'autres outils (ex: pare-feu pfSense)

## Sources intégrées

| Source | Type de données | Authentification |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) | URLs malveillantes | Auth-Key (abuse.ch) |
| [ThreatFox](https://threatfox.abuse.ch/) | IOC multi-types + score de confiance | Auth-Key (abuse.ch) |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Serveurs C2 de botnets | Auth-Key (abuse.ch) |
| [AlienVault OTX](https://otx.alienvault.com/) | Pulses (rapports de campagne) + IOC | Clé API (SDK OTXv2) |
| [OpenPhish](https://openphish.com/) | URLs de phishing | Aucune (flux public) |

## Architecture

```
Sources CTI publiques
        │
        ▼
Scripts de collecte (Python)
   - normalisation
   - upsert en base
        │
        ▼
Base de données (SQLite)
        │
        ▼
Moteur de scoring / decay
   - formule inspirée de MISP
   - score(t) = base_score × (1 − (t/lifetime)^(1/decay_speed))
        │
        ▼
Export (STIX 2.1 / CSV)
        │
        ▼
Consommateurs (ex: pfSense via alias / pfBlockerNG)
```

## Installation

```bash
git clone https://github.com/<ton-utilisateur>/cti-platform.git
cd cti-platform
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Crée un fichier `.env` à la racine (non versionné) avec tes clés API :

```
URLHAUS_AUTH_KEY=ta_cle
THREATFOX_AUTH_KEY=ta_cle
OTX_API_KEY=ta_cle
```

- Clé abuse.ch (URLhaus / ThreatFox / Feodo Tracker) : à générer sur https://auth.abuse.ch/
- Clé OTX : à générer sur https://otx.alienvault.com/settings

## Initialisation de la base

```bash
python init_db.py
```

## Collecte des IOC

```bash
python collect_urlhaus.py
python collect_threat.py
python collect_fedo.py
python collect_otx.py
python collect_openPhish.py
```

## Mise à jour des scores (decay)

```bash
python update_scores.py --db iocs.db
```

## Modèle de scoring

Chaque IOC reçoit un score initial (`base_score`), issu soit de la confiance native de la source (ex: `confidence_level` de ThreatFox), soit d'une valeur par défaut selon son type. Ce score décroît dans le temps selon une formule inspirée du modèle de decay de MISP, jusqu'à un seuil en dessous duquel l'IOC est considéré comme expiré (`is_active = 0`). Un nouveau "sighting" (ré-observation dans un flux) réinitialise le score.

| Type | Durée de vie (lifetime) | Seuil d'expiration |
|---|---|---|
| IP | 3 jours | 30 |
| URL | 5 jours | 30 |
| Domaine | 30 jours | 30 |
| Hash (MD5/SHA1/SHA256) | 3650 jours | 5 |

## Automatisation (cron)

```bash
0 * * * * cd /chemin/vers/cti-platform && venv/bin/python collect_urlhaus.py
15 * * * * cd /chemin/vers/cti-platform && venv/bin/python collect_threat.py
30 * * * * cd /chemin/vers/cti-platform && venv/bin/python collect_otx.py
45 * * * * cd /chemin/vers/cti-platform && venv/bin/python update_scores.py
```

## État du projet

Projet en cours de développement (stage/projet académique). Prochaines étapes :
- Normalisation complète vers STIX 2.1
- Export CSV/texte pour intégration pfSense
- Tracking CVE (NVD, CISA KEV, EPSS)
- Filtrage par contexte (secteur, TLP, type de menace)

## Licence

À définir.

## Avertissement

Ce projet est à but éducatif / démonstratif. Les IOC collectés proviennent de sources publiques et doivent être validés avant tout usage opérationnel (blocage automatique, etc.).
