# CTI-Powered Phishing Detection Gateway

Open-source CTI platform aggregating IOCs from public feeds (URLhaus, ThreatFox, OTX, OpenPhish, Feodo Tracker), with normalization, MISP-inspired decay scoring, STIX/CSV export, and a mail gateway that scans incoming emails and blocks any message containing a known malicious IOC.

## Objectives

This project aims to build a functional and reliable CTI platform. The approach is structured around the following key steps:

- Set up an automated IOC collection system from multiple public Cyber Threat Intelligence sources
- Design a database to centralize IOCs, their history, their sources, and associated malware profiles
- Correlate information from different sources to improve the reliability of collected intelligence
- Enrich IOCs with contextual information (malware profiles, MITRE ATT&CK techniques, CVEs, confidence score, decay score, etc.)
- Develop a REST API to query IOCs, their context, and related IOCs
- Integrate an on-demand external verification via VirusTotal to complement internal intelligence when it is insufficient
- Develop a visualization interface to facilitate the analysis and use of CTI intelligence
- Integrate the platform with a Secure Email Gateway (Haraka) to enable real-time analysis of IOCs extracted from emails and support decision-making (accept, quarantine, or reject messages)

## Sources

| Source                                          | Data type                          | Authentication      |
| ----------------------------------------------- | ---------------------------------- | ------------------- |
| [URLhaus](https://urlhaus.abuse.ch/)            | Malicious URLs                     | Auth-Key (abuse.ch) |
| [ThreatFox](https://threatfox.abuse.ch/)        | Multi-type IOCs + confidence score | Auth-Key (abuse.ch) |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 servers                  | Auth-Key (abuse.ch) |
| [AlienVault OTX](https://otx.alienvault.com/)   | Pulses (campaign reports) + IOCs   | API key (OTXv2 SDK) |
| [OpenPhish](https://openphish.com/)             | Phishing URLs                      | None (public feed)  |
| [VirusTotal](https://www.virustotal.com/)       | On-demand verification             | API key             |

## Architecture

![Platform architecture](architecure_cti.png)

```
Public CTI sources
        │
        ▼
Collection scripts (Python)
   - normalization
   - upsert into database
        │
        ▼
Database (SQLite)
        │
        ▼
Scoring / decay engine
   - MISP-inspired formula
   - score(t) = base_score × (1 − (t/lifetime)^(1/decay_speed))
        │
        ▼
REST API + visualization interface
        │
        ▼
Export (STIX 2.1 / CSV)  ──────────────►  Consumers (e.g. pfSense via alias / pfBlockerNG)
        │
        ▼
Secure Email Gateway (Haraka)
   - real-time IOC scan of incoming emails
   - accept / quarantine / reject decision
```

## Installation

```bash
git clone https://github.com/<your-username>/cti-phishing-gateway.git
cd cti-phishing-gateway
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create a `.env` file at the project root (not versioned) with your API keys:

```
URLHAUS_AUTH_KEY=your_key
THREATFOX_AUTH_KEY=your_key
OTX_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
```

- abuse.ch key (URLhaus / ThreatFox / Feodo Tracker): generate at https://auth.abuse.ch/
- OTX key: generate at https://otx.alienvault.com/settings
- VirusTotal key: generate at https://www.virustotal.com/gui/my-apikey

## Database initialization

```bash
python init_db.py
```

## IOC collection

```bash
python collect_urlhaus.py
python collect_threat.py
python collect_fedo.py
python collect_otx.py
python collect_openPhish.py
```

## Score update (decay)

```bash
python update_scores.py --db iocs.db
```

## Scoring model

Each IOC receives an initial score (`base_score`), either from the source's native confidence (e.g. ThreatFox's `confidence_level`) or from a default value based on its type. This score decays over time following a MISP-inspired formula, until it falls below a threshold at which the IOC is considered expired (`is_active = 0`). A new sighting (re-observed in a feed) resets the score.

| Type                   | Lifetime  | Expiration threshold |
| ---------------------- | --------- | -------------------- |
| IP                     | 3 days    | 30                   |
| URL                    | 5 days    | 30                   |
| Domain                 | 30 days   | 30                   |
| Hash (MD5/SHA1/SHA256) | 3650 days | 5                    |

## Automation (cron)

```bash
0 * * * * cd /path/to/cti-phishing-gateway && venv/bin/python collect_urlhaus.py
15 * * * * cd /path/to/cti-phishing-gateway && venv/bin/python collect_threat.py
30 * * * * cd /path/to/cti-phishing-gateway && venv/bin/python collect_otx.py
45 * * * * cd /path/to/cti-phishing-gateway && venv/bin/python update_scores.py
```

## Mail gateway integration (Haraka)

