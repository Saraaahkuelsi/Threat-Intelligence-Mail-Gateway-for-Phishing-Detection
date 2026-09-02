import sqlite3

def init_db(chemin_db="iocs.db"):
    conn = sqlite3.connect(chemin_db)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            -- Identification de l'IOC
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            port INTEGER,

            -- Contexte de la menace
            tags TEXT,
            threat_type TEXT,
            malware_name TEXT,
            mitre_techniques TEXT,
            related_cves TEXT,
            country TEXT,

            -- Scoring
            confidence INTEGER CHECK(confidence BETWEEN 0 AND 100),
            severity TEXT,

            -- Lifecycle
            first_seen TEXT NOT NULL,
            last_seen TEXT,
            expiration TEXT,
            status TEXT DEFAULT 'active',
            is_active INTEGER DEFAULT 1,

            UNIQUE(type, value)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ioc_id INTEGER NOT NULL,

            source TEXT NOT NULL,
            source_id TEXT,
            source_reference TEXT,
            pulse_name TEXT,

            collected_at TEXT NOT NULL,

            UNIQUE(ioc_id, source),

            FOREIGN KEY (ioc_id) REFERENCES iocs(id)
        )
    """)

    # Index pour accélérer les recherches
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_type_value
        ON iocs(type, value)
    """)

    conn.commit()
    conn.close()
    print(f"Base de données initialisée : {chemin_db}")

if __name__ == "__main__":
    init_db()
