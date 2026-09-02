import argparse
import sqlite3
from datetime import datetime, timezone

DECAY_MODELS = {
    "ip":       {"lifetime": 3,    "decay_speed": 2.3, "threshold": 30, "default_base_score": 80},
    "ipv4":     {"lifetime": 3,    "decay_speed": 2.3, "threshold": 30, "default_base_score": 80},
    "ipv6":     {"lifetime": 3,    "decay_speed": 2.3, "threshold": 30, "default_base_score": 80},
    "url":      {"lifetime": 5,    "decay_speed": 2.3, "threshold": 30, "default_base_score": 80},
    "domain":   {"lifetime": 30,   "decay_speed": 2.0, "threshold": 30, "default_base_score": 80},
    "hostname": {"lifetime": 30,   "decay_speed": 2.0, "threshold": 30, "default_base_score": 80},
    "md5":      {"lifetime": 3650, "decay_speed": 1.0, "threshold": 5,  "default_base_score": 90},
    "sha1":     {"lifetime": 3650, "decay_speed": 1.0, "threshold": 5,  "default_base_score": 90},
    "sha256":   {"lifetime": 3650, "decay_speed": 1.0, "threshold": 5,  "default_base_score": 90},
    "generic":  {"lifetime": 120,  "decay_speed": 2.0, "threshold": 30, "default_base_score": 80},
     "hash": {
    "lifetime": 3650,
    "decay_speed": 1.0,
    "threshold": 5,
    "default_base_score": 90
}
}


def get_model(ioc_type):
    return DECAY_MODELS.get((ioc_type or "").lower(), DECAY_MODELS["generic"])


def parse_dt(value):
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00").replace(" UTC", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        try:
            dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_score(ioc_type, base_score, last_seen_dt, native_expiration_dt, now):
    if native_expiration_dt:
        return 0.0 if now >= native_expiration_dt else base_score

    model = get_model(ioc_type)
    lifetime = model["lifetime"]
    decay_speed = model["decay_speed"]

    if not last_seen_dt:
        return base_score

    t_days = (now - last_seen_dt).total_seconds() / 86400
    if t_days <= 0:
        return base_score
    if t_days >= lifetime:
        return 0.0

    score = base_score * (1 - (t_days / lifetime) ** (1 / decay_speed))
    return max(0.0, round(score, 2))


def update_all_scores(db_path):
    now = datetime.now(timezone.utc)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("""
        SELECT id, type, confidence, first_seen, last_seen, expiration, is_active
        FROM iocs
        WHERE is_active = 1
    """).fetchall()

    updated, expired_count = 0, 0

    for row in rows:
        ioc_type = row["type"]
        model = get_model(ioc_type)

        base_score = row["confidence"] if row["confidence"] is not None else model["default_base_score"]
        last_seen_dt = parse_dt(row["last_seen"]) or parse_dt(row["first_seen"])
        native_expiration_dt = parse_dt(row["expiration"])

        score = compute_score(ioc_type, base_score, last_seen_dt, native_expiration_dt, now)
        is_expired = score < model["threshold"]

        cur.execute("""
            UPDATE iocs
            SET current_score = ?,
                score_updated_at = ?,
                is_active = ?
            WHERE id = ?
        """, (score, now.isoformat(), 0 if is_expired else 1, row["id"]))

        updated += 1
        if is_expired:
            expired_count += 1

    conn.commit()
    conn.close()

    print(f"IOC traités          : {updated}")
    print(f"Nouvellement expirés : {expired_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="iocs.db")
    args = parser.parse_args()

    update_all_scores(args.db)
