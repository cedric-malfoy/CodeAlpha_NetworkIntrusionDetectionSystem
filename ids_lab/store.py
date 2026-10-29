"""Transactional, idempotent incident storage and bounded read-only queries."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3


def iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, incident_id TEXT NOT NULL,
                timestamp REAL NOT NULL, last_timestamp REAL NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
                sport INTEGER, dport INTEGER, protocol TEXT, rule_ids TEXT NOT NULL,
                ml INTEGER NOT NULL, score REAL, severity INTEGER NOT NULL, features TEXT
            );
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS events_incident ON events(incident_id);
            CREATE TABLE IF NOT EXISTS runtime (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)

    def state(self, key, value):
        self.db.execute("INSERT INTO runtime VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))
        self.db.commit()

    def alert(self, run_id, window, rule_ids, ml, score, config):
        event_id = hashlib.sha256((run_id + window["flow_id"]).encode()).hexdigest()[:24]
        previous = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        rules = sorted(set(rule_ids) | set(json.loads(previous["rule_ids"]) if previous else []))
        ml = bool(ml or previous and previous["ml"])
        if not rules and not ml:
            return None
        severity = min([config["rules"][key]["severity"] for key in rules] + ([config["rules"]["ML"]["severity"]] if ml else []))
        timestamp = window["first"]
        # Fixed event-time 60-second incident buckets are deterministic across restarts.
        identity = (run_id, window["src"], window["dst"], int(timestamp // 60))
        incident_id = hashlib.sha256(repr(identity).encode()).hexdigest()[:16]
        self.db.execute("""INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET rule_ids=excluded.rule_ids, ml=excluded.ml,
            score=COALESCE(excluded.score,events.score), severity=excluded.severity,
            timestamp=MIN(events.timestamp,excluded.timestamp),
            last_timestamp=MAX(events.last_timestamp,excluded.last_timestamp),
            features=COALESCE(excluded.features,events.features)""",
            (event_id, run_id, incident_id, timestamp, window.get("last", timestamp), window["src"], window["dst"], window["sport"], window["dport"],
             window["protocol"], json.dumps(rules), int(ml), score, severity,
             json.dumps(window["values"]) if "values" in window else None))
        self.db.commit()
        return {"id": event_id, "incident_id": incident_id, "detector": "Both" if rules and ml else "Rule" if rules else "ML", "rules": rules, "score": score}

    def close(self):
        self.db.close()


def connect_readonly(path):
    database = Path(path).resolve()
    if not database.exists():
        return None
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    if connection.execute("SELECT name FROM sqlite_master WHERE name='events'").fetchone() is None:
        connection.close()
        return None
    return connection


def read_state(db):
    return {row["key"]: json.loads(row["value"]) for row in db.execute("SELECT * FROM runtime")} if db else {}


def query_events(db, severity="", detector="", source="", rule="", limit=100):
    if db is None:
        return []
    conditions, values = [], []
    if severity:
        conditions.append("severity=?")
        values.append(int(severity))
    if source:
        conditions.append("src=?")
        values.append(source)
    if detector == "ML":
        conditions.append("ml=1 AND rule_ids='[]'")
    elif detector == "Rule":
        conditions.append("ml=0 AND rule_ids!='[]'")
    elif detector == "Both":
        conditions.append("ml=1 AND rule_ids!='[]'")
    if rule:
        conditions.append("EXISTS (SELECT 1 FROM json_each(events.rule_ids) WHERE value=?)")
        values.append(rule)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    rows = db.execute("SELECT * FROM events" + where + " ORDER BY timestamp DESC, id LIMIT ?", [*values, min(500, max(1, int(limit)))])
    result = []
    for row in rows:
        entry = dict(row)
        entry["rule_ids"] = json.loads(entry["rule_ids"])
        entry["detector"] = "Both" if entry["rule_ids"] and entry["ml"] else "Rule" if entry["rule_ids"] else "ML"
        entry["time"] = iso(entry["timestamp"])
        entry["last_seen"] = iso(entry["last_timestamp"])
        entry["features"] = json.loads(entry["features"]) if entry["features"] else None
        result.append(entry)
    return result


def summary(db):
    state = read_state(db)
    if db is None:
        return {"events": 0, "incidents": 0, "severities": {}, "sources": [], "timeline": [], "state": state}
    return {
        "events": db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "incidents": db.execute("SELECT COUNT(DISTINCT incident_id) FROM events").fetchone()[0],
        "severities": {str(row[0]): row[1] for row in db.execute("SELECT severity,COUNT(*) FROM events GROUP BY severity")},
        "sources": [dict(row) for row in db.execute("SELECT src,COUNT(*) AS count FROM events GROUP BY src ORDER BY count DESC LIMIT 5")],
        "timeline": [dict(row) for row in db.execute("SELECT CAST(timestamp/5 AS INTEGER)*5 AS time,COUNT(*) AS count FROM events GROUP BY 1 ORDER BY 1 DESC LIMIT 24")][::-1],
        "state": state,
    }
