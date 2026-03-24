import sqlite3

DB_NAME = "events.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            source_ip TEXT,
            event_type TEXT,
            message TEXT,
            fingerprint TEXT UNIQUE
        )
        """
    )

    # Si la tabla ya existía de antes sin fingerprint, la agregamos
    cur.execute("PRAGMA table_info(events)")
    columns = [row[1] for row in cur.fetchall()]

    if "fingerprint" not in columns:
        cur.execute("ALTER TABLE events ADD COLUMN fingerprint TEXT")

    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint)"
    )

    conn.commit()
    conn.close()


def save_event(timestamp, severity, source_ip, event_type, message, fingerprint=None):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT OR IGNORE INTO events (timestamp, severity, source_ip, event_type, message, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, severity, source_ip, event_type, message, fingerprint),
    )

    conn.commit()
    conn.close()


def get_all_events():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, timestamp, severity, source_ip, event_type, message
        FROM events
        ORDER BY id DESC
        """
    )

    rows = cur.fetchall()
    conn.close()
    return rows


def search_events(keyword):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, timestamp, severity, source_ip, event_type, message
        FROM events
        WHERE message LIKE ? OR source_ip LIKE ? OR event_type LIKE ?
        ORDER BY id DESC
        """,
        (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"),
    )

    rows = cur.fetchall()
    conn.close()
    return rows
