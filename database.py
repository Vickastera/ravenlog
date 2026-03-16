import sqlite3

DB_NAME = "events.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        severity TEXT,
        source_ip TEXT,
        event_type TEXT,
        message TEXT
    )
    """)

    conn.commit()
    conn.close()

def save_event(timestamp, severity, source_ip, event_type, message):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO events (timestamp, severity, source_ip, event_type, message)
    VALUES (?, ?, ?, ?, ?)
    """, (timestamp, severity, source_ip, event_type, message))

    conn.commit()
    conn.close()

def get_all_events():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT * FROM events ORDER BY id DESC")
    rows = cur.fetchall()

    conn.close()
    return rows

def search_events(keyword):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    SELECT * FROM events
    WHERE message LIKE ? OR source_ip LIKE ? OR event_type LIKE ?
    ORDER BY id DESC
    """, (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"))

    rows = cur.fetchall()
    conn.close()
    return rows
