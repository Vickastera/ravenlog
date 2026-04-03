# 🛡️ LogSentinel

LogSentinel is a lightweight security log monitoring tool built with Python, Flask, and SQLite.
It parses server logs, detects suspicious activity, stores normalized events, and exposes both a web dashboard and a JSON API for investigation.

🌐 **Live demo:** https://logsentinel-bm52.onrender.com

![Dashboard](dashboard-preview.png)

---

## Features

- Parse server log files
- Detect suspicious events:
  - Multiple failed login attempts
  - Unauthorized access attempts to `/admin`
  - `/wp-login.php` scans
  - `/phpmyadmin` scans
- Store detected events in SQLite with deduplication
- Web dashboard for viewing and searching events
- JSON API endpoint for programmatic access
- Event summary: total events, count by type, top source IPs
- Search by IP address, event type, or message text

---

## Tech Stack

Python · Flask · SQLite · HTML/CSS

---

## Quick Start
```bash
git clone https://github.com/Vickastera/logsentinel.git
cd logsentinel
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python collector.py
python app.py
```

Then open http://localhost:5000 in your browser.

---

## API
```
GET /api/events           → returns all events
GET /api/events?q=keyword → filter by IP, event type or message
```

---

## Project Structure

- `app.py` → Flask dashboard + JSON API
- `analyzer.py` → detects suspicious patterns
- `collector.py` → reads and processes log files
- `database.py` → SQLite persistence and search
- `tests/` → unit tests
