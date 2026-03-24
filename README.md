# LogSentinel

LogSentinel is a lightweight defensive security monitoring project built with Python, Flask, and SQLite.

It parses server logs, detects suspicious activity patterns, stores normalized events, and exposes both a web dashboard and a JSON API for investigation.

---

## Features

- Parse server logs
- Detect suspicious activity patterns
- Store events in SQLite
- De-duplicate events using log-line fingerprints
- Search events by IP, event type, or keyword
- Simple Flask web dashboard
- Dashboard summary statistics
- JSON API endpoint for events

---

## Detected Events

LogSentinel currently detects:

- Failed login attempts
- Unauthorized access attempts to `/admin`
- `/wp-login.php` scans
- `/phpmyadmin` scans

---

## Project Structure

- `collector.py` → reads and processes log lines
- `analyzer.py` → detects suspicious patterns and normalizes events
- `database.py` → handles SQLite persistence and search
- `app.py` → Flask dashboard + JSON API
- `tests/` → unit tests

---

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python collector.py
python app.py
