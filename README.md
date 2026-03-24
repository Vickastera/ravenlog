# LogSentinel

Lightweight security monitoring tool for server logs and suspicious activity detection.

## Features
- Parse server logs
- Detect suspicious activity patterns
- Store events in SQLite
- De-duplicate events using log-line fingerprints
- Search events by IP, event type, or keyword
- Simple web dashboard (Flask)

## Tech Stack
- Python
- Flask
- SQLite

## Detected Events
- Failed login attempts
- Unauthorized access attempts to `/admin`
- `/wp-login.php` scans
- `/phpmyadmin` scans

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python collector.py
python app.py
```

Then open `http://127.0.0.1:5000`.

## Run Tests
```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Current Status
- ✅ Log parser working (`collector.py`)
- ✅ Suspicious pattern analyzer working (`analyzer.py`)
- ✅ SQLite persistence working (`database.py`)
- ✅ Duplicate event prevention by fingerprint (`database.py` + `collector.py`)
- ✅ Unit tests for analyzer and database (`tests/`)
- ✅ Flask dashboard with search working (`app.py`)

## How to Continue (Suggested Next Steps)
1. Add event stats in dashboard (top IPs, events by severity, events by type).
2. Add a REST API (`/api/events`) for external integrations.
3. Prepare deployment with Docker + `gunicorn`.
4. Add alerting integrations (email, Slack, webhook).

## Project Goal
Educational and defensive security monitoring for small teams and server administrators.
