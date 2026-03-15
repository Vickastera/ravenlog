# LogSentinel

Lightweight security monitoring tool for server logs and suspicious activity detection.

## Features
- Parse server logs
- Detect suspicious activity patterns
- Store events in SQLite
- Search events by IP, event type, or keyword
- Simple web dashboard (Flask)

## Tech Stack
- Python
- Flask
- SQLite

## Detected Events
- Failed login attempts
- Unauthorized access attempts
- /admin scans
- /wp-login.php scans
- /phpmyadmin scans

## Project Goal
Educational and defensive security monitoring for small teams and server administrators.

## Roadmap
- [x] Create GitHub repository
- [ ] Build log parser
- [ ] Detect suspicious patterns
- [ ] Store events in SQLite
- [ ] Build Flask dashboard
- [ ] Add filters and event stats
- [ ] Deploy MVP
