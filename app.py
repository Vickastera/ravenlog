import os
import smtplib
import hashlib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, jsonify
from database import get_all_events, search_events, init_db
from collector import process_logs

app = Flask(__name__)
init_db()

MAIL_USER = os.environ.get("MAIL_USER", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")


def send_alert_email(event_type, source_ip, message):
    if not MAIL_USER or not MAIL_PASSWORD:
        print("[EMAIL ERROR] MAIL_USER or MAIL_PASSWORD not set")
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = MAIL_USER
        msg["To"] = MAIL_USER
        msg["Subject"] = f"🐦 RavenLog Alert: {event_type} detected"

        body = f"""
RavenLog detected a suspicious event:

Event Type: {event_type}
Source IP:  {source_ip}
Message:    {message}

Check your dashboard: https://logsentinel-bm52.onrender.com
        """

        msg.attach(MIMEText(body, "plain"))

        # Force IPv4 for smtp.gmail.com (Render can fail with IPv6 route)
        smtp_host = "smtp.gmail.com"
        smtp_port = 587

        addr_info = socket.getaddrinfo(
            smtp_host,
            smtp_port,
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        if not addr_info:
            raise Exception("Could not resolve IPv4 address for smtp.gmail.com")

        family, socktype, proto, canonname, sockaddr = addr_info[0]
        smtp_ip = sockaddr[0]

        with smtplib.SMTP(timeout=20) as server:
            server.connect(smtp_ip, smtp_port)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(MAIL_USER, MAIL_PASSWORD)
            server.sendmail(MAIL_USER, MAIL_USER, msg.as_string())

        print(f"[EMAIL SENT] {event_type} | {source_ip}")

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def run_collector_with_alerts():
    from analyzer import analyze_line
    from database import save_event

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    LOG_FILE = os.path.join(BASE_DIR, "sample_logs", "server.log")

    if not os.path.exists(LOG_FILE):
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            result = analyze_line(line)

            if result:
                parts = line.split(" ", 2)
                timestamp = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else "UNKNOWN"
                severity = "ERROR" if "ERROR" in line else "WARNING" if "WARNING" in line else "INFO"
                fingerprint = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()

                saved = save_event(
                    timestamp=timestamp,
                    severity=severity,
                    source_ip=result["source_ip"],
                    event_type=result["event_type"],
                    message=result["message"],
                    fingerprint=fingerprint,
                )

                if saved:
                    send_alert_email(
                        event_type=result["event_type"],
                        source_ip=result["source_ip"],
                        message=result["message"],
                    )

                print(f"[ALERTA] {result['event_type']} | {result['source_ip']} | {result['message']}")


# Procesa logs al iniciar la app
run_collector_with_alerts()


def summarize_events(events):
    event_type_counts = {}
    source_ip_counts = {}

    for event in events:
        source_ip = event[3] or "unknown"
        event_type = event[4] or "unknown"

        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        source_ip_counts[source_ip] = source_ip_counts.get(source_ip, 0) + 1

    top_source_ips = sorted(
        source_ip_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )[:5]

    return {
        "total_events": len(events),
        "event_type_counts": event_type_counts,
        "top_source_ips": top_source_ips,
    }


@app.route("/")
def home():
    query = request.args.get("q", "").strip()
    severity_filter = request.args.get("severity", "").strip().upper()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    if query:
        events = search_events(query)
    else:
        events = get_all_events()

    if severity_filter:
        events = [e for e in events if e[2] == severity_filter]

    if date_from:
        events = [e for e in events if e[1] and e[1] >= date_from]

    if date_to:
        events = [e for e in events if e[1] and e[1] <= date_to + " 23:59:59"]

    stats = summarize_events(events)

    event_type_html = (
        "<p class='muted'>No events found.</p>"
        if not stats["event_type_counts"]
        else "<ul class='stats-list'>" + "".join(
            f"<li><span>{event_type}</span><strong>{count}</strong></li>"
            for event_type, count in stats["event_type_counts"].items()
        ) + "</ul>"
    )

    top_ips_html = (
        "<p class='muted'>No source IPs available.</p>"
        if not stats["top_source_ips"]
        else "<ul class='stats-list'>" + "".join(
            f"<li><span>{ip}</span><strong>{count}</strong></li>"
            for ip, count in stats["top_source_ips"]
        ) + "</ul>"
    )

    rows_html = ""
    for event in events:
        severity = event[2] or "UNKNOWN"
        severity_class = "sev-info"

        if severity == "ERROR":
            severity_class = "sev-error"
        elif severity == "WARNING":
            severity_class = "sev-warning"
        elif severity == "INFO":
            severity_class = "sev-info"

        rows_html += f"""
        <tr>
            <td>{event[0]}</td>
            <td>{event[1]}</td>
            <td><span class="badge {severity_class}">{severity}</span></td>
            <td>{event[3]}</td>
            <td>{event[4]}</td>
            <td>{event[5]}</td>
        </tr>
        """

    if not rows_html:
        rows_html = """
        <tr>
            <td colspan="6" class="empty-row">No events to display.</td>
        </tr>
        """

    selected_error = "selected" if severity_filter == "ERROR" else ""
    selected_warning = "selected" if severity_filter == "WARNING" else ""
    selected_info = "selected" if severity_filter == "INFO" else ""

    html = """
    <html>
    <head>
        <title>RavenLog</title>
        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #0f172a;
                color: #e5e7eb;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 30px;
            }

            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
                flex-wrap: wrap;
                gap: 12px;
            }

            .title {
                margin: 0;
                font-size: 32px;
                color: #f8fafc;
            }

            .subtitle {
                margin: 6px 0 0;
                color: #94a3b8;
                font-size: 14px;
            }

            .search-card,
            .card,
            .table-card {
                background: #111827;
                border: 1px solid #1f2937;
                border-radius: 16px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
            }

            .search-card {
                padding: 18px;
                margin-bottom: 24px;
            }

            .search-form {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
            }

            .search-input {
                flex: 1;
                min-width: 240px;
                padding: 12px 14px;
                border-radius: 10px;
                border: 1px solid #334155;
                background: #0b1220;
                color: #e5e7eb;
                outline: none;
            }

            .search-input::placeholder {
                color: #64748b;
            }

            .severity-select {
                flex: 0;
                min-width: 160px;
                padding: 12px 14px;
                border-radius: 10px;
                border: 1px solid #334155;
                background: #0b1220;
                color: #e5e7eb;
                outline: none;
                cursor: pointer;
            }

            .date-input {
                flex: 0;
                min-width: 160px;
                padding: 12px 14px;
                border-radius: 10px;
                border: 1px solid #334155;
                background: #0b1220;
                color: #e5e7eb;
                outline: none;
            }

            .date-label {
                color: #94a3b8;
                font-size: 13px;
                display: flex;
                flex-direction: column;
                gap: 4px;
            }

            .search-btn {
                padding: 12px 18px;
                border: none;
                border-radius: 10px;
                background: #2563eb;
                color: white;
                font-weight: bold;
                cursor: pointer;
            }

            .search-btn:hover {
                background: #1d4ed8;
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                gap: 18px;
                margin-bottom: 24px;
            }

            .card {
                padding: 20px;
            }

            .card h3 {
                margin: 0 0 12px;
                font-size: 16px;
                color: #cbd5e1;
            }

            .big-number {
                font-size: 34px;
                font-weight: bold;
                color: #f8fafc;
            }

            .muted {
                color: #94a3b8;
                margin: 0;
            }

            .stats-list {
                list-style: none;
                padding: 0;
                margin: 0;
            }

            .stats-list li {
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px solid #1f2937;
                color: #e5e7eb;
            }

            .stats-list li:last-child {
                border-bottom: none;
            }

            .table-card {
                overflow: hidden;
            }

            .table-header {
                padding: 18px 20px;
                border-bottom: 1px solid #1f2937;
                font-size: 18px;
                font-weight: bold;
                color: #f8fafc;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th {
                text-align: left;
                padding: 14px 16px;
                background: #0b1220;
                color: #94a3b8;
                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            td {
                padding: 14px 16px;
                border-top: 1px solid #1f2937;
                color: #e5e7eb;
                vertical-align: top;
            }

            tr:hover {
                background: #0b1220;
            }

            .badge {
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: bold;
            }

            .sev-error {
                background: rgba(239, 68, 68, 0.18);
                color: #fca5a5;
                border: 1px solid rgba(239, 68, 68, 0.35);
            }

            .sev-warning {
                background: rgba(245, 158, 11, 0.18);
                color: #fcd34d;
                border: 1px solid rgba(245, 158, 11, 0.35);
            }

            .sev-info {
                background: rgba(59, 130, 246, 0.18);
                color: #93c5fd;
                border: 1px solid rgba(59, 130, 246, 0.35);
            }

            .empty-row {
                text-align: center;
                color: #94a3b8;
                padding: 30px;
            }

            .footer-note {
                margin-top: 18px;
                color: #64748b;
                font-size: 13px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1 class="title">🐦 RavenLog</h1>
                    <p class="subtitle">Security log monitoring dashboard with SQLite + Flask API</p>
                </div>
            </div>

            <div class="search-card">
                <form method="get" class="search-form">
                    <input
                        class="search-input"
                        type="text"
                        name="q"
                        placeholder="Search by IP, event type, or message..."
                        value="{{ query }}"
                    >
                    <select name="severity" class="severity-select">
                        <option value="">All severities</option>
                        <option value="ERROR" {{ selected_error }}>ERROR</option>
                        <option value="WARNING" {{ selected_warning }}>WARNING</option>
                        <option value="INFO" {{ selected_info }}>INFO</option>
                    </select>
                    <label class="date-label">
                        From
                        <input type="date" name="date_from" class="date-input" value="{{ date_from }}">
                    </label>
                    <label class="date-label">
                        To
                        <input type="date" name="date_to" class="date-input" value="{{ date_to }}">
                    </label>
                    <button class="search-btn" type="submit">Search</button>
                </form>
            </div>

            <div class="stats-grid">
                <div class="card">
                    <h3>Total Displayed Events</h3>
                    <div class="big-number">{{ total_events }}</div>
                </div>

                <div class="card">
                    <h3>Count by Event Type</h3>
                    {{ event_type_html }}
                </div>

                <div class="card">
                    <h3>Top 5 Source IPs</h3>
                    {{ top_ips_html }}
                </div>
            </div>

            <div class="table-card">
                <div class="table-header">Detected Security Events</div>
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Event Type</th>
                        <th>Message</th>
                    </tr>
                    {{ rows_html }}
                </table>
            </div>

            <p class="footer-note">
                Tip: Try searches like <strong>failed_login</strong>, <strong>sql_injection</strong>, or an IP such as <strong>185.23.44.12</strong>.
            </p>
        </div>
    </body>
    </html>
    """.replace("{{ query }}", query)\
      .replace("{{ total_events }}", str(stats["total_events"]))\
      .replace("{{ event_type_html }}", event_type_html)\
      .replace("{{ top_ips_html }}", top_ips_html)\
      .replace("{{ rows_html }}", rows_html)\
      .replace("{{ selected_error }}", selected_error)\
      .replace("{{ selected_warning }}", selected_warning)\
      .replace("{{ selected_info }}", selected_info)\
      .replace("{{ date_from }}", date_from)\
      .replace("{{ date_to }}", date_to)

    return html


@app.route("/api/events")
def api_events():
    query = request.args.get("q", "").strip()

    if query:
        events = search_events(query)
    else:
        events = get_all_events()

    data = []
    for event in events:
        data.append({
            "id": event[0],
            "timestamp": event[1],
            "severity": event[2],
            "source_ip": event[3],
            "event_type": event[4],
            "message": event[5],
        })

    return jsonify(data)


@app.route("/test-email")
def test_email():
    send_alert_email(
        event_type="test_alert",
        source_ip="127.0.0.1",
        message="This is a test email from RavenLog"
    )
    return "Test email sent (check logs)", 200


@app.route("/reset-db")
def reset_db():
    return "Use /test-email to test alerts safely on free Render.", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
