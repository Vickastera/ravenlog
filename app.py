from collections import Counter
from flask import Flask, request, jsonify
from database import get_all_events, search_events

app = Flask(__name__)


def summarize_events(events):
    event_type_counts = Counter()
    source_ip_counts = Counter()

    for event in events:
        event_type = event[4]
        source_ip = event[3]

        if event_type:
            event_type_counts[event_type] += 1

        if source_ip:
            source_ip_counts[source_ip] += 1

    return {
        "total_events": len(events),
        "event_type_counts": dict(event_type_counts),
        "top_source_ips": source_ip_counts.most_common(5),
    }


def build_event_type_html(event_type_counts):
    if not event_type_counts:
        return '<p class="empty">No events to summarize.</p>'

    html = "<ul>"
    for event_type, count in event_type_counts.items():
        html += f"<li><strong>{event_type}</strong>: {count}</li>"
    html += "</ul>"
    return html


def build_top_ips_html(top_source_ips):
    if not top_source_ips:
        return '<p class="empty">No source IPs to display.</p>'

    html = "<ul>"
    for ip, count in top_source_ips:
        html += f"<li><strong>{ip}</strong>: {count} events</li>"
    html += "</ul>"
    return html


def event_to_dict(event):
    return {
        "id": event[0],
        "timestamp": event[1],
        "severity": event[2],
        "source_ip": event[3],
        "event_type": event[4],
        "message": event[5],
    }


@app.route("/")
def home():
    query = request.args.get("q", "").strip()

    if query:
        events = search_events(query)
    else:
        events = get_all_events()

    stats = summarize_events(events)

    html = """
    <html>
    <head>
        <title>LogSentinel</title>
        <style>
            body { font-family: Arial; margin: 40px; background: #f7f7f7; }
            h1 { color: #222; }
            h2 { color: #333; margin-top: 30px; }
            table { width: 100%; border-collapse: collapse; background: white; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #333; color: white; }
            form { margin-bottom: 20px; }
            input[type=text] { padding: 8px; width: 300px; }
            button { padding: 8px 12px; }
            .stats-box {
                background: white;
                border: 1px solid #ddd;
                padding: 20px;
                margin-bottom: 20px;
            }
            .stats-section {
                margin-bottom: 20px;
            }
            ul {
                margin: 10px 0;
                padding-left: 20px;
            }
            .empty {
                color: #666;
                font-style: italic;
            }
            .api-link {
                margin-top: 10px;
                display: inline-block;
            }
        </style>
    </head>
    <body>
        <h1>LogSentinel Dashboard</h1>
        <form method="get">
            <input type="text" name="q" placeholder="Buscar IP, evento o texto..." value="{query}">
            <button type="submit">Buscar</button>
        </form>

        <p class="api-link">
            <a href="/api/events">View JSON API</a>
        </p>

        <div class="stats-box">
            <div class="stats-section">
                <h2>Summary</h2>
                <p><strong>Total displayed events:</strong> {total_events}</p>
            </div>

            <div class="stats-section">
                <h2>Count by Event Type</h2>
                {event_type_html}
            </div>

            <div class="stats-section">
                <h2>Top 5 Source IPs</h2>
                {top_ips_html}
            </div>
        </div>

        <table>
            <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Event Type</th>
                <th>Message</th>
            </tr>
    """.format(
        query=query,
        total_events=stats["total_events"],
        event_type_html=build_event_type_html(stats["event_type_counts"]),
        top_ips_html=build_top_ips_html(stats["top_source_ips"]),
    )

    for event in events:
        html += f"""
        <tr>
            <td>{event[0]}</td>
            <td>{event[1]}</td>
            <td>{event[2]}</td>
            <td>{event[3]}</td>
            <td>{event[4]}</td>
            <td>{event[5]}</td>
        </tr>
        """

    html += """
        </table>
    </body>
    </html>
    """

    return html


@app.route("/api/events")
def api_events():
    query = request.args.get("q", "").strip()

    if query:
        events = search_events(query)
    else:
        events = get_all_events()

    return jsonify([event_to_dict(event) for event in events])


if __name__ == "__main__":
    app.run(debug=True) 
