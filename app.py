from flask import Flask, request
from database import get_all_events, search_events

app = Flask(__name__)

@app.route("/")
def home():
    query = request.args.get("q", "").strip()

    if query:
        events = search_events(query)
    else:
        events = get_all_events()

    html = """
    <html>
    <head>
        <title>LogSentinel</title>
        <style>
            body { font-family: Arial; margin: 40px; background: #f7f7f7; }
            h1 { color: #222; }
            table { width: 100%; border-collapse: collapse; background: white; }
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #333; color: white; }
            form { margin-bottom: 20px; }
            input[type=text] { padding: 8px; width: 300px; }
            button { padding: 8px 12px; }
        </style>
    </head>
    <body>
        <h1>LogSentinel Dashboard</h1>
        <form method="get">
            <input type="text" name="q" placeholder="Buscar IP, evento o texto..." value="{query}">
            <button type="submit">Buscar</button>
        </form>
        <table>
            <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Source IP</th>
                <th>Event Type</th>
                <th>Message</th>
            </tr>
    """.format(query=query)

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

if __name__ == "__main__":
    app.run(debug=True)
