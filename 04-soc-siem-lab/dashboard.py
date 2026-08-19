"""
dashboard.py
------------
Minimal Flask dashboard over the SQLite database populated by
siem_ingest.py / detection_rules.py. Read-only: it never mutates the DB,
it just queries and renders it. Run the pipeline first:

    python3 log_generator.py
    python3 siem_ingest.py
    python3 detection_rules.py
    python3 dashboard.py

Then open http://127.0.0.1:5000/
"""

import os
import sqlite3

from flask import Flask, jsonify, render_template

import siem_ingest

HERE = os.path.dirname(__file__)
DB_PATH = os.path.join(HERE, "data", "siem.db")

app = Flask(__name__)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_conn()
    event_counts = siem_ingest.event_type_counts(conn)
    total = sum(event_counts.values())

    alerts = [dict(r) for r in conn.execute(
        "SELECT * FROM alerts ORDER BY severity = 'high' DESC, window_start"
    ).fetchall()]

    events = [dict(r) for r in conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 100"
    ).fetchall()]

    conn.close()
    return render_template(
        "dashboard.html",
        event_counts=event_counts,
        event_counts_total=total,
        alerts=alerts,
        events=events,
        db_path=DB_PATH,
    )


@app.route("/api/events")
def api_events():
    conn = get_conn()
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 500"
    ).fetchall()]
    conn.close()
    return jsonify(events)


@app.route("/api/alerts")
def api_alerts():
    conn = get_conn()
    alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts").fetchall()]
    conn.close()
    return jsonify(alerts)


@app.route("/api/timeline")
def api_timeline():
    """Failed-login counts bucketed by hour, for the dashboard chart."""
    conn = get_conn()
    rows = conn.execute(
        """SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS n
           FROM events WHERE event_type = 'auth_failed'
           GROUP BY hour ORDER BY hour"""
    ).fetchall()
    conn.close()
    return jsonify({
        "labels": [r["hour"] + ":00" for r in rows],
        "counts": [r["n"] for r in rows],
    })


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "db_exists": os.path.exists(DB_PATH)})


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        raise SystemExit(
            f"No database at {DB_PATH}. Run log_generator.py, siem_ingest.py, "
            f"and detection_rules.py first."
        )
    app.run(host="127.0.0.1", port=5000, debug=False)
