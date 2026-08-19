"""
detection_rules.py
-------------------
Generic, data-independent detection logic that runs against the `events`
table populated by siem_ingest.py. Nothing here references the specific
IPs/usernames log_generator.py happens to use -- the rules operate purely
on event_type/src_ip/timestamp/dst_port, exactly as they would against a
real production feed.

Both rules use a sliding time window over per-source-IP activity ("how many
qualifying events land within any T-second/minute window for this IP"),
which is the standard approach real SIEMs (Splunk ESSOC, Elastic Security,
Sigma correlation rules) use for burst-style detections -- a simple total
count over the whole log would miss a burst buried in a long baseline, and
a fixed-bucket count (e.g. "per calendar minute") would miss a burst that
straddles a bucket boundary.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

# --- Brute force -----------------------------------------------------------
# Threshold rationale: legitimate users occasionally mistype a password once,
# rarely twice. Automated credential-stuffing tools (Hydra, Medusa, ncrack)
# issue attempts every 1-3 seconds per thread. 8 failed attempts from the
# same source IP inside a 5-minute window is comfortably above plausible
# human error and comfortably below the volume an automated tool produces in
# that time, matching the ballpark of common SIEM defaults (Splunk ESSOC's
# "Failed Login" correlation search defaults to 6 in 5 minutes; we use 8 to
# reduce false positives from shared NAT egress IPs).
BRUTE_FORCE_FAILED_THRESHOLD = 8
BRUTE_FORCE_WINDOW_MINUTES = 5

# --- Port scan ---------------------------------------------------------
# Threshold rationale: a normal client touches 1-2 ports on a server (e.g.
# ssh + a health check). Reconnaissance scanners (nmap etc.) probe many
# ports from one source in a short burst. 8 distinct destination ports from
# one source IP inside 30 seconds is the same order of magnitude as
# Suricata/Snort's default portscan preprocessor sensitivity ("many
# connections to many ports from one host in a short interval").
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 8
PORT_SCAN_WINDOW_SECONDS = 30


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _sliding_window_bursts(timestamps: list[datetime], window: timedelta, threshold: int):
    """Given sorted timestamps for one source, return every maximal window
    whose event count first crosses `threshold` (two-pointer sliding window,
    O(n)). Returns list of (window_start, window_end, count) using the
    actual first/last event timestamps inside the qualifying window, which
    is more informative in a report than the raw window boundaries."""
    bursts = []
    n = len(timestamps)
    left = 0
    for right in range(n):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold:
            bursts.append((timestamps[left], timestamps[right], count))
    if not bursts:
        return []
    # Collapse overlapping qualifying windows into one alert per burst,
    # keeping the widest (highest-count) window for each contiguous run.
    merged = [bursts[0]]
    for b in bursts[1:]:
        prev = merged[-1]
        if b[0] <= prev[1]:
            if b[2] > prev[2]:
                merged[-1] = b
        else:
            merged.append(b)
    return merged


def detect_brute_force(conn: sqlite3.Connection,
                        threshold: int = BRUTE_FORCE_FAILED_THRESHOLD,
                        window_minutes: int = BRUTE_FORCE_WINDOW_MINUTES) -> list[dict]:
    window = timedelta(minutes=window_minutes)
    rows = conn.execute(
        """SELECT src_ip, timestamp, username FROM events
           WHERE event_type = 'auth_failed' AND src_ip IS NOT NULL
           ORDER BY src_ip, timestamp"""
    ).fetchall()

    by_ip: dict[str, list] = {}
    for r in rows:
        by_ip.setdefault(r["src_ip"], []).append((_parse_ts(r["timestamp"]), r["username"]))

    alerts = []
    for src_ip, events in by_ip.items():
        timestamps = [e[0] for e in events]
        for start, end, count in _sliding_window_bursts(timestamps, window, threshold):
            usernames = sorted({u for ts, u in events if start <= ts <= end})
            alerts.append({
                "rule": "brute_force_ssh",
                "severity": "high",
                "src_ip": src_ip,
                "target": None,
                "window_start": start.isoformat(),
                "window_end": end.isoformat(),
                "event_count": count,
                "usernames_attempted": usernames,
                "detail": (f"{count} failed SSH logins from {src_ip} between "
                           f"{start.isoformat()} and {end.isoformat()} "
                           f"({len(usernames)} distinct usernames tried: "
                           f"{', '.join(usernames[:8])}{'...' if len(usernames) > 8 else ''}) "
                           f"-- exceeds threshold of {threshold} in {window_minutes} min."),
            })
    return alerts


def detect_port_scan(conn: sqlite3.Connection,
                      threshold: int = PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
                      window_seconds: int = PORT_SCAN_WINDOW_SECONDS) -> list[dict]:
    window = timedelta(seconds=window_seconds)
    rows = conn.execute(
        """SELECT src_ip, dst_ip, dst_port, timestamp FROM events
           WHERE event_type = 'conn_block' AND src_ip IS NOT NULL
           ORDER BY src_ip, timestamp"""
    ).fetchall()

    by_ip: dict[str, list] = {}
    for r in rows:
        by_ip.setdefault(r["src_ip"], []).append(
            (_parse_ts(r["timestamp"]), r["dst_port"], r["dst_ip"])
        )

    alerts = []
    for src_ip, events in by_ip.items():
        # distinct-port count needs its own sliding window (not a plain
        # count) because a scan burst can be surrounded by unrelated blocks
        timestamps = [e[0] for e in events]
        n = len(events)
        left = 0
        seen_windows = []
        for right in range(n):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            ports_in_window = {events[i][1] for i in range(left, right + 1)}
            if len(ports_in_window) >= threshold:
                seen_windows.append((timestamps[left], timestamps[right], left, right))
        if not seen_windows:
            continue
        # collapse overlapping windows, keep the widest port coverage
        best = max(seen_windows, key=lambda w: w[3] - w[2])
        start, end, left, right = best
        dst_ips = sorted({events[i][2] for i in range(left, right + 1)})
        ports = sorted({events[i][1] for i in range(left, right + 1)})
        alerts.append({
            "rule": "port_scan",
            "severity": "medium",
            "src_ip": src_ip,
            "target": ", ".join(dst_ips),
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "event_count": right - left + 1,
            "distinct_ports": ports,
            "detail": (f"{src_ip} probed {len(ports)} distinct ports on {', '.join(dst_ips)} "
                       f"between {start.isoformat()} and {end.isoformat()} "
                       f"(ports: {', '.join(str(p) for p in ports)}) "
                       f"-- exceeds threshold of {threshold} distinct ports in "
                       f"{window_seconds}s."),
        })
    return alerts


def run_all_rules(conn: sqlite3.Connection) -> list[dict]:
    return detect_brute_force(conn) + detect_port_scan(conn)


def persist_alerts(conn: sqlite3.Connection, alerts: list[dict]) -> list[str]:
    """Write alerts into the `alerts` table (schema created by
    siem_ingest.get_connection) and return the generated alert_ids."""
    ids = []
    now = datetime.now(timezone.utc).isoformat()
    for i, a in enumerate(alerts):
        alert_id = f"ALERT-{a['rule'].upper()}-{i+1:03d}"
        conn.execute(
            """INSERT OR REPLACE INTO alerts
               (alert_id, rule, severity, src_ip, target, window_start, window_end,
                event_count, detail, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (alert_id, a["rule"], a["severity"], a["src_ip"], a.get("target"),
             a["window_start"], a["window_end"], a["event_count"], a["detail"], now),
        )
        ids.append(alert_id)
    conn.commit()
    return ids


if __name__ == "__main__":
    import os
    import siem_ingest

    here = os.path.dirname(__file__)
    db_path = os.path.join(here, "data", "siem.db")
    conn = siem_ingest.get_connection(db_path)

    alerts = run_all_rules(conn)
    ids = persist_alerts(conn, alerts)

    print(f"Generated {len(alerts)} alert(s):")
    for alert_id, a in zip(ids, alerts):
        print(f"\n[{alert_id}] {a['rule']} ({a['severity']}) src={a['src_ip']}")
        print(f"  {a['detail']}")

    conn.close()
