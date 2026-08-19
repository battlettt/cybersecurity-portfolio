"""
siem_ingest.py
--------------
Parses the syslog-style log produced by log_generator.py and loads it into
a SQLite database as structured events. SQLite is used instead of a real
log store (Elasticsearch etc.) because it needs zero setup, supports SQL
aggregation, and is more than adequate for the data volumes a lab like this
produces -- the schema below is deliberately shaped so it would map
cleanly onto an Elasticsearch/ECS index (see PRODUCTION_SETUP.md).
"""

import os
import re
import sqlite3
from datetime import datetime

# PID brackets are optional: sshd logs `sshd[1234]: ...` but kernel/netfilter
# lines have no per-message PID, just `kernel: ...` -- both are valid syslog.
LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) (?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

SSH_FAILED_INVALID_RE = re.compile(
    r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$"
)
SSH_FAILED_VALID_RE = re.compile(
    r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$"
)
SSH_ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2$"
)
UFW_BLOCK_RE = re.compile(
    r"\[UFW BLOCK\].*SRC=(?P<src>\S+) DST=(?P<dst>\S+).*PROTO=(?P<proto>\S+) "
    r"SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+)"
)
# Outbound flow-record style line, emitted by a host netflow/connection-tracking
# agent. Used by Project 8's exfiltration stage (Stage 3) -- added here rather
# than duplicated in the capstone because it's a natural extension of the same
# ingestion schema, not a different log source.
NETFLOW_OUTBOUND_RE = re.compile(
    r"OUTBOUND SRC=(?P<src>\S+) DST=(?P<dst>\S+) BYTES=(?P<bytes>\d+) "
    r"DURATION=(?P<duration>\d+)s PROTO=(?P<proto>\S+) DPT=(?P<dpt>\d+)"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,       -- ISO 8601, UTC
    host TEXT NOT NULL,
    process TEXT NOT NULL,
    pid INTEGER,
    event_type TEXT NOT NULL,      -- auth_failed | auth_success | conn_block | data_exfil
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    src_port INTEGER,
    username TEXT,
    valid_user INTEGER,            -- 1/0/NULL: was the guessed username a real account?
    bytes_transferred INTEGER,     -- populated for data_exfil events only
    raw_line TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_srcip_ts ON events (src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events (event_type, timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    target TEXT,
    window_start TEXT,
    window_end TEXT,
    event_count INTEGER,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def parse_line(line: str):
    """Return a dict of column values for one log line, or None if the line
    doesn't match a format we understand (unparsed lines are logged, never
    silently dropped, so ingestion coverage can be audited)."""
    line = line.rstrip("\n")
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None

    ts, host, proc, pid, msg = (
        m.group("ts"), m.group("host"), m.group("proc").strip(), m.group("pid"), m.group("msg")
    )

    base = dict(timestamp=ts, host=host, process=proc, pid=(int(pid) if pid else None), raw_line=line,
                event_type=None, src_ip=None, dst_ip=None, dst_port=None,
                src_port=None, username=None, valid_user=None, bytes_transferred=None)

    if proc == "sshd":
        m2 = SSH_ACCEPTED_RE.match(msg)
        if m2:
            base.update(event_type="auth_success", username=m2.group("user"),
                         src_ip=m2.group("ip"), src_port=int(m2.group("port")), valid_user=1)
            return base
        m2 = SSH_FAILED_INVALID_RE.match(msg)
        if m2:
            base.update(event_type="auth_failed", username=m2.group("user"),
                         src_ip=m2.group("ip"), src_port=int(m2.group("port")), valid_user=0)
            return base
        m2 = SSH_FAILED_VALID_RE.match(msg)
        if m2:
            base.update(event_type="auth_failed", username=m2.group("user"),
                         src_ip=m2.group("ip"), src_port=int(m2.group("port")), valid_user=1)
            return base
    elif proc == "kernel":
        m2 = UFW_BLOCK_RE.search(msg)
        if m2:
            base.update(event_type="conn_block", src_ip=m2.group("src"), dst_ip=m2.group("dst"),
                         dst_port=int(m2.group("dpt")), src_port=int(m2.group("spt")))
            return base
    elif proc == "netflow":
        m2 = NETFLOW_OUTBOUND_RE.search(msg)
        if m2:
            base.update(event_type="data_exfil", src_ip=m2.group("src"), dst_ip=m2.group("dst"),
                         dst_port=int(m2.group("dpt")), bytes_transferred=int(m2.group("bytes")))
            return base

    return None  # recognized syslog envelope, unrecognized message body


def ingest_file(log_path: str, db_path: str, reset: bool = True) -> dict:
    """Parse `log_path` and load every event into `db_path`. Returns a
    summary dict (used both for the CLI output and for unit-style checks)."""
    if reset and os.path.exists(db_path):
        os.remove(db_path)

    conn = get_connection(db_path)
    cur = conn.cursor()

    total_lines = 0
    parsed = 0
    unparsed_samples = []

    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue
            total_lines += 1
            event = parse_line(line)
            if event is None:
                if len(unparsed_samples) < 5:
                    unparsed_samples.append(line.strip())
                continue
            parsed += 1
            cur.execute(
                """INSERT INTO events
                   (timestamp, host, process, pid, event_type, src_ip, dst_ip,
                    dst_port, src_port, username, valid_user, bytes_transferred, raw_line)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event["timestamp"], event["host"], event["process"], event["pid"],
                 event["event_type"], event["src_ip"], event["dst_ip"], event["dst_port"],
                 event["src_port"], event["username"], event["valid_user"],
                 event["bytes_transferred"], event["raw_line"]),
            )

    conn.commit()

    summary = {
        "total_lines": total_lines,
        "parsed_events": parsed,
        "unparsed_lines": total_lines - parsed,
        "unparsed_samples": unparsed_samples,
        "db_path": db_path,
    }
    conn.close()
    return summary


def event_type_counts(conn: sqlite3.Connection) -> dict:
    rows = conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type"
    ).fetchall()
    return {r["event_type"]: r["n"] for r in rows}


if __name__ == "__main__":
    here = os.path.dirname(__file__)
    log_path = os.path.join(here, "data", "auth.log")
    db_path = os.path.join(here, "data", "siem.db")

    summary = ingest_file(log_path, db_path)
    print(f"Parsed {summary['parsed_events']}/{summary['total_lines']} lines into {db_path}")
    if summary["unparsed_lines"]:
        print(f"WARNING: {summary['unparsed_lines']} unparsed lines, samples:")
        for s in summary["unparsed_samples"]:
            print(f"  {s}")

    conn = get_connection(db_path)
    print("Event type counts:", event_type_counts(conn))
    conn.close()
