# Project 4 — Home SOC / SIEM Lab

A rule-based SIEM: simulated log generation, structured ingestion into
SQLite, sliding-window detection logic for SSH brute force and port scans,
a Flask alert dashboard, and a SOC-analyst-style incident report — all
written from first principles, plus a documented (unexecuted) production
path using a real ELK stack.

**Resume bullet:** Built a home SOC lab with a Python-based log ingestion
pipeline and rule-based SIEM alerting engine (SQLite + sliding time-window
detection); generated and detected simulated SSH brute-force and port-scan
attacks end-to-end, verified via a live Flask dashboard, and produced a
full incident report grounded in the actual pipeline output.

## Two tracks — read this first

| | Track A (this README focuses on it) | Track B |
|---|---|---|
| What | Python + SQLite SIEM simulation | Real Elasticsearch/Logstash/Kibana/Filebeat stack |
| Status | **Verified — actually run in this environment**, output below is real | **Documentation-only** — this sandbox has no `docker` binary, so it was never started or tested here |
| Files | `log_generator.py`, `siem_ingest.py`, `detection_rules.py`, `dashboard.py`, `run_pipeline.py` | `docker-compose.yml`, `elk/`, `PRODUCTION_SETUP.md` |

Track A is the proof-of-work: every number below came from actually running
these scripts, not from writing them and assuming they'd work. Track B shows
the same detections implemented against the tooling a real SOC would use;
see `PRODUCTION_SETUP.md` for exact run/verify steps once Docker is
available.

## Architecture (Track A)

```
log_generator.py  -->  data/auth.log  -->  siem_ingest.py  -->  data/siem.db (SQLite)
                                                                       |
                                                          detection_rules.py
                                                          (sliding-window rules)
                                                                       |
                                                              alerts table
                                                                       |
                                                              dashboard.py (Flask)
```

- **`log_generator.py`** — writes a syslog-style log (RFC3339 timestamp +
  `host process[pid]: message`) mixing normal SSH logins from 6 simulated
  employee accounts with two embedded attacks: an SSH brute-force burst and
  a firewall-logged TCP port scan. Deterministic (`random.seed(42)`).
- **`siem_ingest.py`** — regex-parses every line into a structured SQLite
  `events` table (`event_type`, `src_ip`, `dst_port`, `username`,
  `timestamp`, raw line preserved). Reports any unparsed lines instead of
  silently dropping them.
- **`detection_rules.py`** — two independent, data-agnostic sliding-window
  rules (thresholds justified in-file and in `incident_report.md` § 4):
  - **Brute force**: ≥8 failed SSH logins from one source IP within 5
    minutes.
  - **Port scan**: ≥8 distinct destination ports from one source IP within
    30 seconds.
- **`dashboard.py`** — read-only Flask app: summary cards, an alerts table,
  a Chart.js failed-logins-per-hour chart, and a recent-events table, plus
  JSON endpoints (`/api/events`, `/api/alerts`, `/api/timeline`,
  `/healthz`).
- **`incident_report.md`** — a full SOC-analyst incident report written
  against the actual alerts this pipeline produced (real timestamps, real
  usernames, real counts — see § "Verified run output" below for the
  source data).

## How to run it

```bash
cd 04-soc-siem-lab
pip install -r requirements.txt      # just Flask
python3 run_pipeline.py              # generate -> ingest -> detect, prints alerts
python3 dashboard.py                 # serves http://127.0.0.1:5000
```

`run_pipeline.py` runs all three stages and prints every alert with its
source IP, time window, and detail string. `dashboard.py` then serves the
resulting database read-only (stop it with Ctrl-C, or `pkill -f dashboard.py`).

## Verified run output (real, captured 2026-08-18)

```
STEP 1: Generating simulated auth.log
{
  "total_lines": 170,
  "brute_force_attempts": 55,
  "port_scan_events": 20,
  "attacker_brute_force_ip": "203.0.113.77",
  "attacker_scan_ip": "198.51.100.23",
  "brute_force_target_host": "web01",
  "scan_target_host": "db01"
}

STEP 2: Ingesting log into SQLite
Parsed 170/170 lines (0 unparsed)
Event type counts: {'auth_failed': 59, 'auth_success': 91, 'conn_block': 20}

STEP 3: Running detection rules

[ALERT-BRUTE_FORCE_SSH-001] BRUTE_FORCE_SSH (severity=high)
  Source IP : 203.0.113.77
  Window    : 2026-08-18T09:12:03.042468+00:00 -> 2026-08-18T09:14:50.813486+00:00
  Count     : 55
  Detail    : 55 failed SSH logins from 203.0.113.77 ... (13 distinct usernames
              tried: admin, administrator, backup, deploy, guest, oracle, pi,
              postgres...) -- exceeds threshold of 8 in 5 min.

[ALERT-PORT_SCAN-002] PORT_SCAN (severity=medium)
  Source IP : 198.51.100.23
  Window    : 2026-08-18T09:56:51.320898+00:00 -> 2026-08-18T09:57:02.753611+00:00
  Count     : 20
  Detail    : 198.51.100.23 probed 20 distinct ports on 10.0.0.5 ... (ports: 21,
              22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2049, 3306,
              3389, 5432, 5900, 6379, 8080, 8443) -- exceeds threshold of 8
              distinct ports in 30s.
```

Both attacks were flagged, with **zero false positives** among the 91
legitimate logins (including several innocuous single-retry-then-success
cases in the baseline traffic).

Dashboard was started and checked live during development:
```
$ curl -s http://127.0.0.1:5000/healthz
{"db_exists":true,"status":"ok"}
$ curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/
200
$ curl -s http://127.0.0.1:5000/api/alerts     # returned both alerts as JSON
$ curl -s http://127.0.0.1:5000/api/timeline   # returned correct per-hour buckets
```
The server was then stopped (`pkill -f "python3 dashboard.py"`) — it is not
left running.

## Files

```
04-soc-siem-lab/
  log_generator.py          Track A: log generation
  siem_ingest.py             Track A: parsing + SQLite ingestion
  detection_rules.py         Track A: sliding-window detection rules
  dashboard.py                Track A: Flask dashboard
  run_pipeline.py             Track A: end-to-end driver used to produce the output above
  templates/dashboard.html    Track A: dashboard UI
  data/auth.log, data/siem.db Track A: generated artifacts (reproducible via run_pipeline.py)
  incident_report.md          SOC incident report grounded in the run above
  docker-compose.yml          Track B: ELK stack (documentation-only, not run)
  elk/                        Track B: Logstash pipeline + Filebeat config
  PRODUCTION_SETUP.md         Track B: how to run/verify once Docker is available
  requirements.txt
```

## Honest limitations

- Track B has never been started, let alone tested, in this environment —
  treat it as "written to spec, unverified" until run against real Docker.
- The detection thresholds are justified against published tool behavior
  and common SIEM defaults (see `incident_report.md` § 4), not tuned
  against a real production traffic baseline — in a real deployment they'd
  need calibration against actual false-positive rates.
- This is a single-host-log simulation; it does not model log delivery
  reliability, clock skew across hosts, or adversarial log tampering.
