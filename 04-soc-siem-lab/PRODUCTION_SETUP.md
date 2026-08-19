# Track B — Production ELK Setup (documentation-only)

> **Status: not run in this environment.** This sandbox has no `docker` binary
> (`docker: command not found`), so none of this has been started, tested, or
> verified here. Everything in this file is a correct, best-practice ELK
> configuration written against the actual log format Track A generates and
> verified against — but it is unexecuted. Track A (`log_generator.py` →
> `siem_ingest.py` → `detection_rules.py` → `dashboard.py`) is the verified,
> actually-run proof-of-work for this project; run this track only once you
> have Docker available locally.

## What this stack is

The same detection problem (SSH brute force + port scan) solved with a real
ELK stack instead of SQLite + Python, so the project demonstrates both "I can
build detection logic from first principles" (Track A) and "I know the
industry-standard tooling" (Track B).

```
auth.log --(Filebeat)--> Logstash (grok parse) --> Elasticsearch --> Kibana
```

## How to run it

1. Generate the log (Track A, already covered):
   ```bash
   python3 log_generator.py     # writes data/auth.log
   ```
2. Bring up the stack:
   ```bash
   docker-compose up -d
   ```
   This starts Elasticsearch (9200), Logstash (5044 beats input), Kibana
   (5601), and Filebeat (tails `data/auth.log` and ships it to Logstash).
3. Wait for Elasticsearch to report healthy (`docker-compose ps`, or
   `curl http://localhost:9200/_cluster/health`), then confirm data is
   flowing:
   ```bash
   curl http://localhost:9200/siem-lab-events-*/_count
   ```
4. Open Kibana at `http://localhost:5601`, create a data view over
   `siem-lab-events-*`, and use Discover / Lens to build the same detections
   Track A implements in Python.

## Sample Kibana / Elasticsearch DSL queries for the same detections

**Brute force (≥8 failed logins from one IP in 5 minutes)** — as a Kibana
Lens/Discover query:
```
event_type: "auth_failed" and src_ip: "203.0.113.77"
```
then use a Kibana **date histogram** (5-minute buckets) split by `src_ip`,
with a **threshold alert rule** (Stack Management → Rules) of type
"Elasticsearch query", condition `count() >= 8` over a 5-minute window,
grouped by `src_ip.keyword` — this is the direct Kibana-native equivalent of
`detection_rules.detect_brute_force()`.

Raw DSL equivalent of the sliding-window count:
```json
GET siem-lab-events-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event_type": "auth_failed" } },
        { "range": { "@timestamp": { "gte": "now-5m" } } }
      ]
    }
  },
  "aggs": {
    "by_src_ip": {
      "terms": { "field": "src_ip.keyword", "min_doc_count": 8 }
    }
  }
}
```

**Port scan (≥8 distinct ports from one IP in 30 seconds)**:
```json
GET siem-lab-events-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "event_type": "conn_block" } },
        { "range": { "@timestamp": { "gte": "now-30s" } } }
      ]
    }
  },
  "aggs": {
    "by_src_ip": {
      "terms": { "field": "src_ip.keyword" },
      "aggs": {
        "distinct_ports": { "cardinality": { "field": "dst_port" } }
      }
    }
  }
}
```
Wire this up as an Elasticsearch query rule with a scripted condition
`ctx.payload.hits.total.value >= 8` on the `distinct_ports` cardinality
bucket, alerting via Kibana's built-in connectors (email/Slack/webhook).

## Kibana dashboard panels worth building

- Time series: failed logins per 5-minute bucket, split by `src_ip`
- Data table: top source IPs by failed-login count, last 24h
- Metric: distinct destination ports touched per source IP, last 5 min
- Map (if GeoIP is added to the Logstash pipeline via the `geoip` filter on
  `src_ip`): attacker source geolocation

## Why Track A exists at all

A from-scratch Python SIEM is *not* what a real SOC runs in production — ELK/
Splunk exist for good reasons (scale, retention, built-in alerting, RBAC,
etc.). Track A exists here because (a) this sandbox has no Docker to actually
run and verify Track B, and (b) writing the detection math (sliding-window
brute-force/port-scan logic) from first principles in plain Python is a
stronger demonstration of understanding *how* these detections work than
pointing at a pre-built Kibana rule type ever could be.
