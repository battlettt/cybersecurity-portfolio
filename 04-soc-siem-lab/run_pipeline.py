"""
run_pipeline.py
----------------
End-to-end driver: generate -> ingest -> detect -> print alerts.
This is what produced the console output pasted into README.md and
incident_report.md -- run it yourself to reproduce the same numbers
(the RNG is seeded in log_generator.py, so the run is deterministic).
"""

import json
import os

import detection_rules
import log_generator
import siem_ingest

HERE = os.path.dirname(__file__)
LOG_PATH = os.path.join(HERE, "data", "auth.log")
DB_PATH = os.path.join(HERE, "data", "siem.db")


def main():
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)

    print("=" * 70)
    print("STEP 1: Generating simulated auth.log")
    print("=" * 70)
    gen_summary = log_generator.build_log(LOG_PATH)
    print(json.dumps(gen_summary, indent=2))

    print("\n" + "=" * 70)
    print("STEP 2: Ingesting log into SQLite")
    print("=" * 70)
    ing_summary = siem_ingest.ingest_file(LOG_PATH, DB_PATH)
    print(f"Parsed {ing_summary['parsed_events']}/{ing_summary['total_lines']} lines "
          f"({ing_summary['unparsed_lines']} unparsed)")

    conn = siem_ingest.get_connection(DB_PATH)
    print("Event type counts:", siem_ingest.event_type_counts(conn))

    print("\n" + "=" * 70)
    print("STEP 3: Running detection rules")
    print("=" * 70)
    alerts = detection_rules.run_all_rules(conn)
    ids = detection_rules.persist_alerts(conn, alerts)

    if not alerts:
        print("No alerts triggered.")
    for alert_id, a in zip(ids, alerts):
        print(f"\n[{alert_id}] {a['rule'].upper()} (severity={a['severity']})")
        print(f"  Source IP : {a['src_ip']}")
        print(f"  Window    : {a['window_start']} -> {a['window_end']}")
        print(f"  Count     : {a['event_count']}")
        print(f"  Detail    : {a['detail']}")

    conn.close()

    print("\n" + "=" * 70)
    print(f"Pipeline complete. DB at {DB_PATH}. Run `python3 dashboard.py` to view it.")
    print("=" * 70)


if __name__ == "__main__":
    main()
