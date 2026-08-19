"""
run_pipeline.py
----------------
End-to-end driver for the capstone: generate the attack-chain log, ingest it
with Project 4's siem_ingest.py, then run both Project 4's stock detection
rules AND this project's chain-specific correlation. This is what produced
the console output pasted into README.md and incident_response_report.md.

Deterministic: attack_chain_simulation.py seeds its own RNG (random.seed
1337), so re-running this reproduces identical timestamps and byte counts.
"""

import json
import os
import sys

import attack_chain_detection
import attack_chain_simulation

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "04-soc-siem-lab"))
import detection_rules  # noqa: E402
import siem_ingest  # noqa: E402

HERE = os.path.dirname(__file__)
LOG_PATH = os.path.join(HERE, "data", "attack_chain.log")
DB_PATH = os.path.join(HERE, "data", "attack_chain.db")


def main():
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)

    print("=" * 72)
    print("STEP 1: Simulating multi-stage attack chain")
    print("=" * 72)
    evidence = attack_chain_simulation.build_full_log(LOG_PATH)
    print(json.dumps(evidence, indent=2))

    evidence_path = os.path.join(HERE, "data", "ground_truth_evidence.json")
    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=2)

    print("\n" + "=" * 72)
    print("STEP 2: Ingesting log (Project 4's siem_ingest.py, reused as-is)")
    print("=" * 72)
    ing = siem_ingest.ingest_file(LOG_PATH, DB_PATH)
    print(f"Parsed {ing['parsed_events']}/{ing['total_lines']} lines "
          f"({ing['unparsed_lines']} unparsed)")

    conn = siem_ingest.get_connection(DB_PATH)
    print("Event type counts:", siem_ingest.event_type_counts(conn))

    print("\n" + "=" * 72)
    print("STEP 3a: Project 4 baseline rules (brute force / port scan)")
    print("=" * 72)
    base_alerts = detection_rules.run_all_rules(conn)
    base_ids = detection_rules.persist_alerts(conn, base_alerts)
    for alert_id, a in zip(base_ids, base_alerts):
        print(f"[{alert_id}] {a['rule']} (severity={a['severity']}) src={a['src_ip']} "
              f"count={a['event_count']}")

    print("\n" + "=" * 72)
    print("STEP 3b: Capstone chain correlation (this project's new rules)")
    print("=" * 72)
    chains = attack_chain_detection.detect_attack_chain(conn)
    chain_ids = attack_chain_detection.persist_chain_alerts(conn, chains)

    if not chains:
        print("No multi-stage chain detected -- see troubleshooting in README.")
    for alert_id, c in zip(chain_ids, chains):
        print(f"\n[{alert_id}] {c['detail']}")
        print("  MITRE ATT&CK mapping:")
        for m in c["mitre_chain"]:
            print(f"    {m['id']:<12} {m['name']:<28} ({m['tactic']})")

    conn.close()

    print("\n" + "=" * 72)
    print(f"Pipeline complete. DB at {DB_PATH}.")
    print("=" * 72)

    return evidence, base_alerts, chains


if __name__ == "__main__":
    main()
