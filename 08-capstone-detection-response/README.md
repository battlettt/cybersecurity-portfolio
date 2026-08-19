# Project 8 (Capstone) — Multi-Stage Attack Chain Detection & Response

Simulates a realistic, multi-stage intrusion — initial access via brute
force, lateral movement, and data exfiltration — against Project 4's SIEM
pipeline, detects every stage (reusing Project 4's rule engine rather than
rebuilding it), maps each stage to real MITRE ATT&CK technique IDs, and
produces a full incident response report grounded in the actual detection
run.

**Resume bullet:** Simulated and detected a multi-stage attack chain
(initial access → lateral movement → exfiltration) against a home-built
SIEM pipeline, mapped to MITRE ATT&CK (T1110, T1078, T1021.004, T1041) with
correlation logic that ties all three stages to one identity, producing a
full incident response report with timeline, root cause, and remediation
recommendations — all verified against a real, reproducible pipeline run.

## How this builds on Project 4

Project 4 (`../04-soc-siem-lab/`) built a generic SIEM: log parsing
(`siem_ingest.py`), SQLite storage, and two independent detection rules
(`detection_rules.py`: brute force, port scan). This capstone:

- **Imports those modules directly** (`sys.path` + `import detection_rules`,
  `import siem_ingest` — see the top of `attack_chain_detection.py` and
  `attack_chain_simulation.py`) rather than copying any of their logic.
- **Extended Project 4's ingestion schema** with one new event type
  (`data_exfil`, parsed from a `netflow`-style log line) and one new
  column (`bytes_transferred`) — a natural, backward-compatible extension
  (Project 4's own pipeline was re-run after this change and produced
  identical results, confirming nothing broke).
- **Adds three new, chain-specific detection rules**
  (`attack_chain_detection.py`) that Project 4 doesn't need on its own:
  successful-brute-force correlation, identity-scoped lateral-movement
  detection, and volumetric exfiltration detection — then **correlates all
  three plus Project 4's original brute-force rule** into one incident-level
  alert.

## Attack narrative simulated

1. **Stage 1 — Initial Access** (`T1110` Brute Force → `T1078` Valid
   Accounts, Credential Access → Initial Access): an external actor at
   `203.0.113.50` runs a 22-attempt password-guessing burst against the
   internet-facing host `web01`, mixing common default usernames with one
   real employee account (`rpatel`) obtained via (simulated) OSINT. The
   burst ends with a successful login as `rpatel`.
2. **Stage 2 — Lateral Movement** (`T1021.004` Remote Services: SSH,
   Lateral Movement): using the now-valid `rpatel` credentials, the
   attacker pivots from `web01` (now acting as a jump host, connecting from
   its own internal IP) via SSH to `app02` and `db01`.
3. **Stage 3 — Exfiltration** (`T1041` Exfiltration Over C2 Channel,
   Exfiltration): a ~812 MB outbound transfer from `db01` to the attacker's
   IP over port 443 (chosen to blend in with normal HTTPS egress).

Total simulated dwell time: **13.1 minutes**, end to end.

## How to run it

```bash
cd 08-capstone-detection-response
python3 run_pipeline.py
```

This regenerates `data/attack_chain.log` (deterministic — `random.seed
(1337)`), ingests it into `data/attack_chain.db` via Project 4's
`siem_ingest.py`, runs Project 4's stock rules, then runs this project's
chain correlation, printing every alert and the full MITRE mapping.

Individual stages can also be run/inspected separately:
```bash
python3 attack_chain_simulation.py   # just generates data/attack_chain.log + ground_truth_evidence.json
python3 attack_chain_detection.py    # just runs detection against an already-ingested DB
```

## Verified run output (real, captured 2026-08-18)

```
STEP 2: Ingesting log (Project 4's siem_ingest.py, reused as-is)
Parsed 99/99 lines (0 unparsed)
Event type counts: {'auth_failed': 25, 'auth_success': 73, 'data_exfil': 1}

STEP 3a: Project 4 baseline rules (brute force / port scan)
[ALERT-BRUTE_FORCE_SSH-001] brute_force_ssh (severity=high) src=203.0.113.50 count=22

STEP 3b: Capstone chain correlation (this project's new rules)

[CHAIN-001] Full attack chain detected for account 'rpatel': brute force
from 203.0.113.50 -> valid-account login on web01 -> lateral movement to
app02, db01 -> 1 exfiltration event(s) totalling 812.3 MB.
  MITRE ATT&CK mapping:
    T1110        Brute Force                  (Credential Access)
    T1078        Valid Accounts               (Initial Access)
    T1021.004    Remote Services: SSH         (Lateral Movement)
    T1041        Exfiltration Over C2 Channel (Exfiltration)
```

Every stage of the simulated chain was independently confirmed in the
database (raw log lines, exact timestamps, and byte counts are all cited in
`incident_response_report.md`), and the correlation logic correctly
declined to raise a chain alert until all three stages tied together for
the same identity — it does not just OR independent alerts together.

## Files

```
08-capstone-detection-response/
  attack_chain_simulation.py     Generates the multi-stage attack log (imports Project 4's log_generator)
  attack_chain_detection.py      Chain-specific detection + correlation (imports Project 4's detection_rules)
  run_pipeline.py                 End-to-end driver used to produce the output above
  data/attack_chain.log           Generated log (reproducible)
  data/attack_chain.db            Generated SQLite DB (reproducible)
  data/ground_truth_evidence.json Exact simulation values, for cross-checking the IR report
  incident_response_report.md     Full IR report: timeline, MITRE table, root cause, remediation, lessons learned
```

## Honest limitations

- This is a single deterministic simulation, not live traffic — thresholds
  and windows (documented in `attack_chain_detection.py`) are justified by
  reasoning about attacker/defender behavior, not tuned against a real
  production false-positive rate.
- The lateral-movement rule is intentionally identity-scoped (it trusts
  that stage 1 already established `rpatel` as compromised) rather than
  fully volume/anomaly-based; a production version would also want a
  baseline of each account's normal host-access pattern to flag *first*
  access to a new host even without a prior brute-force alert.
- Like Project 4, no Docker/ELK stack was available in the environment this
  was built in — this capstone extends Project 4's Track A (Python/SQLite)
  only; the same chain-detection logic could be reimplemented as
  Elasticsearch/Kibana correlation rules using the same approach documented
  in Project 4's `PRODUCTION_SETUP.md`.
