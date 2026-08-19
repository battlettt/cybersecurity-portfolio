"""
attack_chain_simulation.py
---------------------------
Generates a log (same format as Project 4's log_generator.py -- reused via
import, not reimplemented) containing a single coherent MULTI-STAGE attack,
plus ordinary baseline traffic around it so the chain has to be found in
noise rather than handed to the detector in isolation.

Narrative: an external actor OSINT's a real employee username (`rpatel`),
brute-forces their SSH password against the internet-facing host, succeeds,
then pivots internally over SSH to two more hosts using those same
credentials, and finally exfiltrates a large data set from the database
host back out to their own infrastructure over what looks like ordinary
HTTPS (port 443) traffic.

Stage -> MITRE ATT&CK (Enterprise) mapping used throughout this project:

  Stage 1a (failed attempts)  T1110      Brute Force              (Credential Access)
  Stage 1b (successful login) T1078      Valid Accounts           (Initial Access)
  Stage 2  (internal pivots)  T1021.004  Remote Services: SSH     (Lateral Movement)
  Stage 3  (large transfer)   T1041      Exfiltration Over C2 Channel (Exfiltration)

These are real, current MITRE ATT&CK Enterprise technique IDs -- see
incident_response_report.md for the full mapping table with tactic names
and the evidence each one is based on.
"""

import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "04-soc-siem-lab"))
import log_generator as lg  # noqa: E402  (Project 4 module, reused not duplicated)

random.seed(1337)  # separate, dedicated seed for this scenario

ATTACKER_IP = "203.0.113.50"          # RFC 5737 TEST-NET-3, unrelated to Project 4's demo IPs
COMPROMISED_USERNAME = "rpatel"        # a real employee account (see log_generator.EMPLOYEE_ACCOUNTS)

INITIAL_ACCESS_HOST = "web01"          # internet-facing, brute-forced directly
INTERNAL_IPS = {                       # each host's own address, used once the
    "web01": "10.0.0.10",              # attacker is pivoting *from* that host
    "app02": "10.0.0.11",
    "db01": "10.0.0.12",
}
LATERAL_TARGETS = ["app02", "db01"]    # hosts reached via SSH using stolen creds
EXFIL_SOURCE_HOST = "db01"             # where the large transfer originates


def netflow_line(ts, host, src_ip, dst_ip, num_bytes, duration_s, dst_port):
    msg = (f"OUTBOUND SRC={src_ip} DST={dst_ip} BYTES={num_bytes} "
           f"DURATION={duration_s}s PROTO=TCP DPT={dst_port}")
    pid = lg.next_pid()
    return f"{lg.fmt(ts)} {host} netflow[{pid}]: {msg}"


def build_attack_chain(start: datetime):
    """Returns (lines, evidence) where evidence records the exact
    timestamps/values used, so the detection script and the IR report can
    both cite the ground truth instead of re-deriving it."""
    lines = []
    evidence = {}

    # ---- Stage 1a: brute force (T1110) ------------------------------
    t = start
    n_attempts = 22
    usernames_tried = []
    for i in range(n_attempts):
        t += timedelta(seconds=random.uniform(2.0, 5.0))
        # The attacker mixes generic default-account guesses with the one
        # real username they harvested via OSINT -- exactly how credential
        # stuffing lists blend "common" and "targeted" entries in practice.
        if i in (7, 14, n_attempts - 1):
            username = COMPROMISED_USERNAME
            valid_user = True
        else:
            username = random.choice(lg.GUESSED_USERNAMES)
            valid_user = False
        usernames_tried.append(username)
        port = random.randint(49152, 65535)
        lines.append(lg.ssh_failed_line(t, INITIAL_ACCESS_HOST, ATTACKER_IP,
                                         username, valid_user, port))
    stage1a_start, stage1a_end = start + timedelta(seconds=2), t
    evidence["stage1a_brute_force"] = {
        "start": lg.fmt(stage1a_start), "end": lg.fmt(stage1a_end),
        "attempts": n_attempts, "src_ip": ATTACKER_IP, "target_host": INITIAL_ACCESS_HOST,
        "usernames_tried": usernames_tried,
    }

    # ---- Stage 1b: successful login (T1078) --------------------------
    t += timedelta(seconds=random.uniform(8, 20))  # attacker's password finally lands
    port = random.randint(49152, 65535)
    lines.append(lg.ssh_accepted_line(t, INITIAL_ACCESS_HOST, ATTACKER_IP,
                                       COMPROMISED_USERNAME, port))
    evidence["stage1b_successful_login"] = {
        "timestamp": lg.fmt(t), "src_ip": ATTACKER_IP, "host": INITIAL_ACCESS_HOST,
        "username": COMPROMISED_USERNAME,
    }
    initial_access_ts = t

    # ---- Stage 2: lateral movement over SSH (T1021.004) ---------------
    lateral_events = []
    jump_ip = INTERNAL_IPS[INITIAL_ACCESS_HOST]
    for target_host in LATERAL_TARGETS:
        t += timedelta(minutes=random.uniform(2, 6))
        port = random.randint(49152, 65535)
        lines.append(lg.ssh_accepted_line(t, target_host, jump_ip,
                                           COMPROMISED_USERNAME, port))
        lateral_events.append({"timestamp": lg.fmt(t), "src_ip": jump_ip,
                                "host": target_host, "username": COMPROMISED_USERNAME})
    evidence["stage2_lateral_movement"] = {
        "pivot_from_host": INITIAL_ACCESS_HOST, "pivot_from_ip": jump_ip,
        "username": COMPROMISED_USERNAME, "events": lateral_events,
    }
    last_lateral_ts = t

    # ---- Stage 3: exfiltration (T1041) --------------------------------
    t += timedelta(minutes=random.uniform(3, 8))
    num_bytes = 812_345_120  # ~775 MB, one abnormally large transfer
    duration_s = 46
    lines.append(netflow_line(t, EXFIL_SOURCE_HOST, INTERNAL_IPS[EXFIL_SOURCE_HOST],
                               ATTACKER_IP, num_bytes, duration_s, 443))
    evidence["stage3_exfiltration"] = {
        "timestamp": lg.fmt(t), "src_host": EXFIL_SOURCE_HOST,
        "src_ip": INTERNAL_IPS[EXFIL_SOURCE_HOST], "dst_ip": ATTACKER_IP,
        "bytes": num_bytes, "duration_s": duration_s, "dst_port": 443,
    }

    evidence["chain_start"] = lg.fmt(stage1a_start)
    evidence["chain_end"] = lg.fmt(t)
    evidence["total_duration_minutes"] = round((t - stage1a_start).total_seconds() / 60, 1)

    return lines, evidence


def build_full_log(output_path: str, baseline_hours: int = 18):
    start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)

    all_lines = []
    morning_end = start + timedelta(hours=7)
    all_lines += lg.generate_baseline(start, hours=7)

    chain_start = morning_end + timedelta(minutes=random.randint(15, 45))
    chain_lines, evidence = build_attack_chain(chain_start)
    all_lines += chain_lines

    afternoon_start = datetime.fromisoformat(evidence["chain_end"]) + timedelta(
        minutes=random.randint(30, 90))
    all_lines += lg.generate_baseline(afternoon_start, hours=max(baseline_hours - 7, 1))

    all_lines.sort(key=lambda line: line.split(" ", 1)[0])

    with open(output_path, "w") as f:
        f.write("\n".join(all_lines) + "\n")

    evidence["total_lines"] = len(all_lines)
    return evidence


if __name__ == "__main__":
    import json

    out_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "attack_chain.log")

    evidence = build_full_log(out_path)
    print(f"Wrote {evidence['total_lines']} log lines to {out_path}")
    print(json.dumps(evidence, indent=2))

    evidence_path = os.path.join(out_dir, "ground_truth_evidence.json")
    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=2)
    print(f"Ground-truth evidence written to {evidence_path}")
