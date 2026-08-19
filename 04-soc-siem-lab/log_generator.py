"""
log_generator.py
-----------------
Generates a realistic, syslog-style host log (SSH auth events + firewall
connection-block events) that mixes ordinary "baseline" activity with two
embedded attacks:

  1. A brute-force SSH credential-stuffing burst against one host.
  2. A TCP port scan against another host (logged as firewall DROP/BLOCK
     entries, the way ufw/iptables would record it).

The output format is one line per event, timestamp-first RFC3339 style,
followed by syslog `host process[pid]: message` — this is the format rsyslog
/ journald produce when configured with high-precision timestamps, so it
reads like a real captured log rather than an invented one. `siem_ingest.py`
parses this exact format.

Nothing here is hardcoded against the detection thresholds in
detection_rules.py -- the point of the lab is that the rules must find the
attack in the noise, not that the generator and the rules were tuned to
match each other.
"""

import random
from datetime import datetime, timedelta, timezone

random.seed(42)  # reproducible runs -> reproducible incident report

# ---------------------------------------------------------------------------
# Cast of characters
# ---------------------------------------------------------------------------

HOSTS = ["web01", "app02", "db01"]

EMPLOYEE_ACCOUNTS = [
    ("jsmith", "10.0.0.15"),
    ("agupta", "10.0.0.22"),
    ("mwong", "10.0.0.31"),
    ("rpatel", "10.0.0.44"),
    ("ktanaka", "10.0.0.51"),
    ("dlopez", "10.0.0.63"),
]

# Common usernames attackers guess against internet-facing SSH -- taken from
# published "top SSH brute-force usernames" lists (Rapid7, honeypot data).
GUESSED_USERNAMES = [
    "root", "admin", "administrator", "test", "guest", "ubuntu",
    "oracle", "postgres", "user", "pi", "deploy", "backup", "support",
]

ATTACKER_BRUTE_FORCE_IP = "203.0.113.77"      # RFC 5737 TEST-NET-3 (safe, non-routable)
ATTACKER_SCAN_IP = "198.51.100.23"            # RFC 5737 TEST-NET-2 (safe, non-routable)
BRUTE_FORCE_TARGET_HOST = "web01"
SCAN_TARGET_HOST = "db01"

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
              1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443]

PID_COUNTER = [10000]


def next_pid():
    PID_COUNTER[0] += random.randint(1, 7)
    return PID_COUNTER[0]


def fmt(ts: datetime) -> str:
    return ts.isoformat(timespec="microseconds")


def ssh_failed_line(ts, host, src_ip, username, valid_user, port):
    pid = next_pid()
    if valid_user:
        msg = f"Failed password for {username} from {src_ip} port {port} ssh2"
    else:
        msg = f"Failed password for invalid user {username} from {src_ip} port {port} ssh2"
    return f"{fmt(ts)} {host} sshd[{pid}]: {msg}"


def ssh_accepted_line(ts, host, src_ip, username, port):
    pid = next_pid()
    msg = f"Accepted password for {username} from {src_ip} port {port} ssh2"
    return f"{fmt(ts)} {host} sshd[{pid}]: {msg}"


def ufw_block_line(ts, host, src_ip, dst_ip, dst_port, src_port):
    msg = (f"[UFW BLOCK] IN=eth0 OUT= SRC={src_ip} DST={dst_ip} LEN=60 "
           f"TTL=44 PROTO=TCP SPT={src_port} DPT={dst_port} WINDOW=1024 SYN")
    return f"{fmt(ts)} {host} kernel: {msg}"


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def generate_baseline(start: datetime, hours: int) -> list[str]:
    """Ordinary employee SSH activity over `hours`, with a handful of
    innocuous typo'd passwords (real users mistype ~2-4% of the time)."""
    lines = []
    end = start + timedelta(hours=hours)
    t = start
    while t < end:
        t += timedelta(minutes=random.randint(4, 26))
        if t >= end:
            break
        username, home_ip = random.choice(EMPLOYEE_ACCOUNTS)
        host = random.choice(HOSTS)
        port = random.randint(49152, 65535)

        if random.random() < 0.06:
            # single mistyped-password retry, then success a few seconds later
            lines.append(ssh_failed_line(t, host, home_ip, username, True, port))
            t2 = t + timedelta(seconds=random.uniform(2, 6))
            lines.append(ssh_accepted_line(t2, host, home_ip, username, port))
        else:
            lines.append(ssh_accepted_line(t, host, home_ip, username, port))
    return lines


def generate_brute_force(start: datetime) -> list[str]:
    """~55 failed SSH attempts from one external IP against one host inside
    a ~3 minute window -- the classic automated credential-stuffing burst
    (tools like Hydra/Medusa fire several attempts per second)."""
    lines = []
    t = start
    n_attempts = 55
    for _ in range(n_attempts):
        t += timedelta(seconds=random.uniform(1.5, 4.5))
        username = random.choice(GUESSED_USERNAMES)
        port = random.randint(49152, 65535)
        lines.append(ssh_failed_line(t, BRUTE_FORCE_TARGET_HOST,
                                      ATTACKER_BRUTE_FORCE_IP, username, False, port))
    return lines, t


def generate_port_scan(start: datetime) -> list[str]:
    """One external IP touches every port in SCAN_PORTS against one host
    inside ~12 seconds -- a fast single-source TCP scan (nmap -T4 style),
    logged as firewall DROPs since nothing is listening on most of them."""
    lines = []
    t = start
    ports = SCAN_PORTS[:]
    random.shuffle(ports)
    for port in ports:
        t += timedelta(milliseconds=random.uniform(300, 900))
        src_port = random.randint(40000, 60000)
        lines.append(ufw_block_line(t, SCAN_TARGET_HOST, ATTACKER_SCAN_IP,
                                     "10.0.0.5", port, src_port))
    return lines, t


def build_log(output_path: str, baseline_hours: int = 24):
    start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)

    all_events = []

    # Baseline: first third of the day, then attacks land mid-afternoon
    # (when SOC analysts stereotypically find them the next morning), then
    # baseline resumes for the rest of the day.
    morning_end = start + timedelta(hours=9)
    all_events += generate_baseline(start, hours=9)

    bf_start = morning_end + timedelta(minutes=random.randint(10, 40))
    bf_lines, bf_end = generate_brute_force(bf_start)
    all_events += bf_lines

    scan_start = bf_end + timedelta(minutes=random.randint(15, 45))
    scan_lines, scan_end = generate_port_scan(scan_start)
    all_events += scan_lines

    afternoon_start = scan_end + timedelta(minutes=random.randint(20, 60))
    remaining_hours = baseline_hours - 9
    all_events += generate_baseline(afternoon_start, hours=max(remaining_hours, 1))

    # Events are generated in scenario order (baseline/attack/baseline) but a
    # real log is time-ordered as it's written -- sort before saving.
    all_events.sort(key=lambda line: line.split(" ", 1)[0])

    with open(output_path, "w") as f:
        f.write("\n".join(all_events) + "\n")

    return {
        "total_lines": len(all_events),
        "brute_force_window": (fmt(bf_start), fmt(bf_end)),
        "brute_force_attempts": len(bf_lines),
        "port_scan_window": (fmt(scan_start), fmt(scan_end)),
        "port_scan_events": len(scan_lines),
        "attacker_brute_force_ip": ATTACKER_BRUTE_FORCE_IP,
        "attacker_scan_ip": ATTACKER_SCAN_IP,
        "brute_force_target_host": BRUTE_FORCE_TARGET_HOST,
        "scan_target_host": SCAN_TARGET_HOST,
    }


if __name__ == "__main__":
    import json
    import os

    out_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "auth.log")

    summary = build_log(out_path)
    print(f"Wrote {summary['total_lines']} log lines to {out_path}")
    print(json.dumps(summary, indent=2))
