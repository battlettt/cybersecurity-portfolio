#!/usr/bin/env python3
"""
Scans an SSH auth log for brute-force login activity: source IPs with more than
`--threshold` failed login attempts inside any `--window`-second sliding window.

Usage:
    python3 log_bruteforce_detector.py sample_data/auth.log
    python3 log_bruteforce_detector.py sample_data/auth.log --window 300 --threshold 5 --json
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# Matches standard OpenSSH auth.log failed-password lines, e.g.:
#   Aug 18 22:03:11 web01 sshd[4021]: Failed password for root from 203.0.113.9 port 51422 ssh2
#   Aug 18 22:03:12 web01 sshd[4021]: Failed password for invalid user admin from 203.0.113.9 port 51423 ssh2
LOG_PATTERN = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2'
)


def parse_log(path, year=None):
    """Yields (datetime, username, ip) for each failed-login line. Skips lines that don't match."""
    year = year or datetime.now().year
    with open(path) as f:
        for line in f:
            m = LOG_PATTERN.match(line)
            if not m:
                continue
            ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
            yield ts, m.group('user'), m.group('ip')


def detect_bruteforce(events, window_seconds=300, threshold=5):
    """
    events: iterable of (datetime, username, ip), must be chronologically sorted.
    Returns a list of alert dicts, one per IP whose failures exceeded `threshold`
    within any `window_seconds` sliding window.
    """
    by_ip = defaultdict(list)  # ip -> list of (ts, user)
    for ts, user, ip in events:
        by_ip[ip].append((ts, user))

    alerts = []
    for ip, hits in by_ip.items():
        hits.sort(key=lambda h: h[0])
        # classic two-pointer sliding window over this IP's own failed attempts
        left = 0
        worst_count = 0
        worst_window = None
        for right in range(len(hits)):
            while (hits[right][0] - hits[left][0]).total_seconds() > window_seconds:
                left += 1
            count = right - left + 1
            if count > worst_count:
                worst_count = count
                worst_window = (hits[left][0], hits[right][0])

        if worst_count >= threshold:
            usernames = sorted({u for _, u in hits})
            alerts.append({
                'source_ip': ip,
                'failed_attempts_total': len(hits),
                'max_attempts_in_window': worst_count,
                'window_seconds': window_seconds,
                'window_start': worst_window[0].isoformat(),
                'window_end': worst_window[1].isoformat(),
                'usernames_tried': usernames,
            })

    alerts.sort(key=lambda a: -a['max_attempts_in_window'])
    return alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('logfile')
    ap.add_argument('--window', type=int, default=300, help='sliding window in seconds (default 300 = 5 min)')
    ap.add_argument('--threshold', type=int, default=5, help='min failed attempts in window to flag (default 5)')
    ap.add_argument('--json', action='store_true', help='output JSON instead of a human-readable report')
    args = ap.parse_args()

    events = sorted(parse_log(args.logfile), key=lambda e: e[0])
    if not events:
        print(f"No failed-login lines matched in {args.logfile}", file=sys.stderr)
        sys.exit(1)

    alerts = detect_bruteforce(events, window_seconds=args.window, threshold=args.threshold)

    if args.json:
        print(json.dumps({'total_failed_events': len(events), 'alerts': alerts}, indent=2))
        return

    print(f"Parsed {len(events)} failed-login events from {args.logfile}")
    print(f"Window: {args.window}s | Threshold: {args.threshold} attempts\n")
    if not alerts:
        print("No brute-force patterns detected.")
        return

    for a in alerts:
        print(f"ALERT  {a['source_ip']}: {a['max_attempts_in_window']} attempts in "
              f"{a['window_seconds']}s window ({a['window_start']} -> {a['window_end']})")
        print(f"       {a['failed_attempts_total']} total failures, "
              f"usernames tried: {', '.join(a['usernames_tried'])}\n")


if __name__ == '__main__':
    main()
