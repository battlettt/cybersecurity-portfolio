#!/usr/bin/env python3
"""
Audits passwords against a basic policy and estimates offline crack time.

Usage:
    python3 password_policy_auditor.py --password "Summer2024!"
    python3 password_policy_auditor.py --file sample_data/passwords.txt
    python3 password_policy_auditor.py --file sample_data/passwords.txt --json
"""
import argparse
import json
import math
import re
import sys

# A small seed list of extremely common passwords (a real audit would use the full
# rockyou.txt / HaveIBeenPwned Pwned Passwords list — this is intentionally a compact
# stand-in so the tool has zero external dependencies).
COMMON_PASSWORDS = {
    "123456", "123456789", "password", "12345678", "qwerty", "12345", "111111",
    "1234567", "sunshine", "iloveyou", "admin", "welcome", "monkey", "login",
    "abc123", "letmein", "dragon", "master", "hello", "freedom", "whatever",
    "qazwsx", "trustno1", "password1", "1q2w3e4r", "starwars", "football",
}

SEQUENTIAL_RUNS = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]

# Crack-speed assumptions (guesses/second), for context — not precise, but the right
# order of magnitude, and the point of showing both is that hash choice matters enormously:
GUESS_RATES = {
    'offline_fast_hash (unsalted MD5/SHA1, single high-end GPU)': 1e10,
    'offline_slow_hash (bcrypt cost=12, single high-end GPU)': 2e3,
    'online_throttled (rate-limited login form, ~10/sec)': 10,
}


def shannon_entropy_bits(password):
    """Estimate entropy assuming a uniform charset sized to whatever character
    classes are actually present — a simple, defensible approximation."""
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 33  # common printable specials
    charset = max(charset, 1)
    return len(password) * math.log2(charset)


def has_sequential_run(password, run_len=4):
    lower = password.lower()
    for run in SEQUENTIAL_RUNS:
        for i in range(len(run) - run_len + 1):
            chunk = run[i:i + run_len]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def has_repeated_run(password, run_len=4):
    for i in range(len(password) - run_len + 1):
        if len(set(password[i:i + run_len])) == 1:
            return True
    return False


def audit_password(password):
    issues = []
    if len(password) < 12:
        issues.append(f'too short ({len(password)} chars, minimum 12)')
    if not re.search(r'[a-z]', password):
        issues.append('missing lowercase letter')
    if not re.search(r'[A-Z]', password):
        issues.append('missing uppercase letter')
    if not re.search(r'[0-9]', password):
        issues.append('missing digit')
    if not re.search(r'[^a-zA-Z0-9]', password):
        issues.append('missing special character')
    if password.lower() in COMMON_PASSWORDS:
        issues.append('found in common-password list')
    if has_sequential_run(password):
        issues.append('contains a sequential run (e.g. "1234", "abcd", "qwer")')
    if has_repeated_run(password):
        issues.append('contains 4+ repeated characters')

    entropy = shannon_entropy_bits(password)
    guesses_needed = 2 ** entropy / 2  # average case: half the keyspace

    crack_times = {}
    for label, rate in GUESS_RATES.items():
        seconds = guesses_needed / rate
        crack_times[label] = human_duration(seconds)

    return {
        'password_masked': password[0] + '*' * (len(password) - 2) + password[-1] if len(password) > 2 else '*' * len(password),
        'length': len(password),
        'entropy_bits': round(entropy, 1),
        'policy_pass': len(issues) == 0,
        'issues': issues,
        'estimated_crack_time': crack_times,
    }


def human_duration(seconds):
    if seconds < 1:
        return '<1 second'
    units = [('years', 365.25 * 86400), ('days', 86400), ('hours', 3600), ('minutes', 60), ('seconds', 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == 'years' and value > 1e6:
                return f'{value:.2e} years'
            return f'{value:.1f} {name}'
    return f'{seconds:.1f} seconds'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--password', help='audit a single password')
    group.add_argument('--file', help='audit one password per line from a file')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    passwords = [args.password] if args.password else [l.strip() for l in open(args.file) if l.strip()]
    results = [audit_password(p) for p in passwords]

    if args.json:
        print(json.dumps(results, indent=2))
        return

    fails = 0
    for r in results:
        status = 'PASS' if r['policy_pass'] else 'FAIL'
        if not r['policy_pass']:
            fails += 1
        print(f"[{status}] {r['password_masked']}  (entropy: {r['entropy_bits']} bits)")
        for issue in r['issues']:
            print(f"        - {issue}")
        for label, duration in r['estimated_crack_time'].items():
            print(f"        Estimated crack time [{label}]: {duration}")
        print()

    print(f"Summary: {len(results) - fails}/{len(results)} passwords pass policy")
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
