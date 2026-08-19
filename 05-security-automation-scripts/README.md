# Project 5 — Security Automation Scripts

Two small, dependency-free Python CLI tools that automate tasks a SOC analyst or sysadmin
actually does by hand: spotting brute-force login activity in an auth log, and auditing
passwords against a real policy with a concrete crack-time estimate (not just a red/green
strength meter). Both are pure Python 3 stdlib — no installs required — and both are unit
tested.

## Resume bullet

> Wrote Python security automation tools — an SSH auth-log brute-force detector using a
> sliding-window algorithm, and a password-policy auditor estimating offline crack time
> across three threat models (fast hash, bcrypt, rate-limited login) — with unit tests
> covering the core algorithms.

## `log_bruteforce_detector.py`

Parses OpenSSH-style `auth.log` lines and flags any source IP with more failed logins than
`--threshold` inside any `--window`-second sliding window (default: 5+ failures in 5
minutes). Uses a classic two-pointer sliding window per IP — O(n) per IP, not a naive
O(n²) re-scan.

```bash
$ python3 log_bruteforce_detector.py sample_data/auth.log
Parsed 11 failed-login events from sample_data/auth.log
Window: 300s | Threshold: 5 attempts

ALERT  203.0.113.9: 8 attempts in 300s window (2026-08-18T22:30:01 -> 2026-08-18T22:30:15)
       8 total failures, usernames tried: admin, administrator, oracle, postgres, root, ubuntu
```

The sample log also contains scattered, normal failed logins from two other IPs (a typo'd
password, an abandoned login attempt) — correctly **not** flagged, because they're spread
across the log rather than clustered in time. That's the actual point of a sliding window
over a flat count: `grep -c "Failed password" | wc -l` can't tell a burst from background
noise, this can.

## `password_policy_auditor.py`

Checks length, character-class diversity, common-password membership, sequential runs
(`1234`, `qwer`), and repeated-character runs — then estimates entropy and translates it
into crack time under three different threat models, because *what's cracking the hash*
matters as much as the password itself:

```bash
$ python3 password_policy_auditor.py --file sample_data/passwords.txt
[FAIL] p******d  (entropy: 37.6 bits)
        - too short (8 chars, minimum 12)
        - missing uppercase letter
        - missing digit
        - missing special character
        - found in common-password list
        Estimated crack time [offline_fast_hash]: 10.4 seconds
        Estimated crack time [offline_slow_hash (bcrypt cost=12)]: 1.7 years
        Estimated crack time [online_throttled]: 330.9 years

[FAIL] S*********!  (entropy: 72.3 bits)
        - too short (11 chars, minimum 12)
        Estimated crack time [offline_fast_hash]: 9012.1 years
        ...

[PASS] T**************Q  (entropy: 105.1 bits)
        Estimated crack time [offline_fast_hash]: 6.97e+13 years
        ...

Summary: 2/9 passwords pass policy
```

(Full output with all 9 sample passwords and all 3 threat models is in
[`sample_data/`](sample_data/) — run the command above to reproduce it.)

**The interesting case in the sample set:** `correcthorsebatterystaple` (the XKCD-936
password) has *117.5 bits of entropy* — higher than several passwords that pass — but
still **fails** the policy, because it's all lowercase. That's a deliberate inclusion: it's
a good discussion point for an interview about the real tension between entropy-based and
composition-based password policies (NIST SP 800-63B's actual current guidance leans
toward the entropy/length view over composition rules — worth bringing up).

## Tests

```bash
$ python3 -m unittest discover -s tests -v
test_does_not_flag_spread_out_failures ... ok
test_flags_burst_from_one_ip ... ok
test_parses_real_log_format ... ok
test_two_ips_only_one_over_threshold ... ok
test_common_password_fails ... ok
test_entropy_increases_with_charset_diversity ... ok
test_repeated_run_detected ... ok
test_sequential_run_detected ... ok
test_short_password_flagged ... ok
test_strong_password_passes ... ok

Ran 10 tests in 0.002s
OK
```

## Design notes / limitations

- The brute-force detector's regex targets standard OpenSSH log format; a production
  version would need to handle multiple log formats (this is exactly what Project 4's SIEM
  lab does with a more general ingestion layer — this script is intentionally the smaller,
  single-purpose sibling).
- The crack-time estimate assumes a uniform random password over the detected character
  classes. Real attackers use dictionary + rule-based attacks (hashcat rules, masks) that
  are dramatically faster against human-generated passwords than brute force — the entropy
  number here is a reasonable upper bound on *security*, not a prediction of real-world
  crack time against a specific tool.
- `COMMON_PASSWORDS` is a 26-entry illustrative stand-in; a real deployment would check
  against the full Have I Been Pwned Pwned Passwords list (via their k-anonymity API, so
  plaintext passwords never leave the machine) instead of a hardcoded set.
