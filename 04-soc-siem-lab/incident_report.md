# Incident Report — INC-2026-0818-01

| Field | Value |
|---|---|
| Report ID | INC-2026-0818-01 |
| Prepared by | SOC Analyst (home lab, Tier 1 triage) |
| Date prepared | 2026-08-18 |
| Detection source | Home SIEM pipeline (`log_generator.py` → `siem_ingest.py` → `detection_rules.py`) |
| Log source | `data/auth.log` (170 lines, hosts `web01`/`app02`/`db01`) |
| Alert IDs | `ALERT-BRUTE_FORCE_SSH-001`, `ALERT-PORT_SCAN-002` |
| Severity | High (brute force), Medium (port scan) |
| Status | Detected in simulated environment; no real production impact |

## 1. Executive Summary

During review of the 24-hour SSH/firewall log for `web01`, `app02`, and `db01`, the SIEM
pipeline's rule engine flagged two related pieces of suspicious activity within roughly
80 minutes of each other on 2026-08-18:

1. A **brute-force SSH credential-stuffing attack** against `web01` from external IP
   `203.0.113.77`, consisting of 55 failed login attempts across 13 distinct usernames
   in under 3 minutes.
2. A **TCP port scan** against `db01` from external IP `198.51.100.23`, which probed
   20 distinct ports in about 12 seconds.

Neither source IP is associated with the organization's employee IP range
(`10.0.0.0/24`, used by all 91 legitimate logins in this log). No successful
authentication was ever recorded from either attacker IP. Based on available evidence,
both events were **reconnaissance/attempted-access activity that did not result in a
compromise**, but both warrant blocking and monitoring per the recommendations below.

## 2. Detection Details

### 2.1 Alert `ALERT-BRUTE_FORCE_SSH-001` — SSH Brute Force

- **Rule**: `brute_force_ssh` (`detection_rules.detect_brute_force`)
- **Trigger condition**: ≥8 failed SSH logins from one source IP within a 5-minute
  sliding window (see § 4 for threshold justification)
- **Source IP**: `203.0.113.77` (external; not in the `10.0.0.0/24` employee range)
- **Target host**: `web01` (the only host this IP contacted)
- **Window observed**: `2026-08-18T09:12:03.042468+00:00` → `2026-08-18T09:14:50.813486+00:00`
  (2 minutes 47 seconds)
- **Volume**: 55 failed login attempts — far above the 8-in-5-minutes threshold
- **Usernames attempted** (13 distinct, all from a common list of default/service
  account names, none of which correspond to real employee accounts in
  `EMPLOYEE_ACCOUNTS`): `support`(6), `guest`(6), `user`(5), `test`(5), `postgres`(5),
  `backup`(5), `admin`(5), `root`(4), `pi`(4), `deploy`(4), `ubuntu`(2), `oracle`(2),
  `administrator`(2)
- **Outcome**: 0 successful logins were ever recorded from `203.0.113.77` in this
  log (verified by direct query: `SELECT COUNT(*) FROM events WHERE src_ip =
  '203.0.113.77' AND event_type = 'auth_success'` → `0`). The attack appears to have
  been unsuccessful or abandoned before a valid credential was found.
- **Representative raw log lines**:
  ```
  2026-08-18T09:12:03.042468+00:00 web01 sshd[10123]: Failed password for invalid user guest from 203.0.113.77 port 65058 ssh2
  2026-08-18T09:12:06.160170+00:00 web01 sshd[10125]: Failed password for invalid user backup from 203.0.113.77 port 64640 ssh2
  2026-08-18T09:12:10.014028+00:00 web01 sshd[10127]: Failed password for invalid user support from 203.0.113.77 port 62490 ssh2
  ```

### 2.2 Alert `ALERT-PORT_SCAN-002` — TCP Port Scan

- **Rule**: `port_scan` (`detection_rules.detect_port_scan`)
- **Trigger condition**: ≥8 distinct destination ports from one source IP within a
  30-second sliding window (see § 4)
- **Source IP**: `198.51.100.23` (external)
- **Target**: `10.0.0.5` (internal, fronted by `db01`'s firewall)
- **Window observed**: `2026-08-18T09:56:51.320898+00:00` → `2026-08-18T09:57:02.753611+00:00`
  (11.4 seconds)
- **Volume**: 20 distinct ports probed — well above the 8-port threshold
- **Ports probed**: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP),
  110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB), 1433 (MSSQL), 1521 (Oracle),
  2049 (NFS), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis),
  8080/8443 (alt HTTP/S) — a broad, service-agnostic sweep typical of automated
  scanning tools (e.g., `nmap` default/top-ports scans) rather than a targeted probe
  of one known service.
- **Outcome**: every probe was blocked at the host firewall (UFW) and logged as a
  `[UFW BLOCK]` DROP; no connection was established.
- **Representative raw log line**:
  ```
  2026-08-18T09:56:51.320898+00:00 db01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.23 DST=10.0.0.5 LEN=60 TTL=44 PROTO=TCP SPT=50278 DPT=25 WINDOW=1024 SYN
  ```

### 2.3 Timing relationship

The port scan began ~42 minutes after the brute-force window ended, from a
*different* external IP against a *different* host. There is no shared source IP or
username between the two events in this log, so — on the evidence in this log alone —
they are treated as two independent opportunistic events rather than a single
coordinated campaign. (Project 8's capstone simulation demonstrates what a *linked*
multi-stage chain from a single actor looks like, and how the same rule engine
detects each stage.)

## 3. Impact Assessment

- **Confidentiality/Integrity/Availability**: No impact identified. No successful
  authentication occurred from either attacker IP, and the firewall rejected every
  port-scan probe before a connection was established.
- **Scope**: Limited to two hosts (`web01`, `db01`) receiving unsolicited external
  traffic; no lateral movement or internal-to-internal suspicious activity was
  observed in this log.
- **Data exposure**: None identified.
- **Overall impact rating**: **Low** (attempted access / reconnaissance, no
  compromise confirmed) — but see recommendations, since brute-force attempts that
  fail today can succeed later if the same weak-credential exposure persists.

## 4. Detection Logic Notes (why these thresholds)

- **Brute force — 8 failed logins / 5 minutes per source IP.** A legitimate user
  mistyping a password happens occasionally (this log's baseline includes several
  single-retry-then-success cases) but essentially never produces more than 2-3
  failures in a row. Automated tools (Hydra, Medusa, ncrack) fire attempts every
  1-3 seconds per thread, so a real attack clears 8 attempts in under 30 seconds. The
  threshold sits well above plausible human error and well below automated-tool
  volume, in the same range as common SIEM defaults (e.g., Splunk ESSOC's stock
  failed-login correlation search defaults to 6-in-5-minutes; 8 was chosen here to
  reduce false positives from shared/NAT'd source IPs).
- **Port scan — 8 distinct destination ports / 30 seconds per source IP.** A normal
  client touches one or two ports on a server. Reconnaissance tools sweep many ports
  in a short burst; 8 ports in 30 seconds is the same order of magnitude as
  Suricata/Snort's default portscan-preprocessor sensitivity.
- Both rules use a **sliding time window** (two-pointer algorithm over sorted
  per-IP timestamps), not a fixed calendar-minute bucket, so a burst that straddles
  a bucket boundary (e.g., 30 events split 4/4 across two clock-minutes) is still
  caught — a known blind spot of naive fixed-bucket counting.

## 5. Recommendations

1. **Block the two attacker IPs** (`203.0.113.77`, `198.51.100.23`) at the perimeter
   firewall/security group; they show no legitimate purpose in this log.
2. **Enforce SSH key-based authentication and disable password auth** on
   internet-facing hosts (`web01` in particular) — this eliminates the entire class
   of credential-stuffing risk regardless of attempt volume.
3. **Rate-limit / fail2ban SSH** so repeated failures from one source are
   auto-blocked well before reaching the alert threshold, rather than relying on
   after-the-fact detection alone.
4. **Restrict `db01` (database host) to internal-only network access**; it should
   not be reachable by an external scanner at all — the fact that `198.51.100.23`
   could reach it and receive firewall DROPs (rather than the packets being dropped
   further upstream) suggests the network perimeter, not just the host firewall, is
   the layer to fix.
5. **Tune and retain these detection rules in production** (see
   `PRODUCTION_SETUP.md` for the equivalent ELK/Kibana implementation) so this class
   of activity is caught automatically going forward, and review the account list
   attackers targeted (`admin`, `root`, `postgres`, etc.) to confirm none of those
   default/service accounts actually exist and are enabled.
6. **No credential reset is required** for this incident specifically, since no
   successful authentication from either attacker IP was observed — but this should
   be re-verified any time thresholds or scope change.

## 6. Reproducibility

This report is derived entirely from one deterministic run of the pipeline
(`log_generator.py` seeds its RNG with `random.seed(42)`). To reproduce these exact
findings:

```bash
cd 04-soc-siem-lab
python3 run_pipeline.py
```

This regenerates `data/auth.log`, rebuilds `data/siem.db`, and reprints both alerts
with the same timestamps, counts, and usernames shown above.
