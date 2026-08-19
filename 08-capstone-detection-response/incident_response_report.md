# Incident Response Report — IR-2026-0818-CHAIN01

| Field | Value |
|---|---|
| Report ID | IR-2026-0818-CHAIN01 |
| Classification | Confirmed compromise — multi-stage attack chain (simulated environment) |
| Prepared by | Incident Response (home-lab capstone, Tier 2/3 write-up) |
| Date prepared | 2026-08-18 |
| Detection pipeline | Project 4 SIEM (`detection_rules.py`) + capstone chain correlation (`attack_chain_detection.py`) |
| Data source | `data/attack_chain.log` (99 lines) → `data/attack_chain.db` |
| Alert IDs | `ALERT-BRUTE_FORCE_SSH-001` (Project 4 rule), `CHAIN-001` (capstone correlation) |
| Affected identity | `rpatel` (employee SSH account) |
| Affected hosts | `web01` (initial access), `app02`, `db01` (lateral movement + exfil source) |

## 1. Executive Summary

On 2026-08-18 between **07:39 and 07:52 UTC** (13.1 minutes), an external
actor at `203.0.113.50` compromised the employee SSH account `rpatel` on the
internet-facing host `web01` via a short, high-volume password-guessing
burst, then used those valid credentials to pivot laterally to two internal
hosts (`app02`, `db01`) and exfiltrate roughly **812 MB (≈775 MiB)** of data
from `db01` back to attacker-controlled infrastructure over port 443.

The pipeline's rule engine detected every stage automatically: Project 4's
existing `detect_brute_force()` rule fired on the initial burst
(`ALERT-BRUTE_FORCE_SSH-001`), and this capstone's chain-correlation logic
(`attack_chain_detection.detect_attack_chain()`) tied the burst, the
resulting successful login, the lateral movement, and the exfiltration
event together into a single correlated incident (`CHAIN-001`) — without
being told in advance which username, IP, or hosts were involved.

This is a simulated environment; the finding below documents what the
pipeline actually observed and flagged in its one and only run
(`random.seed(1337)`, fully reproducible via `python3 run_pipeline.py`).

## 2. Detailed Timeline (UTC, all timestamps from actual pipeline run)

| Time | Event | Evidence / Alert |
|---|---|---|
| 07:39:02.000 | First failed SSH login attempt from `203.0.113.50` against `web01`, username `oracle` | `data/attack_chain.log` line 1 of burst |
| 07:39:02 – 07:40:15 | 22 failed SSH login attempts from `203.0.113.50` against `web01`, cycling through common default usernames (`admin`, `root`, `test`, `guest`, `oracle`, `postgres`, `ubuntu`, `support`, `backup`, `deploy`, `user`) interspersed 3 times with `rpatel` — a real employee account | `ALERT-BRUTE_FORCE_SSH-001`: 22 events, threshold 8/5min |
| 07:40:15.372 | Final failed attempt in the burst, username `rpatel` | last pre-success failure |
| **07:40:33.590** | **`Accepted password for rpatel from 203.0.113.50 port 64279 ssh2`** on `web01` — 18 seconds after the burst ended | `CHAIN-001` stage 1 (T1110 → T1078) |
| 07:45:32.285 | `Accepted password for rpatel from 10.0.0.10 port 51572 ssh2` on `app02` — login originates from `web01`'s own internal IP (`10.0.0.10`), i.e. the attacker pivoting *from* the host they just compromised | `CHAIN-001` stage 2 (T1021.004) |
| 07:47:48.518 | `Accepted password for rpatel from 10.0.0.10 port 53613 ssh2` on `db01` — second internal pivot, same jump-host IP | `CHAIN-001` stage 2 (T1021.004) |
| **07:52:10.424** | `netflow` record: **812,345,120 bytes (812.3 MB)** transferred from `db01` (`10.0.0.12`) to `203.0.113.50:443` over 46 seconds | `CHAIN-001` stage 3 (T1041) |

**Total dwell time observed: 13.1 minutes** from first failed login to
completed exfiltration — consistent with an automated or well-rehearsed
attack chain rather than manual, exploratory activity.

## 3. MITRE ATT&CK Mapping

| Stage | Technique ID | Technique Name | Tactic | Evidence Observed |
|---|---|---|---|---|
| 1a | **T1110** | Brute Force | Credential Access | 22 failed SSH logins from `203.0.113.50` to `web01` in 73 seconds (`ALERT-BRUTE_FORCE_SSH-001`) |
| 1b | **T1078** | Valid Accounts | Initial Access | Successful login as `rpatel` from `203.0.113.50` at 07:40:33.590, 18s after the burst — same account was among the failed attempts |
| 2 | **T1021.004** | Remote Services: SSH | Lateral Movement | Two subsequent successful SSH logins as `rpatel`, sourced from `web01`'s internal IP (`10.0.0.10`), reaching `app02` (07:45:32) and `db01` (07:47:48) |
| 3 | **T1041** | Exfiltration Over C2 Channel | Exfiltration | 812.3 MB outbound transfer from `db01` to `203.0.113.50` on port 443 at 07:52:10, exceeding the 100 MB volumetric detection threshold |

*Mapping note:* T1078 (Valid Accounts) is scoped here to its **Initial
Access** use — the same technique ID also covers Persistence, Privilege
Escalation, and Defense Evasion in the ATT&CK matrix, but only the
initial-access use is evidenced by this data (there is no evidence of
persistence mechanisms being installed). T1021 has several sub-techniques
per remote-service protocol; `.004` (SSH) is used because every lateral
hop in this log is an SSH `Accepted password` event. Port 443 for the
exfiltration channel was chosen deliberately in the simulation to model
blending-in with routine HTTPS egress, which is the premise behind
classifying it as T1041 (C2-channel exfiltration) rather than a bespoke
exfiltration protocol.

## 4. Detection Coverage

| Alert | Rule | Source | What it caught |
|---|---|---|---|
| `ALERT-BRUTE_FORCE_SSH-001` | `detection_rules.detect_brute_force` | Project 4 (reused unmodified) | Stage 1a burst |
| `CHAIN-001` | `attack_chain_detection.detect_attack_chain` | Capstone (this project) | Full chain: confirms stage 1b via `detect_successful_brute_force`, stage 2 via `detect_lateral_movement`, stage 3 via `detect_exfiltration`, then correlates all three for one identity in causal order |

`CHAIN-001` only fires when all three sub-detections tie together **for the
same account, in the correct order, within the configured windows** —
i.e. it is not simply "OR-ing" independent alerts together. Full detail on
each sub-rule's threshold and justification is in
`attack_chain_detection.py`.

## 5. Root Cause

1. **Password authentication was enabled on an internet-facing SSH
   service** (`web01`), making brute-force attacks against it possible at
   all.
2. **The compromised account's username was guessable/known** to the
   attacker (the simulation models this as OSINT/breach-list knowledge —
   `rpatel` was interspersed with generic default-account guesses rather
   than appearing only in a targeted list, suggesting the attacker treated
   it as one entry among many, consistent with a credential-stuffing list
   that happened to include a leaked or guessed real username).
3. **No account lockout or adaptive rate-limiting was in effect** — 22
   attempts in 73 seconds were not throttled or blocked at the host or
   network layer before the correct password was found.
4. **Flat internal network trust** — once `rpatel`'s credentials were valid
   on `web01`, the same credentials worked unchallenged via SSH on `app02`
   and `db01`, with no additional authentication factor, network
   segmentation, or anomaly-based step-up challenge for lateral,
   host-to-host authentication.
5. **No egress data-volume controls** — a 775 MiB transfer from the
   database host to an unrecognized external IP over port 443 was not
   blocked, rate-limited, or flagged by any preventive control (only
   detected after the fact by this pipeline's volumetric rule).

## 6. Containment & Remediation Recommendations

**Immediate (containment):**
1. Disable/reset the `rpatel` account credentials and force re-authentication with MFA.
2. Block `203.0.113.50` at the network perimeter.
3. Isolate `web01`, `app02`, and `db01` from further outbound connections pending forensic review; treat all three as potentially compromised, not just the initial-access host.
4. Review `db01` for what data was actually accessible/exfiltrated in the 812 MB transfer and follow data-breach notification procedures if it contained regulated data.

**Short-term (remediation):**
5. Disable SSH password authentication in favor of key-based auth + MFA on all internet-facing hosts, starting with `web01`.
6. Deploy account lockout / fail2ban-style throttling so a burst like the one observed here is blocked automatically, not just detected.
7. Segment the internal network so that a credential valid on the internet-facing tier is not automatically valid on internal application and database tiers (e.g., separate credential scopes, bastion-only access to `db01`, or a PAM/jump-host solution with its own MFA).
8. Add egress volumetric alerting/DLP on database hosts specifically — `db01` should rarely if ever originate a several-hundred-MB outbound transfer to an unrecognized destination.

**Longer-term (program-level):**
9. Formalize this detection pipeline's rules (Project 4 + this capstone) as production alert definitions (see Project 4's `PRODUCTION_SETUP.md` for the ELK-equivalent implementation) so this class of chain is caught and auto-triaged going forward, not just reproduced in a lab.
10. Periodically audit which employee usernames/emails are discoverable via OSINT and rotate/monitor those accounts with extra scrutiny.

## 7. Lessons Learned

- **Chained, low-and-slow-looking activity can still complete in minutes.**
  This entire chain — initial compromise through exfiltration — took 13.1
  minutes. Detections that only look at single-stage volume (e.g., "was
  there a brute force?") would have caught stage 1 but not confirmed
  impact; the value of this capstone was specifically building the
  **correlation** layer that ties stages together into one incident with a
  concrete blast-radius (`app02`, `db01` compromised; 812 MB exfiltrated),
  rather than three disconnected low-context alerts.
- **Reusing Project 4's detection code instead of rewriting it** confirmed
  the original rules generalize: `detect_brute_force()` fired correctly
  against a completely different dataset (different seed, different
  usernames, different IP) with no changes required, which is exactly the
  property a production detection rule needs.
- **Identity-scoped correlation (stage 2) is a different detection pattern
  from volume-scoped correlation (stage 1 and stage 3)** — lateral movement
  detection here deliberately does not use a sliding-window volume
  threshold; it uses "this specific account, already known compromised,
  logging into unexpected additional hosts." Building both patterns in one
  project demonstrates they are not interchangeable.
- **A single volumetric threshold is a blunt instrument** for exfiltration
  detection — 100 MB was appropriate for this lab's baseline (which
  generates no large transfers at all), but a real deployment needs this
  threshold calibrated against actual legitimate large-transfer traffic
  (backups, replication, batch exports) or it will either miss slow/smaller
  exfiltration or drown analysts in false positives from routine transfers.

## 8. Reproducibility

```bash
cd 08-capstone-detection-response
python3 run_pipeline.py
```

`attack_chain_simulation.py` seeds its RNG (`random.seed(1337)`)
independently of Project 4's generator, so this reproduces the exact
timestamps, byte counts, and alert IDs cited throughout this report. Raw
ground-truth values are also written to `data/ground_truth_evidence.json`
on every run for cross-checking.
