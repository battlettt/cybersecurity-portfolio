# Resume Bullets

Ready-to-paste lines for each project. Pick 2-4 that fit the role you're applying to —
don't dump all 9, that reads as unfocused. A good default split:

- **Applying to a SOC/Blue Team-leaning role:** lead with #4, #8, #5, #3
- **Applying to AppSec/Security Engineer:** lead with #1, #2, #5
- **Applying to Cloud Security/DevSecOps-leaning role:** lead with #9, #1, #5
- **Applying to GRC/Risk-leaning role:** lead with #6, #1 (for technical credibility), #9
- **General "cybersecurity" entry-level application:** #1, #4 or #8, #6 — one of each lane

Each bullet below is written from real, verified project output — not aspirational. Adjust
numbers/specifics only if you change the underlying project.

---

### Project 1 — Vulnerable-to-Secure Web App
> Built and exploited a full-stack React/Node/MySQL application demonstrating 4 OWASP Top 10
> vulnerabilities (SQL injection, stored XSS, broken authentication, broken access control),
> then remediated each with parameterized queries, output sanitization, bcrypt password
> hashing, and JWT-based authorization — documenting the full attack-and-fix lifecycle with
> live exploit scripts and screenshots.

### Project 2 — SQL Injection Deep Dive
> Demonstrated and remediated classic, UNION-based, and blind SQL injection against a live
> MySQL-backed Node.js application using automated Python exploit scripts; root-caused the
> flaw to string-concatenated queries and secured it with parameterized queries, verifying
> all three attack types failed post-fix.

### Project 3 — Network Traffic Anomaly Detector
> Developed a Python-based network anomaly detector applying statistical hypothesis testing
> (z-score baseline deviation across Poisson- and Normal-fitted traffic features) to
> identify port-scan and data-exfiltration patterns, achieving 100% recall / 80% precision
> (2.8% false positive rate, F1 = 0.889) on a labeled synthetic dataset (500 one-second
> windows, held-out evaluation).

### Project 4 — Home SOC / SIEM Lab
> Built a home SOC lab with a Python-based log ingestion pipeline and rule-based SIEM
> alerting engine (SQLite + sliding time-window detection) processing 190K+ logs/sec
> with a sub-20-second detection threshold on simulated SSH brute-force and port-scan
> attacks; verified end-to-end via a live Flask dashboard, with a full incident report
> grounded in the actual pipeline output.
>
> Live demo: cybersecurity-portfolio-siem-dashboard.onrender.com — this is the one worth
> pasting a link to directly in an application, not just describing.

### Project 5 — Security Automation Scripts
> Wrote Python security automation tools — an SSH auth-log brute-force detector using a
> sliding-window algorithm, and a password-policy auditor estimating offline crack time
> across three threat models (fast hash, bcrypt, rate-limited login) — with unit tests
> covering the core detection algorithms.

### Project 6 — GRC Risk Assessment (NIST CSF)
> Authored a NIST CSF-aligned cybersecurity risk assessment for a simulated mid-size
> organization: a 12-asset inventory, a 10-item risk register scoring both inherent and
> residual risk, and a full security policy framework mapped to all five NIST CSF functions
> (Identify, Protect, Detect, Respond, Recover), each control traced to a specific
> identified risk.

### Project 7 — CTF Write-Up Blog
*(Use once you have 3+ real write-ups published — the scaffold alone isn't a resume line yet.)*
> Maintain a public technical blog documenting methodology for completed TryHackMe,
> HackTheBox, and OverTheWire challenges — [N] write-ups published, covering [topics].

### Project 8 — Capstone: Detection & Response
> Simulated and detected a multi-stage attack chain (initial access → lateral movement →
> exfiltration) against a home-built SIEM pipeline, mapped to MITRE ATT&CK (T1110, T1078,
> T1021.004, T1041) with correlation logic tying all three stages to one identity, producing
> a full incident response report with timeline, root cause, and remediation
> recommendations — all verified against a real, reproducible pipeline run.

### Project 9 — Cloud / IaC Misconfiguration Scanner
> Built a Python static-analysis tool that parses Terraform IaC and flags AWS
> misconfigurations (public S3 ACLs, world-open SSH/RDP security groups, wildcard IAM admin
> policies, unencrypted RDS/EBS storage) across 5 rule checks; verified against a
> deliberately vulnerable Terraform set (7/7 findings correctly flagged) and a remediated
> set (0 false positives), with 9 passing unit tests covering the parser and rule logic.

---

## LinkedIn "Featured" section

Link the GitHub repo itself, plus the Project 1 README specifically (it has the most visual
proof — screenshots of live exploits and fixes) and, once published, the CTF write-up blog.

## A note on honesty

Project 7's blog ships with one clearly-labeled **template** post (OverTheWire Bandit
0-2), not a real completed write-up — it exists to show the format, not to claim work that
wasn't done. Replace it with your own write-up before linking that blog anywhere, and don't
use its resume bullet until you actually have real entries. Everything else in this
portfolio — every exploit, every test, every statistical result — was actually run and its
real output captured; that's worth preserving as you extend this, because it's the reason
the whole portfolio survives a "walk me through how this works" follow-up question.
