# Cybersecurity Portfolio

Nine hands-on projects built to accompany a Management Engineering → Cybersecurity career
transition — moving from zero security-specific background to a portfolio that demonstrates
applied skill across offensive security (AppSec, SQLi, XSS), defensive security (SIEM,
detection engineering, incident response), data-driven security (statistical anomaly
detection), cloud security (IaC misconfiguration scanning), and GRC (risk assessment, NIST
CSF policy).

**Every exploit, detection, and statistical claim in this portfolio was actually executed
and verified — not written and assumed to work.** Where a claim is simulated rather than
captured from a live environment (e.g., network traffic, since raw packet capture needs
root), that's stated explicitly in the relevant README rather than glossed over.

**[Read the in-depth technical walkthrough →](https://battlettt.github.io/cybersecurity-portfolio/deep-dive.html)** — how each project's
mechanism actually works, the real captured evidence, and the specific judgment calls worth
being able to defend in an interview, for all 9 projects on one page.

## Projects

| # | Project | What it demonstrates | Link |
|---|---|---|---|
| 1 | **Vulnerable-to-Secure Web App** (flagship) | Full-stack AppSec: found *and fixed* 4 OWASP Top 10 vulnerabilities in a live React/Node/MySQL app, with screenshot proof of each exploit and each fix | [`01-vulnerable-web-app/`](01-vulnerable-web-app/) |
| 2 | **SQL Injection Deep Dive** | Classic, UNION-based, and blind SQLi against a live MySQL app, via automated Python exploit scripts | [`02-sql-injection-lab/`](02-sql-injection-lab/) |
| 3 | **Network Anomaly Detector** | Statistics applied to security: Poisson/Normal baseline fitting + hypothesis testing to flag port scans and exfiltration, with measured recall/false-positive rate | [`03-network-anomaly-detector/`](03-network-anomaly-detector/) |
| 4 | **Home SOC / SIEM Lab** | Blue team: log ingestion, sliding-window detection rules, a live alerting dashboard, and a real incident report | [`04-soc-siem-lab/`](04-soc-siem-lab/) |
| 5 | **Security Automation Scripts** | Practical tooling: an auth-log brute-force detector and a password-policy/crack-time auditor, both unit tested | [`05-security-automation-scripts/`](05-security-automation-scripts/) |
| 6 | **GRC Risk Assessment (NIST CSF)** | Business-facing security: a full risk register and policy framework for a fictional company, mapped to NIST CSF | [`06-grc-risk-assessment/`](06-grc-risk-assessment/) |
| 7 | **CTF Write-Up Blog** | A GitHub Pages-ready scaffold for documenting hands-on room/machine methodology as it accumulates | [`07-ctf-writeup-blog/`](07-ctf-writeup-blog/) |
| 8 | **Capstone: Detection & Response** | Ties it together: a multi-stage attack chain mapped to MITRE ATT&CK, detected end-to-end, with a full IR report | [`08-capstone-detection-response/`](08-capstone-detection-response/) |
| 9 | **Cloud / IaC Misconfiguration Scanner** | Static analysis over Terraform: 5 rules catching public S3, world-open admin ports, wildcard IAM, and unencrypted storage, unit tested and verified against a before/after fixture set | [`09-cloud-iac-security-scanner/`](09-cloud-iac-security-scanner/) |

## How these connect to a Waterloo Management Engineering background

- **Projects 1 & 2** reuse the same React/Node/MySQL stack from prior coursework — the
  point is "I already knew how to build this, so I went and broke it on purpose to learn
  the attacker's side."
- **Project 3** applies hypothesis testing and distribution fitting directly — the same
  statistical framework from MSCI 253/243, aimed at threat-hunting instead of a homework
  set.
- **Project 5**'s brute-force detector uses the identical sliding-window algorithm as
  Project 4's SIEM, just as a smaller standalone tool — showing the same technique at two
  different scales.
- **Project 6** is the one that leans hardest into the degree itself: a real GRC/risk
  deliverable, which is exactly the hybrid technical-plus-business profile that's in short
  supply in this field.
- **Project 8** is the "senior" piece that ties offense (attack simulation), defense
  (detection), and communication (the IR report) together in one narrative.
- **Project 9** rounds out the on-prem-only set with cloud/IaC — the one surface area
  (public cloud misconfiguration) that's absent from Projects 1-8 despite being where a
  large share of real-world incidents actually originate.

## What's actually verified vs. documented-only

Being specific about this matters more than it sounds — it's the difference between a
portfolio that survives a technical follow-up question and one that doesn't:

- **Fully executed and verified, with captured real output:** Projects 1, 2, 3, 5, 6, 9, and
  the Track A / primary path of Projects 4 and 8.
- **Simulated but explicitly labeled as such, because the sandbox this was built in has no
  root access for raw packet capture:** Project 3's traffic data (Scapy-constructed packet
  objects with genuine computed byte sizes, not live-captured).
- **Documentation-only (Track B), because this environment has no Docker available:** the
  ELK-stack `docker-compose.yml` configs in Projects 4 and (by extension) 8. The primary,
  verified detection path in both projects is a lightweight Python/SQLite/Flask pipeline
  that was actually run — Track B is the production-equivalent path for when Docker is
  available locally, clearly labeled as such in each README.

## Setup requirements by project

| Project | Requires |
|---|---|
| 1, 2 | Node.js, MySQL (or adjust to SQLite — see each README) |
| 3, 4, 5, 8 | Python 3.10+ (stdlib + `pip install -r requirements.txt` per project) |
| 6 | Node.js (only to regenerate the `.docx` — the document itself needs nothing) |
| 7 | Nothing locally — GitHub Pages builds it |
| 9 | Python 3.10+ (standard library only — no installs required) |

Each project's own README has exact run commands.

## Publishing this to GitHub

```bash
cd cybersecurity-portfolio
git add .
git commit -m "Cybersecurity portfolio: 8 projects, AppSec through GRC"
git remote add origin https://github.com/<you>/cybersecurity-portfolio.git
git push -u origin main
```

See [`RESUME_BULLETS.md`](RESUME_BULLETS.md) for ready-to-paste resume lines, and each
project's own README for the full write-up, real captured output, and screenshots.
