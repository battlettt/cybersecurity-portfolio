# Project 9 — Cloud / IaC Misconfiguration Scanner

A Python static-analysis tool that scans Terraform (`.tf`) files for common
AWS misconfigurations — public S3 buckets, world-open SSH/RDP, over-broad
IAM policies, and unencrypted storage — before that infrastructure is ever
applied. Includes a deliberately vulnerable Terraform set and a fixed set
(same before/after pattern as [Project 1](../01-vulnerable-web-app/)),
5 rules, and a unit-tested parser.

## Resume bullet

> Built a Python static-analysis tool that parses Terraform IaC and flags
> AWS misconfigurations (public S3 ACLs, world-open SSH/RDP security
> groups, wildcard IAM admin policies, unencrypted RDS/EBS storage) across
> 5 rule checks; verified against a deliberately vulnerable Terraform set
> (7/7 findings correctly flagged) and a remediated set (0 false
> positives), with 9 passing unit tests covering the parser and rule logic.

## Why this project

The rest of this portfolio is on-prem: web app, SQL, network telemetry,
SOC/SIEM, endpoint automation. Nothing touches cloud infrastructure, which
is where a large share of real-world misconfiguration incidents actually
happen (public S3 buckets, permissive security groups, over-privileged IAM
roles). This project closes that gap the same way the rest of the
portfolio was built: something real, run against real fixtures, with
output actually captured — not a tool that's asserted to work.

## Honesty note: what this scanner actually is

This does **not** call the AWS API and does **not** need an AWS account —
it's pure static analysis over local `.tf` text, which means every result
below was fully reproducible without cloud credentials or cost.

The parser (`scanner/hcl_lite.py`) is intentionally scoped, and says so in
its own docstring: it handles `resource` blocks, flat attributes, one level
of nested unlabeled blocks (`ingress { }`, `versioning { }`), and heredoc
string assignments — not the full HCL grammar (no `for_each`, `dynamic`
blocks, modules, or interpolation functions). That's enough to correctly
parse every fixture in `vulnerable/` and `fixed/`, but pointing it at
arbitrary production Terraform would need a real parser (e.g.
`python-hcl2`) first. Same reasoning as Project 3's labeled-simulated
traffic data: state the boundary of what's real rather than let a reader
assume more than what was actually built.

The 5 checks are informally mapped to themes from the CIS AWS Foundations
Benchmark and the AWS Well-Architected Framework's Security Pillar (public
storage, world-open admin ports, over-broad IAM, unencrypted data at
rest). They're not claimed as certified/official CIS control mappings —
see `scanner/rules.py`'s module docstring.

## Rules

| Rule ID | Severity | Checks |
|---|---|---|
| `CLOUD-S3-PUBLIC-ACL` | HIGH | S3 bucket ACL is `public-read` or `public-read-write` |
| `CLOUD-S3-NO-VERSIONING` | LOW | S3 bucket has no versioning block, or versioning explicitly disabled |
| `CLOUD-SG-OPEN-ADMIN-PORT` | HIGH | Security group allows SSH (22) or RDP (3389) from `0.0.0.0/0` |
| `CLOUD-IAM-WILDCARD-ADMIN` | HIGH | IAM policy statement allows `Action: "*"` on `Resource: "*"` |
| `CLOUD-STORAGE-UNENCRYPTED` | MEDIUM | RDS instance or EBS volume has encryption disabled |

## Real captured output

Run against `vulnerable/` — all 5 resources across 4 files correctly
flagged (7 findings, since the security group has two separate open admin
ports and the storage rule fires once per resource):

```
$ python3 run_scan.py vulnerable
Scanned 5 resource(s) in vulnerable/
------------------------------------------------------------
[HIGH] CLOUD-IAM-WILDCARD-ADMIN — aws_iam_policy.deploy_bot
[HIGH] CLOUD-S3-PUBLIC-ACL — aws_s3_bucket.reports
[HIGH] CLOUD-SG-OPEN-ADMIN-PORT — aws_security_group.web (SSH)
[HIGH] CLOUD-SG-OPEN-ADMIN-PORT — aws_security_group.web (RDP)
[MEDIUM] CLOUD-STORAGE-UNENCRYPTED — aws_db_instance.prod
[MEDIUM] CLOUD-STORAGE-UNENCRYPTED — aws_ebs_volume.app_data
[LOW] CLOUD-S3-NO-VERSIONING — aws_s3_bucket.reports
------------------------------------------------------------
7 finding(s): 4 HIGH, 2 MEDIUM, 1 LOW
```

Run against `fixed/` — same 5 resources, remediated, zero findings:

```
$ python3 run_scan.py fixed
Scanned 5 resource(s) in fixed/
------------------------------------------------------------
No findings. 0 misconfigurations detected.
```

Full output captured in [`reports/scan_vulnerable.txt`](reports/scan_vulnerable.txt)
and [`reports/scan_fixed.txt`](reports/scan_fixed.txt). Exit code is `1`
when findings exist and `0` on a clean scan, so it's CI-gateable as-is.

## Tests

9 unit tests covering the parser (flat attrs, repeated nested blocks,
heredoc-with-embedded-braces) and the rules (each vulnerable fixture
flagged, the fixed set clean, plus edge cases like `public-read-write`
and a correctly-scoped IAM policy that should *not* fire). Real run
captured in [`reports/test_output.txt`](reports/test_output.txt):

```
$ python3 -m unittest discover -s tests -v
...
Ran 9 tests in 0.002s

OK
```

## Running it yourself

Pure Python 3 standard library — no installs required.

```bash
cd 09-cloud-iac-security-scanner
python3 run_scan.py vulnerable   # exit code 1, 7 findings
python3 run_scan.py fixed        # exit code 0, clean
python3 -m unittest discover -s tests -v
```

## Files

- `scanner/hcl_lite.py` — the scoped Terraform parser
- `scanner/rules.py` — the 5 misconfiguration checks
- `run_scan.py` — CLI entry point
- `vulnerable/` / `fixed/` — before/after Terraform fixtures (S3, security
  group, IAM policy, RDS + EBS)
- `tests/test_scanner.py` — unit tests
- `reports/` — real captured output from both the scanner and the test run
