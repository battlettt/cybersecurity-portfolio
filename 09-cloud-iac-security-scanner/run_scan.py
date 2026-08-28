#!/usr/bin/env python3
"""
run_scan.py — CLI entry point for the IaC scanner.

Usage:
    python3 run_scan.py <directory-of-.tf-files>

Exit code is 1 if any findings were reported, 0 if the directory is clean
(mirrors how real static-analysis tools signal CI pass/fail).
"""

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from scanner.hcl_lite import parse_resources
from scanner.rules import scan_resources


SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}


def scan_directory(directory):
    resources = []
    for path in sorted(glob.glob(os.path.join(directory, '*.tf'))):
        with open(path) as f:
            resources.extend(parse_resources(f.read()))
    return resources, scan_resources(resources)


def print_report(directory, resources, findings):
    print(f'Scanned {len(resources)} resource(s) in {directory}/')
    print('-' * 60)
    if not findings:
        print('No findings. 0 misconfigurations detected.')
        return
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for f in findings_sorted:
        print(f'[{f.severity}] {f.rule_id} — {f.resource}')
        print(f'  {f.title}')
        print(f'  {f.detail}')
        print()
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ', '.join(f'{v} {k}' for k, v in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))
    print('-' * 60)
    print(f'{len(findings)} finding(s): {summary}')


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 run_scan.py <directory-of-.tf-files>')
        sys.exit(2)
    directory = sys.argv[1]
    resources, findings = scan_directory(directory)
    print_report(directory, resources, findings)
    sys.exit(1 if findings else 0)


if __name__ == '__main__':
    main()
