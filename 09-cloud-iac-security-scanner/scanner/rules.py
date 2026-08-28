"""
rules.py — misconfiguration checks, informally mapped to themes from the
CIS AWS Foundations Benchmark and the AWS Well-Architected Framework
(Security Pillar).

"Informally mapped" is deliberate wording: this scanner checks the same
underlying issues those frameworks call out (public storage, world-open
admin ports, over-broad IAM, unencrypted data at rest), but it is a
teaching/portfolio tool, not a certified compliance product, and it does
not cite specific numbered CIS control IDs since correctness of exact
section numbering isn't independently verified here.
"""

import re
from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    severity: str  # HIGH, MEDIUM, LOW
    resource: str
    title: str
    detail: str


def check_s3_public_acl(resource):
    if resource.type != 'aws_s3_bucket':
        return None
    acl = resource.attrs.get('acl')
    if acl in ('public-read', 'public-read-write'):
        return Finding(
            rule_id='CLOUD-S3-PUBLIC-ACL',
            severity='HIGH',
            resource=resource.address,
            title='S3 bucket ACL grants public access',
            detail=f'acl = "{acl}" allows anyone on the internet to read'
                   + (' and write to' if acl == 'public-read-write' else '')
                   + ' this bucket. Use "private" and front any public content with signed URLs or CloudFront.',
        )
    return None


def check_s3_versioning(resource):
    if resource.type != 'aws_s3_bucket':
        return None
    versioning_blocks = resource.blocks.get('versioning', [])
    if not versioning_blocks:
        return Finding(
            rule_id='CLOUD-S3-NO-VERSIONING',
            severity='LOW',
            resource=resource.address,
            title='S3 bucket has no versioning block',
            detail='No versioning configuration found; defaults to disabled, so an overwrite '
                   'or accidental delete is unrecoverable. Add a versioning block with enabled = true.',
        )
    enabled = versioning_blocks[0].attrs.get('enabled')
    if enabled is False:
        return Finding(
            rule_id='CLOUD-S3-NO-VERSIONING',
            severity='LOW',
            resource=resource.address,
            title='S3 bucket versioning explicitly disabled',
            detail='versioning.enabled = false — an overwrite or accidental delete is unrecoverable.',
        )
    return None


_ADMIN_PORTS = {22: 'SSH', 3389: 'RDP'}


def check_security_group_open_admin_ports(resource):
    if resource.type != 'aws_security_group':
        return None
    findings = []
    for ingress in resource.blocks.get('ingress', []):
        attrs = ingress.attrs
        cidrs = attrs.get('cidr_blocks', [])
        try:
            from_port = int(attrs.get('from_port'))
            to_port = int(attrs.get('to_port'))
        except (TypeError, ValueError):
            continue
        if '0.0.0.0/0' not in cidrs:
            continue
        for port, label in _ADMIN_PORTS.items():
            if from_port <= port <= to_port:
                findings.append(Finding(
                    rule_id='CLOUD-SG-OPEN-ADMIN-PORT',
                    severity='HIGH',
                    resource=resource.address,
                    title=f'{label} port open to the entire internet',
                    detail=f'ingress allows {label} (port {port}) from cidr_blocks = ["0.0.0.0/0"]. '
                           f'Restrict to a specific CIDR (VPN/bastion range) instead.',
                ))
    return findings or None


def check_iam_wildcard_admin(resource):
    if resource.type != 'aws_iam_policy':
        return None
    policy_text = resource.attrs.get('policy', '')
    if not isinstance(policy_text, str):
        return None
    has_wildcard_action = re.search(r'"Action"\s*:\s*"\*"', policy_text) is not None
    has_wildcard_resource = re.search(r'"Resource"\s*:\s*"\*"', policy_text) is not None
    if has_wildcard_action and has_wildcard_resource:
        return Finding(
            rule_id='CLOUD-IAM-WILDCARD-ADMIN',
            severity='HIGH',
            resource=resource.address,
            title='IAM policy grants full admin access ("*" on "*")',
            detail='Statement allows Action "*" on Resource "*" — equivalent to AdministratorAccess. '
                   'Scope to the specific actions and resource ARNs the role actually needs.',
        )
    return None


def check_unencrypted_storage(resource):
    if resource.type == 'aws_db_instance' and resource.attrs.get('storage_encrypted') is False:
        return Finding(
            rule_id='CLOUD-STORAGE-UNENCRYPTED',
            severity='MEDIUM',
            resource=resource.address,
            title='RDS instance storage is not encrypted at rest',
            detail='storage_encrypted = false. Set to true (requires a new instance if retrofitting).',
        )
    if resource.type == 'aws_ebs_volume' and resource.attrs.get('encrypted') is False:
        return Finding(
            rule_id='CLOUD-STORAGE-UNENCRYPTED',
            severity='MEDIUM',
            resource=resource.address,
            title='EBS volume is not encrypted at rest',
            detail='encrypted = false. Set to true; existing volumes need a snapshot-and-recreate to retrofit.',
        )
    return None


ALL_CHECKS = [
    check_s3_public_acl,
    check_s3_versioning,
    check_security_group_open_admin_ports,
    check_iam_wildcard_admin,
    check_unencrypted_storage,
]


def scan_resources(resources):
    findings = []
    for resource in resources:
        for check in ALL_CHECKS:
            result = check(resource)
            if result is None:
                continue
            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)
    return findings
