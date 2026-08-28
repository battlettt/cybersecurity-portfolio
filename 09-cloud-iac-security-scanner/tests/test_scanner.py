import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner.hcl_lite import parse_resources
from scanner.rules import scan_resources, check_s3_public_acl, check_iam_wildcard_admin

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..')


def load(directory):
    resources = []
    for name in sorted(os.listdir(os.path.join(FIXTURE_DIR, directory))):
        if not name.endswith('.tf'):
            continue
        with open(os.path.join(FIXTURE_DIR, directory, name)) as f:
            resources.extend(parse_resources(f.read()))
    return resources


class TestHclLiteParser(unittest.TestCase):
    def test_parses_flat_attrs(self):
        text = '''
        resource "aws_db_instance" "prod" {
          identifier        = "meridian-prod-db"
          storage_encrypted = false
        }
        '''
        resources = parse_resources(text)
        self.assertEqual(len(resources), 1)
        r = resources[0]
        self.assertEqual(r.type, 'aws_db_instance')
        self.assertEqual(r.name, 'prod')
        self.assertEqual(r.attrs['identifier'], 'meridian-prod-db')
        self.assertIs(r.attrs['storage_encrypted'], False)

    def test_parses_repeated_nested_blocks_and_lists(self):
        text = '''
        resource "aws_security_group" "web" {
          name = "web-sg"

          ingress {
            from_port   = 22
            to_port     = 22
            cidr_blocks = ["0.0.0.0/0"]
          }

          ingress {
            from_port   = 443
            to_port     = 443
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        '''
        r = parse_resources(text)[0]
        self.assertEqual(len(r.blocks['ingress']), 2)
        self.assertEqual(r.blocks['ingress'][0].attrs['from_port'], 22)
        self.assertEqual(r.blocks['ingress'][0].attrs['cidr_blocks'], ['0.0.0.0/0'])

    def test_parses_heredoc_without_breaking_on_embedded_braces(self):
        text = '''
        resource "aws_iam_policy" "bot" {
          name = "bot-policy"
          policy = <<POLICY
{
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
POLICY
        }
        '''
        r = parse_resources(text)[0]
        self.assertIn('"Action": "*"', r.attrs['policy'])
        self.assertIn('"Resource": "*"', r.attrs['policy'])


class TestRulesAgainstFixtures(unittest.TestCase):
    def test_vulnerable_fixtures_each_trigger_a_finding(self):
        resources = load('vulnerable')
        findings = scan_resources(resources)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn('CLOUD-S3-PUBLIC-ACL', rule_ids)
        self.assertIn('CLOUD-S3-NO-VERSIONING', rule_ids)
        self.assertIn('CLOUD-SG-OPEN-ADMIN-PORT', rule_ids)
        self.assertIn('CLOUD-IAM-WILDCARD-ADMIN', rule_ids)
        self.assertIn('CLOUD-STORAGE-UNENCRYPTED', rule_ids)
        # both SSH and RDP flagged separately on the same security group
        sg_findings = [f for f in findings if f.rule_id == 'CLOUD-SG-OPEN-ADMIN-PORT']
        self.assertEqual(len(sg_findings), 2)
        # both the RDS instance and the EBS volume flagged
        storage_findings = [f for f in findings if f.rule_id == 'CLOUD-STORAGE-UNENCRYPTED']
        self.assertEqual(len(storage_findings), 2)

    def test_fixed_fixtures_produce_zero_findings(self):
        resources = load('fixed')
        findings = scan_resources(resources)
        self.assertEqual(findings, [], f'Expected a clean scan, got: {findings}')

    def test_s3_public_read_write_is_also_flagged(self):
        text = '''
        resource "aws_s3_bucket" "x" {
          bucket = "test"
          acl    = "public-read-write"
          versioning { enabled = true }
        }
        '''
        r = parse_resources(text)[0]
        finding = check_s3_public_acl(r)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, 'HIGH')

    def test_private_acl_is_not_flagged(self):
        text = '''
        resource "aws_s3_bucket" "x" {
          bucket = "test"
          acl    = "private"
        }
        '''
        r = parse_resources(text)[0]
        self.assertIsNone(check_s3_public_acl(r))

    def test_scoped_iam_policy_is_not_flagged(self):
        text = '''
        resource "aws_iam_policy" "x" {
          name   = "scoped"
          policy = <<POLICY
{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}]}
POLICY
        }
        '''
        r = parse_resources(text)[0]
        self.assertIsNone(check_iam_wildcard_admin(r))

    def test_security_group_restricted_to_vpc_cidr_is_not_flagged(self):
        text = '''
        resource "aws_security_group" "x" {
          name = "sg"
          ingress {
            from_port   = 22
            to_port     = 22
            cidr_blocks = ["10.0.0.0/16"]
          }
        }
        '''
        resources = parse_resources(text)
        findings = scan_resources(resources)
        self.assertEqual(findings, [])


if __name__ == '__main__':
    unittest.main()
