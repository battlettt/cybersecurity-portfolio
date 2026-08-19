import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from password_policy_auditor import audit_password, has_sequential_run, has_repeated_run


class TestPasswordAuditor(unittest.TestCase):
    def test_common_password_fails(self):
        r = audit_password('password')
        self.assertFalse(r['policy_pass'])
        self.assertIn('found in common-password list', r['issues'])

    def test_short_password_flagged(self):
        r = audit_password('Ab1!')
        self.assertIn('too short (4 chars, minimum 12)', r['issues'])

    def test_strong_password_passes(self):
        r = audit_password('7hI$IsAG3nu1n3lyStr0ngP@ss!')
        self.assertTrue(r['policy_pass'], r['issues'])
        self.assertGreater(r['entropy_bits'], 80)

    def test_sequential_run_detected(self):
        self.assertTrue(has_sequential_run('myPass1234word'))
        self.assertFalse(has_sequential_run('myP@ss9137word'))

    def test_repeated_run_detected(self):
        self.assertTrue(has_repeated_run('aaaaBBBB1111'))
        self.assertFalse(has_repeated_run('abABcdCD1234'))

    def test_entropy_increases_with_charset_diversity(self):
        r_lower = audit_password('abcdefghijkl')
        r_mixed = audit_password('abcDEF123!@#')
        self.assertGreater(r_mixed['entropy_bits'], r_lower['entropy_bits'])


if __name__ == '__main__':
    unittest.main()
