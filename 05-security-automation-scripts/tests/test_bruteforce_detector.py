import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from log_bruteforce_detector import detect_bruteforce, parse_log


class TestBruteforceDetector(unittest.TestCase):
    def test_flags_burst_from_one_ip(self):
        base = datetime(2026, 1, 1, 12, 0, 0)
        events = [(base + timedelta(seconds=i * 2), 'root', '203.0.113.9') for i in range(6)]
        alerts = detect_bruteforce(events, window_seconds=300, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['source_ip'], '203.0.113.9')
        self.assertEqual(alerts[0]['max_attempts_in_window'], 6)

    def test_does_not_flag_spread_out_failures(self):
        base = datetime(2026, 1, 1, 12, 0, 0)
        # 6 failures but 1 hour apart each -> never more than 1 in a 5-min window
        events = [(base + timedelta(hours=i), 'root', '203.0.113.9') for i in range(6)]
        alerts = detect_bruteforce(events, window_seconds=300, threshold=5)
        self.assertEqual(alerts, [])

    def test_two_ips_only_one_over_threshold(self):
        base = datetime(2026, 1, 1, 12, 0, 0)
        events = [(base + timedelta(seconds=i * 2), 'root', '203.0.113.9') for i in range(6)]
        events += [(base + timedelta(seconds=i * 2), 'alice', '198.51.100.23') for i in range(2)]
        alerts = detect_bruteforce(events, window_seconds=300, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['source_ip'], '203.0.113.9')

    def test_parses_real_log_format(self):
        events = list(parse_log(os.path.join(os.path.dirname(__file__), '..', 'sample_data', 'auth.log')))
        # 11 "Failed password" lines in the sample log (Accepted lines are correctly ignored)
        self.assertEqual(len(events), 11)
        ips = {ip for _, _, ip in events}
        self.assertIn('203.0.113.9', ips)


if __name__ == '__main__':
    unittest.main()
