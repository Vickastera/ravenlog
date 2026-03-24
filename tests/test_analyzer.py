import unittest

from analyzer import analyze_line


class AnalyzerTests(unittest.TestCase):
    def test_failed_login_detection(self):
        line = "2026-03-15 10:03:45 WARNING Failed login from 185.23.44.12"
        event = analyze_line(line)
        self.assertEqual(event["event_type"], "failed_login")
        self.assertEqual(event["source_ip"], "185.23.44.12")

    def test_admin_probe_detection(self):
        line = "2026-03-15 10:04:01 ERROR Unauthorized access attempt to /admin from 45.77.12.99"
        event = analyze_line(line)
        self.assertEqual(event["event_type"], "admin_probe")
        self.assertEqual(event["source_ip"], "45.77.12.99")

    def test_non_suspicious_line(self):
        line = "2026-03-15 10:06:12 INFO Request to /home from 192.168.1.11"
        self.assertIsNone(analyze_line(line))


if __name__ == "__main__":
    unittest.main()
