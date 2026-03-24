import os
import tempfile
import unittest

import database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db_name = database.DB_NAME
        database.DB_NAME = os.path.join(self.tmp.name, "test_events.db")
        database.init_db()

    def tearDown(self):
        database.DB_NAME = self.old_db_name
        self.tmp.cleanup()

    def test_save_and_query_event(self):
        database.save_event(
            timestamp="2026-03-15 10:03:45",
            severity="WARNING",
            source_ip="185.23.44.12",
            event_type="failed_login",
            message="Multiple failed login attempts detected",
            fingerprint="abc123",
        )
        events = database.get_all_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][3], "185.23.44.12")

    def test_deduplicates_by_fingerprint(self):
        payload = {
            "timestamp": "2026-03-15 10:03:45",
            "severity": "WARNING",
            "source_ip": "185.23.44.12",
            "event_type": "failed_login",
            "message": "Multiple failed login attempts detected",
            "fingerprint": "same-hash",
        }
        database.save_event(**payload)
        database.save_event(**payload)
        self.assertEqual(len(database.get_all_events()), 1)


if __name__ == "__main__":
    unittest.main()
