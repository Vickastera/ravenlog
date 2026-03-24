import unittest
from unittest.mock import patch

from app import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch("app.get_all_events")
    def test_api_events_returns_all_events(self, mock_get_all_events):
        mock_get_all_events.return_value = [
            (1, "2026-03-15 10:03:45", "WARNING", "185.23.44.12", "failed_login", "Multiple failed login attempt detected")
        ]

        response = self.client.get("/api/events")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["event_type"], "failed_login")
        self.assertEqual(data[0]["source_ip"], "185.23.44.12")

    @patch("app.search_events")
    def test_api_events_search_query(self, mock_search_events):
        mock_search_events.return_value = [
            (2, "2026-03-15 10:04:01", "ERROR", "45.77.12.99", "admin_probe", "Unauthorized access attempt to /admin")
        ]

        response = self.client.get("/api/events?q=admin")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["event_type"], "admin_probe")
        self.assertEqual(data[0]["source_ip"], "45.77.12.99")


if __name__ == "__main__":
    unittest.main()
