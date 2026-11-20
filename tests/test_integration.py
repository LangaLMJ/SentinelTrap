
import json
import tempfile
import unittest
from pathlib import Path
from sys import path

# Allow imports from src/
path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentineltrap.collector import (
    read_events,
    group_events_by_session,
)
from sentineltrap.database import insert_events, get_events
from sentineltrap.analyzer import summarize_events, analyze_sessions


class TestIntegration(unittest.TestCase):

    def test_complete_event_pipeline(self):
        """Verify collection, storage, retrieval, and analysis."""

        # Fictional SSH events used only for testing
        sample_events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "test123",
                "src_ip": "192.0.2.10",
                "timestamp": "2026-11-01T10:00:00Z",
            },
            {
                "eventid": "cowrie.login.success",
                "session": "test123",
                "src_ip": "192.0.2.10",
                "username": "root",
                "password": "fictional-password",
                "timestamp": "2026-11-01T10:00:10Z",
            },
            {
                "eventid": "cowrie.command.input",
                "session": "test123",
                "input": "whoami",
                "timestamp": "2026-11-01T10:00:20Z",
            },
            {
                "eventid": "cowrie.session.closed",
                "session": "test123",
                "timestamp": "2026-11-01T10:01:00Z",
            },
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "cowrie.jsonl"
            db_path = str(Path(temp_dir) / "test.db")

            # Step 1: Create a temporary JSONL log
            with log_path.open("w", encoding="utf-8") as file:
                for event in sample_events:
                    file.write(json.dumps(event) + "\n")

            # Step 2: Collect security events
            collected_events = read_events(str(log_path))

            self.assertEqual(len(collected_events), 4)

            # Step 3: Store events in SQLite
            inserted_count = insert_events(collected_events, db_path)

            self.assertEqual(inserted_count, 4)

            # Step 4: Retrieve stored events
            stored_events = get_events(db_path)

            self.assertEqual(len(stored_events), 4)

            # Verify that passwords were not stored
            for event in stored_events:
                self.assertNotIn("password", event)

            # Step 5: Analyse overall security activity
            summary = summarize_events(stored_events)

            self.assertEqual(summary["total_events"], 4)
            self.assertEqual(summary["total_sessions"], 1)
            self.assertEqual(summary["ssh_connections"], 1)
            self.assertEqual(summary["successful_logins"], 1)
            self.assertEqual(summary["commands_entered"], 1)

            # Step 6: Group and analyse individual sessions
            sessions = group_events_by_session(stored_events)
            reports = analyze_sessions(sessions)

            self.assertIn("test123", reports)

            report = reports["test123"]

            self.assertEqual(report["total_events"], 4)
            self.assertEqual(report["successful_logins"], 1)
            self.assertEqual(report["commands"], ["whoami"])
            self.assertEqual(report["duration_seconds"], 60.0)

            # Step 7: Verify duplicate prevention
            second_insert = insert_events(collected_events, db_path)

            self.assertEqual(second_insert, 0)
            self.assertEqual(len(get_events(db_path)), 4)


if __name__ == "__main__":
    unittest.main()
