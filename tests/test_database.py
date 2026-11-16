
import sqlite3
import tempfile
import unittest
from pathlib import Path
from sys import path

# Allow imports from src/
path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sentineltrap.database import (
    initialize_database,
    insert_events,
    get_events,
    get_events_by_session,
)


class TestDatabase(unittest.TestCase):

    def test_database_initialization(self):
        """Verify that initializing the database creates the events table."""

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            initialize_database(str(db_path))

            self.assertTrue(db_path.exists())

            with sqlite3.connect(db_path) as connection:
                result = connection.execute("""
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    AND name = 'security_events'
                """).fetchone()

            self.assertIsNotNone(result)

    def test_database_initialization_twice(self):
        """Verify that database initialization is repeatable."""

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"

            initialize_database(str(db_path))
            initialize_database(str(db_path))

            self.assertTrue(db_path.exists())

    def test_insert_events(self):
        """Verify that valid security events are stored."""

        events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "abc123",
                "src_ip": "192.0.2.10",
                "timestamp": "2026-11-01T10:00:00Z"
            },
            {
                "eventid": "cowrie.login.success",
                "session": "abc123",
                "username": "root",
                "password": "fake-test-password"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "test.db")

            inserted = insert_events(events, db_path)

            self.assertEqual(inserted, 2)

            with sqlite3.connect(db_path) as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0]

                raw_events = connection.execute(
                    "SELECT raw_event FROM security_events"
                ).fetchall()

            self.assertEqual(count, 2)

            for row in raw_events:
                self.assertNotIn("fake-test-password", row[0])

    def test_prevent_duplicate_events(self):
        """Verify that repeated imports do not duplicate events."""

        events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "abc123",
                "timestamp": "2026-11-01T10:00:00Z"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "test.db")

            first_insert = insert_events(events, db_path)
            second_insert = insert_events(events, db_path)

            self.assertEqual(first_insert, 1)
            self.assertEqual(second_insert, 0)

            with sqlite3.connect(db_path) as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0]

            self.assertEqual(count, 1)

    def test_get_events(self):
        """Verify that stored security events can be retrieved."""

        events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "abc123",
                "src_ip": "192.0.2.10"
            },
            {
                "eventid": "cowrie.login.success",
                "session": "abc123"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "test.db")

            insert_events(events, db_path)
            stored_events = get_events(db_path)

            self.assertEqual(len(stored_events), 2)
            self.assertEqual(
                stored_events[0]["eventid"],
                "cowrie.session.connect"
            )
            self.assertEqual(
                stored_events[1]["eventid"],
                "cowrie.login.success"
            )

    def test_get_events_by_session(self):
        """Verify that retrieval returns only the requested SSH session."""

        events = [
            {
                "eventid": "cowrie.session.connect",
                "session": "abc123"
            },
            {
                "eventid": "cowrie.login.success",
                "session": "abc123"
            },
            {
                "eventid": "cowrie.session.connect",
                "session": "xyz789"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "test.db")

            insert_events(events, db_path)

            session_events = get_events_by_session(
                "abc123",
                db_path
            )

            self.assertEqual(len(session_events), 2)

            for event in session_events:
                self.assertEqual(event["session"], "abc123")

            # A nonexistent session should return no events
            missing_events = get_events_by_session(
                "nonexistent",
                db_path
            )

            self.assertEqual(missing_events, [])


if __name__ == "__main__":
    unittest.main()
