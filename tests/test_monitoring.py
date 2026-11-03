from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import monitoring


class MonitorCycleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.database_path = Path(temporary_directory.name) / "monitor.db"
        connection = sqlite3.connect(self.database_path)
        connection.executescript(
            """
            CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE assets (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                port INTEGER,
                enabled INTEGER NOT NULL,
                maintenance_until TEXT,
                maintenance_reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE live_status (
                asset_id INTEGER PRIMARY KEY,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL,
                message TEXT NOT NULL,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                alert_started_at TEXT
            );
            CREATE TABLE checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL,
                message TEXT NOT NULL
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            );
            INSERT INTO app_settings VALUES ('monitor_mode', 'dashboard');
            INSERT INTO app_settings VALUES ('monitor_interval_seconds', '5');
            INSERT INTO app_settings VALUES ('failure_threshold', '2');
            INSERT INTO app_settings VALUES ('alert_snooze_until', '');
            INSERT INTO assets (id, name, kind, target, port, enabled)
            VALUES (1, 'Servidor de teste', 'IP', '127.0.0.1', 443, 1);
            """
        )
        connection.commit()
        connection.close()

    def test_alert_starts_after_two_failures_and_resolves_online(self) -> None:
        with patch(
            "monitoring.check_asset",
            side_effect=[
                self.result("OFFLINE"),
                self.result("OFFLINE"),
                self.result("ONLINE"),
            ],
        ):
            self.assertEqual(
                monitoring.run_monitor_cycle(
                    self.database_path, expected_mode="dashboard"
                ),
                (1, 0),
            )
            self.assertEqual(monitoring.active_alerts(self.database_path), [])
            monitoring.run_monitor_cycle(
                self.database_path, expected_mode="dashboard"
            )
            self.assertEqual(
                [item["name"] for item in monitoring.active_alerts(self.database_path)],
                ["Servidor de teste"],
            )
            connection = sqlite3.connect(self.database_path)
            silence_until = (
                datetime.now().astimezone() + timedelta(minutes=30)
            ).isoformat()
            connection.execute(
                "UPDATE app_settings SET value = ? WHERE key = 'alert_snooze_until'",
                (silence_until,),
            )
            connection.commit()
            connection.close()
            self.assertEqual(monitoring.active_alerts(self.database_path), [])
            monitoring.run_monitor_cycle(
                self.database_path, expected_mode="dashboard"
            )
            self.assertEqual(monitoring.active_alerts(self.database_path), [])

    def test_maintenance_and_mode_gate_skip_network_checks(self) -> None:
        connection = sqlite3.connect(self.database_path)
        until = (datetime.now().astimezone() + timedelta(hours=1)).isoformat()
        connection.execute(
            "UPDATE assets SET maintenance_until = ? WHERE id = 1", (until,)
        )
        connection.commit()
        connection.close()
        with patch("monitoring.check_asset") as check:
            self.assertEqual(
                monitoring.run_monitor_cycle(
                    self.database_path, expected_mode="dashboard"
                ),
                (0, 1),
            )
            check.assert_not_called()
            connection = sqlite3.connect(self.database_path)
            connection.execute(
                "UPDATE app_settings SET value = 'disabled' WHERE key = 'monitor_mode'"
            )
            connection.commit()
            connection.close()
            self.assertEqual(
                monitoring.run_monitor_cycle(
                    self.database_path, expected_mode="dashboard"
                ),
                (0, 0),
            )
            check.assert_not_called()

    def test_worker_once_respects_mode_and_configured_interval(self) -> None:
        connection = sqlite3.connect(self.database_path)
        connection.execute(
            "UPDATE app_settings SET value = 'worker' WHERE key = 'monitor_mode'"
        )
        connection.execute(
            "INSERT INTO app_settings VALUES ('monitor_last_cycle', '')"
        )
        connection.commit()
        connection.close()

        with patch("monitoring.run_monitor_cycle") as run_cycle:
            monitoring.run_worker(self.database_path, once=True)
            run_cycle.assert_called_once_with(
                self.database_path, expected_mode="worker"
            )

        connection = sqlite3.connect(self.database_path)
        connection.execute(
            "UPDATE app_settings SET value = ? WHERE key = 'monitor_last_cycle'",
            (datetime.now().astimezone().isoformat(timespec="seconds"),),
        )
        connection.commit()
        connection.close()
        with patch("monitoring.run_monitor_cycle") as run_cycle:
            monitoring.run_worker(self.database_path, once=True)
            run_cycle.assert_not_called()

    def result(self, status: str) -> dict[str, object]:
        return {
            "asset_id": 1,
            "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "status": status,
            "latency_ms": 8.5 if status == "ONLINE" else None,
            "message": f"Teste {status}",
        }


if __name__ == "__main__":
    unittest.main()
