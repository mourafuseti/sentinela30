from __future__ import annotations

import sqlite3
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests


CHECK_TIMEOUT_SECONDS = 3
LIVE_HISTORY_SAMPLE_SECONDS = 60
DEFAULT_FAILURE_THRESHOLD = 2


def database(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def check_asset(asset: dict[str, Any]) -> dict[str, Any]:
    started = datetime.now().astimezone()
    try:
        if asset["kind"] == "IP":
            with socket.create_connection(
                (asset["target"], int(asset["port"])), timeout=CHECK_TIMEOUT_SECONDS
            ):
                pass
            message = f"Conexão TCP na porta {asset['port']} estabelecida."
        else:
            response = requests.head(
                asset["target"],
                timeout=CHECK_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
            try:
                if response.status_code in {405, 501}:
                    response.close()
                    response = requests.get(
                        asset["target"],
                        timeout=CHECK_TIMEOUT_SECONDS,
                        allow_redirects=False,
                        stream=True,
                    )
                status_code = response.status_code
            finally:
                response.close()

            if status_code >= 500:
                raise requests.HTTPError(f"Site respondeu HTTP {status_code}.")
            message = (
                f"Resposta HTTP {status_code} (erro do cliente)."
                if status_code >= 400
                else f"Resposta HTTP {status_code}."
            )

        return {
            "asset_id": asset["id"],
            "checked_at": started.isoformat(timespec="seconds"),
            "status": "ONLINE",
            "latency_ms": round(
                (datetime.now().astimezone() - started).total_seconds() * 1000, 1
            ),
            "message": message,
        }
    except (OSError, requests.RequestException) as error:
        detail = str(error).strip() or error.__class__.__name__
        return {
            "asset_id": asset["id"],
            "checked_at": started.isoformat(timespec="seconds"),
            "status": "OFFLINE",
            "latency_ms": None,
            "message": detail[:240],
        }


def monitor_settings(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        row["key"]: row["value"]
        for row in connection.execute(
            "SELECT key, value FROM app_settings WHERE key IN "
            "('monitor_mode', 'monitor_interval_seconds', 'failure_threshold', "
            "'monitor_last_cycle')"
        ).fetchall()
    }


def run_monitor_cycle(
    db_path: Path,
    actor: str = "monitoramento",
    expected_mode: str | None = None,
    force: bool = False,
) -> tuple[int, int]:
    connection = database(db_path)
    try:
        settings = monitor_settings(connection)
        if not force and settings.get("monitor_mode", "dashboard") == "disabled":
            return 0, 0
        if (
            not force
            and expected_mode
            and settings.get("monitor_mode", "dashboard") != expected_mode
        ):
            return 0, 0
        all_assets = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, name, kind, target, port, enabled, maintenance_until,
                       maintenance_reason
                FROM assets
                WHERE enabled = 1 AND (kind = 'Site' OR port IS NOT NULL)
                """
            ).fetchall()
        ]
        skipped_count = connection.execute(
            """
            SELECT COUNT(*) FROM assets
            WHERE enabled = 1 AND kind = 'IP' AND port IS NULL
            """
        ).fetchone()[0]
        now = datetime.now().astimezone()
        assets = []
        for asset in all_assets:
            maintenance_until = asset["maintenance_until"]
            if maintenance_until and datetime.fromisoformat(maintenance_until) > now:
                skipped_count += 1
                continue
            assets.append(asset)
        if not assets:
            connection.execute(
                """
                INSERT INTO app_settings (key, value)
                VALUES ('monitor_last_cycle', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (now.isoformat(timespec="seconds"),),
            )
            connection.commit()
            return 0, skipped_count
        threshold = int(
            settings.get("failure_threshold", str(DEFAULT_FAILURE_THRESHOLD))
        )
        with ThreadPoolExecutor(max_workers=min(12, len(assets))) as executor:
            results = list(executor.map(check_asset, assets))

        prior_state = {
            row["asset_id"]: dict(row)
            for row in connection.execute(
                "SELECT asset_id, status, consecutive_failures, alert_started_at "
                "FROM live_status"
            ).fetchall()
        }
        asset_by_id = {asset["id"]: asset for asset in assets}
        sample_rows: list[dict[str, Any]] = []
        audit_rows: list[tuple[str, str, str, str]] = []
        for result in results:
            asset = asset_by_id[result["asset_id"]]
            previous = prior_state.get(result["asset_id"])
            if result["status"] == "OFFLINE":
                failures = (
                    previous["consecutive_failures"] + 1
                    if previous and previous["status"] == "OFFLINE"
                    else 1
                )
                alert_started_at = (
                    previous["alert_started_at"]
                    if previous and previous["alert_started_at"]
                    else result["checked_at"]
                    if failures >= threshold
                    else None
                )
            else:
                failures = 0
                alert_started_at = None

            result["consecutive_failures"] = failures
            result["alert_started_at"] = alert_started_at
            last_sample = connection.execute(
                "SELECT checked_at FROM checks WHERE asset_id = ? "
                "ORDER BY checked_at DESC, id DESC LIMIT 1",
                (result["asset_id"],),
            ).fetchone()
            if last_sample is None or (
                now - datetime.fromisoformat(last_sample["checked_at"])
            ).total_seconds() >= LIVE_HISTORY_SAMPLE_SECONDS:
                sample_rows.append(result)

            previous_alert = bool(
                previous
                and previous["consecutive_failures"] >= threshold
                and previous["alert_started_at"]
            )
            current_alert = failures >= threshold and bool(alert_started_at)
            if previous and previous["status"] != result["status"]:
                audit_rows.append(
                    (
                        result["checked_at"],
                        actor,
                        "asset_status_changed",
                        f"{asset['name']}: {previous['status']} → {result['status']}.",
                    )
                )
            if current_alert and not previous_alert:
                audit_rows.append(
                    (
                        result["checked_at"],
                        actor,
                        "alert_started",
                        f"{asset['name']} offline após {failures} falhas consecutivas.",
                    )
                )
            elif previous_alert and not current_alert:
                audit_rows.append(
                    (
                        result["checked_at"],
                        actor,
                        "alert_resolved",
                        f"{asset['name']} voltou online.",
                    )
                )

        connection.executemany(
            """
            INSERT INTO live_status (
                asset_id, checked_at, status, latency_ms, message,
                consecutive_failures, alert_started_at
            )
            VALUES (
                :asset_id, :checked_at, :status, :latency_ms, :message,
                :consecutive_failures, :alert_started_at
            )
            ON CONFLICT(asset_id) DO UPDATE SET
                checked_at = excluded.checked_at,
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                message = excluded.message,
                consecutive_failures = excluded.consecutive_failures,
                alert_started_at = excluded.alert_started_at
            """,
            results,
        )
        if sample_rows:
            connection.executemany(
                """
                INSERT INTO checks (asset_id, checked_at, status, latency_ms, message)
                VALUES (:asset_id, :checked_at, :status, :latency_ms, :message)
                """,
                sample_rows,
            )
        if audit_rows:
            connection.executemany(
                """
                INSERT INTO audit_log (occurred_at, username, action, details)
                VALUES (?, ?, ?, ?)
                """,
                audit_rows,
            )
        connection.execute(
            """
            INSERT INTO app_settings (key, value)
            VALUES ('monitor_last_cycle', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (now.isoformat(timespec="seconds"),),
        )
        connection.commit()
        return len(assets), skipped_count
    finally:
        connection.close()


def active_alerts(db_path: Path) -> list[dict[str, Any]]:
    connection = database(db_path)
    try:
        now = datetime.now().astimezone()
        snooze = connection.execute(
            "SELECT value FROM app_settings WHERE key = 'alert_snooze_until'"
        ).fetchone()
        if snooze and snooze["value"]:
            if datetime.fromisoformat(snooze["value"]) > now:
                return []
        settings = monitor_settings(connection)
        threshold = int(
            settings.get("failure_threshold", str(DEFAULT_FAILURE_THRESHOLD))
        )
        rows = connection.execute(
            """
            SELECT a.id, a.name, a.target, l.checked_at, l.message,
                   l.consecutive_failures, l.alert_started_at,
                   a.maintenance_until, a.maintenance_reason,
                   a.kind, a.criticality, a.environment
            FROM live_status AS l
            JOIN assets AS a ON a.id = l.asset_id
            WHERE a.enabled = 1 AND l.status = 'OFFLINE'
                  AND l.consecutive_failures >= ?
                  AND l.alert_started_at IS NOT NULL
            ORDER BY l.alert_started_at
            """,
            (threshold,),
        ).fetchall()
        return [
            dict(row)
            for row in rows
            if not row["maintenance_until"]
            or datetime.fromisoformat(row["maintenance_until"]) <= now
        ]
    finally:
        connection.close()


def run_worker(db_path: Path, once: bool = False) -> None:
    if not db_path.is_file():
        raise FileNotFoundError(f"Banco de dados não encontrado: {db_path}")
    connection = database(db_path)
    try:
        settings = monitor_settings(connection)
        if settings.get("monitor_mode", "dashboard") != "worker":
            raise RuntimeError(
                "O modo configurado não é 'worker'. Altere-o na seção Operação."
            )
        interval = int(settings.get("monitor_interval_seconds", "15"))
        last_cycle = settings.get("monitor_last_cycle")
    finally:
        connection.close()

    if once and last_cycle:
        elapsed = (
            datetime.now().astimezone() - datetime.fromisoformat(last_cycle)
        ).total_seconds()
        if elapsed < interval:
            return

    while True:
        run_monitor_cycle(db_path, expected_mode="worker")
        if once:
            return
        time.sleep(interval)


def set_app_setting(db_path: Path, key: str, value: str) -> None:
    connection = database(db_path)
    try:
        connection.execute(
            """
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        connection.commit()
    finally:
        connection.close()
