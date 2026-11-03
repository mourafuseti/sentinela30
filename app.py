from __future__ import annotations

import hashlib
import hmac
import io
import ipaddress
import math
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import wave
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree

import pandas as pd
import requests
import streamlit as st


DATABASE_PATH = Path(__file__).with_name("netwatch.db")
CHECK_TIMEOUT_SECONDS = 3
REFRESH_INTERVAL_SECONDS = 30
LIVE_CHECK_INTERVAL_SECONDS = 3
LIVE_HISTORY_SAMPLE_SECONDS = 60
MAX_NMAP_XML_BYTES = 5 * 1024 * 1024
MAX_NMAP_TARGETS = 8
NMAP_PORTS = (22, 53, 80, 443, 445, 3389, 8080)
NMAP_SCAN_TIMEOUT_SECONDS = 180
PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_MAX_LENGTH = 128
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15
PASSWORD_MIN_LENGTH = 12
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    with database() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('IP', 'Site')),
                target TEXT NOT NULL,
                port INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('ONLINE', 'OFFLINE')),
                latency_ms REAL,
                message TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS live_status (
                asset_id INTEGER PRIMARY KEY,
                checked_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('ONLINE', 'OFFLINE')),
                latency_ms REAL,
                message TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS device_discoveries (
                asset_id INTEGER PRIMARY KEY,
                hostname TEXT,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS network_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
                UNIQUE (asset_id, protocol, port)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS checks_asset_checked ON checks (asset_id, checked_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'visitante')),
                must_change_password INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                failed_count INTEGER NOT NULL DEFAULT 0,
                window_started_at TEXT NOT NULL,
                locked_until TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS audit_log_occurred ON audit_log (occurred_at DESC)"
        )
        user_count = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]
        if user_count == 0:
            salt, password_hash = hash_password("admin")
            now = datetime.now().astimezone().isoformat(timespec="seconds")
            connection.execute(
                """
                INSERT INTO users (
                    username, password_salt, password_hash, role,
                    must_change_password, is_active, created_at, updated_at
                )
                VALUES ('admin', ?, ?, 'admin', 1, 1, ?, ?)
                """,
                (salt, password_hash, now, now),
            )
            connection.execute(
                """
                INSERT INTO audit_log (occurred_at, username, action, details)
                VALUES (?, 'system', 'bootstrap_admin_created',
                        'Conta inicial admin criada; troca de senha obrigatória.')
                """,
                (now,),
            )


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return salt.hex(), password_hash.hex()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PASSWORD_HASH_ITERATIONS,
    ).hex()
    return hmac.compare_digest(actual_hash, expected_hash)


def audit_event(action: str, details: str, username: str | None = None) -> None:
    actor = username or st.session_state.get("username", "system")
    occurred_at = datetime.now().astimezone().isoformat(timespec="seconds")
    with database() as connection:
        insert_audit_event(connection, occurred_at, actor, action, details)


def insert_audit_event(
    connection: sqlite3.Connection,
    occurred_at: str,
    username: str,
    action: str,
    details: str,
) -> None:
    connection.execute(
        """
        INSERT INTO audit_log (occurred_at, username, action, details)
        VALUES (?, ?, ?, ?)
        """,
        (occurred_at, username, action, details[:500]),
    )


def authenticate(username: str, password: str) -> tuple[bool, str]:
    now = datetime.now().astimezone()
    clean_username = username.strip() or "desconhecido"
    with database() as connection:
        attempt = connection.execute(
            """
            SELECT failed_count, window_started_at, locked_until
            FROM login_attempts WHERE username = ?
            """,
            (clean_username,),
        ).fetchone()
        if attempt and attempt["locked_until"]:
            locked_until = datetime.fromisoformat(attempt["locked_until"])
            if locked_until > now:
                return False, "Muitas tentativas. Aguarde 15 minutos e tente novamente."

        user = connection.execute(
            """
            SELECT id, username, password_salt, password_hash, role,
                   must_change_password, is_active
            FROM users WHERE username = ?
            """,
            (clean_username,),
        ).fetchone()
        authenticated = bool(
            user
            and user["is_active"]
            and len(password) <= PASSWORD_MAX_LENGTH
            and verify_password(password, user["password_salt"], user["password_hash"])
        )
        if authenticated:
            connection.execute(
                "DELETE FROM login_attempts WHERE username = ?", (clean_username,)
            )
            st.session_state["authenticated"] = True
            st.session_state["user_id"] = user["id"]
            st.session_state["username"] = user["username"]
            st.session_state["role"] = user["role"]
            st.session_state["must_change_password"] = bool(
                user["must_change_password"]
            )
        else:
            if (
                not attempt
                or now - datetime.fromisoformat(attempt["window_started_at"])
                > timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
                or attempt["locked_until"]
            ):
                failed_count = 0
                window_started_at = now.isoformat(timespec="seconds")
            else:
                failed_count = attempt["failed_count"]
                window_started_at = attempt["window_started_at"]
            failed_count += 1
            locked_until = (
                (now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat(
                    timespec="seconds"
                )
                if failed_count >= MAX_LOGIN_ATTEMPTS
                else None
            )
            connection.execute(
                """
                INSERT INTO login_attempts (
                    username, failed_count, window_started_at, locked_until
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    failed_count = excluded.failed_count,
                    window_started_at = excluded.window_started_at,
                    locked_until = excluded.locked_until
                """,
                (clean_username, failed_count, window_started_at, locked_until),
            )
            insert_audit_event(
                connection,
                now.isoformat(timespec="seconds"),
                clean_username,
                "login_failed",
                f"Falha de autenticação; tentativa {failed_count}.",
            )
            if locked_until:
                return False, "Muitas tentativas. A conta ficará bloqueada por 15 minutos."
            return False, "Usuário ou senha inválidos."

    audit_event("login_success", "Autenticação realizada.", clean_username)
    return True, ""


def current_user_is_active() -> bool:
    user_id = st.session_state.get("user_id")
    if not user_id:
        return False
    with database() as connection:
        user = connection.execute(
            "SELECT username, role, must_change_password, is_active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not user or not user["is_active"]:
        return False
    st.session_state["username"] = user["username"]
    st.session_state["role"] = user["role"]
    st.session_state["must_change_password"] = bool(user["must_change_password"])
    return True


def require_admin() -> None:
    if not current_user_is_active() or st.session_state.get("role") != "admin":
        raise PermissionError("Esta ação exige uma conta de administrador.")


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"A senha deve ter pelo menos {PASSWORD_MIN_LENGTH} caracteres."
        )
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"A senha deve ter no máximo {PASSWORD_MAX_LENGTH} caracteres."
        )
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 3:
        raise ValueError(
            "Use pelo menos três destes grupos: minúsculas, maiúsculas, números e símbolos."
        )


def list_users() -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            """
            SELECT id, username, role, must_change_password, is_active, created_at,
                   updated_at
            FROM users ORDER BY username COLLATE NOCASE
            """
        ).fetchall()
    return [dict(row) for row in rows]


def list_audit_events(limit: int = 500) -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            """
            SELECT occurred_at, username, action, details
            FROM audit_log ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_user(username: str, password: str, role: str) -> None:
    require_admin()
    clean_username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", clean_username):
        raise ValueError(
            "O usuário deve ter de 3 a 32 caracteres: letras, números, ponto, hífen ou sublinhado."
        )
    if role not in {"admin", "visitante"}:
        raise ValueError("Selecione um perfil válido.")
    validate_password(password)
    salt, password_hash = hash_password(password)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    try:
        with database() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    username, password_salt, password_hash, role,
                    must_change_password, is_active, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (clean_username, salt, password_hash, role, now, now),
            )
    except sqlite3.IntegrityError as error:
        raise ValueError("Este nome de usuário já está cadastrado.") from error
    audit_event("user_created", f"Conta {clean_username} criada com perfil {role}.")


def set_user_password(user_id: int, password: str) -> None:
    require_admin()
    validate_password(password)
    salt, password_hash = hash_password(password)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    with database() as connection:
        user = connection.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            raise ValueError("A conta selecionada não foi encontrada.")
        connection.execute(
            """
            UPDATE users
            SET password_salt = ?, password_hash = ?, must_change_password = 1,
                updated_at = ?
            WHERE id = ?
            """,
            (salt, password_hash, now, user_id),
        )
        connection.execute(
            "DELETE FROM login_attempts WHERE username = ?", (user["username"],)
        )
    audit_event(
        "user_password_reset",
        f"Senha temporária definida para {user['username']}.",
    )


def set_user_active(user_id: int, is_active: bool) -> None:
    require_admin()
    if user_id == st.session_state.get("user_id") and not is_active:
        raise ValueError("Não é possível desativar a própria conta.")
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    with database() as connection:
        user = connection.execute(
            "SELECT username, role, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            raise ValueError("A conta selecionada não foi encontrada.")
        if user["is_active"] == int(is_active):
            return
        if not is_active and user["role"] == "admin":
            remaining_admins = connection.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE role = 'admin' AND is_active = 1 AND id != ?
                """,
                (user_id,),
            ).fetchone()[0]
            if remaining_admins == 0:
                raise ValueError("Mantenha pelo menos um administrador ativo.")
        connection.execute(
            "UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?",
            (int(is_active), now, user_id),
        )
    audit_event(
        "user_activated" if is_active else "user_deactivated",
        f"Status da conta {user['username']} alterado.",
    )


def set_user_role(user_id: int, role: str) -> None:
    require_admin()
    if role not in {"admin", "visitante"}:
        raise ValueError("Selecione um perfil válido.")
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    with database() as connection:
        user = connection.execute(
            "SELECT username, role, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            raise ValueError("A conta selecionada não foi encontrada.")
        if (
            user["role"] == "admin"
            and role != "admin"
            and user["is_active"]
        ):
            remaining_admins = connection.execute(
                """
                SELECT COUNT(*) FROM users
                WHERE role = 'admin' AND is_active = 1 AND id != ?
                """,
                (user_id,),
            ).fetchone()[0]
            if remaining_admins == 0:
                raise ValueError("Mantenha pelo menos um administrador ativo.")
        connection.execute(
            "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
            (role, now, user_id),
        )
    audit_event(
        "user_role_changed",
        f"Perfil de {user['username']} alterado para {role}.",
    )


def change_current_password(
    current_password: str, new_password: str, confirmation: str
) -> None:
    user_id = st.session_state.get("user_id")
    if not user_id:
        raise PermissionError("Entre na sua conta para alterar a senha.")
    if new_password != confirmation:
        raise ValueError("A nova senha e a confirmação não são iguais.")
    validate_password(new_password)
    with database() as connection:
        user = connection.execute(
            "SELECT username, password_salt, password_hash FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None or not verify_password(
            current_password, user["password_salt"], user["password_hash"]
        ):
            raise ValueError("A senha atual está incorreta.")
        salt, password_hash = hash_password(new_password)
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        connection.execute(
            """
            UPDATE users
            SET password_salt = ?, password_hash = ?, must_change_password = 0,
                updated_at = ?
            WHERE id = ?
            """,
            (salt, password_hash, now, user_id),
        )
    st.session_state["must_change_password"] = False
    audit_event("password_changed", "Senha alterada.")


def list_assets() -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            """
            SELECT a.id, a.name, a.kind, a.target, a.port, a.enabled,
                   COALESCE(l.checked_at, c.checked_at) AS checked_at,
                   CASE WHEN l.asset_id IS NOT NULL THEN l.status ELSE c.status END AS status,
                   CASE WHEN l.asset_id IS NOT NULL THEN l.latency_ms ELSE c.latency_ms END AS latency_ms,
                   CASE WHEN l.asset_id IS NOT NULL THEN l.message ELSE c.message END AS message,
                   d.hostname,
                   (
                       SELECT group_concat(
                           trim(
                               port || '/' || protocol || ' ' || service || ' ' ||
                               COALESCE(product, '') || ' ' || COALESCE(version, '')
                           ),
                           ', '
                       )
                       FROM network_services
                       WHERE asset_id = a.id
                   ) AS discovered_services
            FROM assets AS a
            LEFT JOIN checks AS c ON c.id = (
                SELECT id FROM checks
                WHERE asset_id = a.id
                ORDER BY checked_at DESC, id DESC
                LIMIT 1
            )
            LEFT JOIN live_status AS l ON l.asset_id = a.id
            LEFT JOIN device_discoveries AS d ON d.asset_id = a.id
            ORDER BY a.name COLLATE NOCASE
            """
        ).fetchall()
    return [dict(row) for row in rows]


def list_networks() -> list[dict[str, Any]]:
    with database() as connection:
        rows = connection.execute(
            "SELECT id, name, cidr, created_at FROM networks ORDER BY name COLLATE NOCASE"
        ).fetchall()
    return [dict(row) for row in rows]


def list_discovered_devices(network_cidr: str) -> list[dict[str, Any]]:
    network = ipaddress.ip_network(network_cidr, strict=True)
    with database() as connection:
        rows = connection.execute(
            """
            SELECT a.id, a.name, a.target, d.hostname, d.discovered_at
            FROM device_discoveries AS d
            JOIN assets AS a ON a.id = d.asset_id
            WHERE a.kind = 'IP'
            ORDER BY a.target
            """
        ).fetchall()
        services = connection.execute(
            """
            SELECT ns.asset_id, ns.protocol, ns.port, ns.service,
                   ns.product, ns.version
            FROM network_services AS ns
            JOIN assets AS a ON a.id = ns.asset_id
            WHERE a.kind = 'IP'
            ORDER BY ns.protocol, ns.port
            """
        ).fetchall()

    services_by_asset: dict[int, list[str]] = {}
    for service in services:
        label = f"{service['port']}/{service['protocol']} · {service['service']}"
        product = " ".join(
            part for part in (service["product"], service["version"]) if part
        )
        if product:
            label = f"{label} · {product}"
        services_by_asset.setdefault(service["asset_id"], []).append(label)

    discovered: list[dict[str, Any]] = []
    for row in rows:
        if ipaddress.ip_address(row["target"]) not in network:
            continue
        discovered.append(
            {
                "asset_id": row["id"],
                "ip": row["target"],
                "name": row["hostname"] or row["name"],
                "hostname": row["hostname"] or "—",
                "ports": ", ".join(services_by_asset.get(row["id"], [])) or "Nenhuma reportada",
                "discovered_at": row["discovered_at"],
            }
        )
    return discovered


def list_checks(days: int = 7, limit: int = 1000) -> list[dict[str, Any]]:
    cutoff = (datetime.now().astimezone() - timedelta(days=days)).isoformat(
        timespec="seconds"
    )
    with database() as connection:
        rows = connection.execute(
            """
            SELECT c.checked_at, a.name, a.kind, a.target, c.status,
                   c.latency_ms, c.message
            FROM checks AS c
            JOIN assets AS a ON a.id = c.asset_id
            WHERE c.checked_at >= ?
            ORDER BY c.checked_at DESC, c.id DESC
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def list_analytics_buckets(
    days: int, asset_id: int | None = None
) -> list[dict[str, Any]]:
    bucket_seconds = 300 if days == 1 else 3600
    cutoff = (datetime.now().astimezone() - timedelta(days=days)).isoformat(
        timespec="seconds"
    )
    filters = ["c.checked_at >= ?", "a.enabled = 1"]
    parameters: list[Any] = [cutoff]
    if asset_id is not None:
        filters.append("c.asset_id = ?")
        parameters.append(asset_id)

    with database() as connection:
        rows = connection.execute(
            f"""
            SELECT
                datetime(
                    (CAST(strftime('%s', c.checked_at) AS INTEGER) / ?) * ?,
                    'unixepoch',
                    'localtime'
                ) AS time_bucket,
                COUNT(*) AS total_checks,
                SUM(CASE WHEN c.status = 'ONLINE' THEN 1 ELSE 0 END) AS online_checks,
                SUM(CASE WHEN c.status = 'OFFLINE' THEN 1 ELSE 0 END) AS offline_checks,
                AVG(CASE WHEN c.status = 'ONLINE' THEN c.latency_ms END) AS avg_latency_ms,
                MIN(CASE WHEN c.status = 'ONLINE' THEN c.latency_ms END) AS min_latency_ms,
                MAX(CASE WHEN c.status = 'ONLINE' THEN c.latency_ms END) AS max_latency_ms,
                COUNT(CASE WHEN c.status = 'ONLINE' AND c.latency_ms IS NOT NULL THEN 1 END)
                    AS latency_samples
            FROM checks AS c
            JOIN assets AS a ON a.id = c.asset_id
            WHERE {" AND ".join(filters)}
            GROUP BY time_bucket
            ORDER BY time_bucket
            """,
            [bucket_seconds, bucket_seconds, *parameters],
        ).fetchall()
    return [dict(row) for row in rows]


def normalize_site_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Informe o endereço do site.")
    if "://" not in raw:
        raw = f"https://{raw}"

    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Use um endereço válido começando com http:// ou https://.")
    if parsed.username or parsed.password:
        raise ValueError("O endereço não deve conter usuário ou senha.")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("A porta informada no endereço é inválida.") from error

    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def validate_target(kind: str, target: str) -> str:
    if kind == "IP":
        try:
            return str(ipaddress.ip_address(target.strip()))
        except ValueError as error:
            raise ValueError("Informe um endereço IPv4 ou IPv6 válido.") from error
    return normalize_site_url(target)


def validate_network_cidr(target: str) -> str:
    try:
        network = ipaddress.ip_network(target.strip(), strict=True)
    except ValueError as error:
        raise ValueError(
            "Informe uma rede IPv4 válida em formato CIDR, como 192.168.1.0/24."
        ) from error
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24:
        raise ValueError("Por enquanto, o cadastro aceita somente redes IPv4 /24.")
    return str(network)


def parse_network_hosts(network_cidr: str, raw_addresses: str) -> tuple[list[str], int]:
    network = ipaddress.ip_network(network_cidr, strict=True)
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24:
        raise ValueError("A faixa selecionada não é uma rede IPv4 /24.")

    addresses: list[str] = []
    seen: set[str] = set()
    repeated = 0
    invalid_lines: list[str] = []

    for line_number, line in enumerate(raw_addresses.splitlines(), start=1):
        value = line.strip()
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            invalid_lines.append(f"linha {line_number}: endereço IP inválido")
            continue
        if not isinstance(address, ipaddress.IPv4Address):
            invalid_lines.append(f"linha {line_number}: informe um endereço IPv4")
            continue
        if address not in network:
            invalid_lines.append(
                f"linha {line_number}: {address} está fora da rede {network}"
            )
            continue
        if address in {network.network_address, network.broadcast_address}:
            invalid_lines.append(
                f"linha {line_number}: {address} é o endereço de rede ou broadcast"
            )
            continue

        normalized = str(address)
        if normalized in seen:
            repeated += 1
            continue
        seen.add(normalized)
        addresses.append(normalized)

    if invalid_lines:
        details = "; ".join(invalid_lines[:5])
        remaining = len(invalid_lines) - 5
        if remaining > 0:
            details += f"; e mais {remaining} endereço(s) inválido(s)"
        raise ValueError(details)
    if not addresses:
        raise ValueError("Cole pelo menos um endereço IPv4 válido, um por linha.")

    return addresses, repeated


def parse_nmap_xml(
    network_cidr: str, content: bytes
) -> tuple[list[dict[str, Any]], int]:
    if not content:
        raise ValueError("O arquivo XML está vazio.")
    if len(content) > MAX_NMAP_XML_BYTES:
        raise ValueError("O arquivo XML excede o limite de 5 MB.")
    lowered_content = content.lower()
    if b"<!doctype" in lowered_content or b"<!entity" in lowered_content:
        raise ValueError("O arquivo não pode conter declarações de DTD ou entidades.")

    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as error:
        raise ValueError("O arquivo enviado não contém um XML válido.") from error
    if root.tag != "nmaprun":
        raise ValueError("Envie um arquivo XML de resultados do Nmap.")

    network = ipaddress.ip_network(network_cidr, strict=True)
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24:
        raise ValueError("A faixa selecionada não é uma rede IPv4 /24.")

    discovered: dict[str, dict[str, Any]] = {}
    out_of_scope = 0
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = next(
            (
                item.get("addr", "")
                for item in host.findall("address")
                if item.get("addrtype") == "ipv4"
            ),
            "",
        )
        try:
            ipv4 = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            continue
        if ipv4 not in network or ipv4 in {
            network.network_address,
            network.broadcast_address,
        }:
            out_of_scope += 1
            continue

        hostname_element = host.find("./hostnames/hostname")
        hostname = (
            hostname_element.get("name", "").strip()[:253]
            if hostname_element is not None
            else ""
        )
        services: list[dict[str, Any]] = []
        for port_element in host.findall("./ports/port"):
            state = port_element.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_element.get("portid", ""))
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue

            service_element = port_element.find("service")
            services.append(
                {
                    "protocol": (port_element.get("protocol") or "unknown")[:8],
                    "port": port,
                    "service": (
                        service_element.get("name", "unknown")
                        if service_element is not None
                        else "unknown"
                    )[:100],
                    "product": (
                        service_element.get("product", "")
                        if service_element is not None
                        else ""
                    )[:150],
                    "version": (
                        service_element.get("version", "")
                        if service_element is not None
                        else ""
                    )[:80],
                }
            )

        host_info = discovered.setdefault(
            str(ipv4),
            {"ip": str(ipv4), "hostname": hostname, "services": {}},
        )
        if hostname and not host_info["hostname"]:
            host_info["hostname"] = hostname
        for service in services:
            key = (service["protocol"], service["port"])
            host_info["services"][key] = service

    for host_info in discovered.values():
        host_info["services"] = list(host_info["services"].values())
    return list(discovered.values()), out_of_scope


def import_nmap_xml(
    network_cidr: str,
    hosts: list[dict[str, Any]],
    created_at: str,
    scanned_ports: set[int] | None = None,
) -> tuple[int, int, int]:
    require_admin()
    network = ipaddress.ip_network(network_cidr, strict=True)
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24:
        raise ValueError("A faixa selecionada não é uma rede IPv4 /24.")
    if any(ipaddress.ip_address(host["ip"]) not in network for host in hosts):
        raise ValueError("O relatório contém um dispositivo fora da rede selecionada.")

    device_count = 0
    service_count = 0
    with database() as connection:
        for host in hosts:
            row = connection.execute(
                "SELECT id, name FROM assets WHERE kind = 'IP' AND target = ?",
                (host["ip"],),
            ).fetchone()
            if row is None:
                cursor = connection.execute(
                    """
                    INSERT INTO assets (name, kind, target, port, created_at)
                    VALUES (?, 'IP', ?, NULL, ?)
                    """,
                    (
                        host["hostname"] or f"Dispositivo {host['ip']}",
                        host["ip"],
                        created_at,
                    ),
                )
                asset_id = int(cursor.lastrowid)
                device_count += 1
            else:
                asset_id = row["id"]
                if host["hostname"] and row["name"] == f"Dispositivo {host['ip']}":
                    connection.execute(
                        "UPDATE assets SET name = ? WHERE id = ?",
                        (host["hostname"], asset_id),
                    )

            connection.execute(
                """
                INSERT INTO device_discoveries (asset_id, hostname, discovered_at)
                VALUES (?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    hostname = COALESCE(excluded.hostname, device_discoveries.hostname),
                    discovered_at = excluded.discovered_at
                """,
                (asset_id, host["hostname"] or None, created_at),
            )
            if scanned_ports is None:
                connection.execute(
                    "DELETE FROM network_services WHERE asset_id = ?", (asset_id,)
                )
            elif scanned_ports:
                placeholders = ",".join("?" for _ in scanned_ports)
                connection.execute(
                    "DELETE FROM network_services "
                    f"WHERE asset_id = ? AND protocol = 'tcp' AND port IN ({placeholders})",
                    (asset_id, *sorted(scanned_ports)),
                )
            connection.executemany(
                """
                INSERT INTO network_services (
                    asset_id, protocol, port, service, product, version, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        asset_id,
                        service["protocol"],
                        service["port"],
                        service["service"],
                        service["product"],
                        service["version"],
                        created_at,
                    )
                    for service in host["services"]
                ],
            )
            service_count += len(host["services"])

    audit_event(
        "nmap_results_imported",
        f"Importados {len(hosts)} equipamento(s) e {service_count} serviço(s) na rede {network}.",
    )
    return device_count, service_count, len(hosts)


def run_nmap_scan(network_cidr: str, targets: list[str]) -> bytes:
    require_admin()
    if not targets:
        raise ValueError("Selecione pelo menos um IP já cadastrado.")
    if len(targets) > MAX_NMAP_TARGETS:
        raise ValueError(
            f"Selecione no máximo {MAX_NMAP_TARGETS} IPs por verificação."
        )

    network = ipaddress.ip_network(network_cidr, strict=True)
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 24:
        raise ValueError("A rede selecionada não é uma faixa IPv4 /24.")

    normalized_targets: list[str] = []
    for target in targets:
        try:
            address = ipaddress.ip_address(target)
        except ValueError as error:
            raise ValueError(f"O endereço selecionado não é um IP válido: {target}") from error
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or address not in network
            or not any(address in private_network for private_network in PRIVATE_IPV4_NETWORKS)
        ):
            raise ValueError(
                f"O endereço {target} não pertence a uma rede privada /24 selecionada."
            )
        normalized_targets.append(str(address))

    executable = shutil.which("nmap") or shutil.which("nmap.exe")
    if executable is None:
        raise RuntimeError(
            "Nmap não foi encontrado. Instale o Nmap e reinicie o Sentinela."
        )

    command = [
        executable,
        "-n",
        "-sT",
        "-sV",
        "--version-light",
        "-T2",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "-p",
        ",".join(str(port) for port in NMAP_PORTS),
        "-oX",
        "-",
        *normalized_targets,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NMAP_SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "A verificação do Nmap excedeu 180 segundos e foi encerrada."
        ) from error
    except OSError as error:
        raise RuntimeError(f"Não foi possível iniciar o Nmap: {error}") from error

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"O Nmap encerrou com código {result.returncode}: "
            f"{detail[:500] or 'sem detalhes adicionais'}"
        )
    audit_event(
        "nmap_scan_completed",
        f"Verificação TCP concluída em {', '.join(normalized_targets)}.",
    )
    return result.stdout.encode("utf-8")


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


def run_checks(assets: list[dict[str, Any]]) -> None:
    require_admin()
    enabled_assets = [asset for asset in assets if asset["enabled"]]
    checkable_assets = [
        asset
        for asset in enabled_assets
        if asset["kind"] == "Site" or asset["port"] is not None
    ]
    skipped_assets = len(enabled_assets) - len(checkable_assets)
    if not checkable_assets:
        st.session_state["flash"] = (
            "warning",
            "Nenhum ativo tem uma porta TCP definida para verificação. "
            "Importe os serviços de um relatório XML do Nmap ou configure uma "
            "porta específica no cadastro do IP.",
        )
        return

    with st.spinner(f"Verificando {len(checkable_assets)} ativo(s)..."):
        with ThreadPoolExecutor(max_workers=min(12, len(checkable_assets))) as executor:
            results = list(executor.map(check_asset, checkable_assets))

    with database() as connection:
        connection.executemany(
            """
            INSERT INTO checks (asset_id, checked_at, status, latency_ms, message)
            VALUES (:asset_id, :checked_at, :status, :latency_ms, :message)
            """,
            results,
        )
        connection.executemany(
            """
            INSERT INTO live_status (asset_id, checked_at, status, latency_ms, message)
            VALUES (:asset_id, :checked_at, :status, :latency_ms, :message)
            ON CONFLICT(asset_id) DO UPDATE SET
                checked_at = excluded.checked_at,
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                message = excluded.message
            """,
            results,
        )
    audit_event("availability_check", f"Verificados {len(results)} ativo(s).")
    online = sum(result["status"] == "ONLINE" for result in results)
    skipped_message = (
        f" {skipped_assets} IP(s) sem porta específica não foram testados."
        if skipped_assets
        else ""
    )
    st.session_state["flash"] = (
        "warning" if online != len(results) or skipped_assets else "success",
        f"Verificação concluída: {online} online e {len(results) - online} offline."
        f"{skipped_message}",
    )


def run_automatic_checks(assets: list[dict[str, Any]]) -> tuple[int, int]:
    require_admin()
    enabled_assets = [asset for asset in assets if asset["enabled"]]
    checkable_assets = [
        asset
        for asset in enabled_assets
        if asset["kind"] == "Site" or asset["port"] is not None
    ]
    skipped_assets = len(enabled_assets) - len(checkable_assets)
    if not checkable_assets:
        return 0, skipped_assets

    with ThreadPoolExecutor(max_workers=min(12, len(checkable_assets))) as executor:
        results = list(executor.map(check_asset, checkable_assets))

    now = datetime.now().astimezone()
    with database() as connection:
        previous_samples = {
            row["asset_id"]: row["checked_at"]
            for row in connection.execute(
                """
                SELECT asset_id, MAX(checked_at) AS checked_at
                FROM checks
                WHERE asset_id IN ({})
                GROUP BY asset_id
                """.format(",".join("?" for _ in checkable_assets)),
                [asset["id"] for asset in checkable_assets],
            ).fetchall()
        }
        previous_statuses = {
            row["asset_id"]: row["status"]
            for row in connection.execute(
                "SELECT asset_id, status FROM live_status WHERE asset_id IN ({})".format(
                    ",".join("?" for _ in checkable_assets)
                ),
                [asset["id"] for asset in checkable_assets],
            ).fetchall()
        }
        connection.executemany(
            """
            INSERT INTO live_status (asset_id, checked_at, status, latency_ms, message)
            VALUES (:asset_id, :checked_at, :status, :latency_ms, :message)
            ON CONFLICT(asset_id) DO UPDATE SET
                checked_at = excluded.checked_at,
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                message = excluded.message
            """,
            results,
        )
        samples_to_store = []
        for result in results:
            asset_id = result["asset_id"]
            last_sample = previous_samples.get(asset_id)
            if last_sample is None or (
                now - datetime.fromisoformat(last_sample)
            ).total_seconds() >= LIVE_HISTORY_SAMPLE_SECONDS:
                samples_to_store.append(result)

            previous_status = previous_statuses.get(asset_id)
            if previous_status and previous_status != result["status"]:
                asset_name = next(
                    asset["name"] for asset in checkable_assets if asset["id"] == asset_id
                )
                insert_audit_event(
                    connection,
                    result["checked_at"],
                    "monitoramento",
                    "asset_status_changed",
                    f"{asset_name}: {previous_status} → {result['status']}.",
                )
        if samples_to_store:
            connection.executemany(
                """
                INSERT INTO checks (asset_id, checked_at, status, latency_ms, message)
                VALUES (:asset_id, :checked_at, :status, :latency_ms, :message)
                """,
                samples_to_store,
            )

    return len(checkable_assets), skipped_assets


@st.cache_data(show_spinner=False)
def siren_audio() -> bytes:
    sample_rate = 12_000
    duration_seconds = 3
    sample_count = sample_rate * duration_seconds
    phase = 0.0
    samples = bytearray()
    for index in range(sample_count):
        position = (index % sample_rate) / sample_rate
        frequency = 650 + 550 * (1 - abs(2 * position - 1))
        phase += 2 * math.pi * frequency / sample_rate
        envelope = min(1.0, index / 120, (sample_count - index) / 120)
        samples.extend(struct.pack("<h", int(6500 * envelope * math.sin(phase))))

    audio = io.BytesIO()
    with wave.open(audio, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(samples)
    return audio.getvalue()


def format_timestamp(value: str | None) -> str:
    if not value:
        return "Ainda não verificado"
    return datetime.fromisoformat(value).astimezone().strftime("%d/%m/%Y %H:%M:%S")


def render_login() -> None:
    _, center, _ = st.columns([1, 1.2, 1])
    with center:
        st.markdown("## :material/shield: Sentinela 3.0")
        st.caption("Central de monitoramento e defesa cibernética")
        with st.form("login_form", clear_on_submit=True):
            username = st.text_input(
                "Usuário", autocomplete="username", max_chars=32
            )
            password = st.text_input(
                "Senha",
                type="password",
                autocomplete="current-password",
                max_chars=PASSWORD_MAX_LENGTH,
            )
            submitted = st.form_submit_button(
                "Entrar", type="primary", width="stretch"
            )
        if submitted:
            authenticated, message = authenticate(username, password)
            if authenticated:
                st.rerun()
            st.error(message)
        st.caption("Acesso restrito. As atividades administrativas são auditadas.")


def render_password_change() -> None:
    st.title("Troca de senha obrigatória")
    st.info(
        "Esta conta está usando uma senha inicial ou temporária. Defina uma senha "
        "forte antes de continuar."
    )
    with st.form("required_password_change_form", clear_on_submit=True):
        current_password = st.text_input(
            "Senha atual", type="password", max_chars=PASSWORD_MAX_LENGTH
        )
        new_password = st.text_input(
            "Nova senha", type="password", max_chars=PASSWORD_MAX_LENGTH
        )
        confirmation = st.text_input(
            "Confirme a nova senha", type="password", max_chars=PASSWORD_MAX_LENGTH
        )
        submitted = st.form_submit_button(
            "Alterar senha e continuar", type="primary"
        )
    st.caption(
        f"Use no mínimo {PASSWORD_MIN_LENGTH} caracteres e pelo menos três grupos: "
        "letras minúsculas, maiúsculas, números e símbolos."
    )
    if submitted:
        try:
            change_current_password(current_password, new_password, confirmation)
            st.success("Senha alterada com sucesso.")
            st.rerun()
        except ValueError as error:
            st.error(str(error))


def render_users() -> None:
    require_admin()
    st.subheader("Gestão de usuários")
    st.caption(
        "Contas com perfil Visitante podem consultar os dados, mas não cadastrar "
        "ativos, importar relatórios ou iniciar verificações."
    )
    with st.form("create_user_form", clear_on_submit=True):
        st.markdown("**Cadastrar conta**")
        username = st.text_input("Nome de usuário", max_chars=32)
        password = st.text_input(
            "Senha inicial",
            type="password",
            autocomplete="new-password",
            max_chars=PASSWORD_MAX_LENGTH,
        )
        password_confirmation = st.text_input(
            "Confirme a senha inicial",
            type="password",
            autocomplete="new-password",
            max_chars=PASSWORD_MAX_LENGTH,
        )
        role = st.selectbox(
            "Perfil",
            options=["visitante", "admin"],
            format_func=lambda value: (
                "Visitante · somente leitura"
                if value == "visitante"
                else "Administrador"
            ),
        )
        create_clicked = st.form_submit_button(
            "Cadastrar usuário", type="primary"
        )
    if create_clicked:
        try:
            if password != password_confirmation:
                raise ValueError("A senha e a confirmação não são iguais.")
            create_user(username, password, role)
            st.success(
                f"Conta {username.strip()} criada. A pessoa deverá trocar a senha no primeiro acesso."
            )
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    users = list_users()
    user_rows = [
        {
            "Usuário": user["username"],
            "Perfil": "Administrador" if user["role"] == "admin" else "Visitante",
            "Status": "Ativo" if user["is_active"] else "Desativado",
            "Troca de senha pendente": (
                "Sim" if user["must_change_password"] else "Não"
            ),
            "Criado em": format_timestamp(user["created_at"]),
        }
        for user in users
    ]
    st.dataframe(
        pd.DataFrame(user_rows),
        hide_index=True,
        width="stretch",
        alt="Contas de usuário e seus perfis de acesso",
    )
    if not users:
        return

    selected_id = st.selectbox(
        "Gerenciar conta",
        options=[user["id"] for user in users],
        format_func=lambda user_id: next(
            user["username"] for user in users if user["id"] == user_id
        ),
    )
    selected = next(user for user in users if user["id"] == selected_id)
    with st.form("user_role_form"):
        selected_role = st.selectbox(
            "Perfil da conta",
            options=["visitante", "admin"],
            index=0 if selected["role"] == "visitante" else 1,
            format_func=lambda value: (
                "Visitante · somente leitura"
                if value == "visitante"
                else "Administrador"
            ),
        )
        save_role = st.form_submit_button("Salvar perfil")
    if save_role:
        try:
            set_user_role(selected_id, selected_role)
            st.success("Perfil atualizado.")
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    with st.form("reset_user_password_form"):
        temporary_password = st.text_input(
            "Nova senha temporária",
            type="password",
            autocomplete="new-password",
            max_chars=PASSWORD_MAX_LENGTH,
        )
        temporary_password_confirmation = st.text_input(
            "Confirme a senha temporária",
            type="password",
            autocomplete="new-password",
            max_chars=PASSWORD_MAX_LENGTH,
        )
        reset_password = st.form_submit_button("Redefinir senha")
    if reset_password:
        try:
            if temporary_password != temporary_password_confirmation:
                raise ValueError("A senha e a confirmação não são iguais.")
            set_user_password(selected_id, temporary_password)
            st.success(
                "Senha redefinida. A conta exigirá a troca no próximo acesso."
            )
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    if selected["id"] == st.session_state.get("user_id"):
        st.caption("Sua própria conta não pode ser desativada nesta tela.")
    else:
        next_active_state = not bool(selected["is_active"])
        action_label = "Reativar conta" if next_active_state else "Desativar conta"
        if st.button(action_label, key=f"user_active_{selected_id}"):
            try:
                set_user_active(selected_id, next_active_state)
                st.success("Status da conta atualizado.")
                st.rerun()
            except ValueError as error:
                st.error(str(error))


def render_audit_log() -> None:
    require_admin()
    st.subheader("Trilha de auditoria")
    events = list_audit_events()
    if not events:
        st.info("Ainda não há eventos registrados.")
        return
    rows = [
        {
            "Data e hora": format_timestamp(event["occurred_at"]),
            "Usuário": event["username"],
            "Ação": event["action"],
            "Detalhes": event["details"],
        }
        for event in events
    ]
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        alt="Eventos de autenticação e ações administrativas",
    )


def render_overview(assets: list[dict[str, Any]]) -> None:
    total = len(assets)
    network_count = len(list_networks())
    enabled_assets = [asset for asset in assets if asset["enabled"]]
    online = sum(asset["status"] == "ONLINE" for asset in enabled_assets)
    offline = sum(asset["status"] == "OFFLINE" for asset in enabled_assets)
    pending = len(enabled_assets) - online - offline
    checks = list_checks(days=1)
    completed = len(checks)
    availability = (
        sum(item["status"] == "ONLINE" for item in checks) / completed * 100
        if completed
        else None
    )

    with st.container(horizontal=True):
        st.metric("Ativos cadastrados", total, border=True)
        st.metric("Redes /24", network_count, border=True)
        st.metric("Online", online, border=True)
        st.metric("Offline", offline, border=True)
        st.metric("Pendentes", pending, border=True)
        st.metric(
            "Disponibilidade · 24h",
            f"{availability:.1f}%" if availability is not None else "—",
            border=True,
        )

    left, right = st.columns([1.5, 1], gap="medium")
    with left:
        with st.container(border=True):
            st.subheader("Ativos monitorados")
            if assets:
                rows = [
                    {
                        "Status": (
                            "Desabilitado"
                            if not asset["enabled"]
                            else "Online"
                            if asset["status"] == "ONLINE"
                            else "Offline"
                            if asset["status"] == "OFFLINE"
                            else "Pendente"
                        ),
                        "Nome": asset["name"],
                        "Tipo": asset["kind"],
                        "Endereço": asset["target"],
                        "Portas encontradas (XML)": (
                            asset["discovered_services"] or "Nenhuma porta importada"
                            if asset["kind"] == "IP"
                            else "—"
                        ),
                        "Latência": (
                            f'{asset["latency_ms"]:.1f} ms'
                            if asset["latency_ms"] is not None
                            else "—"
                        ),
                        "Última verificação": format_timestamp(asset["checked_at"]),
                    }
                    for asset in assets
                ]
                st.dataframe(
                    pd.DataFrame(rows),
                    hide_index=True,
                    width="stretch",
                    alt="Status atual dos IPs e sites cadastrados",
                )
            else:
                st.info(
                    "Nenhum ativo cadastrado. Use o formulário na barra lateral para adicionar um IP ou site."
                )

    with right:
        with st.container(border=True):
            st.subheader("Latência · últimas 24 horas")
            latency_checks = [
                item
                for item in checks
                if item["status"] == "ONLINE" and item["latency_ms"] is not None
            ]
            recorded_points = {
                (item["name"], item["checked_at"]) for item in latency_checks
            }
            latency_checks.extend(
                {
                    "name": asset["name"],
                    "checked_at": asset["checked_at"],
                    "latency_ms": asset["latency_ms"],
                }
                for asset in enabled_assets
                if asset["status"] == "ONLINE"
                and asset["latency_ms"] is not None
                and asset["checked_at"]
                and (
                    datetime.now().astimezone()
                    - datetime.fromisoformat(asset["checked_at"])
                ).total_seconds()
                <= 24 * 60 * 60
                and (asset["name"], asset["checked_at"]) not in recorded_points
            )
            if latency_checks:
                chart_data = pd.DataFrame(latency_checks)
                chart_data["Verificado em"] = pd.to_datetime(
                    chart_data["checked_at"], format="mixed"
                )
                st.line_chart(
                    chart_data,
                    x="Verificado em",
                    y="latency_ms",
                    color="name",
                    x_label="Horário",
                    y_label="Latência (ms)",
                    height=280,
                    alt="Latência dos ativos online ao longo das últimas 24 horas",
                )
            else:
                st.caption("O gráfico aparecerá após a primeira verificação.")

            st.divider()
            st.markdown("**Últimos eventos**")
            if checks:
                for item in checks[:5]:
                    icon = (
                        ":green[:material/check_circle:]"
                        if item["status"] == "ONLINE"
                        else ":red[:material/error:]"
                    )
                    st.markdown(
                        f'{icon} **{item["name"]}** · {item["message"]}'
                    )
                    st.caption(format_timestamp(item["checked_at"]))
            else:
                st.caption("Ainda não há verificações registradas.")


def render_assets(assets: list[dict[str, Any]]) -> None:
    st.subheader("Cadastro de ativos")
    st.caption(
        "Cadastre IPs sem presumir portas. Os serviços importados de XML aparecem "
        "automaticamente; a verificação TCP usa somente a porta configurada."
    )
    if not assets:
        st.info("Seu inventário está vazio. Cadastre o primeiro ativo pela barra lateral.")
        return

    rows = [
        {
            "Nome": asset["name"],
            "Tipo": asset["kind"],
            "Endereço": asset["target"],
            "Porta de verificação TCP": (
                asset["port"] or "Não definida" if asset["kind"] == "IP" else "—"
            ),
            "Portas encontradas (XML)": (
                asset["discovered_services"] or "Nenhuma porta importada"
                if asset["kind"] == "IP"
                else "—"
            ),
            "Hostname (XML)": (
                asset["hostname"] or "—" if asset["kind"] == "IP" else "—"
            ),
            "Monitoramento": "Habilitado" if asset["enabled"] else "Desabilitado",
            "Status": asset["status"] or "Pendente",
            "Última verificação": format_timestamp(asset["checked_at"]),
        }
        for asset in assets
    ]
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        alt="Inventário de IPs e sites monitorados",
    )
    if st.session_state.get("role") != "admin":
        st.info("Perfil Visitante: inventário disponível somente para consulta.")
        return

    selected_id = st.selectbox(
        "Selecione um ativo para editar ou remover",
        options=[asset["id"] for asset in assets],
        format_func=lambda asset_id: next(
            asset["name"] for asset in assets if asset["id"] == asset_id
        ),
    )
    selected = next(asset for asset in assets if asset["id"] == selected_id)
    with st.form("edit_asset_form"):
        name = st.text_input("Nome do ativo", value=selected["name"], max_chars=80)
        if selected["kind"] == "IP":
            target_input = st.text_input("Endereço IP", value=selected["target"])
            check_specific_port = st.checkbox(
                "Verificar uma porta TCP específica",
                value=selected["port"] is not None,
                key=f"asset_port_enabled_{selected_id}",
            )
            port = (
                st.number_input(
                    "Porta TCP para verificação",
                    min_value=1,
                    max_value=65535,
                    value=int(selected["port"] or 443),
                    step=1,
                    key=f"asset_port_{selected_id}",
                )
                if check_specific_port
                else None
            )
        else:
            target_input = st.text_input("URL do site", value=selected["target"])
            port = None
        enabled = st.checkbox(
            "Monitoramento habilitado", value=bool(selected["enabled"])
        )
        save, remove = st.columns(2)
        save_clicked = save.form_submit_button(
            "Salvar alterações", type="primary", width="stretch"
        )
        remove_clicked = remove.form_submit_button(
            "Remover ativo", width="stretch"
        )

    if save_clicked:
        require_admin()
        try:
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Informe um nome para o ativo.")
            clean_target = validate_target(selected["kind"], target_input)
            with database() as connection:
                connection.execute(
                    """
                    UPDATE assets
                    SET name = ?, target = ?, port = ?, enabled = ?
                    WHERE id = ?
                    """,
                    (
                        clean_name,
                        clean_target,
                        port,
                        int(enabled),
                        selected_id,
                    ),
                )
            audit_event(
                "asset_updated",
                f"Ativo {selected['name']} atualizado para {clean_target}.",
            )
            st.session_state["flash"] = ("success", "Ativo atualizado.")
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    if remove_clicked:
        require_admin()
        with database() as connection:
            connection.execute("DELETE FROM checks WHERE asset_id = ?", (selected_id,))
            connection.execute("DELETE FROM assets WHERE id = ?", (selected_id,))
        audit_event(
            "asset_deleted",
            f"Ativo {selected['name']} ({selected['target']}) removido.",
        )
        st.session_state["flash"] = (
            "success",
            "Ativo e seu histórico foram removidos.",
        )
        st.rerun()


def render_history() -> None:
    st.subheader("Histórico de verificações")
    period = st.selectbox(
        "Período",
        options=[1, 7, 30],
        format_func=lambda days: f"Último(s) {days} dia(s)",
        index=1,
    )
    history = list_checks(days=period)
    if not history:
        st.info("Não há verificações no período selecionado.")
        return

    rows = [
        {
            "Data e hora": format_timestamp(item["checked_at"]),
            "Status": "Online" if item["status"] == "ONLINE" else "Offline",
            "Nome": item["name"],
            "Tipo": item["kind"],
            "Endereço": item["target"],
            "Latência": (
                f'{item["latency_ms"]:.1f} ms'
                if item["latency_ms"] is not None
                else "—"
            ),
            "Detalhe": item["message"],
        }
        for item in history
    ]
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        alt="Histórico de disponibilidade dos ativos monitorados",
    )


def render_analytics() -> None:
    st.subheader("Análise de disponibilidade e latência")
    st.caption(
        "Tendências calculadas a partir das verificações históricas. "
        "A disponibilidade é a proporção de respostas online observadas, não um SLA."
    )
    assets = [asset for asset in list_assets() if asset["enabled"]]
    filters = st.columns(2)
    with filters[0]:
        days = st.selectbox(
            "Período da análise",
            options=[1, 7, 30],
            format_func=lambda value: {
                1: "Últimas 24 horas",
                7: "Últimos 7 dias",
                30: "Últimos 30 dias",
            }[value],
            key="analytics_period",
        )
    with filters[1]:
        selected_asset_id = st.selectbox(
            "Ativo para análise",
            options=[None, *[asset["id"] for asset in assets]],
            format_func=lambda asset_id: (
                "Todos os ativos habilitados"
                if asset_id is None
                else next(
                    asset["name"] for asset in assets if asset["id"] == asset_id
                )
            ),
            key="analytics_asset",
        )

    buckets = list_analytics_buckets(days, selected_asset_id)
    if not buckets:
        st.info(
            "Ainda não há verificações no período. Mantenha a Visão geral aberta "
            "como administrador ou use Verificar agora para gerar histórico."
        )
        return

    total_checks = sum(bucket["total_checks"] for bucket in buckets)
    online_checks = sum(bucket["online_checks"] for bucket in buckets)
    offline_checks = sum(bucket["offline_checks"] for bucket in buckets)
    latency_samples = sum(bucket["latency_samples"] for bucket in buckets)
    weighted_latency = sum(
        (bucket["avg_latency_ms"] or 0) * bucket["latency_samples"]
        for bucket in buckets
    )
    availability = online_checks / total_checks * 100
    average_latency = (
        weighted_latency / latency_samples if latency_samples else None
    )

    with st.container(horizontal=True):
        st.metric(
            "Respostas online",
            f"{availability:.2f}%",
            border=True,
        )
        st.metric("Verificações", f"{total_checks:,}", border=True)
        st.metric("Respostas offline", f"{offline_checks:,}", border=True)
        st.metric(
            "Latência média",
            f"{average_latency:.1f} ms" if average_latency is not None else "—",
            border=True,
        )

    chart_data = pd.DataFrame(buckets)
    chart_data["Horário"] = pd.to_datetime(
        chart_data["time_bucket"], format="mixed"
    )
    chart_data["Disponibilidade (%)"] = (
        chart_data["online_checks"] / chart_data["total_checks"] * 100
    )
    chart_data["Latência média (ms)"] = chart_data["avg_latency_ms"]
    chart_data["Online"] = chart_data["online_checks"]
    chart_data["Offline"] = chart_data["offline_checks"]

    left, right = st.columns(2, gap="medium")
    with left:
        with st.container(border=True):
            st.subheader("Disponibilidade ao longo do tempo")
            st.line_chart(
                chart_data,
                x="Horário",
                y="Disponibilidade (%)",
                x_label="Horário",
                y_label="Respostas online (%)",
                color="#5DD39E",
                height=300,
                alt="Percentual de verificações respondidas online por intervalo",
            )
    with right:
        with st.container(border=True):
            st.subheader("Latência média")
            st.line_chart(
                chart_data,
                x="Horário",
                y="Latência média (ms)",
                x_label="Horário",
                y_label="Latência (ms)",
                color="#27C6DA",
                height=300,
                alt="Latência média das respostas online por intervalo",
            )
    with st.container(border=True):
        st.subheader("Verificações online e offline")
        st.bar_chart(
            chart_data,
            x="Horário",
            y=["Online", "Offline"],
            x_label="Horário",
            y_label="Quantidade de verificações",
            color=["#5DD39E", "#F27575"],
            stack=True,
            height=320,
            alt="Contagem de verificações online e offline ao longo do tempo",
        )


def render_networks() -> None:
    networks = list_networks()
    is_admin = st.session_state.get("role") == "admin"
    ip_assets = [asset for asset in list_assets() if asset["kind"] == "IP"]
    st.subheader("Redes cadastradas")
    st.caption(
        "Nmap é manual e verifica somente IPs privados cadastrados que você selecionar; "
        "a faixa inteira nunca é percorrida automaticamente."
    )
    if not networks:
        st.info(
            "Nenhuma rede cadastrada."
            if not is_admin
            else "Nenhuma rede cadastrada. Adicione uma faixa /24 pela barra lateral."
        )
        return

    rows = []
    for item in networks:
        network = ipaddress.ip_network(item["cidr"])
        registered_count = sum(
            ipaddress.ip_address(asset["target"]) in network for asset in ip_assets
        )
        rows.append(
            {
                "Rede": item["name"],
                "CIDR": item["cidr"],
                "Faixa": f"{network.network_address} – {network.broadcast_address}",
                "IPs utilizáveis": network.num_addresses - 2,
                "IPs cadastrados": f"{registered_count} / {network.num_addresses - 2}",
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        alt="Redes IPv4 /24 cadastradas como referência",
    )

    selected_id = st.selectbox(
        "Selecione uma rede para editar ou excluir",
        options=[item["id"] for item in networks],
        format_func=lambda network_id: next(
            f'{item["name"]} · {item["cidr"]}'
            for item in networks
            if item["id"] == network_id
        ),
        key="selected_network_id",
    )
    selected_network = next(item for item in networks if item["id"] == selected_id)
    network = ipaddress.ip_network(selected_network["cidr"])
    scan_candidates = [
        asset
        for asset in ip_assets
        if ipaddress.ip_address(asset["target"]) in network
        and any(
            ipaddress.ip_address(asset["target"]) in private_network
            for private_network in PRIVATE_IPV4_NETWORKS
        )
    ]

    st.markdown("### Verificação manual com Nmap")
    st.caption(
        "Somente IPs privados já cadastrados nesta rede e as sete portas TCP "
        "comuns abaixo. O Sentinela não varre os 254 endereços da faixa."
    )
    executable = shutil.which("nmap") or shutil.which("nmap.exe")
    if not is_admin:
        st.info("Perfil Visitante: verificações e importações estão desabilitadas.")
    elif executable is None:
        st.info(
            "Nmap não encontrado no PATH. Instale o Nmap oficial e reinicie o Sentinela."
        )
        st.link_button(
            "Baixar Nmap para Windows",
            "https://nmap.org/download.html#windows",
        )
    elif not scan_candidates:
        st.info(
            "Cadastre ou importe IPs privados individuais nesta rede antes de usar o Nmap."
        )
    else:
        scan_choices = {
            asset["target"]: f'{asset["name"]} · {asset["target"]}'
            for asset in scan_candidates
        }
        selected_targets = st.multiselect(
            "IPs cadastrados que serão verificados",
            options=list(scan_choices),
            format_func=lambda target: scan_choices[target],
            max_selections=MAX_NMAP_TARGETS,
            key=f"nmap_targets_{selected_network['id']}",
        )
        st.caption(
            "Portas TCP verificadas: "
            + ", ".join(str(port) for port in NMAP_PORTS)
            + f". Limite de {MAX_NMAP_TARGETS} equipamentos por execução."
        )
        scan_authorized = st.checkbox(
            "Confirmo que tenho autorização para verificar estes equipamentos.",
            key=f"nmap_authorized_{selected_network['id']}",
        )
        scan_clicked = st.button(
            "Verificar serviços selecionados",
            key=f"run_nmap_{selected_network['id']}",
            type="primary",
            disabled=not selected_targets or not scan_authorized,
        )
        if scan_clicked:
            try:
                audit_event(
                    "nmap_scan_started",
                    f"Verificação manual solicitada para {', '.join(selected_targets)} em {selected_network['cidr']}.",
                )
                with st.spinner(
                    f"Verificando {len(selected_targets)} equipamento(s) "
                    "nas portas comuns..."
                ):
                    xml_content = run_nmap_scan(
                        selected_network["cidr"], selected_targets
                    )
                    hosts, out_of_scope = parse_nmap_xml(
                        selected_network["cidr"], xml_content
                    )
                    if not hosts:
                        raise RuntimeError(
                            "O Nmap não retornou hosts para os IPs selecionados. "
                            "Confira se o Nmap e o Npcap estão instalados."
                        )
                    device_count, service_count, host_count = import_nmap_xml(
                        selected_network["cidr"],
                        hosts,
                        datetime.now().astimezone().isoformat(timespec="seconds"),
                        scanned_ports=set(NMAP_PORTS),
                    )
                st.session_state["flash"] = (
                    "success",
                    f"Nmap concluído: {host_count} equipamento(s) respondendo, "
                    f"{service_count} porta(s)/serviço(s) aberto(s) identificado(s). "
                    "Veja os resultados em Equipamentos e portas reportados.",
                )
                st.rerun()
            except (RuntimeError, ValueError) as error:
                audit_event("nmap_scan_failed", str(error))
                st.error(str(error))

    with st.expander("Editar rede"):
        with st.form(f"edit_network_form_{selected_id}"):
            edited_name = st.text_input(
                "Nome da rede",
                value=selected_network["name"],
                max_chars=80,
                disabled=not is_admin,
            )
            edited_cidr = st.text_input(
                "Faixa CIDR",
                value=selected_network["cidr"],
                disabled=not is_admin,
            )
            save_network = st.form_submit_button(
                "Salvar alterações", type="primary", disabled=not is_admin
            )

        if save_network:
            require_admin()
            try:
                clean_name = edited_name.strip()
                if not clean_name:
                    raise ValueError("Informe um nome para a rede.")
                clean_cidr = validate_network_cidr(edited_cidr)
                with database() as connection:
                    duplicate = connection.execute(
                        "SELECT 1 FROM networks WHERE cidr = ? AND id != ?",
                        (clean_cidr, selected_id),
                    ).fetchone()
                    if duplicate:
                        raise ValueError(
                            "Esta faixa já está cadastrada em outra rede."
                        )
                    connection.execute(
                        "UPDATE networks SET name = ?, cidr = ? WHERE id = ?",
                        (clean_name, clean_cidr, selected_id),
                    )
                audit_event(
                    "network_updated",
                    f"Rede {selected_network['cidr']} atualizada para {clean_cidr}.",
                )
                st.session_state["flash"] = ("success", "Rede atualizada.")
                st.rerun()
            except ValueError as error:
                st.error(str(error))

    with st.expander("Excluir rede"):
        st.caption(
            "A exclusão remove somente o cadastro da faixa. Os IPs e históricos "
            "já cadastrados permanecem no inventário."
        )
        with st.form(f"delete_network_form_{selected_id}"):
            confirm_delete = st.checkbox(
                f"Confirmo a exclusão de {selected_network['cidr']}",
                disabled=not is_admin,
            )
            delete_network = st.form_submit_button(
                "Excluir rede", type="secondary", disabled=not is_admin
            )
        if delete_network:
            require_admin()
            if not confirm_delete:
                st.error("Marque a confirmação antes de excluir a rede.")
            else:
                with database() as connection:
                    connection.execute(
                        "DELETE FROM networks WHERE id = ?", (selected_id,)
                    )
                audit_event(
                    "network_deleted",
                    f"Rede {selected_network['name']} ({selected_network['cidr']}) excluída.",
                )
                st.session_state["flash"] = ("success", "Rede excluída.")
                st.rerun()

    st.markdown(f"### Importar dispositivos de {selected_network['cidr']}")
    st.caption(
        "Importe um relatório XML do Nmap gerado em uma rede que você "
        "administra. O Sentinela apenas lê o arquivo: não executa "
        "varreduras nem acessa dispositivos. Hostnames e identificação de "
        "serviços dependem das informações presentes no relatório."
    )
    xml_file = st.file_uploader(
        "Relatório XML do Nmap (máximo 5 MB)",
        type=["xml"],
        key="nmap_xml_upload",
        help="Os hosts e serviços encontrados serão adicionados ao inventário da rede selecionada.",
        disabled=not is_admin,
    )
    import_clicked = st.button(
        "Importar dispositivos e portas",
        type="primary",
        key="import_nmap_xml",
        disabled=not is_admin,
    )

    if import_clicked:
        require_admin()
        try:
            if xml_file is None:
                raise ValueError("Selecione um relatório XML para importar.")
            hosts, out_of_scope = parse_nmap_xml(
                selected_network["cidr"], xml_file.getvalue()
            )
            if not hosts:
                raise ValueError(
                    "O relatório não contém hosts IPv4 ativos dentro da rede selecionada."
                )
            device_count, service_count, host_count = import_nmap_xml(
                selected_network["cidr"],
                hosts,
                datetime.now().astimezone().isoformat(timespec="seconds"),
            )
            st.session_state["flash"] = (
                "success",
                f"Importação concluída: {host_count} host(s) ativo(s), "
                f"{device_count} IP(s) novo(s) cadastrado(s) e "
                f"{service_count} porta(s)/serviço(s) aberto(s) registrado(s). "
                f"{out_of_scope} host(s) fora da rede ignorado(s).",
            )
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    with st.expander("Cadastrar IPs informados pelo roteador"):
        st.caption(
            "Cole os IPv4 da lista de dispositivos conectados ou leases DHCP, "
            "um endereço por linha."
        )
        with st.form("network_hosts_form", clear_on_submit=True):
            host_addresses = st.text_area(
                "Endereços IP da rede",
                placeholder="192.168.0.10\n192.168.0.25",
                height=100,
                disabled=not is_admin,
            )
            add_hosts_clicked = st.form_submit_button(
                "Cadastrar IPs informados", disabled=not is_admin
            )

    if add_hosts_clicked:
        require_admin()
        try:
            addresses, repeated_count = parse_network_hosts(
                selected_network["cidr"], host_addresses
            )
            created_at = datetime.now().astimezone().isoformat(timespec="seconds")
            with database() as connection:
                existing_rows = connection.execute(
                    "SELECT target FROM assets WHERE kind = 'IP'"
                ).fetchall()
                existing_targets = {row["target"] for row in existing_rows}
                new_addresses = [
                    address for address in addresses if address not in existing_targets
                ]
                connection.executemany(
                    """
                    INSERT INTO assets (name, kind, target, port, created_at)
                    VALUES (?, 'IP', ?, NULL, ?)
                    """,
                    [
                        (
                            f"Dispositivo {address}",
                            address,
                            created_at,
                        )
                        for address in new_addresses
                    ],
                )
            audit_event(
                "network_hosts_registered",
                f"Registrados {len(new_addresses)} IP(s) na rede {selected_network['cidr']}.",
            )
            duplicate_count = len(addresses) - len(new_addresses) + repeated_count
            st.session_state["flash"] = (
                "success",
                f"{len(new_addresses)} IP(s) novo(s) cadastrado(s); "
                f"{duplicate_count} duplicado(s) ignorado(s).",
            )
            st.rerun()
        except ValueError as error:
            st.error(str(error))

    devices = list_discovered_devices(selected_network["cidr"])
    with st.container(border=True):
        st.markdown("**Equipamentos e portas reportados**")
        if devices:
            device_rows = [
                {
                    "IP": device["ip"],
                    "Equipamento": device["name"],
                    "Hostname": device["hostname"],
                    "Portas/serviços no último relatório": device["ports"],
                    "Importado em": format_timestamp(device["discovered_at"]),
                }
                for device in devices
            ]
            st.dataframe(
                pd.DataFrame(device_rows),
                hide_index=True,
                width="stretch",
                alt="Hosts e portas abertos reportados no XML importado",
            )
        else:
            st.caption("Nenhum dispositivo foi importado para esta rede.")


@st.fragment(run_every=LIVE_CHECK_INTERVAL_SECONDS, key="live_overview")
def render_live_overview() -> None:
    if not current_user_is_active():
        for key in ("authenticated", "user_id", "username", "role", "must_change_password"):
            st.session_state.pop(key, None)
        st.rerun()

    assets = list_assets()
    if st.session_state.get("role") == "admin":
        checkable_count, skipped_count = run_automatic_checks(assets)
        assets = list_assets()
    else:
        checkable_count = 0
        skipped_count = 0

    st.caption(
        f"Verificação automática a cada {LIVE_CHECK_INTERVAL_SECONDS} segundos · "
        f"Última atualização: {datetime.now().astimezone().strftime('%H:%M:%S')}"
    )
    if st.session_state.get("role") != "admin":
        st.caption(
            "Perfil Visitante: exibe o último status registrado, sem iniciar verificações."
        )
    if st.session_state.get("role") == "admin" and checkable_count == 0:
        st.info(
            "Nenhum ativo habilitado tem uma porta TCP ou URL configurada para monitoramento."
        )
    if skipped_count:
        st.caption(
            f"{skipped_count} ativo(s) habilitado(s), sem porta configurada, "
            "permanecem pendentes e não são sondados."
        )

    render_overview(assets)
    offline_assets = [
        asset for asset in assets if asset["enabled"] and asset["status"] == "OFFLINE"
    ]
    if offline_assets:
        names = ", ".join(asset["name"] for asset in offline_assets[:5])
        more = (
            f" e mais {len(offline_assets) - 5}"
            if len(offline_assets) > 5
            else ""
        )
        st.error(
            f"Alarme: {len(offline_assets)} ativo(s) offline — {names}{more}. "
            "A sirene será repetida até todos voltarem online.",
            icon=":material/notification_important:",
        )
        st.audio(
            siren_audio(),
            format="audio/wav",
            loop=True,
            autoplay=True,
            alt="Sirene repetitiva de alerta para ativos offline",
        )
        st.caption(
            "Se o navegador bloquear a reprodução automática, use os controles de áudio."
        )


@st.fragment(run_every=REFRESH_INTERVAL_SECONDS)
def render_live_section(section: str) -> None:
    st.caption(
        f"Atualização automática a cada {REFRESH_INTERVAL_SECONDS} segundos · "
        f"Última atualização: {datetime.now().astimezone().strftime('%H:%M:%S')}"
    )
    assets = list_assets()
    if section == "Ativos":
        render_assets(assets)
    elif section == "Redes /24":
        render_networks()
    elif section == "Histórico":
        render_history()
    elif section == "Análises":
        render_analytics()
    elif section == "Usuários":
        render_users()
    elif section == "Auditoria":
        render_audit_log()


st.set_page_config(
    page_title="Sentinela 3.0 · Monitoramento de rede",
    page_icon=":material/network_check:",
    layout="wide",
)

initialize_database()

if not st.session_state.get("authenticated") or not current_user_is_active():
    for key in ("authenticated", "user_id", "username", "role", "must_change_password"):
        st.session_state.pop(key, None)
    render_login()
    st.stop()

if st.session_state.get("must_change_password"):
    render_password_change()
    st.stop()

is_admin = st.session_state.get("role") == "admin"
with st.sidebar:
    st.markdown("## :material/shield: SENTINELA 3.0")
    st.caption("CENTRAL DE DEFESA CIBERNÉTICA")
    st.divider()
    st.markdown(f"**{st.session_state['username']}** · {'Administrador' if is_admin else 'Visitante'}")
    if is_admin:
        st.markdown("### Cadastrar ativo")
        asset_kind = st.selectbox("Tipo de cadastro", ["IP", "Site", "Rede /24"])
        with st.form("add_asset_form", clear_on_submit=True):
            asset_name = st.text_input(
                "Nome",
                placeholder=(
                    "Opcional · será usado Dispositivo <IP>"
                    if asset_kind == "IP"
                    else "Ex.: Servidor principal"
                ),
            )
            target_label = {
                "IP": "Endereço IP",
                "Site": "URL ou domínio",
                "Rede /24": "Faixa CIDR",
            }[asset_kind]
            target_placeholder = {
                "IP": "192.168.1.1",
                "Site": "https://exemplo.com",
                "Rede /24": "192.168.1.0/24",
            }[asset_kind]
            asset_target = st.text_input(target_label, placeholder=target_placeholder)
            add_clicked = st.form_submit_button(
                "Adicionar ativo", type="primary", width="stretch"
            )

        if add_clicked:
            require_admin()
            try:
                clean_name = asset_name.strip()
                if not clean_name and asset_kind != "IP":
                    raise ValueError("Informe um nome para o ativo.")
                if asset_kind == "Rede /24":
                    clean_target = validate_network_cidr(asset_target)
                    with database() as connection:
                        duplicate = connection.execute(
                            "SELECT 1 FROM networks WHERE cidr = ?", (clean_target,)
                        ).fetchone()
                        if duplicate:
                            raise ValueError("Esta faixa de rede já está cadastrada.")
                        connection.execute(
                            "INSERT INTO networks (name, cidr, created_at) VALUES (?, ?, ?)",
                            (
                                clean_name,
                                clean_target,
                                datetime.now().astimezone().isoformat(timespec="seconds"),
                            ),
                        )
                    audit_event("network_created", f"Rede {clean_name} ({clean_target}) cadastrada.")
                    flash_message = "Rede /24 cadastrada como referência."
                else:
                    clean_target = validate_target(asset_kind, asset_target)
                    display_name = clean_name or f"Dispositivo {clean_target}"
                    with database() as connection:
                        duplicate = connection.execute(
                            """
                            SELECT 1 FROM assets
                            WHERE kind = ? AND target = ?
                            """,
                            (asset_kind, clean_target),
                        ).fetchone()
                        if duplicate:
                            raise ValueError("Este endereço já está cadastrado.")
                        connection.execute(
                            """
                            INSERT INTO assets (name, kind, target, port, created_at)
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                display_name,
                                asset_kind,
                                clean_target,
                                None,
                                datetime.now().astimezone().isoformat(timespec="seconds"),
                            ),
                        )
                    audit_event(
                        "asset_created",
                        f"Ativo {display_name} ({asset_kind}: {clean_target}) cadastrado.",
                    )
                    flash_message = "Ativo cadastrado."
                st.session_state["flash"] = ("success", flash_message)
                st.rerun()
            except ValueError as error:
                st.error(str(error))
    else:
        st.info("Perfil Visitante: acesso somente para consulta.")
    st.divider()
    if st.button("Sair", width="stretch"):
        audit_event("logout", "Sessão encerrada.")
        for key in ("authenticated", "user_id", "username", "role", "must_change_password"):
            st.session_state.pop(key, None)
        st.rerun()
    st.caption(
        "Como administrador, mantenha a Visão geral aberta para verificar "
        "automaticamente os ativos configurados a cada 3 segundos."
    )

st.title("Sentinela 3.0")
st.caption("Defesa cibernética · monitoramento, inventário e trilha de auditoria")
flash = st.session_state.pop("flash", None)
if flash:
    level, message = flash
    if level == "warning":
        st.warning(message)
    else:
        st.success(message)
sections = ["Visão geral", "Ativos", "Redes /24", "Histórico", "Análises"]
if is_admin:
    sections.extend(["Usuários", "Auditoria"])
nav_col, action_col = st.columns([3, 1], vertical_alignment="bottom")
with nav_col:
    section = st.segmented_control(
        "Seção",
        sections,
        default="Visão geral",
        label_visibility="collapsed",
    )
with action_col:
    check_clicked = (
        st.button(
            ":material/refresh: Verificar agora",
            type="primary",
            width="stretch",
        )
        if is_admin
        else False
    )

if check_clicked:
    run_checks(list_assets())
    st.rerun()

if section == "Visão geral":
    render_live_overview()
else:
    render_live_section(section or "Ativos")
