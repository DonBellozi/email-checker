from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "/app/data/email-checker.db")

DEFAULT_DOMAINS = [
    "gmail.com", "googlemail.com",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru", "internet.ru",
    "yandex.ru", "ya.ru",
    "rambler.ru",
    "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "me.com",
    "yahoo.com",
    "proton.me", "protonmail.com",
]

DEFAULT_SETTINGS = {
    "cache_positive_hours": "168",
    "cache_negative_hours": "24",
    "cache_temporary_minutes": "30",
    "smtp_timeout_seconds": "4",
    "dns_timeout_seconds": "3",
    "ipv6_enabled": "1",
    "max_addresses": "100",
}

DEFAULT_SMTP_STATUSES = [
    ("2.0.0", "Письмо доставлено", "Доставка завершена успешно."),
    ("4.2.2", "Доставка задерживается", "Почтовый ящик временно недоступен или переполнен. Сервер может повторить попытку позже."),
    ("4.4.1", "Доставка задерживается", "Не удалось связаться с сервером назначения. Сервер продолжит повторные попытки."),
    ("4.7.1", "Доставка временно отклонена", "Сервер получателя временно отклонил сообщение политикой безопасности или антиспамом."),
    ("5.1.1", "Получатель не найден", "Почтовый сервер сообщает, что такого адреса получателя нет."),
    ("5.1.2", "Проверьте домен", "Не удалось определить домен или систему назначения получателя."),
    ("5.2.1", "Почтовый ящик недоступен", "Ящик существует, но не принимает сообщения."),
    ("5.2.2", "Почтовый ящик переполнен", "На стороне получателя недостаточно свободного места."),
    ("5.3.4", "Сообщение слишком большое", "Размер письма превышает ограничение почтовой системы."),
    ("5.4.1", "Проверьте адрес или маршрут", "Сервер не смог доставить письмо по указанному адресу или маршруту."),
    ("5.7.1", "Письмо отклонено", "Сообщение отклонено политикой безопасности или антиспамом сервера получателя."),
]


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS standard_domains (
                domain TEXT PRIMARY KEY COLLATE NOCASE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domain_cache (
                domain TEXT PRIMARY KEY COLLATE NOCASE,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS smtp_statuses (
                code TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_user (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL,
                password_hash BLOB NOT NULL
            );
            """
        )
        for key, value in DEFAULT_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (key, value))
        for domain in DEFAULT_DOMAINS:
            conn.execute(
                "INSERT OR IGNORE INTO standard_domains(domain, created_at) VALUES(?, ?)",
                (domain, utcnow_iso()),
            )
        for code, title, explanation in DEFAULT_SMTP_STATUSES:
            conn.execute(
                "INSERT OR IGNORE INTO smtp_statuses(code, title, explanation) VALUES(?, ?, ?)",
                (code, title, explanation),
            )


def get_setting(key: str, default: str | None = None) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def get_settings() -> dict[str, str]:
    with connect() as conn:
        return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM settings")}


def set_settings(values: dict[str, str]) -> None:
    with connect() as conn:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )


def list_standard_domains() -> list[str]:
    with connect() as conn:
        return [r["domain"] for r in conn.execute("SELECT domain FROM standard_domains ORDER BY domain")]


def add_standard_domain(domain: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO standard_domains(domain, created_at) VALUES(?, ?)",
            (domain.lower(), utcnow_iso()),
        )


def delete_standard_domain(domain: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM standard_domains WHERE domain = ?", (domain.lower(),))


def get_cache(domain: str) -> dict | None:
    now = datetime.now(timezone.utc)
    with connect() as conn:
        row = conn.execute("SELECT * FROM domain_cache WHERE domain = ?", (domain.lower(),)).fetchone()
        if not row:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None
        if expires <= now:
            conn.execute("DELETE FROM domain_cache WHERE domain = ?", (domain.lower(),))
            return None
        payload = json.loads(row["payload"])
        payload["cached"] = True
        payload["checked_at"] = row["checked_at"]
        payload["expires_at"] = row["expires_at"]
        return payload


def put_cache(domain: str, status: str, payload: dict, expires_at: str) -> None:
    checked = utcnow_iso()
    body = dict(payload)
    body.pop("cached", None)
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO domain_cache(domain, status, payload, checked_at, expires_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                status=excluded.status,
                payload=excluded.payload,
                checked_at=excluded.checked_at,
                expires_at=excluded.expires_at
            """,
            (domain.lower(), status, json.dumps(body, ensure_ascii=False), checked, expires_at),
        )


def list_cache(limit: int = 500) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT domain, status, payload, checked_at, expires_at FROM domain_cache ORDER BY checked_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        payload = json.loads(row["payload"])
        result.append({
            "domain": row["domain"],
            "status": row["status"],
            "checked_at": row["checked_at"],
            "expires_at": row["expires_at"],
            "ipv4": payload.get("ipv4", []),
            "ipv6": payload.get("ipv6", []),
            "smtp_protocol": payload.get("smtp_protocol"),
        })
    return result


def clear_cache() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM domain_cache")


def get_smtp_status(code: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT code, title, explanation FROM smtp_statuses WHERE code = ?", (code,)).fetchone()
        return dict(row) if row else None


def list_smtp_statuses() -> list[dict]:
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT code, title, explanation FROM smtp_statuses ORDER BY code")]


def upsert_smtp_status(code: str, title: str, explanation: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO smtp_statuses(code, title, explanation) VALUES(?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET title=excluded.title, explanation=excluded.explanation
            """,
            (code.strip(), title.strip(), explanation.strip()),
        )


def delete_smtp_status(code: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM smtp_statuses WHERE code = ?", (code,))
