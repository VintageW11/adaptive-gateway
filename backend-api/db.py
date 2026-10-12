"""SQLite persistence for AutoVPN accounts, sessions, and bound devices."""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

DATA_DIR = Path(os.environ.get(
    "AUTOVPN_DATA_DIR",
    str(Path(__file__).resolve().parent.parent / "data"),
))
DB_PATH = DATA_DIR / "autovpn.db"

# scrypt params — fine for lab / few accounts
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, dig_hex = stored.split("$", 2)
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=32,
        )
        return secrets.compare_digest(digest.hex(), dig_hex)
    except Exception:
        return False


def init_db() -> None:
    """Create schema. Keep existing accounts; never seed a known password."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE COLLATE NOCASE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('admin','user')),
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_devices (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              ip TEXT,
              mac TEXT,
              created_at REAL NOT NULL,
              UNIQUE(user_id, ip)
            );
            CREATE TABLE IF NOT EXISTS bug_reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user TEXT NOT NULL,
              created REAL NOT NULL,
              title TEXT NOT NULL,
              body TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'new'
                CHECK(status IN ('new','seen','done')),
              note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices(user_id);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_bug_reports_created ON bug_reports(created);
            """
        )
        bug_cols = {r[1] for r in conn.execute("PRAGMA table_info(bug_reports)").fetchall()}
        if "note" not in bug_cols:
            conn.execute("ALTER TABLE bug_reports ADD COLUMN note TEXT")
        user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "data_consent" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN data_consent INTEGER NOT NULL DEFAULT 0")
        if "data_consent_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN data_consent_at REAL")
        if "gateway_connected" not in user_cols:
            conn.execute(
                "ALTER TABLE users ADD COLUMN gateway_connected INTEGER NOT NULL DEFAULT 1"
            )
        dups = conn.execute(
            """
            SELECT ip FROM user_devices
            WHERE ip IS NOT NULL AND ip != ''
            GROUP BY ip HAVING COUNT(*) > 1
            """
        ).fetchall()
        for d in dups:
            extras = conn.execute(
                "SELECT id FROM user_devices WHERE ip = ? ORDER BY id",
                (d["ip"],),
            ).fetchall()
            for extra in extras[1:]:
                conn.execute("UPDATE user_devices SET ip = NULL WHERE id = ?", (extra["id"],))
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_ip "
            "ON user_devices(ip) WHERE ip IS NOT NULL AND ip != ''"
        )
        # Ensure legacy demo account is gone. Do not insert admin/admin.
        conn.execute("DELETE FROM users WHERE username = ? AND role = ?", ("user", "user"))
        conn.execute(
            "DELETE FROM sessions WHERE created_at < ?",
            (time.time() - 14 * 24 * 3600,),
        )
        conn.commit()


def _password_is_strong(password: str) -> bool:
    if len(password or "") < 8:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_lower and has_upper and has_digit and has_symbol


def create_user(username: str, password: str, role: str = "user", allow_admin: bool = False) -> dict | None:
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("username and password required")
    if len(username) < 3:
        raise ValueError("username must be at least 3 characters")
    if not _password_is_strong(password):
        raise ValueError(
            "Password must be at least 8 characters and include an uppercase letter, "
            "a lowercase letter, a number, and a symbol."
        )
    if username.lower() == "admin" and role != "admin":
        raise ValueError("username reserved")
    if role == "admin" and not allow_admin:
        role = "user"
    role = role if role in ("admin", "user") else "user"
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, gateway_connected) VALUES (?,?,?,?,1)",
                (username, hash_password(password), role, time.time()),
            )
            conn.commit()
            return {"id": cur.lastrowid, "username": username, "role": role, "data_consent": False}
    except sqlite3.IntegrityError:
        raise ValueError("username already taken") from None


def _consent_flag(row) -> bool:
    try:
        return bool(int(row["data_consent"] or 0))
    except (KeyError, TypeError, ValueError):
        return False


def authenticate(username: str, password: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, data_consent FROM users WHERE username = ? COLLATE NOCASE",
            ((username or "").strip(),),
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "data_consent": _consent_flag(row),
    }


def create_session(user_id: int) -> str:
    token = secrets.token_hex(24)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)",
            (token, user_id, time.time()),
        )
        conn.commit()
    return token


def user_from_token(token: str | None) -> dict | None:
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, u.data_consent
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "data_consent": _consent_flag(row),
    }


def delete_session(token: str | None) -> None:
    if not token:
        return
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def list_accounts(query: str = "") -> list[dict]:
    q = (query or "").strip()
    with _connect() as conn:
        if q:
            rows = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.created_at,
                       (SELECT COUNT(*) FROM user_devices d WHERE d.user_id = u.id) AS device_count
                FROM users u
                WHERE u.username LIKE ? COLLATE NOCASE
                ORDER BY u.role DESC, u.username COLLATE NOCASE
                """,
                (f"%{q}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.created_at,
                       (SELECT COUNT(*) FROM user_devices d WHERE d.user_id = u.id) AS device_count
                FROM users u
                ORDER BY u.role DESC, u.username COLLATE NOCASE
                """
            ).fetchall()
    return [
        {
            "id": r["id"],
            "username": r["username"],
            "role": r["role"],
            "created_at": r["created_at"],
            "device_count": r["device_count"],
        }
        for r in rows
    ]


def get_account(user_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, username, role, created_at, data_consent, data_consent_at, gateway_connected FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "data_consent": _consent_flag(row),
        "data_consent_at": row["data_consent_at"],
        "gateway_connected": bool(row["gateway_connected"]),
    }


def is_gateway_connected(user_id: int) -> bool:
    acct = get_account(user_id)
    if not acct:
        return False
    return bool(acct.get("gateway_connected"))


def set_gateway_connected(user_id: int, connected: bool) -> dict | None:
    if not user_id:
        return None
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET gateway_connected = ? WHERE id = ?",
            (1 if connected else 0, user_id),
        )
    return get_account(user_id)


def list_user_devices(user_id: int) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, user_id, name, ip, mac, created_at
            FROM user_devices WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _claim_addr_exclusive(conn: sqlite3.Connection, user_id: int, ip: str | None, mac: str | None) -> None:
    """This account owns the address. Other accounts keep the row, not the IP/MAC."""
    if ip:
        conn.execute(
            "UPDATE user_devices SET ip = NULL WHERE ip = ? AND user_id != ?",
            (ip, user_id),
        )
    if mac:
        conn.execute(
            "UPDATE user_devices SET mac = NULL WHERE mac = ? AND user_id != ?",
            (mac, user_id),
        )


def get_user_id_for_ip(ip: str) -> int | None:
    ip = (ip or "").strip()
    if not ip:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT user_id FROM user_devices WHERE ip = ?",
            (ip,),
        ).fetchone()
    return int(row["user_id"]) if row else None


def add_user_device(user_id: int, name: str, ip: str | None, mac: str | None) -> dict:
    name = (name or "").strip() or "My device"
    ip = (ip or "").strip() or None
    mac = (mac or "").strip().upper() or None
    with _connect() as conn:
        _claim_addr_exclusive(conn, user_id, ip, mac)
        if ip:
            existing = conn.execute(
                "SELECT id FROM user_devices WHERE user_id = ? AND ip = ?",
                (user_id, ip),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE user_devices SET name = ?, mac = COALESCE(?, mac) WHERE id = ?",
                    (name, mac, existing["id"]),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT id, user_id, name, ip, mac, created_at FROM user_devices WHERE id = ?",
                    (existing["id"],),
                ).fetchone()
                return dict(row)
        cur = conn.execute(
            """
            INSERT INTO user_devices (user_id, name, ip, mac, created_at)
            VALUES (?,?,?,?,?)
            """,
            (user_id, name, ip, mac, time.time()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, user_id, name, ip, mac, created_at FROM user_devices WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
        return dict(row)


def update_user_device_addr(
    user_id: int, device_id: int, ip: str | None, mac: str | None = None,
) -> dict | None:
    """Move a bound device to a new DHCP/overlay IP. Does not insert a second row."""
    ip = (ip or "").strip() or None
    mac = (mac or "").strip().upper() or None
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM user_devices WHERE id = ? AND user_id = ?",
            (device_id, user_id),
        ).fetchone()
        if not row:
            return None
        _claim_addr_exclusive(conn, user_id, ip, mac)
        conn.execute(
            "UPDATE user_devices SET ip = ?, mac = COALESCE(?, mac) WHERE id = ? AND user_id = ?",
            (ip, mac, device_id, user_id),
        )
        conn.commit()
        out = conn.execute(
            "SELECT id, user_id, name, ip, mac, created_at FROM user_devices WHERE id = ?",
            (device_id,),
        ).fetchone()
    return dict(out) if out else None


def get_user_device(user_id: int, device_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, name, ip, mac, created_at
            FROM user_devices WHERE id = ? AND user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()
    return dict(row) if row else None


def delete_user_device(user_id: int, device_id: int) -> dict | None:
    """Unbind a device from this account. Does not touch live VPN ifaces."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, name, ip, mac, created_at
            FROM user_devices WHERE id = ? AND user_id = ?
            """,
            (device_id, user_id),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "DELETE FROM user_devices WHERE id = ? AND user_id = ?",
            (device_id, user_id),
        )
        conn.commit()
    return dict(row)


def has_admin() -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
    return row is not None


def admin_count() -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
        ).fetchone()
    return int(row["n"] if row else 0)


def delete_user(user_id: int) -> dict:
    """Delete an account, sessions, and bound devices. Refuses the last admin."""
    acct = get_account(user_id)
    if not acct:
        raise ValueError("account not found")
    if acct["role"] == "admin" and admin_count() <= 1:
        raise ValueError("cannot delete the last admin")
    with _connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return acct


def set_data_consent(user_id: int, consented: bool) -> dict | None:
    """Record data-collection consent on the account. Lab UI only sets True."""
    if not user_id:
        return None
    ts = time.time() if consented else None
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET data_consent = ?, data_consent_at = ? WHERE id = ?",
            (1 if consented else 0, ts, user_id),
        )
        conn.commit()
    return get_account(user_id)


def get_first_admin() -> dict | None:
    """Prefer username 'admin', else the oldest admin row."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, username, role, created_at, data_consent FROM users
            WHERE role = 'admin'
            ORDER BY CASE WHEN username = 'admin' COLLATE NOCASE THEN 0 ELSE 1 END,
                     id ASC
            LIMIT 1
            """
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "data_consent": _consent_flag(row),
    }


def set_password(user_id: int, password: str) -> None:
    """Reset a password. Never called from the public UI."""
    if not password or len(password) < 4:
        raise ValueError("password must be at least 4 characters")
    acct = get_account(user_id)
    if not acct:
        raise ValueError("account not found")
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), user_id),
        )
        conn.commit()


def keep_single_lan_admin(password: str | None = None) -> dict:
    """Wipe extra lab users; keep one admin for 192.168.50.x logins.

    If password is set, that admin's hash is replaced. The caller must tell the
    operator; do not print the password in HTML or README.
    """
    keep = get_first_admin()
    deleted: list[str] = []
    with _connect() as conn:
        rows = conn.execute("SELECT id, username, role FROM users").fetchall()
        for row in rows:
            if keep and row["id"] == keep["id"]:
                continue
            deleted.append(row["username"])
            conn.execute("DELETE FROM users WHERE id = ?", (row["id"],))
        conn.commit()
    created = False
    password_reset = False
    if keep is None and password:
        keep = create_user("admin", password, role="admin", allow_admin=True)
        created = True
        password_reset = True
    elif keep is not None and password:
        set_password(keep["id"], password)
        password_reset = True
        keep = get_account(keep["id"]) or keep
    return {
        "kept": keep,
        "deleted": deleted,
        "created": created,
        "password_reset": password_reset,
    }


_BUG_STATUSES = ("new", "seen", "done")


def _bug_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "user": row["user"],
        "created": row["created"],
        "title": row["title"],
        "body": row["body"],
        "status": row["status"],
        "note": row["note"] or "",
    }


def create_bug(username: str, title: str, body: str) -> dict:
    title = (title or "").strip()
    body = (body or "").strip()
    username = (username or "").strip() or "unknown"
    if not title:
        raise ValueError("title required")
    if not body:
        raise ValueError("description required")
    if len(title) > 200:
        raise ValueError("title must be 200 characters or less")
    if len(body) > 4000:
        raise ValueError("description must be 4000 characters or less")
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO bug_reports (user, created, title, body, status)
            VALUES (?,?,?,?,?)
            """,
            (username, time.time(), title, body, "new"),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, user, created, title, body, status, note FROM bug_reports WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()
    return _bug_row(row)


def list_bugs() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, user, created, title, body, status, note
            FROM bug_reports
            ORDER BY created DESC, id DESC
            """
        ).fetchall()
    return [_bug_row(r) for r in rows]


def get_bug(bug_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, user, created, title, body, status, note FROM bug_reports WHERE id = ?",
            (bug_id,),
        ).fetchone()
    return _bug_row(row) if row else None


def update_bug(bug_id: int, status: str | None = None, note: str | None = None) -> dict:
    bug = get_bug(bug_id)
    if not bug:
        raise ValueError("bug not found")
    new_status = bug["status"]
    new_note = bug["note"]
    if status is not None:
        status = str(status).strip().lower()
        if status not in _BUG_STATUSES:
            raise ValueError("status must be new, seen, or done")
        new_status = status
    if note is not None:
        new_note = str(note)
        if len(new_note) > 2000:
            raise ValueError("note must be 2000 characters or less")
    with _connect() as conn:
        conn.execute(
            "UPDATE bug_reports SET status = ?, note = ? WHERE id = ?",
            (new_status, new_note, bug_id),
        )
        conn.commit()
    updated = get_bug(bug_id)
    if not updated:
        raise ValueError("bug not found")
    return updated
