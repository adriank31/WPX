"""
SQLite persistence layer for attack results.
Stores completed attack outcomes so they survive server restarts.
"""

import sqlite3
import json
import time
from pathlib import Path

DB_PATH = Path("core/db/results.db")


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the results and recon_aps tables if they do not exist."""
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id          TEXT PRIMARY KEY,
                timestamp   REAL NOT NULL,
                module      TEXT NOT NULL,
                target_bssid TEXT DEFAULT '',
                target_ssid  TEXT DEFAULT '',
                result       TEXT DEFAULT '',
                extra_data   TEXT DEFAULT '{}'
            )
        """)
        # item 6: persistent recon inventory — upserted by BSSID so repeated
        # scans across sessions build a running target list instead of
        # losing everything when the in-memory dict is cleared/restarted.
        c.execute("""
            CREATE TABLE IF NOT EXISTS recon_aps (
                bssid        TEXT PRIMARY KEY,
                essid        TEXT DEFAULT '',
                channel      TEXT DEFAULT '',
                privacy      TEXT DEFAULT '',
                power        TEXT DEFAULT '',
                vendor       TEXT DEFAULT '',
                vulnerabilities TEXT DEFAULT '[]',
                first_seen   REAL NOT NULL,
                last_seen    REAL NOT NULL
            )
        """)
        c.commit()


def save_result(
    task_id: str,
    module: str,
    target_bssid: str = "",
    target_ssid: str = "",
    result: str = "",
    extra_data: dict = None,
) -> None:
    """Upsert one attack result row."""
    try:
        with _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?,?)",
                (
                    task_id,
                    time.time(),
                    module,
                    target_bssid,
                    target_ssid,
                    result,
                    json.dumps(extra_data or {}),
                ),
            )
            c.commit()
    except Exception as e:
        print(f"[!] DB save error: {e}")


def get_results(limit: int = 200):
    """Return recent results, newest first."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT * FROM results ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["extra_data"] = json.loads(d["extra_data"])
                except Exception:
                    pass
                out.append(d)
            return out
    except Exception:
        return []


def save_recon_ap(
    bssid: str,
    essid: str = "",
    channel: str = "",
    privacy: str = "",
    power: str = "",
    vendor: str = "",
    vulnerabilities: list = None,
) -> None:
    """Item 6: upsert one discovered AP into the persistent recon inventory.

    Keeps first_seen from the original row and bumps last_seen + refreshes
    the rest of the fields with whatever was most recently observed.
    """
    try:
        now = time.time()
        with _conn() as c:
            existing = c.execute(
                "SELECT first_seen FROM recon_aps WHERE bssid = ?", (bssid,)
            ).fetchone()
            first_seen = existing["first_seen"] if existing else now
            c.execute(
                """INSERT OR REPLACE INTO recon_aps
                   (bssid, essid, channel, privacy, power, vendor,
                    vulnerabilities, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    bssid, essid, channel, privacy, power, vendor,
                    json.dumps(vulnerabilities or []),
                    first_seen, now,
                ),
            )
            c.commit()
    except Exception as e:
        print(f"[!] DB recon save error: {e}")


def get_recon_history(limit: int = 500):
    """Item 6: return all-time discovered APs, most recently seen first."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT * FROM recon_aps ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["vulnerabilities"] = json.loads(d["vulnerabilities"])
                except Exception:
                    d["vulnerabilities"] = []
                out.append(d)
            return out
    except Exception:
        return []
