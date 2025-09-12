import sqlite3, json, os
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
DB = str(Path(__file__).parent.parent / 'data' / 'integ.db')


def init_db():
    data_dir = Path(DB).parent
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS manifests (tenant TEXT PRIMARY KEY, manifest TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS tenants (
                tenant TEXT PRIMARY KEY,
                api_key TEXT,
                allowed_origins TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            # Reports table migration handled in original main; create minimal if absent
            c.execute("PRAGMA table_info(reports)")
            cols = {r[1] for r in c.fetchall()}
            if not cols:
                c.execute('''CREATE TABLE reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    payload TEXT,
                    at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
            conn.commit()
            logger.info('DB initialized')
    except sqlite3.Error as e:
        logger.error(f"DB init error: {e}")


def get_tenant_record(tenant_id: str):
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM tenants WHERE tenant=?", (tenant_id,))
            row = c.fetchone()
            return dict(row) if row else None
    except sqlite3.Error as e:
        logger.error(f"DB error fetching tenant {tenant_id}: {e}")
        return None
