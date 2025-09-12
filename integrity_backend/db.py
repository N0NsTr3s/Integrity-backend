import sqlite3, json, os
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
DB = str(Path(__file__).parent.parent / 'data' / 'integ.db')


def ensure_reports_columns():
    """Ensure reports table has all required columns for dashboard"""
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            
            # Check if reports table exists at all
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reports'")
            if not c.fetchone():
                # Create the reports table with all necessary columns
                c.execute("""
                CREATE TABLE reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    report_type TEXT NOT NULL DEFAULT 'unknown',
                    page_url TEXT,
                    client_ip TEXT,
                    browser TEXT,
                    browser_version TEXT,
                    platform TEXT,
                    user_agent TEXT,
                    findings_count INTEGER DEFAULT 0,
                    injections_count INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    payload TEXT
                )
                """)
                
                # Add indexes for better performance
                c.execute("""CREATE INDEX idx_reports_tenant ON reports(tenant)""")
                c.execute("""CREATE INDEX idx_reports_type ON reports(report_type)""")
                c.execute("""CREATE INDEX idx_reports_timestamp ON reports(at)""")
                
                logger.info("Created reports table with complete schema")
                return
            
            # If table exists, get current columns
            c.execute("PRAGMA table_info(reports)")
            existing_columns = {row[1] for row in c.fetchall()}
            
            # Add missing columns if needed
            needed_columns = {
                'report_type': 'TEXT NOT NULL DEFAULT "unknown"',
                'findings_count': 'INTEGER DEFAULT 0',
                'injections_count': 'INTEGER DEFAULT 0', 
                'risk_level': 'TEXT DEFAULT "low"',
                'browser': 'TEXT',
                'browser_version': 'TEXT',
                'platform': 'TEXT',
                'user_agent': 'TEXT',
                'page_url': 'TEXT'
            }
            
            for col_name, col_type in needed_columns.items():
                if col_name not in existing_columns:
                    try:
                        c.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}")
                        logger.info(f"Added column {col_name} to reports table")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"Could not add column {col_name}: {e}")
            
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database column migration error: {e}")


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
    ensure_reports_columns()


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
