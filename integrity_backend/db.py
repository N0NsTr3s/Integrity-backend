import sqlite3
import logging
import json
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Database setup
DB_DIR = Path(__file__).parent.parent / 'data'
DB_DIR.mkdir(parents=True, exist_ok=True)
DB = str(DB_DIR / 'integ.db')

def init_db():
    """Initialize database tables and add missing columns"""
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            
            # Create manifests table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS manifests (tenant TEXT PRIMARY KEY, manifest TEXT)''')
            
            # Create tenants table if not exists
            c.execute('''CREATE TABLE IF NOT EXISTS tenants (
                tenant TEXT PRIMARY KEY,
                api_key TEXT,
                allowed_origins TEXT,   -- JSON array string
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            
            # Handle reports table - check if exists first
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reports'")
            if not c.fetchone():
                # Create the reports table with all necessary columns
                c.execute('''CREATE TABLE reports (
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
                )''')
                
                # Add indexes for better performance
                c.execute('''CREATE INDEX idx_reports_tenant ON reports(tenant)''')
                c.execute('''CREATE INDEX idx_reports_type ON reports(report_type)''')
                c.execute('''CREATE INDEX idx_reports_timestamp ON reports(at)''')
                
                logger.info("Created reports table with complete schema")
            else:
                # Table exists, check columns and add missing ones
                c.execute("PRAGMA table_info(reports)")
                existing_columns = {row[1] for row in c.fetchall()}
                
                # Define required columns with their types
                needed_columns = {
                    'tenant': 'TEXT NOT NULL',
                    'report_type': 'TEXT NOT NULL DEFAULT "unknown"',
                    'page_url': 'TEXT',
                    'client_ip': 'TEXT',
                    'browser': 'TEXT',
                    'browser_version': 'TEXT',
                    'platform': 'TEXT',
                    'user_agent': 'TEXT',
                    'findings_count': 'INTEGER DEFAULT 0',
                    'injections_count': 'INTEGER DEFAULT 0',
                    'risk_level': 'TEXT DEFAULT "low"',
                    'at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
                    'payload': 'TEXT'
                }
                
                # Add missing columns
                for col_name, col_type in needed_columns.items():
                    if col_name not in existing_columns:
                        try:
                            c.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}")
                            logger.info(f"Added column {col_name} to reports table")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Could not add column {col_name}: {e}")
            
            # Ensure indexes exist (won't fail if they already exist)
            try:
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports(tenant)''')
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type)''')
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON reports(at)''')
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_client_ip ON reports(client_ip)''')
            except sqlite3.OperationalError:
                pass  # Indexes might already exist
                
            conn.commit()
            logger.info("Database schema initialized successfully")
            
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")

def get_tenant_record(tenant_id: str):
    """Get tenant record from database"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM tenants WHERE tenant = ?", (tenant_id,))
            row = c.fetchone()
            if row:
                # Parse allowed_origins JSON if exists
                result = dict(row)
                if 'allowed_origins' in result and result['allowed_origins']:
                    try:
                        result['allowed_origins'] = json.loads(result['allowed_origins'])
                    except:
                        result['allowed_origins'] = []
                return result
            return None
    except sqlite3.Error as e:
        logger.error(f"Database error getting tenant: {e}")
        return None
