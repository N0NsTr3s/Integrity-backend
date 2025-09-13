import logging
import json
import os
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logger = logging.getLogger(__name__)

# PostgreSQL Connection Details
DB_HOST = os.environ.get('DB_HOST', 'reder_db_host')
DB_NAME = os.environ.get('DB_NAME', 'integrity_db')
DB_USER = os.environ.get('DB_USER', 'render_secret_user')
DB_PASS = os.environ.get('DB_PASS', 'render_secret_password')
DB_PORT = os.environ.get('DB_PORT', '5432')

def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT
        )
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_db():
    """Initialize database tables and add missing columns"""
    try:
        conn = get_db_connection()
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as c:
            
            # Create manifests table if not exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS manifests (
                    tenant TEXT PRIMARY KEY, 
                    manifest TEXT
                )
            ''')
            
            # Create tenants table if not exists
            c.execute('''
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant TEXT PRIMARY KEY,
                    api_key TEXT,
                    allowed_origins TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Handle reports table - check if exists first
            c.execute('''
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'reports'
                )
            ''')
            table_exists = c.fetchone()[0] # pyright: ignore[reportOptionalSubscript]
            
            if not table_exists:
                # Create the reports table with all necessary columns
                c.execute('''
                    CREATE TABLE reports (
                        id SERIAL PRIMARY KEY,
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
                ''')
                
                # Add indexes for better performance
                c.execute('CREATE INDEX idx_reports_tenant ON reports(tenant)')
                c.execute('CREATE INDEX idx_reports_type ON reports(report_type)')
                c.execute('CREATE INDEX idx_reports_timestamp ON reports(at)')
                c.execute('CREATE INDEX idx_reports_client_ip ON reports(client_ip)')
                
                logger.info("Created reports table with complete schema")
            else:
                # Table exists, check columns and add missing ones
                c.execute('''
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'reports'
                ''')
                existing_columns = {row[0] for row in c.fetchall()}
                
                # Define required columns with their types
                needed_columns = {
                    'tenant': 'TEXT NOT NULL',
                    'report_type': 'TEXT NOT NULL DEFAULT \'unknown\'',
                    'page_url': 'TEXT',
                    'client_ip': 'TEXT',
                    'browser': 'TEXT',
                    'browser_version': 'TEXT',
                    'platform': 'TEXT',
                    'user_agent': 'TEXT',
                    'findings_count': 'INTEGER DEFAULT 0',
                    'injections_count': 'INTEGER DEFAULT 0',
                    'risk_level': 'TEXT DEFAULT \'low\'',
                    'at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
                    'payload': 'TEXT'
                }
                
                # Add missing columns
                for col_name, col_type in needed_columns.items():
                    if col_name.lower() not in existing_columns:
                        try:
                            c.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_type}")
                            logger.info(f"Added column {col_name} to reports table")
                        except psycopg2.Error as e:
                            logger.warning(f"Could not add column {col_name}: {e}")
            
            logger.info("Database schema initialized successfully")
        conn.close()
            
    except psycopg2.Error as e:
        logger.error(f"Database initialization error: {e}")

def get_tenant_record(tenant_id: str):
    """Get tenant record from database"""
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as c:
            c.execute("SELECT * FROM tenants WHERE tenant = %s", (tenant_id,))
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
        conn.close()
    except psycopg2.Error as e:
        logger.error(f"Database error getting tenant: {e}")
        return None
