import logging
import json
import os
import re
import html
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# PostgreSQL Connection Details
DB_HOST = os.environ.get('DB_HOST', 'reder_db_host')
DB_NAME = os.environ.get('DB_NAME', 'integrity_db_ap6p')
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

# Add these sanitization helper functions

def sanitize_string(value: Optional[str], max_length: int = 1000) -> Optional[str]:
    """
    Sanitize a string value by stripping dangerous characters and truncating it.
    
    Args:
        value: The string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string or None if input is None
    """
    if value is None:
        return None
    
    # Convert to string if not already
    if not isinstance(value, str):
        value = str(value)
    
    # Remove any control characters
    value = ''.join(c for c in value if ord(c) >= 32 or c == '\n' or c == '\t')
    
    # HTML encode to prevent XSS when displayed
    value = html.escape(value)
    
    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + "..."
    
    return value

def sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize a report payload before storing in database.
    
    Args:
        payload: The payload dictionary
        
    Returns:
        Sanitized payload dictionary
    """
    if not payload or not isinstance(payload, dict):
        return {}
    
    result = {}
    
    # Copy and sanitize top-level fields
    for key, value in payload.items():
        # Skip if key is not a string or is too long
        if not isinstance(key, str) or len(key) > 100:
            continue
            
        if isinstance(value, str):
            # Sanitize string values
            result[key] = sanitize_string(value)
        elif isinstance(value, (int, float, bool)) or value is None:
            # Primitive types are safe
            result[key] = value
        elif isinstance(value, dict):
            # Recursively sanitize nested dictionaries
            result[key] = sanitize_payload(value)
        elif isinstance(value, list):
            # Sanitize lists (important for findings and injections)
            sanitized_list = []
            for item in value[:1000]:  # Limit list length
                if isinstance(item, dict):
                    sanitized_list.append(sanitize_payload(item))
                elif isinstance(item, str):
                    sanitized_list.append(sanitize_string(item))
                elif isinstance(item, (int, float, bool)) or item is None:
                    sanitized_list.append(item)
                # Skip other types
            result[key] = sanitized_list
    
    return result

def sanitize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Specifically sanitize findings data which may contain file paths and security issues.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Sanitized findings list
    """
    if not findings or not isinstance(findings, list):
        return []
    
    sanitized_findings = []
    
    # Limit number of findings to prevent DoS
    for finding in findings[:1000]:
        if not isinstance(finding, dict):
            continue
            
        sanitized_finding = {}
        
        # Sanitize common finding fields
        if 'url' in finding:
            sanitized_finding['url'] = sanitize_string(finding['url'], 2000)
        
        if 'path' in finding:
            sanitized_finding['path'] = sanitize_string(finding['path'], 2000)
            
        if 'issue' in finding:
            sanitized_finding['issue'] = sanitize_string(finding['issue'], 100)
            
        if 'risk_level' in finding:
            # Ensure risk_level is one of allowed values
            risk = finding['risk_level']
            if risk in ('critical', 'high', 'medium', 'low', 'info'):
                sanitized_finding['risk_level'] = risk
            else:
                sanitized_finding['risk_level'] = 'low'
        
        # Copy other fields with generic sanitization
        for key, value in finding.items():
            if key not in sanitized_finding:
                if isinstance(value, str):
                    sanitized_finding[key] = sanitize_string(value)
                elif isinstance(value, (int, float, bool)) or value is None:
                    sanitized_finding[key] = value
        
        sanitized_findings.append(sanitized_finding)
    
    return sanitized_findings

def sanitize_injections(injections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Specifically sanitize injection data which may contain malicious scripts.
    
    Args:
        injections: List of injection dictionaries
        
    Returns:
        Sanitized injections list
    """
    if not injections or not isinstance(injections, list):
        return []
    
    sanitized_injections = []
    
    # Limit number of injections to prevent DoS
    for injection in injections[:1000]:
        if not isinstance(injection, dict):
            continue
            
        sanitized_injection = {}
        
        # Sanitize common injection fields
        if 'element' in injection:
            sanitized_injection['element'] = sanitize_string(injection['element'], 100)
        
        if 'html' in injection:
            # HTML content is especially sensitive - limit length more strictly
            sanitized_injection['html'] = sanitize_string(injection['html'], 5000)
            
        if 'source' in injection:
            sanitized_injection['source'] = sanitize_string(injection['source'], 2000)
            
        if 'risk_level' in injection:
            # Ensure risk_level is one of allowed values
            risk = injection['risk_level']
            if risk in ('critical', 'high', 'medium', 'low', 'info'):
                sanitized_injection['risk_level'] = risk
            else:
                sanitized_injection['risk_level'] = 'medium'  # Default injections to medium
        
        # Copy other fields with generic sanitization
        for key, value in injection.items():
            if key not in sanitized_injection:
                if isinstance(value, str):
                    sanitized_injection[key] = sanitize_string(value)
                elif isinstance(value, (int, float, bool)) or value is None:
                    sanitized_injection[key] = value
                elif isinstance(value, dict):
                    sanitized_injection[key] = sanitize_payload(value)
        
        sanitized_injections.append(sanitized_injection)
    
    return sanitized_injections

def safe_json_dumps(obj: Any) -> str:
    """
    Safely convert object to JSON string with error handling.
    
    Args:
        obj: Object to convert
        
    Returns:
        JSON string or empty JSON object if error
    """
    try:
        return json.dumps(obj)
    except (TypeError, OverflowError, ValueError) as e:
        logger.error(f"JSON serialization error: {e}")
        return "{}"


