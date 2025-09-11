from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware  # Add this import
from pydantic import BaseModel, field_validator
import sqlite3, json, base64, os, hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
import re

DB = 'data/integ.db'
app = FastAPI(title='Script Integrity SaaS')
data_dir = Path(DB).parent
data_dir.mkdir(parents=True, exist_ok=True)
# Add CORS middleware immediately after app creation
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://n0nstr3s.github.io",  # Your GitHub Pages
        "http://localhost:3000",
        "http://localhost:8000", 
        "http://127.0.0.1:*",
        "file://*"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

static_path = Path('static')
static_path.mkdir(parents=True, exist_ok=True)
app.mount('/static', StaticFiles(directory=str(static_path)), name='static')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS manifests (tenant TEXT PRIMARY KEY, manifest TEXT)''')
            
            # Check if reports table exists and what columns it has
            c.execute("PRAGMA table_info(reports)")
            existing_columns = {row[1] for row in c.fetchall()}
            
            if not existing_columns:
                # Create new table with enhanced schema
                c.execute('''CREATE TABLE reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    report_type TEXT NOT NULL,
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
                logger.info("Created new reports table with enhanced schema")
            elif 'report_type' not in existing_columns:
                # Migrate existing table
                logger.info("Migrating existing reports table to enhanced schema")
                
                # Add new columns to existing table
                new_columns = [
                    ('report_type', 'TEXT NOT NULL DEFAULT "unknown"'),
                    ('page_url', 'TEXT'),
                    ('client_ip', 'TEXT'),
                    ('browser', 'TEXT'),
                    ('browser_version', 'TEXT'),
                    ('platform', 'TEXT'),
                    ('user_agent', 'TEXT'),
                    ('findings_count', 'INTEGER DEFAULT 0'),
                    ('injections_count', 'INTEGER DEFAULT 0'),
                    ('risk_level', 'TEXT DEFAULT "low"')
                ]
                
                for col_name, col_def in new_columns:
                    try:
                        c.execute(f"ALTER TABLE reports ADD COLUMN {col_name} {col_def}")
                        logger.info(f"Added column {col_name}")
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" not in str(e):
                            logger.warning(f"Could not add column {col_name}: {e}")
            
            # Add indexes for better query performance
            try:
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_tenant_type ON reports(tenant, report_type)''')
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON reports(at)''')
                c.execute('''CREATE INDEX IF NOT EXISTS idx_reports_risk ON reports(risk_level)''')
            except sqlite3.OperationalError:
                pass  # Indexes might already exist
            
            conn.commit()
            logger.info("Database initialization completed successfully")
            
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")

init_db()

@app.get('/')
async def root():
    index_file = static_path / 'index.html'
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"status": "ok", "service": "Script Integrity SaaS"}

@app.get('/index.html')
async def index_html():
    index_file = static_path / 'index.html'
    if index_file.exists():
        return FileResponse(str(index_file))
    raise HTTPException(status_code=404, detail="index.html not found")

@app.get('/ip-details-page/{ip_address_param}')
async def serve_ip_details_page(ip_address_param: str):
    """Serve the IP details HTML page"""
    ip_details_file = static_path / 'ip-details.html'
    if ip_details_file.exists():
        return FileResponse(str(ip_details_file))
    raise HTTPException(status_code=404, detail="IP details page not found")

@app.get('/integrity.js')
async def serve_integrity_js():
    js_file = Path('integrity.js')
    if js_file.exists():
        return FileResponse(str(js_file), media_type='application/javascript')
    raise HTTPException(status_code=404, detail='integrity.js not found')

class ManifestPush(BaseModel):
    manifest: Dict[str, Any]

class Report(BaseModel):
    tenant: str
    page: str
    time: str
    type: Optional[str] = 'file_integrity'  # 'file_integrity' or 'dom_injection'
    findings: List[Any] = []
    injected: List[Any] = []
    injections: List[Any] = []  # For DOM injection reports
    
    @field_validator('tenant')
    def tenant_must_be_valid(cls, v):
        if not v or not isinstance(v, str) or len(v) > 50:
            raise ValueError('Invalid tenant identifier')
        return v

def verify_manifest_signature(manifest_dict: Dict[str, Any]) -> bool:
    sig = manifest_dict.get('signature')
    if not sig: 
        return False
    pub_pem = manifest_dict.get('public_key_pem')
    if not pub_pem: 
        return False
        
    copy = dict(manifest_dict)
    copy.pop('signature', None)
    payload = json.dumps(copy, sort_keys=True).encode('utf-8')
    
    try:
        signature = base64.b64decode(sig)
        public_key = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
        
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, payload, hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        else:
            logger.warning(f"Unsupported key type: {type(public_key)}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

@app.post("/tenant/{tenant_id}/manifest/push")
async def push_manifest(tenant_id: str, payload: Dict[str, Any]):
    manifest = payload.get('manifest') if isinstance(payload, dict) and 'manifest' in payload else payload

    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail="Invalid manifest payload")

    if 'signature' in manifest:
        if not verify_manifest_signature(manifest):
            raise HTTPException(status_code=400, detail="Invalid manifest signature")
    else:
        logger.info(f"Storing unsigned manifest for tenant {tenant_id}")

    try:
        with sqlite3.connect(DB) as conn:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO manifests (tenant, manifest) VALUES (?, ?)", 
                      (tenant_id, json.dumps(manifest)))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error on manifest push: {e}")
        raise HTTPException(status_code=500, detail="Could not store manifest")

    return {"status": "stored"}

@app.get("/tenant/{tenant_id}/manifest")
async def get_manifest(tenant_id: str):
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT manifest FROM manifests WHERE tenant=?", (tenant_id,))
            row = c.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Database error on manifest get: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve manifest")

    if row:
        return json.loads(row['manifest'])
    raise HTTPException(status_code=404, detail="No manifest found")

def analyze_injection_risk(injection: Dict[str, Any]) -> Dict[str, Any]:
    """Enhanced risk analysis for DOM injections"""
    tag = injection.get('tag', '').lower()
    attributes = injection.get('attributes', {})
    
    risk_factors = []
    
    # High-risk tags
    if tag in ['script', 'iframe', 'object', 'embed']:
        risk_factors.append(f'dangerous_tag_{tag}')
    
    # Dangerous event handlers
    event_handlers = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur']
    for handler in event_handlers:
        if handler in attributes:
            risk_factors.append(f'inline_event_{handler}')
    
    # Suspicious URLs
    src = attributes.get('src', '') or attributes.get('href', '')
    if src:
        if src.startswith('data:'):
            risk_factors.append('data_url')
        if src.startswith('javascript:'):
            risk_factors.append('javascript_url')
        # Check for IP addresses or suspicious domains
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', src):
            risk_factors.append('ip_address')
        if re.search(r'[a-z0-9]{10,}\.(tk|ml|ga|cf)', src, re.IGNORECASE):
            risk_factors.append('suspicious_tld')
    
    # CSS injection patterns
    style = attributes.get('style', '')
    if style and any(keyword in style.lower() for keyword in ['expression', 'javascript:', 'vbscript:']):
        risk_factors.append('css_injection')
    
    # Calculate risk level
    risk_score = len(risk_factors)
    if risk_score >= 3:
        final_risk = 'critical'
    elif risk_score >= 2:
        final_risk = 'high'
    elif risk_score >= 1:
        final_risk = 'medium'
    else:
        final_risk = 'low'
    
    return {
        'risk_factors': risk_factors,
        'risk_score': risk_score,
        'final_risk': final_risk
    }

def extract_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information from request headers"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get('user-agent', 'unknown')
    
    # Extract forwarded IP if behind proxy
    forwarded_for = request.headers.get('x-forwarded-for')
    if forwarded_for:
        # Take the first IP in the chain
        client_ip = forwarded_for.split(',')[0].strip()
    
    # Parse browser info from user-agent
    browser_info = parse_user_agent(user_agent)
    
    return {
        'client_ip': client_ip,
        'user_agent': user_agent,
        'forwarded_for': request.headers.get('x-forwarded-for'),
        'referer': request.headers.get('referer'),
        'browser': browser_info.get('browser', 'unknown'),
        'browser_version': browser_info.get('version', 'unknown'),
        'platform': browser_info.get('platform', 'unknown'),
        'accept_language': request.headers.get('accept-language'),
        'accept_encoding': request.headers.get('accept-encoding')
    }

def parse_user_agent(user_agent: str) -> Dict[str, str]:
    """Basic user-agent parsing to extract browser and version"""
    ua_lower = user_agent.lower()
    
    # Chrome/Chromium detection
    if 'chrome/' in ua_lower:
        chrome_match = re.search(r'chrome/([0-9.]+)', ua_lower)
        version = chrome_match.group(1) if chrome_match else 'unknown'
        if 'edg/' in ua_lower:  # Edge
            edge_match = re.search(r'edg/([0-9.]+)', ua_lower)
            return {'browser': 'Edge', 'version': edge_match.group(1) if edge_match else version, 'platform': get_platform(user_agent)}
        return {'browser': 'Chrome', 'version': version, 'platform': get_platform(user_agent)}
    
    # Firefox detection
    elif 'firefox/' in ua_lower:
        firefox_match = re.search(r'firefox/([0-9.]+)', ua_lower)
        version = firefox_match.group(1) if firefox_match else 'unknown'
        return {'browser': 'Firefox', 'version': version, 'platform': get_platform(user_agent)}
    
    # Safari detection
    elif 'safari/' in ua_lower and 'chrome' not in ua_lower:
        safari_match = re.search(r'version/([0-9.]+)', ua_lower)
        version = safari_match.group(1) if safari_match else 'unknown'
        return {'browser': 'Safari', 'version': version, 'platform': get_platform(user_agent)}
    
    # Internet Explorer
    elif 'trident/' in ua_lower or 'msie' in ua_lower:
        ie_match = re.search(r'(?:msie |rv:)([0-9.]+)', ua_lower)
        version = ie_match.group(1) if ie_match else 'unknown'
        return {'browser': 'Internet Explorer', 'version': version, 'platform': get_platform(user_agent)}
    
    return {'browser': 'Unknown', 'version': 'unknown', 'platform': get_platform(user_agent)}

def get_platform(user_agent: str) -> str:
    """Extract platform information from user-agent"""
    ua_lower = user_agent.lower()
    
    if 'windows nt 10' in ua_lower:
        return 'Windows 10'
    elif 'windows nt 6.3' in ua_lower:
        return 'Windows 8.1'
    elif 'windows nt 6.2' in ua_lower:
        return 'Windows 8'
    elif 'windows nt 6.1' in ua_lower:
        return 'Windows 7'
    elif 'windows' in ua_lower:
        return 'Windows'
    elif 'mac os x' in ua_lower:
        mac_match = re.search(r'mac os x ([0-9_]+)', ua_lower)
        if mac_match:
            return f"macOS {mac_match.group(1).replace('_', '.')}"
        return 'macOS'
    elif 'linux' in ua_lower:
        return 'Linux'
    elif 'android' in ua_lower:
        android_match = re.search(r'android ([0-9.]+)', ua_lower)
        if android_match:
            return f"Android {android_match.group(1)}"
        return 'Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        ios_match = re.search(r'os ([0-9_]+)', ua_lower)
        if ios_match:
            return f"iOS {ios_match.group(1).replace('_', '.')}"
        return 'iOS'
    
    return 'Unknown'

@app.post("/tenant/{tenant_id}/report")
async def report_issue(tenant_id: str, request: Request):
    try:
        report_payload = await request.json()
    except Exception:
        body = await request.body()
        try:
            report_payload = json.loads(body.decode('utf-8') or '{}')
        except Exception:
            report_payload = {"raw": body.decode('utf-8', errors='replace')}

    # Extract client information from request
    client_info = extract_client_info(request)
    
    # Add client info to the report
    if isinstance(report_payload, dict):
        report_payload['client_info'] = client_info # pyright: ignore[reportArgumentType]
        # Also add timestamp if not present
        if 'time' not in report_payload:
            report_payload['time'] = datetime.utcnow().isoformat() + 'Z'

    report_type = report_payload.get('type', 'file_integrity') if isinstance(report_payload, dict) else 'unknown'
    
    # Enhanced logging for different report types
    if report_type == 'dom_injection':
        injections = report_payload.get('injections', [])
        high_risk = report_payload.get('high_risk_count', 0)
        critical = report_payload.get('critical_count', 0)
        browser = client_info.get('browser', 'unknown')
        ip = client_info.get('client_ip', 'unknown')
        logger.warning(f"DOM INJECTION REPORT! tenant={tenant_id} ip={ip} browser={browser} count={len(injections)} high_risk={high_risk} critical={critical}")
        
        # Enhanced risk analysis for DOM injections
        for injection in injections:
            if isinstance(injection, dict):
                risk_analysis = analyze_injection_risk(injection)
                injection.update(risk_analysis)
        
        # Update risk counts
        critical_count = sum(1 for inj in injections if isinstance(inj, dict) and inj.get('final_risk') == 'critical')
        high_risk_count = sum(1 for inj in injections if isinstance(inj, dict) and inj.get('final_risk') in ['critical', 'high'])
        
        report_payload['enhanced_critical_count'] = critical_count # type: ignore
        report_payload['enhanced_high_risk_count'] = high_risk_count # type: ignore
        
        # Always store DOM injection reports
        try:
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                # Try to use new schema first, fall back to old if needed
                try:
                    overall_risk = 'critical' if critical_count > 0 else ('high' if high_risk_count > 0 else 'medium' if len(injections) > 0 else 'low')
                    page_url = report_payload.get('page', 'unknown') if isinstance(report_payload, dict) else 'unknown'
                    
                    c.execute("""INSERT INTO reports 
                        (tenant, report_type, page_url, client_ip, browser, browser_version, platform, user_agent,
                         findings_count, injections_count, risk_level, payload) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                        (tenant_id, 'dom_injection', page_url, ip, browser, 
                         client_info.get('browser_version', 'unknown'), client_info.get('platform', 'unknown'), 
                         client_info.get('user_agent', 'unknown'), 0, len(injections), overall_risk, 
                         json.dumps(report_payload)))
                except sqlite3.OperationalError:
                    # Fall back to old schema
                    c.execute("INSERT INTO reports (tenant, payload) VALUES (?, ?)", 
                              (tenant_id, json.dumps(report_payload)))
                
                conn.commit()
                report_id = c.lastrowid
                
                if critical_count > 0:
                    logger.critical(f"CRITICAL DOM INJECTION! tenant={tenant_id} report_id={report_id} critical={critical_count}")
                
        except sqlite3.Error as e:
            logger.error(f"Database error on DOM injection report: {e}")
            raise HTTPException(status_code=500, detail="Could not store injection report")
        
        return {"status": "dom_injection_reported", "report_id": report_id, "critical_count": critical_count}
    
    elif report_type == 'file_integrity':
        browser = client_info.get('browser', 'unknown')
        ip = client_info.get('client_ip', 'unknown')
        try:
            logger.info(f"File integrity report for tenant={tenant_id} ip={ip} browser={browser} preview={json.dumps(report_payload)[:300]}")
        except Exception:
            logger.info(f"File integrity report for tenant={tenant_id} ip={ip} browser={browser} (unserializable payload)")
        
        # Enhanced file integrity handling with better hash comparison
        findings = report_payload.get('findings', []) if isinstance(report_payload, dict) else []
        
        # Filter out false positives from base64 padding differences
        valid_findings = []
        for finding in findings:
            if isinstance(finding, dict):
                expected = finding.get('expected', '')
                actual = finding.get('actual', '')
                
                # Normalize base64 padding for comparison
                expected_normalized = expected.rstrip('=') + '=' * (-len(expected.rstrip('=')) % 4)
                actual_normalized = actual.rstrip('=') + '=' * (-len(actual.rstrip('=')) % 4) if actual else ''
                
                if expected_normalized != actual_normalized:
                    valid_findings.append(finding)
                    logger.warning(f"Genuine file integrity issue: {finding.get('path')} expected={expected_normalized[:20]}... actual={actual_normalized[:20]}...")
                else:
                    logger.info(f"Ignored base64 padding difference for {finding.get('path')}")
        
        # Only report if there are genuine findings
        if not valid_findings:
            logger.info(f"No valid file integrity issues for tenant={tenant_id}")
            return {"status": "no_issues", "message": "All files verified successfully"}
        
        # Update payload with valid findings
        if isinstance(report_payload, dict):
            report_payload['valid_findings'] = valid_findings # pyright: ignore[reportArgumentType]

        try:
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                # Try to use new schema first, fall back to old if needed
                try:
                    c.execute("""INSERT INTO reports 
                        (tenant, report_type, page_url, client_ip, browser, browser_version, platform, user_agent,
                         findings_count, injections_count, risk_level, payload) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", 
                        (tenant_id, report_type, report_payload.get('page', 'unknown') if isinstance(report_payload, dict) else 'unknown', 
                         ip, browser, client_info.get('browser_version', 'unknown'), client_info.get('platform', 'unknown'), 
                         client_info.get('user_agent', 'unknown'), len(valid_findings), 0, 'high' if valid_findings else 'low', 
                         json.dumps(report_payload)))
                except sqlite3.OperationalError:
                    # Fall back to old schema
                    c.execute("INSERT INTO reports (tenant, payload) VALUES (?, ?)", 
                              (tenant_id, json.dumps(report_payload)))
                
                conn.commit()
                report_id = c.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Database error on file integrity report: {e}")
            raise HTTPException(status_code=500, detail="Could not store report")

        return {"status": "file_integrity_reported", "report_id": report_id, "findings_count": len(valid_findings)}
    
    else:
        # Unknown report type - store anyway but log
        logger.warning(f"Unknown report type '{report_type}' for tenant={tenant_id}")
        try:
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO reports (tenant, payload) VALUES (?, ?)", 
                          (tenant_id, json.dumps(report_payload)))
                conn.commit()
                report_id = c.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Database error on unknown report: {e}")
            raise HTTPException(status_code=500, detail="Could not store report")

        return {"status": "unknown_report_stored", "report_id": report_id}

@app.get('/debug/reports/{tenant_id}')
async def debug_reports(tenant_id: str, limit: int = 20, report_type: Optional[str] = None):
    """Get reports with optional filtering by type"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            if report_type:
                c.execute("""
                    SELECT id, at, payload FROM reports 
                    WHERE tenant=? AND json_extract(payload, '$.type') = ?
                    ORDER BY id DESC LIMIT ?
                """, (tenant_id, report_type, limit))
            else:
                c.execute("""
                    SELECT id, at, payload FROM reports 
                    WHERE tenant=? ORDER BY id DESC LIMIT ?
                """, (tenant_id, limit))
            
            rows = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error on debug reports: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve reports")

    out = []
    for r in rows:
        try:
            payload = json.loads(r['payload'])
        except Exception:
            payload = r['payload']
        
        out.append({
            'id': r['id'], 
            'at': r['at'], 
            'type': payload.get('type', 'unknown') if isinstance(payload, dict) else 'unknown',
            'payload': payload
        })
    
    return {'tenant': tenant_id, 'count': len(out), 'filter': report_type, 'reports': out}

@app.get('/dashboard/{tenant_id}')
async def dashboard(tenant_id: str, days: int = 7):
    """Enhanced dashboard with summary statistics from the new database schema"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get summary statistics
            c.execute("""
                SELECT 
                    report_type,
                    COUNT(*) as count,
                    SUM(findings_count) as total_findings,
                    SUM(injections_count) as total_injections,
                    AVG(findings_count) as avg_findings,
                    AVG(injections_count) as avg_injections,
                    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical_reports,
                    COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_risk_reports
                FROM reports 
                WHERE tenant = ? AND at >= datetime('now', '-{} days')
                GROUP BY report_type
                ORDER BY count DESC
            """.format(days), (tenant_id,))
            
            summary_stats = [dict(row) for row in c.fetchall()]
            
            # Get browser statistics
            c.execute("""
                SELECT 
                    browser,
                    browser_version,
                    COUNT(*) as count,
                    COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as high_risk_count
                FROM reports 
                WHERE tenant = ? AND at >= datetime('now', '-{} days') AND browser IS NOT NULL
                GROUP BY browser, browser_version
                ORDER BY count DESC
                LIMIT 10
            """.format(days), (tenant_id,))
            
            browser_stats = [dict(row) for row in c.fetchall()]
            
            # Get recent high-risk reports
            c.execute("""
                SELECT 
                    id, report_type, page_url, client_ip, browser, risk_level, 
                    findings_count, injections_count, at,
                    substr(payload, 1, 200) as payload_preview
                FROM reports 
                WHERE tenant = ? AND risk_level IN ('high', 'critical') 
                    AND at >= datetime('now', '-{} days')
                ORDER BY at DESC
                LIMIT 20
            """.format(days), (tenant_id,))
            
            high_risk_reports = [dict(row) for row in c.fetchall()]
            
            # Get top client IPs
            c.execute("""
                SELECT 
                    client_ip,
                    COUNT(*) as total_reports,
                    COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as risk_reports,
                    MAX(at) as last_seen
                FROM reports 
                WHERE tenant = ? AND at >= datetime('now', '-{} days') AND client_ip IS NOT NULL
                GROUP BY client_ip
                ORDER BY risk_reports DESC, total_reports DESC
                LIMIT 10
            """.format(days), (tenant_id,))
            
            client_stats = [dict(row) for row in c.fetchall()]
            
    except sqlite3.Error as e:
        logger.error(f"Database error on dashboard: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve dashboard data")
    
    return {
        'tenant': tenant_id,
        'period_days': days,
        'summary': summary_stats,
        'browsers': browser_stats,
        'high_risk_reports': high_risk_reports,
        'client_statistics': client_stats,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }

@app.get('/ip-correlation/{tenant_id}')
async def ip_correlation(tenant_id: str, days: int = 7):
    """Advanced IP address incident correlation and risk analysis"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get IP incident correlation with risk scoring
            c.execute("""
                SELECT 
                    client_ip,
                    COUNT(*) as total_incidents,
                    COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as high_risk_incidents,
                    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical_incidents,
                    COUNT(DISTINCT report_type) as attack_type_count,
                    GROUP_CONCAT(DISTINCT report_type) as attack_types_raw,
                    SUM(findings_count) as total_findings,
                    SUM(injections_count) as total_injections,
                    MIN(at) as first_seen,
                    MAX(at) as last_seen,
                    COUNT(DISTINCT page_url) as affected_pages,
                    COUNT(DISTINCT browser) as browser_variants
                FROM reports 
                WHERE tenant = ? AND at >= datetime('now', '-{} days') 
                    AND client_ip IS NOT NULL AND client_ip != ''
                GROUP BY client_ip
                HAVING total_incidents > 0
                ORDER BY high_risk_incidents DESC, total_incidents DESC
                LIMIT 20
            """.format(days), (tenant_id,))
            
            ip_data = []
            for row in c.fetchall():
                # Calculate risk score (0-10)
                risk_score = min(10, (
                    (row['critical_incidents'] * 4) +
                    (row['high_risk_incidents'] * 2) +
                    (row['total_incidents'] * 0.5) +
                    (row['attack_type_count'] * 1) +
                    (row['total_findings'] * 0.3) +
                    (row['total_injections'] * 0.8)
                ))
                
                attack_types = row['attack_types_raw'].split(',') if row['attack_types_raw'] else []
                
                ip_data.append({
                    'client_ip': row['client_ip'],
                    'total_incidents': row['total_incidents'],
                    'high_risk_incidents': row['high_risk_incidents'],
                    'critical_incidents': row['critical_incidents'],
                    'risk_score': round(risk_score, 1),
                    'attack_types': attack_types,
                    'total_findings': row['total_findings'] or 0,
                    'total_injections': row['total_injections'] or 0,
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen'],
                    'affected_pages': row['affected_pages'],
                    'browser_variants': row['browser_variants']
                })
            
            # Get timeline of incidents for visualization
            c.execute("""
                SELECT 
                    client_ip, report_type, risk_level, page_url, browser,
                    findings_count, injections_count, at
                FROM reports 
                WHERE tenant = ? AND at >= datetime('now', '-{} days')
                    AND client_ip IS NOT NULL AND client_ip != ''
                    AND risk_level IN ('high', 'critical')
                ORDER BY at DESC
                LIMIT 50
            """.format(days), (tenant_id,))
            
            timeline_data = [dict(row) for row in c.fetchall()]
            
    except sqlite3.Error as e:
        logger.error(f"Database error on IP correlation: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve IP correlation data")
    
    return {
        'tenant': tenant_id,
        'period_days': days,
        'ip_incidents': ip_data,
        'timeline_incidents': timeline_data,
        'total_unique_ips': len(ip_data),
        'high_risk_ips': len([ip for ip in ip_data if ip['risk_score'] >= 5]),
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }

@app.get('/ip-details/{ip_address}')
async def ip_details(ip_address: str, tenant_id: str = 'demo', days: int = 30):
    """Detailed incident report for a specific IP address"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get all incidents for this IP
            c.execute("""
                SELECT 
                    id, report_type, page_url, browser, browser_version, platform,
                    user_agent, findings_count, injections_count, risk_level, at,
                    substr(payload, 1, 500) as payload_preview
                FROM reports 
                WHERE tenant = ? AND client_ip = ? AND at >= datetime('now', '-{} days')
                ORDER BY at DESC
            """.format(days), (tenant_id, ip_address))
            
            incidents = [dict(row) for row in c.fetchall()]
            
            if not incidents:
                raise HTTPException(status_code=404, detail=f"No incidents found for IP {ip_address}")
            
            # Calculate summary statistics
            total_incidents = len(incidents)
            critical_count = len([i for i in incidents if i['risk_level'] == 'critical'])
            high_risk_count = len([i for i in incidents if i['risk_level'] in ['high', 'critical']])
            unique_pages = len(set(i['page_url'] for i in incidents if i['page_url']))
            
    except sqlite3.Error as e:
        logger.error(f"Database error on IP details: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve IP details")
    
    return {
        'ip_address': ip_address,
        'tenant': tenant_id,
        'period_days': days,
        'summary': {
            'total_incidents': total_incidents,
            'critical_incidents': critical_count,
            'high_risk_incidents': high_risk_count,
            'unique_pages_affected': unique_pages,
            'first_seen': incidents[-1]['at'] if incidents else None,
            'last_seen': incidents[0]['at'] if incidents else None
        },
        'incidents': incidents,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }

@app.get('/tenant/{tenant_id}/injections')
async def get_injections(tenant_id: str, limit: int = 50, risk_level: Optional[str] = None):
    """Get DOM injection reports specifically"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT id, at, payload FROM reports 
                WHERE tenant=? AND json_extract(payload, '$.type') = 'dom_injection'
                ORDER BY id DESC LIMIT ?
            """, (tenant_id, limit))
            rows = c.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error on injection retrieval: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve injections")

    injections = []
    for r in rows:
        try:
            payload = json.loads(r['payload'])
            
            if risk_level:
                injection_list = payload.get('injections', [])
                filtered_injections = [inj for inj in injection_list if inj.get('final_risk') == risk_level]
                if not filtered_injections:
                    continue
                payload['injections'] = filtered_injections
            
            injections.append({
                'id': r['id'], 
                'timestamp': r['at'], 
                'page': payload.get('page'),
                'total_injections': payload.get('total_injections', 0),
                'critical_count': payload.get('enhanced_critical_count', payload.get('critical_count', 0)),
                'high_risk_count': payload.get('enhanced_high_risk_count', payload.get('high_risk_count', 0)),
                'injections': payload.get('injections', [])
            })
        except Exception as e:
            logger.error(f"Error processing injection report {r['id']}: {e}")
            continue
    
    return {'tenant': tenant_id, 'count': len(injections), 'risk_filter': risk_level, 'injections': injections}

def compute_file_sha256_b64(path: Path) -> str | None:
    try:
        with open(path, 'rb') as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
            return base64.b64encode(h.digest()).decode()
    except Exception:
        return None

@app.get('/tenant/{tenant_id}/manifest/compare')
async def manifest_compare(tenant_id: str, create_report: bool = False):
    """Compare stored manifest file hashes with current files on disk (unchanged)"""
    try:
        with sqlite3.connect(DB) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT manifest FROM manifests WHERE tenant=?", (tenant_id,))
            row = c.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Database error on manifest compare: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve manifest")

    if not row:
        raise HTTPException(status_code=404, detail="No manifest found for tenant")

    manifest = json.loads(row['manifest'])
    files = manifest.get('files') or {}
    results = []
    
    for path_str, meta in files.items():
        manifest_sha = meta.get('sha256')
        candidate_paths = []
        p = Path(path_str.lstrip('/'))
        candidate_paths.append(Path(path_str))
        candidate_paths.append(Path('static') / p)
        candidate_paths.append(p)
        found = None
        
        for cand in candidate_paths:
            if cand.exists() and cand.is_file():
                found = cand
                break

        current_sha = compute_file_sha256_b64(found) if found else None
        results.append({
            'path': path_str,
            'manifest_sha': manifest_sha,
            'current_sha': current_sha,
            'match': (manifest_sha == current_sha) if manifest_sha is not None and current_sha is not None else False,
            'found_on_disk': bool(found),
            'disk_path': str(found) if found else None
        })

    mismatches = [r for r in results if not r['match']]
    report_created = False
    report_id = None
    
    if create_report and mismatches:
        report_payload = {
            'tenant': tenant_id,
            'page': 'manifest_compare',
            'time': datetime.utcnow().isoformat() + 'Z',
            'type': 'file_integrity',
            'findings': mismatches,
            'injected': []
        }
        try:
            with sqlite3.connect(DB) as conn:
                c = conn.cursor()
                c.execute("INSERT INTO reports (tenant, payload) VALUES (?, ?)",
                          (tenant_id, json.dumps(report_payload)))
                conn.commit()
                report_id = c.lastrowid
                report_created = True
                logger.info(f"Auto-created file integrity report id={report_id} for tenant={tenant_id} with {len(mismatches)} mismatches")
        except sqlite3.Error as e:
            logger.error(f"Database error when creating auto-report: {e}")

    return {'tenant': tenant_id, 'results': results, 'report_created': report_created, 'report_id': report_id}