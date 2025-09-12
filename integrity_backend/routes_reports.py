from fastapi import APIRouter, HTTPException, Request
import sqlite3, json, logging, os
from .db import get_tenant_record
from .utils import parse_user_agent, analyze_injection_risk
from datetime import datetime
from pathlib import Path
import jwt

logger = logging.getLogger(__name__)
router = APIRouter()

# Get JWT_SECRET from environment
JWT_SECRET = os.environ.get('JWT_SECRET')

def origin_allowed_for_tenant(request: Request, tenant_id: str) -> bool:
    origin = request.headers.get('origin')
    if not origin:
        return True
    tenant_rec = get_tenant_record(tenant_id)
    if not tenant_rec or not tenant_rec.get('allowed_origins'):
        return False
    try:
        allowed = json.loads(tenant_rec['allowed_origins'])
    except Exception:
        return False
    if '*' in allowed: return True
    return origin in allowed

# Use this function before processing reports
def verify_auth_for_tenant(request: Request, tenant_id: str) -> bool:
    """
    Verify authentication using one of:
    1. Valid JWT in Authorization: Bearer header
    2. Valid API key in x-api-key header
    3. Request origin matches tenant's allowed_origins
    """
    # 1. Check JWT token first (Authorization: Bearer)
    auth_header = request.headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.replace('Bearer ', '', 1).strip()
        try:
            if JWT_SECRET:
                # Verify JWT token
                payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], audience="integrity-report")
                if payload.get('tenant') == tenant_id:
                    return True
        except jwt.ExpiredSignatureError:
            # Token expired - fall through to other auth methods
            pass
        except Exception as e:
            print(f"Token validation error: {e}")
            # Invalid token - fall through to other auth methods
            pass
    
    # 2. Check API key
    api_key = request.headers.get('x-api-key')
    if api_key:
        tenant_rec = get_tenant_record(tenant_id)
        if tenant_rec and tenant_rec.get('api_key') == api_key:
            return True
    
    # 3. Check Origin against allowed_origins
    origin = request.headers.get('Origin') or request.headers.get('Referer') or ''
    if origin:
        tenant_rec = get_tenant_record(tenant_id)
        if tenant_rec:
            allowed_origins = tenant_rec.get('allowed_origins') or []
            if '*' in allowed_origins or any(origin.startswith(o) for o in allowed_origins):
                return True
    
    # No valid authentication found
    return False


@router.post('/tenant/{tenant_id}/report')
async def report_issue(tenant_id: str, request: Request):
    # Use only one authentication check - the comprehensive one
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
        
    # Continue with report processing...
    try:
        report_payload = await request.json()
    except Exception:
        body = await request.body()
        try:
            report_payload = json.loads(body.decode('utf-8') or '{}')
        except Exception:
            report_payload = {'raw': body.decode('utf-8', errors='replace')}
    
    client_ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent','')
    browser_info = parse_user_agent(ua)
    # add client info
    if isinstance(report_payload, dict):
        # attach client info as a nested object
        report_payload['client_info'] = { # pyright: ignore[reportArgumentType]
            'client_ip': client_ip,
            'user_agent': ua,
            'browser': browser_info.get('browser'),
            'browser_version': browser_info.get('version'),
            'platform': browser_info.get('platform')
        }
    # Extract report_type from payload or use a default
    report_type = report_payload.get('type', 'unknown')
    
    # Extract findings_count if available
    findings = report_payload.get('findings', [])
    findings_count = len(findings) if isinstance(findings, list) else 0
    
    # Extract injections_count if available
    injections = report_payload.get('injections', [])
    injections_count = len(injections) if isinstance(injections, list) else 0
    
    # Determine risk level based on findings
    risk_level = 'low'
    if findings_count > 10 or injections_count > 5:
        risk_level = 'critical'
    elif findings_count > 5 or injections_count > 2:
        risk_level = 'high'
    elif findings_count > 0 or injections_count > 0:
        risk_level = 'medium'
        
    # simplified storage
    try:
        db_path = str(Path(__file__).parent.parent / 'data' / 'integ.db')
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO reports (
                    tenant, report_type, page_url, client_ip, browser, 
                    browser_version, platform, user_agent, findings_count, 
                    injections_count, risk_level, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_id, 
                report_type,
                report_payload.get('page_info', {}).get('url'), # pyright: ignore[reportAttributeAccessIssue]
                client_ip,
                browser_info.get('name'),
                browser_info.get('version'),
                browser_info.get('os'),
                ua,
                findings_count,
                injections_count,
                risk_level,
                json.dumps(report_payload)
            ))
            conn.commit()
            report_id = c.lastrowid
    except sqlite3.Error as e:
        logger.error(f"Database error storing report: {e}")
        raise HTTPException(status_code=500, detail='Could not store report')

    return {'status': 'stored', 'report_id': report_id}
