import os
import json
import logging
from fastapi import APIRouter, HTTPException, Request
from datetime import datetime
from .db import (get_db_connection, get_tenant_record, sanitize_payload, sanitize_findings, 
                sanitize_injections, safe_json_dumps)
from .utils import parse_user_agent, analyze_injection_risk
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
    # Authentication check remains the same
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        report_payload = await request.json()
    except Exception:
        body = await request.body()
        try:
            report_payload = json.loads(body.decode('utf-8') or '{}')
        except Exception:
            report_payload = {'raw': body.decode('utf-8', errors='replace')}
    
    # Sanitize the entire payload
    report_payload = sanitize_payload(report_payload)
    
    # Extract structured data from report payload
    report_type = report_payload.get('type', 'unknown')
    
    # Extract page info
    page_info = report_payload.get('page_info', {})
    page_url = page_info.get('url', None)
    
    # Extract browser info
    browser_info = report_payload.get('browser_info', {})
    browser = browser_info.get('browser', 'Unknown')
    browser_version = browser_info.get('version', 'Unknown')
    platform = browser_info.get('platform', 'Unknown')
    user_agent = browser_info.get('userAgent', None)
    
    # Get client IP (preferably from X-Forwarded-For or fallback to direct client)
    client_ip = request.headers.get('x-forwarded-for', '').split(',')[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else 'unknown'
    
    # Sanitize findings and injections specifically
    raw_findings = report_payload.get('findings', [])
    findings = sanitize_findings(raw_findings)
    findings_count = len(findings)
    
    raw_injections = report_payload.get('injections', [])
    injections = sanitize_injections(raw_injections)
    injections_count = len(injections)
    
    # Update the payload with sanitized data
    report_payload['findings'] = findings
    report_payload['injections'] = injections
    
    # Determine risk level as before but use sanitized data
    if 'risk_level' in report_payload:
        risk_level = report_payload.get('risk_level')
    else:
        # Calculate risk level from findings/injections
        risk_level = 'low'
        
        # Check for critical injections
        critical_count = report_payload.get('critical_count', 0)
        high_risk_count = report_payload.get('high_risk_count', 0)
        
        if critical_count > 0 or any(i.get('risk_level') == 'critical' for i in injections):
            risk_level = 'critical'
        elif high_risk_count > 0 or findings_count > 5 or injections_count > 2:
            risk_level = 'high'
        elif findings_count > 0 or injections_count > 0:
            risk_level = 'medium'
    
    # Insert the processed report into the database using safe JSON serialization
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("""
                INSERT INTO reports (
                    tenant, report_type, page_url, client_ip, browser, 
                    browser_version, platform, user_agent, findings_count, 
                    injections_count, risk_level, payload
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                tenant_id, 
                report_type,
                page_url,
                client_ip,
                browser,
                browser_version,
                platform,
                user_agent,
                findings_count,
                injections_count,
                risk_level,
                safe_json_dumps(report_payload)  # Use safe JSON serialization
            ))
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database error: {e}")
    
    return {"status": "received"}
