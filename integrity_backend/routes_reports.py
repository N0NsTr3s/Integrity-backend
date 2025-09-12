from fastapi import APIRouter, HTTPException, Request
import sqlite3, json, logging
from .db import get_tenant_record
from .utils import parse_user_agent, analyze_injection_risk
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()


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


@router.post('/tenant/{tenant_id}/report')
async def report_issue(tenant_id: str, request: Request):
    tenant_rec = get_tenant_record(tenant_id)
    provided_key = (request.headers.get('x-api-key') or request.headers.get('authorization') or '').replace('Bearer ', '').strip()
    server_key_ok = False
    if tenant_rec and tenant_rec.get('api_key'):
        if provided_key and provided_key == tenant_rec.get('api_key'):
            server_key_ok = True
    if not server_key_ok:
        if not origin_allowed_for_tenant(request, tenant_id):
            raise HTTPException(status_code=401, detail='unauthorized')
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
    report_type = report_payload.get('type','file_integrity') if isinstance(report_payload, dict) else 'unknown'

    # simplified storage
    try:
        db_path = str(Path(__file__).parent.parent / 'data' / 'integ.db')
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO reports (tenant, payload) VALUES (?, ?)", (tenant_id, json.dumps(report_payload)))
            conn.commit()
            report_id = c.lastrowid
    except sqlite3.Error as e:
        logger.error(f"Database error storing report: {e}")
        raise HTTPException(status_code=500, detail='Could not store report')

    return {'status': 'stored', 'report_id': report_id}
