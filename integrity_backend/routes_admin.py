from fastapi import APIRouter, Request, HTTPException
import os, sqlite3, json, logging
from .db import get_tenant_record
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()


def check_admin_secret(request: Request) -> bool:
    admin_secret = os.environ.get('ADMIN_SECRET', '')
    if not admin_secret:
        return False
    provided = request.headers.get('x-admin-secret') or request.headers.get('authorization') or ''
    return provided == admin_secret


@router.post('/admin/tenant/{tenant_id}')
async def admin_create_update_tenant(tenant_id: str, payload: dict, request: Request):
    if not check_admin_secret(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    api_key = payload.get('api_key')
    allowed_origins = payload.get('allowed_origins', [])
    if not isinstance(allowed_origins, list):
        raise HTTPException(status_code=400, detail='allowed_origins must be a list')
    try:
        with sqlite3.connect(str(Path(__file__).parent.parent / 'data' / 'integ.db')) as conn:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO tenants (tenant, api_key, allowed_origins) VALUES (?, ?, ?)",
                      (tenant_id, api_key, json.dumps(allowed_origins)))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error on tenant upsert: {e}")
        raise HTTPException(status_code=500, detail='Could not store tenant')
    return {'status': 'ok', 'tenant': tenant_id}


@router.get('/admin/tenants')
async def admin_list_tenants(request: Request):
    if not check_admin_secret(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    try:
        with sqlite3.connect(str(Path(__file__).parent.parent / 'data' / 'integ.db')) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT tenant, api_key, allowed_origins, created_at FROM tenants ORDER BY tenant')
            rows = [dict(r) for r in c.fetchall()]
            for r in rows:
                try:
                    r['allowed_origins'] = json.loads(r.get('allowed_origins') or '[]')
                except Exception:
                    r['allowed_origins'] = []
    except sqlite3.Error as e:
        logger.error(f"Database error listing tenants: {e}")
        raise HTTPException(status_code=500, detail='Could not list tenants')
    return {'count': len(rows), 'tenants': rows}


@router.get('/admin/tenant/{tenant_id}')
async def admin_get_tenant(tenant_id: str, request: Request):
    if not check_admin_secret(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    rec = get_tenant_record(tenant_id)
    if not rec:
        raise HTTPException(status_code=404, detail='not found')
    try:
        rec['allowed_origins'] = json.loads(rec.get('allowed_origins') or '[]')
    except Exception:
        rec['allowed_origins'] = []
    return rec


@router.delete('/admin/tenant/{tenant_id}')
async def admin_delete_tenant(tenant_id: str, request: Request):
    if not check_admin_secret(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    try:
        with sqlite3.connect(str(Path(__file__).parent.parent / 'data' / 'integ.db')) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM tenants WHERE tenant=?', (tenant_id,))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error deleting tenant: {e}")
        raise HTTPException(status_code=500, detail='Could not delete tenant')
    return {'status': 'deleted', 'tenant': tenant_id}
