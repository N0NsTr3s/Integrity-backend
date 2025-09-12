from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
import sqlite3, json, logging
from pathlib import Path
import jwt
import os
from .routes_reports import verify_auth_for_tenant  # Reuse the same auth function

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post('/tenant/{tenant_id}/manifest/push')
async def push_manifest(tenant_id: str, payload: dict, request: Request):
    # Require authentication - the same way as other endpoints
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    # For additional security, this admin-like function should also verify:
    # 1. Either a valid API key (not just a token)
    # 2. Or the ADMIN_SECRET
    admin_secret = os.environ.get('ADMIN_SECRET', '')
    provided_admin = request.headers.get('x-admin-secret', '')
    api_key_valid = False
    
    # Check if API key is provided and valid
    provided_key = request.headers.get('x-api-key', '')
    if provided_key:
        from .db import get_tenant_record
        tenant_rec = get_tenant_record(tenant_id)
        if tenant_rec and tenant_rec.get('api_key') == provided_key:
            api_key_valid = True
    
    # Require either admin secret or valid API key for this sensitive operation
    if not (admin_secret and provided_admin == admin_secret) and not api_key_valid:
        raise HTTPException(status_code=403, detail="forbidden - requires admin or API key")
    
    # Continue with existing manifest storage logic
    manifest = payload.get('manifest') if isinstance(payload, dict) and 'manifest' in payload else payload
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail='Invalid manifest payload')
    try:
        db_path = str(Path(__file__).parent.parent / 'data' / 'integ.db')
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO manifests (tenant, manifest) VALUES (?, ?)",
                      (tenant_id, json.dumps(manifest)))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error on manifest push: {e}")
        raise HTTPException(status_code=500, detail='Could not store manifest')
    return {'status': 'stored'}


@router.get('/tenant/{tenant_id}/manifest')
async def get_manifest(tenant_id: str, request: Request):
    # Make token authentication mandatory
    if not verify_auth_for_tenant(request, tenant_id):
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        db_path = str(Path(__file__).parent.parent / 'data' / 'integ.db')
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT manifest FROM manifests WHERE tenant=?", (tenant_id,))
            row = c.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Database error on manifest get: {e}")
        raise HTTPException(status_code=500, detail='Could not retrieve manifest')
    if row:
        return json.loads(row['manifest'])
    raise HTTPException(status_code=404, detail='No manifest found')
