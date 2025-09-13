from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
import json, logging
from pathlib import Path
import jwt
import os
from .routes_reports import verify_auth_for_tenant  # Reuse the same auth function
from .db import get_db_connection

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
        conn = get_db_connection()
        with conn.cursor() as c:
            # Use INSERT ... ON CONFLICT for PostgreSQL to achieve "INSERT OR REPLACE"
            c.execute("""
                INSERT INTO manifests (tenant, manifest)
                VALUES (%s, %s)
                ON CONFLICT (tenant) DO UPDATE SET
                    manifest = EXCLUDED.manifest
            """, (tenant_id, json.dumps(manifest)))
            conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Database error on manifest push: {e}")
        raise HTTPException(status_code=500, detail='Could not store manifest')
    return {'status': 'stored'}



@router.get("/manifest/{tenant_id}")
async def get_manifest(tenant_id: str, request: Request):
    """Get manifest for tenant"""
    # You may want to add authentication here depending on your requirements
    
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("SELECT manifest FROM manifests WHERE tenant = %s", (tenant_id,))
            row = c.fetchone()
            
            if not row:
                # Return empty manifest if not found
                return {}
            
            # Parse JSON manifest
            try:
                manifest = json.loads(row[0]) if row[0] else {}
                return manifest
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in manifest for tenant {tenant_id}")
                return {}
        conn.close()
    except Exception as e:
        logger.error(f"Database error getting manifest: {e}")
        raise HTTPException(status_code=500, detail="database_error")
