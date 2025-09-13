import os
import json
import logging
from fastapi import APIRouter, HTTPException, Request, Body
from .db import get_db_connection

logger = logging.getLogger(__name__)
router = APIRouter()

ADMIN_SECRET = os.environ.get('ADMIN_SECRET')

@router.post('/tenant/{tenant_id}/manifest/push')
async def push_manifest(tenant_id: str, payload: dict, request: Request):
    # Require authentication - either admin secret or regular token
    admin_secret = request.headers.get("x-admin-secret")
    if not ADMIN_SECRET or admin_secret != ADMIN_SECRET:
        from .routes_reports import verify_auth_for_tenant
        if not verify_auth_for_tenant(request, tenant_id):
            raise HTTPException(status_code=401, detail="unauthorized")
    
    manifest = payload.get('manifest', {})
    manifest_json = json.dumps(manifest)
    
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            # Use PostgreSQL upsert syntax
            c.execute("""
                INSERT INTO manifests (tenant, manifest) 
                VALUES (%s, %s)
                ON CONFLICT (tenant) 
                DO UPDATE SET manifest = %s
            """, (tenant_id, manifest_json, manifest_json))
            conn.commit()
        conn.close()
        
        return {
            "tenant": tenant_id,
            "status": "manifest_updated",
            "manifest_size": len(manifest_json)
        }
    except Exception as e:
        logger.error(f"Database error updating manifest: {e}")
        raise HTTPException(status_code=500, detail="database_error")


@router.get("/manifest/{tenant_id}")
async def get_manifest(tenant_id: str, request: Request):
    logger.info(f"Manifest request for tenant {tenant_id} from {request.client.host}") # pyright: ignore[reportOptionalMemberAccess]
    logger.info(f"Request headers: {request.headers}")
    """Get manifest for tenant"""
    try:
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as c:
                c.execute("SELECT manifest FROM manifests WHERE tenant = %s", (tenant_id,))
                row = c.fetchone()
                
                if not row:
                    # Log and return empty manifest if not found
                    logger.warning(f"No manifest found for tenant {tenant_id}")
                    return {}
                
                # Parse JSON manifest
                try:
                    manifest_json = row[0] if row[0] else '{}'
                    manifest = json.loads(manifest_json)
                    return manifest
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in manifest for tenant {tenant_id}: {e}")
                    return {}
        finally:
            if conn:
                conn.close()
    except Exception as e:
        logger.error(f"Database error getting manifest: {e}")
        raise HTTPException(status_code=500, detail="database_error")


@router.get("/tenant/{tenant_id}/manifest")
async def get_tenant_manifest(tenant_id: str, request: Request):
    """Legacy route - forwards to the standard manifest endpoint"""
    return await get_manifest(tenant_id, request)
