import os
import json
import logging
from fastapi import APIRouter, HTTPException, Request, Body
from .db import get_db_connection  # Update this import

logger = logging.getLogger(__name__)
router = APIRouter()

ADMIN_SECRET = os.environ.get('ADMIN_SECRET')
if not ADMIN_SECRET:
    logger.warning("ADMIN_SECRET not set in environment - admin endpoints will fail")

@router.post("/admin/tenant/{tenant_id}")
async def upsert_tenant(tenant_id: str, request: Request, data: dict = Body(...)):
    """Create or update tenant record"""
    # Check admin secret
    admin_secret = request.headers.get("x-admin-secret")
    if not ADMIN_SECRET or admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")
    
    api_key = data.get('api_key', None)
    if not api_key:
        api_key = os.urandom(16).hex()  # Generate random API key if not provided
    
    allowed_origins = data.get('allowed_origins', ['*'])  # Default to wildcard
    allowed_origins_json = json.dumps(allowed_origins)
    
    try:
        # Get PostgreSQL connection
        conn = get_db_connection()
        with conn.cursor() as c:
            # Use PostgreSQL upsert syntax
            c.execute("""
                INSERT INTO tenants (tenant, api_key, allowed_origins) 
                VALUES (%s, %s, %s)
                ON CONFLICT (tenant) 
                DO UPDATE SET api_key = %s, allowed_origins = %s
            """, (tenant_id, api_key, allowed_origins_json, api_key, allowed_origins_json))
            conn.commit()
        conn.close()
        
        return {
            "tenant": tenant_id,
            "api_key": api_key,
            "allowed_origins": allowed_origins
        }
    except Exception as e:
        logger.error(f"Database error on tenant upsert: {e}")
        raise HTTPException(status_code=500, detail="database_error")

@router.get("/admin/tenant/{tenant_id}")
async def get_tenant(tenant_id: str, request: Request):
    """Get tenant details"""
    # Check admin secret
    admin_secret = request.headers.get("x-admin-secret")
    if not ADMIN_SECRET or admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("SELECT tenant, api_key, allowed_origins FROM tenants WHERE tenant = %s", (tenant_id,))
            row = c.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="tenant_not_found")
            
            # Parse allowed_origins JSON
            allowed_origins = []
            if row[2]:  # Index for allowed_origins column
                try:
                    allowed_origins = json.loads(row[2])
                except:
                    pass
            
            return {
                "tenant": row[0],  # tenant_id
                "api_key": row[1],  # api_key
                "allowed_origins": allowed_origins
            }
        conn.close()
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        logger.error(f"Database error on tenant get: {e}")
        raise HTTPException(status_code=500, detail="database_error")

@router.get("/admin/tenants")
async def list_tenants(request: Request):
    """List all tenants"""
    # Check admin secret
    admin_secret = request.headers.get("x-admin-secret")
    if not ADMIN_SECRET or admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")
    
    try:
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("SELECT tenant FROM tenants")
            tenants = [row[0] for row in c.fetchall()]
            return {"tenants": tenants}
        conn.close()
    except Exception as e:
        logger.error(f"Database error on tenants list: {e}")
        raise HTTPException(status_code=500, detail="database_error")

@router.post("/admin/manifest/{tenant_id}")
async def update_manifest(tenant_id: str, request: Request, data: dict = Body(...)):
    """Update tenant manifest"""
    # Check admin secret
    admin_secret = request.headers.get("x-admin-secret")
    if not ADMIN_SECRET or admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")
    
    manifest = data.get('manifest', {})
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
            "manifest": manifest
        }
    except Exception as e:
        logger.error(f"Database error on manifest update: {e}")
        raise HTTPException(status_code=500, detail="database_error")
