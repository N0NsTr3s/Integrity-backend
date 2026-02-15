import os
import time
import jwt
import json
import logging
from fastapi import APIRouter, HTTPException, Request
from .db import get_db_connection, get_tenant_record

logger = logging.getLogger(__name__)
router = APIRouter()

TOKEN_TTL_SECONDS = int(os.environ.get('TOKEN_TTL_SECONDS', '300'))
JWT_SECRET = os.environ.get('JWT_SECRET', None)
if not JWT_SECRET:
    print("[WARNING] JWT_SECRET not set — token endpoint will fail without a secret")

@router.post("/tenant/{tenant_id}/token")
async def issue_tenant_token(tenant_id: str, request: Request):
    """
    Issue a short-lived JWT for browser clients. Validates that the request Origin/Referer
    matches tenant.allowed_origins. Returns {"token": "...", "expires_in": seconds}.
    """
    if not JWT_SECRET:
        logger.error("Token issuer not configured - JWT_SECRET missing in environment")
        raise HTTPException(status_code=500, detail="token_issuer_not_configured")

    tenant_rec = get_tenant_record(tenant_id)
    if not tenant_rec:
        logger.error(f"Tenant record not found for {tenant_id}")
        raise HTTPException(status_code=404, detail="tenant_not_found")

    # Enhanced origin check with better debugging
    origin = request.headers.get('Origin') or request.headers.get('Referer') or ''
    allowed_origins = tenant_rec.get('allowed_origins') or []
    
    # Debug logging
    logger.info(f"Token request: tenant={tenant_id}, origin='{origin}'")
    logger.info(f"Allowed origins: {allowed_origins}")

    # Skip origin check if wildcard is allowed
    if '*' in allowed_origins:
        logger.info("Wildcard origin allowed, skipping check")
    else:
        # Flexible origin matching
        origin_ok = False
        for allowed in allowed_origins:
            # Handle special cases:
            # 1. Direct match
            if allowed == origin:
                logger.info(f"Origin direct match: {origin} == {allowed}")
                origin_ok = True
                break
                
            # 2. Origin is base domain of allowed origin (example.com matches example.com/path)
            if allowed.startswith(origin):
                logger.info(f"Origin base match: {origin} is base of {allowed}")
                origin_ok = True
                break
                
            # 3. Allowed is base domain of origin (example.com/path matches example.com)
            if origin.startswith(allowed):
                logger.info(f"Origin path match: {origin} starts with {allowed}")
                origin_ok = True
                break
                
        if not origin_ok:
            logger.warning(f"Origin forbidden: '{origin}' does not match any allowed origin: {allowed_origins}")
            raise HTTPException(status_code=403, detail=f"forbidden_origin")
    
    # Generate token
    now = int(time.time())
    payload = {
        "tenant": tenant_id,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "aud": "integrity-report"
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    logger.info(f"Issued token for tenant {tenant_id}")
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS}