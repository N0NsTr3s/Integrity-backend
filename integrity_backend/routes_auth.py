import os
import time
import jwt
from fastapi import APIRouter, Request, HTTPException
from .db import get_tenant_record

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
        raise HTTPException(status_code=500, detail="token_issuer_not_configured")

    tenant_rec = get_tenant_record(tenant_id)
    if not tenant_rec:
        raise HTTPException(status_code=404, detail="tenant_not_found")

    # Check if origin matches tenant's allowed origins
    origin = request.headers.get('Origin') or request.headers.get('Referer') or ''
    allowed = tenant_rec.get('allowed_origins') or []
    if not (origin and ('*' in allowed or any(origin.startswith(a) for a in allowed))):
        raise HTTPException(status_code=403, detail="forbidden_origin")

    now = int(time.time())
    payload = {
        "tenant": tenant_id,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "aud": "integrity-report"
    }
    token = jwt.encode(payload=payload, key=JWT_SECRET, algorithm="HS256")
    return {"token": token, "expires_in": TOKEN_TTL_SECONDS}