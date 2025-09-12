from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
import sqlite3, json, logging
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post('/tenant/{tenant_id}/manifest/push')
async def push_manifest(tenant_id: str, payload: dict):
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
async def get_manifest(tenant_id: str):
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
