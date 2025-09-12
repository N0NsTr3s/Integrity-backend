from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
from pathlib import Path
from .db import init_db
from .routes_manifest import router as manifest_router
from .routes_reports import router as reports_router
from .routes_admin import router as admin_router
from .routes_auth import router as auth_router
from .routes_dashboard import router as dashboard_router  # Add this line

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database before creating app
init_db()

# Then create the FastAPI app
app = FastAPI(title='Script Integrity SaaS')

# configure CORS and static mounting
static_path = Path(__file__).parent.parent / 'static'
static_path.mkdir(parents=True, exist_ok=True)
app.mount('/static', StaticFiles(directory=str(static_path)), name='static')

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://n0nstr3s.github.io",
        "https://integrity-backend-yrq3.onrender.com",
        "https://n0nstr3s.github.io/Integrity",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# include routers
app.include_router(manifest_router)
app.include_router(reports_router)
app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(dashboard_router)  # Add this line

# expose static_path for compatibility
__all__ = ['app']


# Basic convenience endpoints
from fastapi import HTTPException
@app.get('/health')
async def health_check():
    return {"status": "healthy", "service": "Script Integrity SaaS"}

@app.get('/')
async def root():
    return {"status": "ok", "service": "Script Integrity SaaS"}

@app.get('/integrity.js')
async def serve_integrity_js():
    js_file = Path(__file__).parent.parent / 'integrity.js'
    if js_file.exists():
        return FileResponse(str(js_file), media_type='application/javascript')
    raise HTTPException(status_code=404, detail='integrity.js not found')

@app.get('/admin')
async def admin_ui():
    admin_file = Path(__file__).parent.parent / 'static' / 'admin.html'
    if admin_file.exists():
        return FileResponse(str(admin_file))
    raise HTTPException(status_code=404, detail='admin UI not found')
