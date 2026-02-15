"""Minimal launcher that runs the FastAPI app from integrity_backend package."""
import os

from integrity_backend import app


if __name__ == '__main__':
    import uvicorn

    port = int(os.environ.get('PORT', 5500))
    uvicorn.run(app, host='0.0.0.0', port=port)
