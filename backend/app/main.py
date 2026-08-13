import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from app.config import SECRET_KEY, ALGORITHM, CORS_ORIGINS
from app.database import ensure_indexes, db
from app.services.elastic import ensure_index, es_healthy
from app.routers.auth import router as auth_router
from app.routers.projects import router as projects_router
from app.routers.api_keys import router as api_keys_router
from app.routers.agents import router as agents_router, cleanup_router as agents_cleanup_router
from app.routers.ingest import router as ingest_router
from app.routers.events import router as events_router
from app.routers.incidents import router as incidents_router
from app.routers.threat import router as threat_router
from app.routers.overview import router as overview_router
from app.routers.ws import router as ws_router
from app.services.threat_feed import start_refresh_loop

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    """Backend dependency health — Mongo is required, Elasticsearch degrades."""

    status: str
    mongo: bool
    elasticsearch: bool
    elasticsearch_detail: str | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_indexes()
    try:
        ensure_index()
    except Exception as e:
        logger.warning(f"Elasticsearch not available: {e}")
    start_refresh_loop()
    yield


app = FastAPI(title="SOC Platform", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(projects_router)
app.include_router(api_keys_router)
app.include_router(agents_router)
app.include_router(agents_cleanup_router)
app.include_router(ingest_router)
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(threat_router)
app.include_router(overview_router)
app.include_router(ws_router)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
def root():
    """Point browsers at the interactive API documentation."""
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, summary="Check backend dependency health")
def health():
    """Report Mongo + Elasticsearch connectivity.

    Mongo is required for the platform to work; Elasticsearch is optional and
    ingestion degrades to a Mongo-only path when it is down.
    """
    mongo_ok = False
    try:
        db.command("ping")
        mongo_ok = True
    except Exception:
        pass
    es_ok = False
    es_detail = None
    try:
        es_ok = es_healthy()
    except Exception as exc:
        es_detail = str(exc)
    return HealthResponse(
        status="ok" if mongo_ok else "degraded",
        mongo=mongo_ok,
        elasticsearch=es_ok,
        elasticsearch_detail=es_detail,
    )


def _find_project_root() -> str:
    """Walk up from this file to the directory that serves agents/install.sh.

    A candidate counts only when it actually holds the install scripts, so a
    stray directory named agents can never shadow the real repo root. Works
    for the native layout (backend/app/...) and the docker layout (/app/app/...
    with /app/agents).
    """
    cur = os.path.dirname(os.path.abspath(__file__))
    while True:
        candidates = (
            os.path.join(cur, "agents", "install.sh"),
            os.path.join(cur, "agents", "install.ps1"),
        )
        if all(os.path.isfile(c) for c in candidates):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


_project_root = _find_project_root()


@app.get("/install.ps1")
def serve_install_ps1():
    path = os.path.join(_project_root, "agents", "install.ps1")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="install.ps1 not found")
    return FileResponse(path, media_type="text/plain")


@app.get("/install.sh")
def serve_install_sh():
    path = os.path.join(_project_root, "agents", "install.sh")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="install.sh not found")
    return FileResponse(path, media_type="text/plain")


@app.get("/agents/journal_watcher.py")
def serve_journal_watcher():
    path = os.path.join(_project_root, "agents", "journal_watcher.py")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="journal_watcher.py not found")
    return FileResponse(path, media_type="text/plain")


@app.get("/usp.js")
def serve_usp_js():
    path = os.path.join(_project_root, "backend", "app", "static", "usp.js")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="usp.js not found")
    return FileResponse(path, media_type="application/javascript")

