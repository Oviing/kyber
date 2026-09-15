from contextlib import asynccontextmanager

from fastapi import FastAPI

from kyber.api.routes_scans import router as scans_router
from kyber.api.routes_targets import router as targets_router
from kyber.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
    except Exception:
        pass  # DB may not be up in unit tests
    yield


app = FastAPI(title="Kyber Red-Team Sandbox API", version="0.1.0", lifespan=lifespan)
app.include_router(targets_router)
app.include_router(scans_router)


@app.get("/health")
def health():
    return {"ok": True, "version": "0.1.0"}
