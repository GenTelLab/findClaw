import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import api_router
from app.config import settings
from app.database import create_tables
from app.fingerprint.engine import FingerprintEngine
from app.services.scan_service import ScanService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)

fingerprint_engine = FingerprintEngine()
scan_service = ScanService(fingerprint_engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables()
    fingerprint_engine.load()
    recovered_scan_count = await scan_service.recover_incomplete_scans()
    if recovered_scan_count:
        logging.getLogger(__name__).warning(
            "Recovered %d interrupted scans after restart",
            recovered_scan_count,
        )
    logging.getLogger(__name__).info(
        "FindClaw started on %s:%d", settings.server_host, settings.server_port
    )
    yield


app = FastAPI(
    title="君同·抓虾 FindClaw",
    description="企业桌面智能体资产发现平台",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(api_router)
app.mount("/", StaticFiles(directory="static", html=True), name="static")
