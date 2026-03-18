from fastapi import APIRouter

from app.api.scan import router as scan_router
from app.api.asset import router as asset_router
from app.api.trends import router as trends_router

api_router = APIRouter(prefix="/api")

api_router.include_router(scan_router)
api_router.include_router(asset_router)
api_router.include_router(trends_router)
