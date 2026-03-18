from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.scan import (
    ScanHistoryDTO,
    ScanRequest,
    ScanResultDTO,
    ScanStatusDTO,
)
from app.services.scan_service import ScanService
from app.utils.result_serializer import serialize_scan_result

router = APIRouter(prefix="/scan", tags=["scan"])


def get_scan_service() -> ScanService:
    from app.main import scan_service
    return scan_service


@router.post("/start")
async def start_scan(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    record = await svc.start_scan(db, request)
    return {"scan_id": record.scan_id, "status": record.status}


@router.get("/status/{scan_id}")
async def get_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    payload = await svc.get_status_payload(db, scan_id)
    if not payload:
        raise HTTPException(404, "Scan not found")
    return ScanStatusDTO.model_validate(payload)


@router.get("/running")
async def get_running(
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    record = await svc.get_running(db)
    if not record:
        return None
    payload = await svc.get_status_payload(db, record.scan_id)
    return ScanStatusDTO.model_validate(payload)


@router.post("/cancel/{scan_id}")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    ok = await svc.cancel_scan(db, scan_id)
    if not ok:
        raise HTTPException(400, "Cannot cancel scan")
    return {"message": "Scan cancelled"}


@router.get("/latest")
async def get_latest(
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    record = await svc.get_latest(db)
    if not record:
        return None
    payload = await svc.get_status_payload(db, record.scan_id)
    return ScanStatusDTO.model_validate(payload)


@router.get("/history")
async def list_history(
    page: int = 1,
    size: int = 20,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    record_list, total = await svc.list_history(db, page, size)
    return {
        "items": [ScanHistoryDTO.model_validate(r) for r in record_list],
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/history/{scan_id}")
async def get_history_detail(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    detail = await svc.get_history_detail(db, scan_id)
    if not detail:
        raise HTTPException(404, "Scan not found")
    status_payload = await svc.get_status_payload(db, scan_id)
    return {
        "record": ScanStatusDTO.model_validate(status_payload),
        "result_list": [
            ScanResultDTO.model_validate(serialize_scan_result(r))
            for r in detail["result_list"]
        ],
    }


@router.delete("/history/{scan_id}")
async def delete_history(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    ok = await svc.delete_history(db, scan_id)
    if not ok:
        raise HTTPException(404, "Scan not found")
    return {"message": "Deleted"}


@router.post("/retry/{scan_id}")
async def retry_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    svc: ScanService = Depends(get_scan_service),
):
    record = await svc.retry_scan(db, scan_id)
    if not record:
        raise HTTPException(400, "Cannot retry this scan")
    return {"scan_id": record.scan_id, "status": record.status}
