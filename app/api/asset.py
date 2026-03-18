from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.scan import AssetTimelineDTO, ScanResultDTO
from app.services.asset_service import AssetService
from app.utils.result_serializer import serialize_scan_result
from app.utils.excel_exporter import ExcelExporter

router = APIRouter(prefix="/assets", tags=["assets"])

_asset_service = AssetService()


@router.get("")
async def list_assets(
    keyword: str | None = None,
    claw_type: str | None = None,
    confidence: str | None = None,
    scan_id: str | None = None,
    page: int = 1,
    size: int = 20,
    db: AsyncSession = Depends(get_db),
):
    result_list, total = await _asset_service.list_assets(
        db, keyword, claw_type, confidence, scan_id, page, size
    )
    return {
        "items": [ScanResultDTO.model_validate(serialize_scan_result(r)) for r in result_list],
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/summary")
async def get_summary(
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    return await _asset_service.get_summary(db, scan_id)


@router.get("/export")
async def export_assets(
    keyword: str | None = None,
    claw_type: str | None = None,
    confidence: str | None = None,
    scan_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    data = await _asset_service.get_export_data(
        db, keyword, claw_type, confidence, scan_id
    )
    buffer = ExcelExporter.export(data)
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=findclaw_export.xlsx"},
    )


@router.get("/export/{export_scan_id}")
async def export_scan(
    export_scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    data = await _asset_service.get_export_data(db, scan_id=export_scan_id)
    buffer = ExcelExporter.export(data)
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=scan_{export_scan_id}.xlsx"},
    )


@router.get("/{ip}/{port}/timeline")
async def get_asset_timeline(
    ip: str,
    port: int,
    db: AsyncSession = Depends(get_db),
):
    current, timeline = await _asset_service.get_asset_timeline(db, ip, port)
    if not current:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetTimelineDTO(
        asset=ScanResultDTO.model_validate(serialize_scan_result(current)),
        timeline=[
            ScanResultDTO.model_validate(serialize_scan_result(item))
            for item in timeline
        ],
    )
