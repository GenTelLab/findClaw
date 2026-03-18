from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan_record import ScanRecord
from app.models.scan_result import ScanResult

router = APIRouter(prefix="/trends", tags=["trends"])


@router.get("/asset-count")
async def asset_count_trend(
    days: int = 30,
    task_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=max(days, 1))
    query = (
        select(
            func.date(ScanRecord.created_at).label("date"),
            func.sum(ScanRecord.confirmed_count).label("confirmed"),
            func.sum(ScanRecord.suspected_count).label("suspected"),
        )
        .where(
            ScanRecord.status == "COMPLETED",
            ScanRecord.created_at >= since,
        )
        .group_by(func.date(ScanRecord.created_at))
        .order_by(func.date(ScanRecord.created_at))
    )

    if task_id:
        query = query.where(ScanRecord.triggered_by == task_id)

    result = await db.execute(query)
    return [
        {
            "date": str(row.date),
            "confirmed": row.confirmed or 0,
            "suspected": row.suspected or 0,
        }
        for row in result.all()
    ]


@router.get("/type-distribution")
async def type_distribution(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(days=max(days, 1))
    subquery = (
        select(ScanRecord.scan_id)
        .where(
            ScanRecord.status == "COMPLETED",
            ScanRecord.created_at >= since,
        )
        .scalar_subquery()
    )

    query = (
        select(
            ScanResult.claw_type,
            func.count(ScanResult.id).label("count"),
        )
        .where(ScanResult.scan_id.in_(subquery))
        .group_by(ScanResult.claw_type)
    )

    result = await db.execute(query)
    return [
        {"type": row.claw_type or "Unknown", "family": row.claw_type or "Unknown", "count": row.count}
        for row in result.all()
    ]
