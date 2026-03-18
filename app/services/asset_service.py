import logging
from collections import OrderedDict
from types import SimpleNamespace

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_result import ScanResult
from app.utils.result_serializer import serialize_scan_result

logger = logging.getLogger(__name__)


class AssetService:

    async def list_assets(
        self,
        db: AsyncSession,
        keyword: str | None = None,
        claw_type: str | None = None,
        confidence: str | None = None,
        scan_id: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[ScanResult], int]:
        query = select(ScanResult)
        query = query.order_by(ScanResult.discovered_at.desc())
        query = _apply_filters(query, keyword, claw_type, confidence, scan_id)

        result = await db.execute(query)
        row_list = list(result.scalars().all())
        asset_list = _build_asset_current_list(row_list)
        total = len(asset_list)
        paged_list = asset_list[(page - 1) * size: page * size]
        return paged_list, total

    async def get_summary(self, db: AsyncSession, scan_id: str | None = None) -> dict:
        query = select(ScanResult).order_by(ScanResult.discovered_at.desc())
        if scan_id:
            query = query.where(ScanResult.scan_id == scan_id)
        result = await db.execute(query)
        asset_list = _build_asset_current_list(list(result.scalars().all()))

        total = len(asset_list)
        confirmed = sum(1 for item in asset_list if item.confidence == "CONFIRMED")
        suspected = total - confirmed

        type_distribution: dict[str, int] = {}
        ip_set: set[str] = set()
        for item in asset_list:
            family = item.family_hint or item.claw_type or "Unknown"
            type_distribution[family] = type_distribution.get(family, 0) + 1
            ip_set.add(item.ip)

        return {
            "total": total,
            "total_assets": total,
            "unique_ip_count": len(ip_set),
            "confirmed_count": confirmed,
            "suspected_count": suspected,
            "type_distribution": type_distribution,
            "family_distribution": type_distribution,
        }

    async def get_export_data(
        self,
        db: AsyncSession,
        keyword: str | None = None,
        claw_type: str | None = None,
        confidence: str | None = None,
        scan_id: str | None = None,
    ) -> list[dict]:
        query = select(ScanResult).order_by(ScanResult.discovered_at.desc())
        query = _apply_filters(query, keyword, claw_type, confidence, scan_id)
        result = await db.execute(query)
        asset_list = _build_asset_current_list(list(result.scalars().all()))
        return [
            {
                "ip": item["ip"],
                "port": item["port"],
                "claw_type": item["claw_type"],
                "family_hint": item["family_hint"],
                "variant_hint": item["variant_hint"],
                "claw_version": item["claw_version"],
                "confidence": item["confidence"],
                "confidence_score": item["confidence_score"],
                "matched_keyword": item["matched_keyword"],
                "matched_rule": item["matched_rule"],
                "discovered_at": item["discovered_at"],
                "is_new": item["is_new"],
                "discovery_source": ", ".join(item["discovery_source_list"]),
                "evidence": " | ".join(item["evidence_list"]),
            }
            for item in [serialize_scan_result(r) for r in asset_list]
        ]

    async def get_asset_timeline(
        self,
        db: AsyncSession,
        ip: str,
        port: int,
    ) -> tuple[ScanResult | None, list[ScanResult]]:
        query = (
            select(ScanResult)
            .where(ScanResult.ip == ip, ScanResult.port == port)
            .order_by(ScanResult.discovered_at.desc())
        )
        result = await db.execute(query)
        row_list = list(result.scalars().all())
        if not row_list:
            return None, []
        asset_list = _build_asset_current_list(row_list)
        current = asset_list[0] if asset_list else None
        return current, row_list


def _apply_filters(
    query: Select,
    keyword: str | None,
    claw_type: str | None,
    confidence: str | None,
    scan_id: str | None,
) -> Select:
    if scan_id:
        query = query.where(ScanResult.scan_id == scan_id)

    if claw_type:
        query = query.where(ScanResult.claw_type == claw_type)

    if confidence:
        query = query.where(ScanResult.confidence == confidence)

    if keyword:
        like = f"%{keyword}%"
        query = query.where(
            ScanResult.ip.ilike(like)
            | ScanResult.claw_type.ilike(like)
            | ScanResult.claw_version.ilike(like)
            | ScanResult.matched_keyword.ilike(like)
            | ScanResult.matched_rule.ilike(like)
        )

    return query


def _build_asset_current_list(row_list: list[ScanResult]) -> list[ScanResult]:
    grouped_map: OrderedDict[tuple[str, int], list[ScanResult]] = OrderedDict()
    for row in row_list:
        key = (row.ip, row.port)
        grouped_map.setdefault(key, []).append(row)

    asset_list: list[ScanResult] = []
    for item_list in grouped_map.values():
        latest = item_list[0]
        asset_list.append(
            SimpleNamespace(
                **latest.__dict__,
                first_seen_at=item_list[-1].discovered_at,
                last_seen_at=item_list[0].discovered_at,
                seen_count=len(item_list),
                scan_count=len({item.scan_id for item in item_list}),
            )
        )
    return asset_list
