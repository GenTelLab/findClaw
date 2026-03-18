import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_result import ScanResult

logger = logging.getLogger(__name__)


class ChangeDetectionService:

    async def detect(
        self,
        db: AsyncSession,
        current_scan_id: str,
        previous_scan_id: str | None,
    ) -> dict:
        current_set = await self._get_result_set(db, current_scan_id)

        if not previous_scan_id:
            await self._mark_new(db, current_scan_id, current_set)
            new_item_list = await self._load_rows_by_ids(db, list(current_set.values()))
            return {
                "new_count": len(current_set),
                "removed_count": 0,
                "unchanged_count": 0,
                "new_item_list": new_item_list,
            }

        previous_set = await self._get_result_set(db, previous_scan_id)

        current_key_set = set(current_set.keys())
        previous_key_set = set(previous_set.keys())

        new_key_set = current_key_set - previous_key_set
        removed_key_set = previous_key_set - current_key_set
        unchanged_key_set = current_key_set & previous_key_set

        await self._mark_new(db, current_scan_id, {k: current_set[k] for k in new_key_set})

        logger.info(
            "Change detection: +%d -%d =%d",
            len(new_key_set), len(removed_key_set), len(unchanged_key_set),
        )

        new_item_list = await self._load_rows_by_ids(
            db, [current_set[key] for key in new_key_set]
        )

        return {
            "new_count": len(new_key_set),
            "removed_count": len(removed_key_set),
            "unchanged_count": len(unchanged_key_set),
            "new_item_list": new_item_list,
        }

    async def _get_result_set(
        self, db: AsyncSession, scan_id: str
    ) -> dict[tuple[str, int, str | None, str | None, str | None], int]:
        result = await db.execute(
            select(ScanResult).where(ScanResult.scan_id == scan_id)
        )
        return {
            (
                r.ip,
                r.port,
                r.claw_type,
                r.claw_version,
                r.matched_rule,
            ): r.id
            for r in result.scalars().all()
        }

    async def _mark_new(
        self,
        db: AsyncSession,
        scan_id: str,
        key_map: dict[tuple[str, int, str | None, str | None, str | None], int],
    ) -> None:
        if not key_map:
            return
        for result_id in key_map.values():
            obj = await db.get(ScanResult, result_id)
            if obj:
                obj.is_new = True
        await db.flush()

    async def _load_rows_by_ids(
        self, db: AsyncSession, result_id_list: list[int]
    ) -> list[ScanResult]:
        if not result_id_list:
            return []

        result = await db.execute(
            select(ScanResult).where(ScanResult.id.in_(result_id_list))
        )
        row_map = {row.id: row for row in result.scalars().all()}
        return [row_map[result_id] for result_id in result_id_list if result_id in row_map]
