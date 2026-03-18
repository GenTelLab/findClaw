import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.fingerprint.engine import FingerprintEngine
from app.models.scan_record import ScanRecord
from app.models.scan_result import ScanResult
from app.scanner.deep_probe import DeepProbeScanner
from app.scanner.mdns_scanner import MdnsScanner
from app.scanner.nmap_executor import OpenPort
from app.scanner.port_discovery import PortDiscoveryScanner
from app.schemas.scan import ScanRequest
from app.utils.ip_parser import IpRangeParser
from app.utils.port_parser import PortRangeParser
from app.utils.result_serializer import serialize_scan_result
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ScanRuntimeState:
    current_phase: str = "PENDING"
    phase_message: str = ""
    progress_percent: float = 0.0


class ScanService:

    def __init__(self, fingerprint_engine: FingerprintEngine):
        self._fingerprint_engine = fingerprint_engine
        self._running_scan_map: dict[str, asyncio.Task] = {}
        self._runtime_state_map: dict[str, ScanRuntimeState] = {}
        self._result_lock_map: dict[str, asyncio.Lock] = {}
        self._scanner_map: dict[str, dict[str, object]] = {}

    async def start_scan(
        self, db: AsyncSession, request: ScanRequest, triggered_by: str | None = None
    ) -> ScanRecord:
        scan_id = str(uuid.uuid4())

        ports_str = request.scan_ports or settings.default_scan_ports
        target = IpRangeParser.parse(request.target_ips)
        total_hosts = IpRangeParser.count_hosts(target)

        record = ScanRecord(
            scan_id=scan_id,
            target_ips=request.target_ips,
            scan_ports=ports_str,
            exclude_ips=request.exclude_ips,
            exclude_ports=request.exclude_ports,
            scan_rate=request.scan_rate,
            parallelism=request.parallelism,
            status="SCANNING",
            total_hosts=total_hosts,
            start_time=datetime.now(timezone.utc),
            triggered_by=triggered_by,
        )
        db.add(record)
        await db.flush()

        self._runtime_state_map[scan_id] = ScanRuntimeState(
            current_phase="DISCOVERY",
            phase_message="端口发现中",
            progress_percent=0.0,
        )
        self._result_lock_map[scan_id] = asyncio.Lock()

        task = asyncio.create_task(self._execute_scan(scan_id, request))
        self._running_scan_map[scan_id] = task

        return record

    async def recover_incomplete_scans(self) -> int:
        async with async_session() as db:
            result = await db.execute(
                select(ScanRecord).where(ScanRecord.status == "SCANNING")
            )
            record_list = list(result.scalars().all())

            now = datetime.now(timezone.utc)
            for record in record_list:
                record.status = "FAILED"
                record.end_time = now
                record.error_message = "Scan interrupted by service restart."
                if record.start_time:
                    delta = now - record.start_time
                    record.duration_ms = int(delta.total_seconds() * 1000)

            await db.commit()
            return len(record_list)

    async def get_status(self, db: AsyncSession, scan_id: str) -> ScanRecord | None:
        result = await db.execute(
            select(ScanRecord).where(ScanRecord.scan_id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_status_payload(
        self, db: AsyncSession, scan_id: str
    ) -> dict | None:
        record = await self.get_status(db, scan_id)
        if not record:
            return None

        recent_result_list = await self._list_recent_results(db, scan_id)
        runtime = self._runtime_state_map.get(scan_id)

        duration_ms = record.duration_ms
        if record.status == "SCANNING" and record.start_time:
            delta = datetime.now(timezone.utc) - record.start_time
            duration_ms = int(delta.total_seconds() * 1000)

        progress = 100.0 if record.status == "COMPLETED" else 0.0
        current_phase = "COMPLETED" if record.status == "COMPLETED" else record.status
        phase_message = ""

        if runtime:
            progress = runtime.progress_percent
            current_phase = runtime.current_phase
            phase_message = runtime.phase_message
        elif record.status == "FAILED":
            progress = 100.0
            current_phase = "FAILED"
            phase_message = "扫描失败"
        elif record.status == "CANCELLED":
            progress = 100.0
            current_phase = "CANCELLED"
            phase_message = "扫描已取消"

        return {
            "scan_id": record.scan_id,
            "target_ips": record.target_ips,
            "scan_ports": record.scan_ports,
            "status": record.status,
            "total_hosts": record.total_hosts,
            "scanned_hosts": record.scanned_hosts,
            "open_ports": record.open_ports,
            "confirmed_count": record.confirmed_count,
            "suspected_count": record.suspected_count,
            "start_time": record.start_time,
            "end_time": record.end_time,
            "duration_ms": duration_ms,
            "error_message": record.error_message,
            "progress": round(progress, 2),
            "current_phase": current_phase,
            "phase_message": phase_message,
            "recent_result_list": [serialize_scan_result(item) for item in recent_result_list],
        }

    async def get_running(self, db: AsyncSession) -> ScanRecord | None:
        result = await db.execute(
            select(ScanRecord)
            .where(ScanRecord.status == "SCANNING")
            .order_by(desc(ScanRecord.created_at))
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def get_latest(self, db: AsyncSession) -> ScanRecord | None:
        result = await db.execute(
            select(ScanRecord).order_by(desc(ScanRecord.created_at)).limit(1)
        )
        return result.scalar_one_or_none()

    async def cancel_scan(self, db: AsyncSession, scan_id: str) -> bool:
        scanner_state = self._scanner_map.get(scan_id, {})

        discovery = scanner_state.get("discovery")
        if discovery:
            await discovery.cancel()

        mdns_scanner = scanner_state.get("mdns")
        if mdns_scanner:
            await mdns_scanner.cancel()

        prober = scanner_state.get("prober")
        if prober:
            await prober.cancel()

        task = self._running_scan_map.get(scan_id)
        if task and not task.done():
            task.cancel()

        record = await self.get_status(db, scan_id)
        if record and record.status == "SCANNING":
            record.status = "CANCELLED"
            record.end_time = datetime.now(timezone.utc)
            if record.start_time:
                delta = record.end_time - record.start_time
                record.duration_ms = int(delta.total_seconds() * 1000)
            self._set_runtime_state(scan_id, "CANCELLED", "扫描已取消", 100.0)
            await db.flush()
            return True
        return False

    async def list_history(
        self, db: AsyncSession, page: int = 1, size: int = 20
    ) -> tuple[list[ScanRecord], int]:
        from sqlalchemy import func

        total_result = await db.execute(select(func.count(ScanRecord.id)))
        total = total_result.scalar() or 0

        result = await db.execute(
            select(ScanRecord)
            .order_by(desc(ScanRecord.created_at))
            .offset((page - 1) * size)
            .limit(size)
        )
        return list(result.scalars().all()), total

    async def get_history_detail(self, db: AsyncSession, scan_id: str) -> dict | None:
        record = await self.get_status(db, scan_id)
        if not record:
            return None

        result = await db.execute(
            select(ScanResult).where(ScanResult.scan_id == scan_id)
        )
        result_list = list(result.scalars().all())

        return {"record": record, "result_list": result_list}

    async def delete_history(self, db: AsyncSession, scan_id: str) -> bool:
        record = await self.get_status(db, scan_id)
        if not record:
            return False
        await db.delete(record)
        await db.flush()
        return True

    async def retry_scan(self, db: AsyncSession, scan_id: str) -> ScanRecord | None:
        record = await self.get_status(db, scan_id)
        if not record or record.status not in ("FAILED", "CANCELLED"):
            return None

        request = ScanRequest(
            target_ips=record.target_ips,
            scan_ports=record.scan_ports,
            exclude_ips=record.exclude_ips,
            exclude_ports=record.exclude_ports,
            scan_rate=record.scan_rate,
            parallelism=record.parallelism,
        )
        return await self.start_scan(db, request, triggered_by=record.triggered_by)

    async def _execute_scan(self, scan_id: str, request: ScanRequest) -> None:
        try:
            target = IpRangeParser.parse(request.target_ips)
            exclude_target = (
                IpRangeParser.parse(request.exclude_ips)
                if request.exclude_ips
                else None
            )
            ports_str = request.scan_ports or settings.default_scan_ports
            port_list = PortRangeParser.expand_claw_related(
                PortRangeParser.parse(ports_str)
            )
            exclude_port_set = set(PortRangeParser.parse(request.exclude_ports))
            port_list = [port for port in port_list if port not in exclude_port_set]

            if not port_list:
                self._set_runtime_state(scan_id, "FINALIZING", "端口被排除后无可扫描目标", 95.0)
                await self._update_record(scan_id, open_ports=0, scanned_hosts=0)
                await self._finalize_scan(scan_id, "COMPLETED")
                return

            nmap_ports = PortRangeParser.to_nmap_format(port_list)
            total_hosts = IpRangeParser.count_hosts(target)

            discovery = PortDiscoveryScanner()
            mdns_scanner = MdnsScanner()
            self._scanner_map[scan_id] = {
                "discovery": discovery,
                "mdns": mdns_scanner,
                "prober": None,
            }
            open_port_list = await discovery.discover(
                target,
                nmap_ports,
                request.scan_rate,
                exclude_targets=request.exclude_ips or "",
                exclude_ports=request.exclude_ports or "",
                on_progress=lambda done, total: self._update_discovery_progress(
                    scan_id, done, total, total_hosts
                ),
            )

            if settings.enable_mdns_discovery:
                self._set_runtime_state(scan_id, "DISCOVERY", "mDNS 补充发现中", 38.0)
                mdns_port_list = await mdns_scanner.discover(
                    target,
                    exclude_target=exclude_target,
                    exclude_port_set=exclude_port_set,
                    timeout=settings.mdns_discovery_timeout,
                )
                open_port_list = _merge_open_ports(open_port_list, mdns_port_list)

            await self._update_record(
                scan_id,
                open_ports=len(open_port_list),
                scanned_hosts=total_hosts,
            )

            if not open_port_list:
                self._set_runtime_state(scan_id, "FINALIZING", "未发现开放端口", 95.0)
                await self._finalize_scan(scan_id, "COMPLETED")
                return

            self._set_runtime_state(scan_id, "PROBING", "深度探测与识别中", 40.0)

            prober = DeepProbeScanner()
            self._scanner_map[scan_id]["prober"] = prober
            await prober.probe_all(
                open_port_list,
                on_progress=lambda done, total: self._update_probe_progress(
                    scan_id, done, total
                ),
                on_result=lambda probe: self._handle_probe_result(scan_id, probe),
            )

            self._set_runtime_state(scan_id, "FINALIZING", "结果汇总中", 98.0)
            await self._finalize_scan(scan_id, "COMPLETED")

        except asyncio.CancelledError:
            logger.info("Scan %s cancelled", scan_id)
            self._set_runtime_state(scan_id, "CANCELLED", "扫描已取消", 100.0)
        except Exception as e:
            logger.exception("Scan %s failed", scan_id)
            self._set_runtime_state(scan_id, "FAILED", "扫描失败", 100.0)
            await self._finalize_scan(scan_id, "FAILED", str(e))
        finally:
            self._running_scan_map.pop(scan_id, None)
            self._scanner_map.pop(scan_id, None)
            self._result_lock_map.pop(scan_id, None)

    async def _update_discovery_progress(
        self,
        scan_id: str,
        done: int,
        total: int,
        total_hosts: int,
    ) -> None:
        progress = _scaled_progress(done, total, 0.0, 40.0)
        scanned_hosts = int(total_hosts * (done / total)) if total else 0
        self._set_runtime_state(scan_id, "DISCOVERY", "端口发现中", progress)
        await self._update_record(scan_id, scanned_hosts=scanned_hosts)

    async def _update_probe_progress(self, scan_id: str, done: int, total: int) -> None:
        progress = _scaled_progress(done, total, 40.0, 95.0)
        self._set_runtime_state(scan_id, "PROBING", "深度探测与识别中", progress)

    async def _update_record(self, scan_id: str, **kwargs) -> None:
        async with async_session() as db:
            result = await db.execute(
                select(ScanRecord).where(ScanRecord.scan_id == scan_id)
            )
            rec = result.scalar_one_or_none()
            if rec:
                for k, v in kwargs.items():
                    setattr(rec, k, v)
                await db.commit()

    async def _handle_probe_result(self, scan_id: str, probe) -> None:
        match = self._fingerprint_engine.match(probe)
        if not match:
            return

        async with self._result_lock_map[scan_id]:
            async with async_session() as db:
                scan_result = ScanResult(
                    scan_id=scan_id,
                    ip=probe.ip,
                    port=probe.port,
                    claw_type=match.claw_type,
                    claw_version=match.claw_version,
                    confidence=match.confidence,
                    confidence_score=match.confidence_score,
                    matched_keyword=match.matched_keyword,
                    matched_rule=match.matched_rule,
                    raw_response=_collect_raw(probe, match),
                )
                db.add(scan_result)

                record_result = await db.execute(
                    select(ScanRecord).where(ScanRecord.scan_id == scan_id)
                )
                rec = record_result.scalar_one_or_none()
                if rec:
                    if match.confidence == "CONFIRMED":
                        rec.confirmed_count += 1
                    else:
                        rec.suspected_count += 1

                await db.commit()

    async def _finalize_scan(
        self, scan_id: str, status: str, error: str | None = None
    ) -> None:
        async with async_session() as db:
            result = await db.execute(
                select(ScanRecord).where(ScanRecord.scan_id == scan_id)
            )
            rec = result.scalar_one_or_none()
            if rec:
                rec.status = status
                rec.end_time = datetime.now(timezone.utc)
                if rec.start_time:
                    delta = rec.end_time - rec.start_time
                    rec.duration_ms = int(delta.total_seconds() * 1000)
                rec.error_message = error
                await db.commit()

        if status == "COMPLETED":
            self._set_runtime_state(scan_id, "COMPLETED", "扫描完成", 100.0)
        elif status == "FAILED":
            self._set_runtime_state(scan_id, "FAILED", "扫描失败", 100.0)

    async def _list_recent_results(
        self, db: AsyncSession, scan_id: str, limit: int = 10
    ) -> list[ScanResult]:
        result = await db.execute(
            select(ScanResult)
            .where(ScanResult.scan_id == scan_id)
            .order_by(desc(ScanResult.discovered_at), desc(ScanResult.id))
            .limit(limit)
        )
        return list(result.scalars().all())

    def _set_runtime_state(
        self,
        scan_id: str,
        current_phase: str,
        phase_message: str,
        progress_percent: float,
    ) -> None:
        self._runtime_state_map[scan_id] = ScanRuntimeState(
            current_phase=current_phase,
            phase_message=phase_message,
            progress_percent=min(max(progress_percent, 0.0), 100.0),
        )


def _collect_raw(probe, match=None) -> dict | None:
    match_meta = {
        "family_hint": getattr(match, "family_hint", None),
        "variant_hint": getattr(match, "variant_hint", None),
        "matched_rule_list": getattr(match, "matched_rule_list", []),
    }
    if not probe.response_list:
        return {
            "__meta__": {
                "discovery_source_list": probe.discovery_source_list,
                "ws_available": probe.ws_available,
                "sse_available": probe.sse_available,
                "nmap_service": probe.nmap_service,
                "nmap_version": probe.nmap_version,
                "nse_output": probe.nse_output,
                "peer_port_list": probe.peer_port_list,
                **match_meta,
            }
        }

    response_map = {
        resp.path: {
            "status": resp.status_code,
            "headers": resp.headers,
            "body": resp.body[:2000],
            "title": resp.title,
            "content_type": resp.content_type,
            "body_hash": resp.body_hash,
            "asset_path_list": resp.asset_path_list,
            "app_hint_list": resp.app_hint_list,
        }
        for resp in probe.response_list
        if not resp.error
    }

    response_map["__meta__"] = {
        "discovery_source_list": probe.discovery_source_list,
        "ws_available": probe.ws_available,
        "sse_available": probe.sse_available,
        "nmap_service": probe.nmap_service,
        "nmap_version": probe.nmap_version,
        "nse_output": probe.nse_output,
        "peer_port_list": probe.peer_port_list,
        **match_meta,
    }

    return response_map


def _scaled_progress(done: int, total: int, start: float, end: float) -> float:
    if total <= 0:
        return start

    ratio = min(max(done / total, 0.0), 1.0)
    return start + (end - start) * ratio


def _merge_open_ports(
    base_port_list: list[OpenPort],
    extra_port_list: list[OpenPort],
) -> list[OpenPort]:
    merged_map: dict[tuple[str, int], OpenPort] = {
        (item.ip, item.port): item for item in base_port_list
    }
    for item in extra_port_list:
        merged_map.setdefault((item.ip, item.port), item)
    return sorted(merged_map.values(), key=lambda item: (item.ip, item.port))
