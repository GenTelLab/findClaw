import asyncio
import logging

from app.config import settings
from app.scanner.cidr_splitter import CidrSplitter
from app.scanner.nmap_executor import (
    NmapExecutor,
    NmapResult,
    OpenPort,
    is_syn_privilege_error,
)
from app.utils.ip_parser import ParsedTarget

logger = logging.getLogger(__name__)

IP_BATCH_SIZE = 20
CIDR_BATCH_SIZE = 8


class PortDiscoveryScanner:

    def __init__(self):
        self._executor = NmapExecutor()
        self._max_parallel = settings.scan_pool_size

    async def discover(
        self,
        target: ParsedTarget,
        ports: str,
        rate: int = 1000,
        exclude_targets: str = "",
        exclude_ports: str = "",
        on_progress: callable = None,
    ) -> list[OpenPort]:
        all_port_list: list[OpenPort] = []
        total_batches = 0

        ip_batch_list = _chunk(target.single_ip_list, IP_BATCH_SIZE)
        cidr_sub_list = CidrSplitter.split_all(target.cidr_list)
        cidr_batch_list = _chunk(cidr_sub_list, CIDR_BATCH_SIZE)

        all_batch_list: list[list[str]] = []
        all_batch_list.extend(ip_batch_list)
        all_batch_list.extend(cidr_batch_list)
        total_batches = len(all_batch_list)

        semaphore = asyncio.Semaphore(self._max_parallel)
        completed = 0

        async def _scan_batch(batch: list[str]) -> NmapResult:
            nonlocal completed
            async with semaphore:
                result = await self._executor.syn_scan(
                    batch,
                    ports,
                    rate,
                    exclude_targets=exclude_targets,
                    exclude_ports=exclude_ports,
                )
                if is_syn_privilege_error(result.error):
                    logger.warning(
                        "SYN scan requires extra privileges, retrying batch with connect scan"
                    )
                    result = await self._executor.connect_scan(
                        batch,
                        ports,
                        rate,
                        exclude_targets=exclude_targets,
                        exclude_ports=exclude_ports,
                    )
                completed += 1
                if on_progress:
                    await on_progress(completed, total_batches)
                return result

        task_list = [_scan_batch(batch) for batch in all_batch_list]
        result_list = await asyncio.gather(*task_list, return_exceptions=True)

        for result in result_list:
            if isinstance(result, Exception):
                logger.error("Batch scan failed: %s", result)
                continue
            if result.error:
                logger.warning("Batch scan error: %s", result.error)
            all_port_list.extend(result.open_port_list)

        logger.info(
            "Port discovery done: %d open ports from %d batches",
            len(all_port_list), total_batches,
        )
        return all_port_list

    async def cancel(self) -> None:
        await self._executor.cancel_all()


def _chunk(items: list, size: int) -> list[list]:
    if not items:
        return []
    return [items[i : i + size] for i in range(0, len(items), size)]
