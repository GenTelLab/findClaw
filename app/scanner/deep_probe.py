import asyncio
import logging

from app.config import settings
from app.scanner.http_prober import HttpProber, ProbeResult
from app.scanner.nmap_executor import NmapExecutor, OpenPort, is_syn_privilege_error
from app.utils.port_parser import PortRangeParser

logger = logging.getLogger(__name__)


class DeepProbeScanner:

    def __init__(self):
        self._http_prober = HttpProber()
        self._nmap = NmapExecutor()
        self._max_parallel = settings.scan_pool_size

    async def probe_all(
        self,
        open_port_list: list[OpenPort],
        on_progress: callable = None,
        on_result: callable = None,
    ) -> list[ProbeResult]:
        ip_port_map = _build_ip_port_map(open_port_list)
        semaphore = asyncio.Semaphore(self._max_parallel)
        total = len(open_port_list)
        completed = 0

        async def _probe_one(op: OpenPort) -> ProbeResult:
            nonlocal completed
            async with semaphore:
                http_task = self._http_prober.probe(op.ip, op.port)
                nmap_task = self._nmap.service_scan(
                    op.ip,
                    op.port,
                    script=(
                        "http-title,http-headers,"
                        f"{settings.nmap_nse_script_path}"
                    ),
                )
                result, nmap_result = await asyncio.gather(http_task, nmap_task)
                result.discovery_source_list = _seed_discovery_source_list(op)
                result.nmap_service = op.service
                result.nmap_version = op.version
                result.nse_output = op.script_output

                result.peer_port_list = [
                    port for port in ip_port_map.get(op.ip, []) if port != op.port
                ]

                if nmap_result.open_port_list:
                    open_port = nmap_result.open_port_list[0]
                    result.nmap_service = open_port.service or result.nmap_service
                    result.nmap_version = open_port.version or result.nmap_version
                    result.nse_output = open_port.script_output or result.nse_output
                    if "nmap" not in result.discovery_source_list:
                        result.discovery_source_list.append("nmap")

                if on_result:
                    await on_result(result)

                completed += 1
                if on_progress:
                    await on_progress(completed, total)
                return result

        probe_result_list = await _run_probe_batch(open_port_list, _probe_one)

        extra_open_port_list = await self._discover_family_candidates(
            probe_result_list, ip_port_map
        )
        if extra_open_port_list:
            for open_port in extra_open_port_list:
                ip_port_map.setdefault(open_port.ip, []).append(open_port.port)
                ip_port_map[open_port.ip] = sorted(set(ip_port_map[open_port.ip]))
            total += len(extra_open_port_list)
            extra_result_list = await _run_probe_batch(extra_open_port_list, _probe_one)
            probe_result_list.extend(extra_result_list)

        logger.info(
            "Deep probe done: %d/%d targets probed",
            len(probe_result_list), total,
        )
        return probe_result_list

    async def cancel(self) -> None:
        await self._nmap.cancel_all()

    async def _discover_family_candidates(
        self,
        probe_result_list: list[ProbeResult],
        ip_port_map: dict[str, list[int]],
    ) -> list[OpenPort]:
        extra_open_port_list: list[OpenPort] = []
        seen_key_set: set[tuple[str, int]] = set()

        for result in probe_result_list:
            if not _should_expand_claw_family(result):
                continue

            known_port_list = ip_port_map.get(result.ip, []) + [result.port]
            family_port_list = PortRangeParser.expand_claw_related(known_port_list)
            candidate_port_list = [
                port for port in family_port_list
                if port not in set(known_port_list)
            ]
            if not candidate_port_list:
                continue

            nmap_ports = PortRangeParser.to_nmap_format(candidate_port_list)
            scan_result = await self._nmap.syn_scan([result.ip], nmap_ports, rate=500)
            if is_syn_privilege_error(scan_result.error):
                scan_result = await self._nmap.connect_scan([result.ip], nmap_ports, rate=500)

            for open_port in scan_result.open_port_list:
                key = (open_port.ip, open_port.port)
                if key in seen_key_set:
                    continue
                seen_key_set.add(key)
                extra_open_port_list.append(open_port)

        return extra_open_port_list


def _build_ip_port_map(open_port_list: list[OpenPort]) -> dict[str, list[int]]:
    ip_port_map: dict[str, set[int]] = {}

    for open_port in open_port_list:
        if open_port.ip not in ip_port_map:
            ip_port_map[open_port.ip] = set()
        ip_port_map[open_port.ip].add(open_port.port)

    return {
        ip: sorted(list(port_set))
        for ip, port_set in ip_port_map.items()
    }


async def _run_probe_batch(
    open_port_list: list[OpenPort],
    probe_one,
) -> list[ProbeResult]:
    task_list = [probe_one(op) for op in open_port_list]
    result_list = await asyncio.gather(*task_list, return_exceptions=True)

    probe_result_list: list[ProbeResult] = []
    for result in result_list:
        if isinstance(result, Exception):
            logger.error("Probe failed: %s", result)
            continue
        probe_result_list.append(result)

    return probe_result_list


def _seed_discovery_source_list(open_port: OpenPort) -> list[str]:
    if open_port.service.startswith("mdns-"):
        return ["mdns"]
    return ["nmap"]


def _should_expand_claw_family(result: ProbeResult) -> bool:
    if result.nmap_service.startswith("mdns-"):
        return True

    if result.nse_output and "claw_detect=" in result.nse_output.lower():
        return True

    if result.ws_available or result.sse_available:
        return True

    for response in result.response_list:
        header_text = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        body_text = f"{response.title} {response.body}".lower()

        if "x-claw-version" in header_text or "x-openclaw-token" in header_text:
            return True
        if response.path in {"/tools/invoke", "/v1/chat/completions", "/v1/responses"} and response.status_code in {401, 405}:
            return True
        if response.app_hint_list:
            return True
        if any("claw" in asset.lower() for asset in response.asset_path_list):
            return True
        if any(
            keyword in body_text
            for keyword in (
                "openclaw",
                "autoclaw",
                "miniclaw",
                "clawdbot",
                "moltbot",
                "connect.challenge",
            )
        ):
            return True

    return False
