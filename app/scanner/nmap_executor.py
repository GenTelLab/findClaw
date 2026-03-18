import asyncio
import logging
import os
import signal
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class OpenPort:
    ip: str
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    script_output: str = ""


@dataclass
class NmapResult:
    open_port_list: list[OpenPort] = field(default_factory=list)
    hosts_scanned: int = 0
    error: str | None = None


class NmapExecutor:

    def __init__(self, nmap_path: str | None = None):
        self._nmap = nmap_path or settings.nmap_path
        self._active_process_list: list[asyncio.subprocess.Process] = []

    async def syn_scan(
        self,
        target_list: list[str],
        ports: str,
        rate: int = 1000,
        exclude_targets: str = "",
        exclude_ports: str = "",
    ) -> NmapResult:
        targets = " ".join(target_list)
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = (
            f"{self._nmap} -sS -T4 --open -p {ports} "
            f"--min-rate {rate} {_build_exclude_args(exclude_targets, exclude_ports)}"
            f"-oX {xml_path} {targets}"
        )

        return await self._execute(cmd, xml_path)

    async def connect_scan(
        self,
        target_list: list[str],
        ports: str,
        rate: int = 1000,
        exclude_targets: str = "",
        exclude_ports: str = "",
    ) -> NmapResult:
        targets = " ".join(target_list)
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = (
            f"{self._nmap} -sT -T4 --open -p {ports} "
            f"--min-rate {rate} {_build_exclude_args(exclude_targets, exclude_ports)}"
            f"-oX {xml_path} {targets}"
        )

        return await self._execute(cmd, xml_path)

    async def service_scan(
        self,
        ip: str,
        port: int,
        script: str | None = None,
        timeout: int = 20,
    ) -> NmapResult:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name

        cmd = f"{self._nmap} -sV -p {port}"
        if script:
            cmd += f" --script {script} --script-timeout {timeout}s"
        cmd += f" -oX {xml_path} {ip}"

        return await self._execute(cmd, xml_path)

    async def _execute(self, cmd: str, xml_path: str) -> NmapResult:
        logger.info("Nmap command: %s", cmd)
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            self._active_process_list.append(proc)
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            error_msg = stderr.decode(errors="ignore").strip()
            parsed = _parse_xml(xml_path)

            if proc.returncode not in (0, None):
                logger.warning("Nmap stderr: %s", error_msg)
                parsed.error = error_msg or f"Nmap exited with code {proc.returncode}"
            elif error_msg:
                logger.info("Nmap stderr: %s", error_msg)

            return parsed

        except asyncio.CancelledError:
            if proc:
                await self._stop_process(proc)
            raise
        except asyncio.TimeoutError:
            if proc:
                await self._stop_process(proc)
            return NmapResult(error="Nmap execution timed out (600s)")
        except Exception as e:
            if proc:
                await self._stop_process(proc)
            logger.exception("Nmap execution failed")
            return NmapResult(error=str(e))
        finally:
            if proc in self._active_process_list:
                self._active_process_list.remove(proc)
            Path(xml_path).unlink(missing_ok=True)

    async def cancel_all(self) -> None:
        process_list = list(self._active_process_list)
        for proc in process_list:
            await self._stop_process(proc)

    async def _stop_process(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return

        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
            return
        except asyncio.TimeoutError:
            pass

        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return

        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            logger.warning("Failed to stop nmap process group pid=%s", proc.pid)


def _parse_xml(xml_path: str) -> NmapResult:
    result = NmapResult()

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        result.error = "Failed to parse Nmap XML output"
        return result

    root = tree.getroot()

    for host_el in root.findall(".//host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue

        result.hosts_scanned += 1
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            script_output = " ".join(
                script_el.get("output", "").strip()
                for script_el in port_el.findall("script")
                if script_el.get("output")
            ).strip()
            result.open_port_list.append(
                OpenPort(
                    ip=ip,
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    service=service_el.get("name", "") if service_el is not None else "",
                    version=service_el.get("version", "") if service_el is not None else "",
                    script_output=script_output,
                )
            )

    return result


def is_syn_privilege_error(error: str | None) -> bool:
    if not error:
        return False

    error_lower = error.lower()
    keyword_list = (
        "requires root privileges",
        "you requested a scan type which requires root privileges",
        "only ethernet devices can use raw packets",
        "dnet: failed to open device",
        "socket trouble",
        "operation not permitted",
    )
    return any(keyword in error_lower for keyword in keyword_list)


def _build_exclude_args(exclude_targets: str, exclude_ports: str) -> str:
    args = ""
    if exclude_targets:
        args += f"--exclude {exclude_targets} "
    if exclude_ports:
        args += f"--exclude-ports {exclude_ports} "
    return args
