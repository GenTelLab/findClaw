import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass

from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf

from app.scanner.nmap_executor import OpenPort
from app.utils.ip_parser import IpRangeParser, ParsedTarget

logger = logging.getLogger(__name__)

CLAW_MDNS_SERVICE_TYPE_LIST = [
    "_openclaw-gw._tcp.local.",
    "_claw-gw._tcp.local.",
    "_clawdbot._tcp.local.",
    "_moltbot._tcp.local.",
    "_autoclaw._tcp.local.",
    "_miniclaw._tcp.local.",
    "_http._tcp.local.",
    "_ws._tcp.local.",
]


@dataclass
class MdnsService:
    ip: str
    port: int
    service_type: str
    service_name: str
    properties: dict[str, str]


class MdnsScanner:

    async def discover(
        self,
        target: ParsedTarget,
        exclude_target: ParsedTarget | None = None,
        exclude_port_set: set[int] | None = None,
        timeout: float = 2.0,
    ) -> list[OpenPort]:
        service_list = await asyncio.to_thread(_browse_services, timeout)
        open_port_list: list[OpenPort] = []
        seen_key_set: set[tuple[str, int]] = set()

        for service in service_list:
            family = _detect_family(service)
            if not family:
                continue
            if not IpRangeParser.contains(target, service.ip):
                continue
            if exclude_target and IpRangeParser.contains(exclude_target, service.ip):
                continue
            if exclude_port_set and service.port in exclude_port_set:
                continue

            key = (service.ip, service.port)
            if key in seen_key_set:
                continue
            seen_key_set.add(key)

            version = service.properties.get("version") or service.properties.get("gatewayPort", "")
            open_port_list.append(
                OpenPort(
                    ip=service.ip,
                    port=service.port,
                    protocol="tcp",
                    service=f"mdns-{family}",
                    version=version,
                    script_output=_format_properties(service, family),
                )
            )

        if open_port_list:
            logger.info("mDNS discovered %d claw candidates", len(open_port_list))

        return open_port_list

    async def cancel(self) -> None:
        return None


class _MdnsListener(ServiceListener):

    def __init__(self):
        self.name_map: dict[str, set[str]] = {}

    def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self.name_map.setdefault(service_type, set()).add(name)

    def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self.name_map.setdefault(service_type, set()).add(name)

    def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        service_name_set = self.name_map.get(service_type)
        if service_name_set and name in service_name_set:
            service_name_set.remove(name)


def _browse_services(timeout: float) -> list[MdnsService]:
    zc = Zeroconf(ip_version=IPVersion.All)
    listener = _MdnsListener()
    browser = ServiceBrowser(zc, CLAW_MDNS_SERVICE_TYPE_LIST, listener)

    try:
        time.sleep(max(timeout, 0.5))
        service_list: list[MdnsService] = []
        for service_type, service_name_set in listener.name_map.items():
            for service_name in sorted(service_name_set):
                info = zc.get_service_info(service_type, service_name, timeout=1500)
                if not info:
                    continue
                properties = _decode_properties(info.properties)
                for ip in _extract_ip_list(info):
                    if not _is_ip_supported(ip):
                        continue
                    service_list.append(
                        MdnsService(
                            ip=ip,
                            port=info.port,
                            service_type=service_type,
                            service_name=service_name,
                            properties=properties,
                        )
                    )
        return service_list
    finally:
        browser.cancel()
        zc.close()


def _extract_ip_list(info) -> list[str]:
    if hasattr(info, "parsed_scoped_addresses"):
        address_list = info.parsed_scoped_addresses()
        if address_list:
            return [addr.split("%", 1)[0] for addr in address_list]

    if hasattr(info, "parsed_addresses"):
        return info.parsed_addresses()

    return []


def _decode_properties(properties: dict) -> dict[str, str]:
    decoded: dict[str, str] = {}
    for key, value in properties.items():
        key_str = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
        if isinstance(value, bytes):
            value_str = value.decode("utf-8", errors="ignore")
        else:
            value_str = str(value)
        decoded[key_str] = value_str
    return decoded


def _format_properties(service: MdnsService, family: str) -> str:
    if not service.properties:
        return f"mdns family={family} serviceType={service.service_type} service={service.service_name}"
    parts = [f"{k}={v}" for k, v in sorted(service.properties.items())]
    return (
        f"mdns family={family} serviceType={service.service_type} service={service.service_name} "
        + " ".join(parts)
    )


def _is_ip_supported(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return parsed.version == 4


def _detect_family(service: MdnsService) -> str | None:
    combined = " ".join(
        [
            service.service_type,
            service.service_name,
            " ".join(f"{k}={v}" for k, v in sorted(service.properties.items())),
        ]
    ).lower()

    if not _has_mdns_claw_signal(combined):
        return None
    if any(keyword in combined for keyword in ("autoclaw", "autoglm", "zhipu")):
        return "autoclaw"
    if "miniclaw" in combined:
        return "miniclaw"
    if any(keyword in combined for keyword in ("clawdbot", "moltbot", "openclaw", "_claw-gw.")):
        return "openclaw"
    if "claw" in combined and ("gateway" in combined or "operator" in combined):
        return "openclaw"
    return None


def _has_mdns_claw_signal(text: str) -> bool:
    keyword_list = (
        "openclaw",
        "autoclaw",
        "miniclaw",
        "clawdbot",
        "moltbot",
        "gateway",
        "claw",
        "operator",
        "gatewayport",
        "x-claw-version",
    )
    return any(keyword in text for keyword in keyword_list)
