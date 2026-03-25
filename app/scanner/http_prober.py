import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

LIGHT_PROBE_PATH_LIST = [
    "/",
    "/health",
    "/status",
    "/ready",
    "/live",
    "/version",
    "/api/version",
    "/mcp",
    "/ws",
    "/tools/invoke",
    "/v1/chat/completions",
    "/v1/responses",
    "/favicon.ico",
]

DEEP_PROBE_PATH_LIST = [
    "/manifest.json",
    "/site.webmanifest",
    "/robots.txt",
    "/api/health",
    "/api/status",
    "/api/ready",
    "/api/live",
    "/api/info",
    "/api/openapi.json",
]

CLAW_SUSPECT_KEYWORD_LIST = [
    "openclaw", "autoclaw", "miniclaw", "clawdbot", "moltbot", "claw",
    "connect.challenge", "tools/invoke",
]

HTTPS_PORT_SET = {443, 8443}
TEXTUAL_CONTENT_TYPE_KEYWORD_LIST = [
    "text/",
    "json",
    "javascript",
    "xml",
    "html",
]
APP_HINT_KEYWORD_LIST = [
    "openclaw",
    "autoclaw",
    "miniclaw",
    "clawdbot",
    "moltbot",
    "connect.challenge",
]
ASSET_PATH_PATTERN = re.compile(
    r"""(?:src|href)=["']([^"']+\.(?:js|css|ico|svg|png|json))["']""",
    re.IGNORECASE,
)


@dataclass
class HttpResponse:
    path: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    title: str = ""
    content_type: str = ""
    body_hash: str = ""
    asset_path_list: list[str] = field(default_factory=list)
    app_hint_list: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class ProbeResult:
    ip: str
    port: int
    response_list: list[HttpResponse] = field(default_factory=list)
    is_suspect: bool = False
    discovery_source_list: list[str] = field(default_factory=list)
    ws_available: bool = False
    sse_available: bool = False
    nmap_service: str = ""
    nmap_version: str = ""
    nse_output: str = ""
    peer_port_list: list[int] = field(default_factory=list)


class HttpProber:

    def __init__(self):
        self._light_timeout = settings.http_probe_timeout
        self._deep_timeout = settings.http_deep_probe_timeout

    async def probe(self, ip: str, port: int) -> ProbeResult:
        result = ProbeResult(ip=ip, port=port)

        light_response_list = await self._probe_path_list(
            ip, port, LIGHT_PROBE_PATH_LIST, self._light_timeout
        )
        result.response_list.extend(light_response_list)

        result.is_suspect = _should_deep_probe(light_response_list)

        if result.is_suspect:
            deep_path_list = _build_deep_probe_path_list(light_response_list)
            if deep_path_list:
                deep_response_list = await self._probe_path_list(
                    ip, port, deep_path_list, self._deep_timeout
                )
                result.response_list.extend(deep_response_list)

            ws_task = self._check_websocket(ip, port)
            sse_task = self._check_sse(ip, port)
            result.ws_available, result.sse_available = await asyncio.gather(ws_task, sse_task)

        return result

    async def _probe_path_list(
        self,
        ip: str,
        port: int,
        path_list: list[str],
        timeout: int,
    ) -> list[HttpResponse]:
        task_list = [
            self._fetch(ip, port, path, timeout) for path in path_list
        ]
        return await asyncio.gather(*task_list)

    async def _fetch(
        self, ip: str, port: int, path: str, timeout: int
    ) -> HttpResponse:
        preferred_scheme = "https" if port in HTTPS_PORT_SET else "http"
        scheme_list = [preferred_scheme, "http" if preferred_scheme == "https" else "https"]
        last_error = ""

        for scheme in scheme_list:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                async with httpx.AsyncClient(
                    timeout=timeout, verify=False, follow_redirects=True
                ) as client:
                    resp = await client.get(url)
                    headers = dict(resp.headers)
                    content_type = headers.get("content-type", "")
                    body = _decode_body(resp.content, content_type)
                    asset_path_list = _extract_asset_path_list(body) if path == "/" else []
                    app_hint_list = _extract_app_hint_list(body, headers, asset_path_list)
                    return HttpResponse(
                        path=path,
                        status_code=resp.status_code,
                        headers=headers,
                        body=body,
                        title=_extract_title(body),
                        content_type=content_type,
                        body_hash=_hash_bytes(resp.content),
                        asset_path_list=asset_path_list,
                        app_hint_list=app_hint_list,
                    )
            except Exception as e:
                last_error = str(e)

        return HttpResponse(path=path, status_code=0, error=last_error)

    async def _check_websocket(self, ip: str, port: int) -> bool:
        preferred_scheme = "https" if port in HTTPS_PORT_SET else "http"
        scheme_list = [preferred_scheme, "http" if preferred_scheme == "https" else "https"]
        ws_header = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGVzdA==",
        }

        for ws_path in ["/", "/ws"]:
            for scheme in scheme_list:
                url = f"{scheme}://{ip}:{port}{ws_path}"
                try:
                    async with httpx.AsyncClient(timeout=5, verify=False) as client:
                        resp = await client.get(url, headers=ws_header)
                        if resp.status_code in {101, 426}:
                            return True
                except Exception:
                    continue

        return False

    async def _check_sse(self, ip: str, port: int) -> bool:
        preferred_scheme = "https" if port in HTTPS_PORT_SET else "http"
        scheme_list = [preferred_scheme, "http" if preferred_scheme == "https" else "https"]

        for scheme in scheme_list:
            url = f"{scheme}://{ip}:{port}/mcp"
            try:
                async with httpx.AsyncClient(timeout=5, verify=False) as client:
                    resp = await client.get(
                        url, headers={"Accept": "text/event-stream"}
                    )
                    content_type = resp.headers.get("content-type", "")
                    if "text/event-stream" in content_type:
                        return True
            except Exception:
                continue

        return False


def _extract_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title>")
    if start == -1:
        return ""
    start += 7
    end = lower.find("</title>", start)
    if end == -1:
        return ""
    return html[start:end].strip()


def _decode_body(content: bytes, content_type: str) -> str:
    if not content:
        return ""
    content_type_lower = content_type.lower()
    if any(keyword in content_type_lower for keyword in TEXTUAL_CONTENT_TYPE_KEYWORD_LIST):
        return content.decode("utf-8", errors="ignore")[:10000]
    return ""


def _hash_bytes(content: bytes) -> str:
    if not content:
        return ""
    return hashlib.sha256(content).hexdigest()[:16]


def _extract_asset_path_list(body: str) -> list[str]:
    if not body:
        return []
    asset_list: list[str] = []
    for match in ASSET_PATH_PATTERN.findall(body):
        cleaned = match.strip()
        if cleaned and cleaned not in asset_list:
            asset_list.append(cleaned[:200])
    return asset_list[:20]


def _build_deep_probe_path_list(response_list: list[HttpResponse]) -> list[str]:
    path_list = list(DEEP_PROBE_PATH_LIST)
    for response in response_list:
        if response.path != "/":
            continue
        for asset_path in response.asset_path_list:
            normalized = _normalize_asset_path(asset_path)
            if normalized and normalized not in path_list:
                path_list.append(normalized)
            if len(path_list) >= 20:
                return path_list
    return path_list


def _normalize_asset_path(asset_path: str) -> str:
    path = asset_path.strip()
    if not path:
        return ""
    if path.startswith(("http://", "https://", "//", "data:")):
        return ""
    if "?" in path:
        path = path.split("?", 1)[0]
    if "#" in path:
        path = path.split("#", 1)[0]
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path.lstrip("./")
    return path[:200]


def _extract_app_hint_list(
    body: str,
    headers: dict[str, str],
    asset_path_list: list[str],
) -> list[str]:
    combined = " ".join([body[:4000], str(headers), " ".join(asset_path_list)]).lower()
    hint_list: list[str] = []
    for keyword in APP_HINT_KEYWORD_LIST:
        if keyword in combined and keyword not in hint_list:
            hint_list.append(keyword)
    return hint_list[:12]


def _has_suspect_keyword(response_list: list[HttpResponse]) -> bool:
    for resp in response_list:
        if resp.error:
            continue
        combined = (
            resp.body
            + resp.title
            + str(resp.headers)
            + " ".join(resp.asset_path_list)
            + " ".join(resp.app_hint_list)
        ).lower()
        if _is_findclaw_self_ui(combined):
            continue
        for kw in CLAW_SUSPECT_KEYWORD_LIST:
            if kw in combined:
                return True
    return False


def _should_deep_probe(response_list: list[HttpResponse]) -> bool:
    if _has_suspect_keyword(response_list):
        return True

    for resp in response_list:
        if resp.error:
            continue

        if resp.path == "/tools/invoke" and resp.status_code in {401, 403, 405}:
            return True

        if resp.path in {"/v1/chat/completions", "/v1/responses"} and resp.status_code in {401, 403, 405}:
            return True

        if resp.path in {"/health", "/status", "/ready", "/live", "/version", "/api/version"} and resp.status_code in {401, 403}:
            return True

        if resp.path == "/mcp":
            if resp.status_code in {401, 403}:
                return True
            if resp.status_code == 200 and "event-stream" in resp.content_type.lower():
                return True

        if resp.path == "/ws" and resp.status_code in {101, 426}:
            return True

        header_text = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        if "x-claw-version" in header_text or "x-openclaw" in header_text:
            return True

        combined = (
            resp.body
            + resp.title
            + header_text
            + " ".join(resp.asset_path_list)
            + " ".join(resp.app_hint_list)
        ).lower()
        if _is_findclaw_self_ui(combined):
            continue

        if resp.app_hint_list or any("claw" in asset.lower() for asset in resp.asset_path_list):
            return True

    return False


def _is_findclaw_self_ui(value: str) -> bool:
    text = value.lower()
    return "findclaw" in text
