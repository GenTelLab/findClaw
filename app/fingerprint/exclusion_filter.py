from app.scanner.http_prober import ProbeResult

_STRONG_BRAND_KEYWORD_SET = frozenset((
    "openclaw",
    "autoclaw",
    "miniclaw",
    "clawdbot",
    "moltbot",
))

_STRONG_HEADER_KEYWORD_SET = frozenset((
    "x-claw-version",
    "x-openclaw-token",
))

_STRONG_NSE_SIGNAL_SET = frozenset((
    "claw_detect=openclaw",
    "claw_detect=autoclaw",
    "claw_detect=miniclaw",
    "claw_detect=clawdbot",
    "claw_detect=moltbot",
    "signal=root:openclaw",
    "signal=root:autoclaw_branding",
    "signal=root:miniclaw",
    "signal=root:clawdbot",
    "signal=root:moltbot",
    "signal=health:openclaw",
    "signal=health:autoclaw",
    "signal=health:miniclaw",
    "signal=health:clawdbot",
    "signal=health:moltbot",
    "signal=status:openclaw",
    "signal=status:autoclaw",
    "signal=status:miniclaw",
    "signal=status:clawdbot",
    "signal=status:moltbot",
    "signal=version:openclaw",
    "signal=header:x-claw-version",
    "signal=header:x-openclaw-token",
))


class ExclusionFilter:

    def __init__(self, exclusion_list: list[dict]):
        self._exclusion_list = exclusion_list

    def should_exclude(self, probe: ProbeResult) -> bool:
        for exc in self._exclusion_list:
            match = exc.get("match", {})
            if self._match_exclusion(probe, match):
                return True
        return False

    def filter(self, probe_list: list[ProbeResult]) -> list[ProbeResult]:
        return [p for p in probe_list if not self.should_exclude(p)]

    def _match_exclusion(self, probe: ProbeResult, match: dict) -> bool:
        if "portEquals" in match:
            if probe.port == match["portEquals"]:
                return True

        if "serverHeaderContains" in match:
            if _has_claw_signal(probe):
                return False
            keyword = match["serverHeaderContains"].lower()
            for resp in probe.response_list:
                server = resp.headers.get("server", "").lower()
                if keyword in server:
                    return True

        if "nmapServiceContains" in match:
            if _has_claw_signal(probe):
                return False
            keyword = match["nmapServiceContains"].lower()
            if keyword in probe.nmap_service.lower():
                return True

        if "titleContains" in match:
            keyword = match["titleContains"].lower()
            for resp in probe.response_list:
                if keyword in resp.title.lower():
                    return True

        if "bodyContains" in match:
            keyword = match["bodyContains"].lower()
            for resp in probe.response_list:
                if keyword in resp.body.lower():
                    return True

        return False


def _has_claw_signal(probe: ProbeResult) -> bool:
    for resp in probe.response_list:
        combined = " ".join(
            [
                resp.title,
                resp.body[:2000],
                " ".join(f"{k}:{v}" for k, v in resp.headers.items()),
            ]
        ).lower()
        if _is_findclaw_self_ui(combined):
            continue
        if any(kw in combined for kw in _STRONG_BRAND_KEYWORD_SET):
            return True
        if any(kw in combined for kw in _STRONG_HEADER_KEYWORD_SET):
            return True

    nse = probe.nse_output.lower()
    if nse and any(sig in nse for sig in _STRONG_NSE_SIGNAL_SET):
        return True

    return False


def _is_findclaw_self_ui(value: str) -> bool:
    return "findclaw" in value.lower()
