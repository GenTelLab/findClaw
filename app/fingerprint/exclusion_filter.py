from app.scanner.http_prober import ProbeResult


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
    clue_list = (
        "openclaw",
        "autoclaw",
        "miniclaw",
        "clawdbot",
        "moltbot",
        "x-claw-version",
        "x-openclaw-token",
        "connect.challenge",
    )

    interesting_path_set = {
        "/tools/invoke",
        "/v1/chat/completions",
        "/v1/responses",
        "/health",
    }

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
        if any(clue in combined for clue in clue_list):
            return True

        if resp.path in interesting_path_set and resp.status_code in {200, 401, 403, 405}:
            return True

    if probe.ws_available or probe.sse_available:
        return True

    if probe.nse_output and "claw_detect=" in probe.nse_output.lower():
        return True

    return False


def _is_findclaw_self_ui(value: str) -> bool:
    return "findclaw" in value.lower()
