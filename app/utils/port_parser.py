COMMON_PROXY_PORT_SET = {80, 443, 3000, 8000, 8080, 8443}
PORT_FAMILY_TEMPLATE_LIST = [
    {
        "name": "openclaw-gateway",
        "base_ports": {8789, 18789, 19000, 28789},
        "base_endings": {0, 89},
        "direct_offsets": [0, 2, 3],
        "browser_offsets": [11, 12, 13, 14, 15, 16],
    },
    {
        "name": "legacy-openclaw",
        "base_ports": set(),
        "base_endings": {89},
        "direct_offsets": [0, 1, 2, 3],
        "browser_offsets": [10, 11, 12, 13, 14, 15, 16],
    },
]


class PortRangeParser:

    @staticmethod
    def parse(raw: str | None) -> list[int]:
        if not raw or not raw.strip():
            return []

        port_set: set[int] = set()
        for token in raw.replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue

            if "-" in token:
                parts = token.split("-", 1)
                start = int(parts[0].strip())
                end = int(parts[1].strip())
                _validate_port(start)
                _validate_port(end)
                port_set.update(range(start, end + 1))
            else:
                port = int(token)
                _validate_port(port)
                port_set.add(port)

        return sorted(port_set)

    @staticmethod
    def to_nmap_format(port_list: list[int]) -> str:
        if not port_list:
            return ""
        return ",".join(str(p) for p in port_list)

    @staticmethod
    def expand_claw_related(port_list: list[int]) -> list[int]:
        expanded_port_set = set(port_list)
        base_port_list = sorted(_infer_base_port_set(port_list))

        for base_port in base_port_list:
            for template in _select_template_list(base_port):
                for delta in template["direct_offsets"]:
                    candidate = base_port + delta
                    if candidate <= 65535:
                        expanded_port_set.add(candidate)

                browser_start = ((base_port // 100) + 1) * 100
                for offset in template["browser_offsets"]:
                    browser_candidate = browser_start + max(offset - min(template["browser_offsets"]), 0)
                    if browser_candidate <= 65535:
                        expanded_port_set.add(browser_candidate)

        return sorted(expanded_port_set)

    @staticmethod
    def infer_claw_base_port_list(port_list: list[int]) -> list[int]:
        return sorted(_infer_base_port_set(port_list))

    @staticmethod
    def infer_claw_family_template_list(port_list: list[int]) -> list[str]:
        template_name_set: set[str] = set()
        for base_port in _infer_base_port_set(port_list):
            for template in _select_template_list(base_port):
                template_name_set.add(template["name"])
        return sorted(template_name_set)


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range: {port}")


def _infer_base_port_set(port_list: list[int]) -> set[int]:
    base_port_set: set[int] = set()

    for port in port_list:
        if port in COMMON_PROXY_PORT_SET:
            continue

        for template in PORT_FAMILY_TEMPLATE_LIST:
            if port in template["base_ports"]:
                base_port_set.add(port)

            for delta in template["direct_offsets"]:
                candidate = port - delta
                if _is_candidate_base_port(candidate, template):
                    base_port_set.add(candidate)

            if port % 100 not in {0, 1, 2, 3, 4, 5, 6}:
                continue
            for delta in template["browser_offsets"]:
                candidate = port - delta
                if _is_candidate_base_port(candidate, template):
                    base_port_set.add(candidate)

    return base_port_set


def _is_candidate_base_port(candidate: int, template: dict) -> bool:
    if candidate < 1 or candidate > 65535:
        return False
    if candidate in COMMON_PROXY_PORT_SET:
        return False
    return candidate in template["base_ports"] or candidate % 100 in template["base_endings"]


def _select_template_list(base_port: int) -> list[dict]:
    matched_template_list = [
        template
        for template in PORT_FAMILY_TEMPLATE_LIST
        if base_port in template["base_ports"] or base_port % 100 in template["base_endings"]
    ]
    return matched_template_list or [PORT_FAMILY_TEMPLATE_LIST[0]]
