import re
from dataclasses import dataclass, field


@dataclass
class MatchResult:
    claw_type: str
    claw_version: str | None = None
    confidence: str = "SUSPECTED"
    confidence_score: int = 0
    matched_keyword: str = ""
    matched_rule: str = ""
    matched_rule_list: list[str] = field(default_factory=list)
    family_hint: str | None = None
    variant_hint: str | None = None


@dataclass
class Condition:
    type: str
    path: str = ""
    method: str = "GET"
    header_name: str = ""
    match: dict = field(default_factory=dict)


@dataclass
class VersionExtract:
    source: str = "header"
    header_name: str = ""
    regex: str = ""


@dataclass
class FingerprintRule:
    id: str
    name: str
    category: str
    priority: int
    family_name: str = ""
    variant_name: str | None = None
    condition_list: list[Condition] = field(default_factory=list)
    condition_mode: str = "anyOf"
    version_extract: VersionExtract | None = None
    confidence_score: int = 50

    def evaluate(self, response_map: dict[str, dict]) -> MatchResult | None:
        if self.condition_mode == "allOf":
            matched = all(
                _evaluate_condition(c, response_map) for c in self.condition_list
            )
        else:
            matched = any(
                _evaluate_condition(c, response_map) for c in self.condition_list
            )

        if not matched:
            return None

        keyword = _collect_keyword(self.condition_list, response_map)
        version = _extract_version(self.version_extract, response_map) if self.version_extract else None
        confidence = "CONFIRMED" if self.category == "confirmed" else "SUSPECTED"

        return MatchResult(
            claw_type=self.family_name or self.name,
            claw_version=version,
            confidence=confidence,
            confidence_score=self.confidence_score,
            matched_keyword=keyword,
            matched_rule=self.id,
            matched_rule_list=[self.id],
            family_hint=self.family_name or self.name,
            variant_hint=self.variant_name,
        )


def _evaluate_condition(condition: Condition, response_map: dict[str, dict]) -> bool:
    if condition.type == "http_path_response":
        resp = response_map.get(condition.path)
        if not resp:
            return False
        return _match_response(resp, condition.match)

    if condition.type == "http_header":
        for resp in response_map.values():
            headers = resp.get("headers", {})
            if condition.match.get("exists"):
                if condition.header_name.lower() in {k.lower() for k in headers}:
                    return True
            if "contains" in condition.match:
                keyword = condition.match["contains"].lower()
                for k, v in headers.items():
                    if k.lower() == condition.header_name.lower() and keyword in v.lower():
                        return True
            if "notContains" in condition.match:
                keyword = condition.match["notContains"].lower()
                header_found = False
                for k, v in headers.items():
                    if k.lower() == condition.header_name.lower():
                        header_found = True
                        if keyword in v.lower():
                            return False
                if header_found:
                    return True
        return False

    if condition.type == "websocket_available":
        return response_map.get("__meta__", {}).get("ws_available", False)

    if condition.type == "sse_available":
        return response_map.get("__meta__", {}).get("sse_available", False)

    if condition.type == "error_page_framework":
        for resp in response_map.values():
            body = resp.get("body", "").lower()
            keyword_list = condition.match.get("bodyContains", [])
            if any(kw.lower() in body for kw in keyword_list):
                return True
        return False

    if condition.type == "nmap_service_contains":
        service = response_map.get("__meta__", {}).get("nmap_service", "").lower()
        keyword = condition.match.get("contains", "").lower()
        return bool(service and keyword and keyword in service)

    if condition.type == "nmap_version_contains":
        version = response_map.get("__meta__", {}).get("nmap_version", "").lower()
        keyword = condition.match.get("contains", "").lower()
        return bool(version and keyword and keyword in version)

    if condition.type == "nse_output_contains":
        output = response_map.get("__meta__", {}).get("nse_output", "").lower()
        keyword_list = [kw.lower() for kw in condition.match.get("anyOf", [])]
        return any(keyword in output for keyword in keyword_list)

    if condition.type == "multi_port_cooccurrence":
        current_port = response_map.get("__meta__", {}).get("port")
        peer_port_list = response_map.get("__meta__", {}).get("peer_port_list", [])
        all_port_set = set(peer_port_list)
        if current_port is not None:
            all_port_set.add(current_port)

        if "portAllOf" in condition.match:
            required_port_set = set(condition.match["portAllOf"])
            if not required_port_set.issubset(all_port_set):
                return False

        if "portAnyOf" in condition.match:
            candidate_port_set = set(condition.match["portAnyOf"])
            if not all_port_set.intersection(candidate_port_set):
                return False

        return True

    return False


def _match_response(resp: dict, match: dict) -> bool:
    if "statusCode" in match:
        if resp.get("status_code") != match["statusCode"]:
            return False

    if "statusCodeIn" in match:
        if resp.get("status_code") not in match["statusCodeIn"]:
            return False

    if "bodyContains" in match:
        body = resp.get("body", "").lower()
        keyword_list = match["bodyContains"]
        op = match.get("operator", "OR")
        if op == "AND":
            if not all(kw.lower() in body for kw in keyword_list):
                return False
        else:
            if not any(kw.lower() in body for kw in keyword_list):
                return False

    if "bodyNotContains" in match:
        body = resp.get("body", "").lower()
        if any(kw.lower() in body for kw in match["bodyNotContains"]):
            return False

    if "titleContains" in match:
        title = resp.get("title", "").lower()
        if not any(kw.lower() in title for kw in match["titleContains"]):
            return False

    if "titleNotContains" in match:
        title = resp.get("title", "").lower()
        if any(kw.lower() in title for kw in match["titleNotContains"]):
            return False

    if "contentTypeContains" in match:
        content_type = resp.get("content_type", "").lower()
        keyword_list = match["contentTypeContains"]
        if not any(kw.lower() in content_type for kw in keyword_list):
            return False

    if "bodyHashIn" in match:
        body_hash = resp.get("body_hash", "").lower()
        hash_list = [value.lower() for value in match["bodyHashIn"]]
        if body_hash not in hash_list:
            return False

    if "assetPathContains" in match:
        asset_list = [item.lower() for item in resp.get("asset_path_list", [])]
        keyword_list = [kw.lower() for kw in match["assetPathContains"]]
        op = match.get("operator", "OR")
        if op == "AND":
            if not all(any(keyword in asset for asset in asset_list) for keyword in keyword_list):
                return False
        else:
            if not any(any(keyword in asset for asset in asset_list) for keyword in keyword_list):
                return False

    if "assetPathNotContains" in match:
        asset_list = [item.lower() for item in resp.get("asset_path_list", [])]
        keyword_list = [kw.lower() for kw in match["assetPathNotContains"]]
        if any(any(keyword in asset for asset in asset_list) for keyword in keyword_list):
            return False

    if "appHintContains" in match:
        hint_list = [item.lower() for item in resp.get("app_hint_list", [])]
        keyword_list = [kw.lower() for kw in match["appHintContains"]]
        op = match.get("operator", "OR")
        if op == "AND":
            if not all(keyword in hint_list for keyword in keyword_list):
                return False
        else:
            if not any(keyword in hint_list for keyword in keyword_list):
                return False

    if "appHintNotContains" in match:
        hint_list = [item.lower() for item in resp.get("app_hint_list", [])]
        keyword_list = [kw.lower() for kw in match["appHintNotContains"]]
        if any(keyword in hint_list for keyword in keyword_list):
            return False

    return True


def _collect_keyword(condition_list: list[Condition], response_map: dict) -> str:
    keyword_set: set[str] = set()
    for c in condition_list:
        body_kw_list = c.match.get("bodyContains", [])
        title_kw_list = c.match.get("titleContains", [])
        asset_kw_list = c.match.get("assetPathContains", [])
        hint_kw_list = c.match.get("appHintContains", [])
        keyword_set.update(body_kw_list)
        keyword_set.update(title_kw_list)
        keyword_set.update(asset_kw_list)
        keyword_set.update(hint_kw_list)
    return ", ".join(sorted(keyword_set)[:5])


def _extract_version(ve: VersionExtract, response_map: dict) -> str | None:
    if ve.source == "header" and ve.header_name:
        for resp in response_map.values():
            headers = resp.get("headers", {})
            for k, v in headers.items():
                if k.lower() == ve.header_name.lower():
                    if ve.regex:
                        m = re.search(ve.regex, v)
                        return m.group(1) if m else v
                    return v
    if ve.source == "nse_output":
        output = response_map.get("__meta__", {}).get("nse_output", "")
        if not output:
            return None
        if ve.regex:
            m = re.search(ve.regex, output, re.IGNORECASE)
            return m.group(1) if m else None
        return output
    return None
