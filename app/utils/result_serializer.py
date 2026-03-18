from app.models.scan_result import ScanResult


def serialize_scan_result(scan_result: ScanResult) -> dict:
    raw = getattr(scan_result, "raw_response", None) or {}
    meta = raw.get("__meta__", {}) if isinstance(raw, dict) else {}

    discovery_source_list = [
        source
        for source in list(meta.get("discovery_source_list", []) or [])
        if source.lower() != "nmap"
    ]
    evidence_list = _build_evidence_list(scan_result, raw, meta)

    return {
        "id": getattr(scan_result, "id"),
        "scan_id": getattr(scan_result, "scan_id"),
        "ip": getattr(scan_result, "ip"),
        "port": getattr(scan_result, "port"),
        "claw_type": getattr(scan_result, "claw_type", None),
        "family_hint": meta.get("family_hint") or getattr(scan_result, "claw_type", None),
        "variant_hint": meta.get("variant_hint") or None,
        "claw_version": getattr(scan_result, "claw_version", None),
        "confidence": getattr(scan_result, "confidence"),
        "confidence_score": getattr(scan_result, "confidence_score", 0),
        "matched_keyword": getattr(scan_result, "matched_keyword", None),
        "matched_rule": getattr(scan_result, "matched_rule", None),
        "matched_rule_list": list(meta.get("matched_rule_list", []) or []),
        "discovered_at": getattr(scan_result, "discovered_at", None),
        "is_new": getattr(scan_result, "is_new", False),
        "discovery_source_list": discovery_source_list,
        "evidence_list": evidence_list,
        "evidence_summary": " | ".join(evidence_list[:4]),
        "service_hint": meta.get("nmap_service") or None,
        "first_seen_at": getattr(scan_result, "first_seen_at", None),
        "last_seen_at": getattr(scan_result, "last_seen_at", getattr(scan_result, "discovered_at", None)),
        "seen_count": getattr(scan_result, "seen_count", 1),
        "scan_count": getattr(scan_result, "scan_count", 1),
    }


def _build_evidence_list(scan_result: ScanResult, raw: dict, meta: dict) -> list[str]:
    evidence_list: list[str] = []

    matched_rule = getattr(scan_result, "matched_rule", None)
    matched_keyword = getattr(scan_result, "matched_keyword", None)
    claw_version = getattr(scan_result, "claw_version", None)

    if matched_rule:
        evidence_list.append(f"规则:{matched_rule}")
    if matched_keyword:
        evidence_list.append(f"关键词:{matched_keyword}")
    if claw_version:
        evidence_list.append(f"版本:{claw_version}")

    nmap_service = meta.get("nmap_service")
    if nmap_service:
        evidence_list.append(f"服务:{nmap_service}")

    if meta.get("ws_available"):
        evidence_list.append("WebSocket:可用")
    if meta.get("sse_available"):
        evidence_list.append("SSE:可用")

    nse_output = meta.get("nse_output", "")
    if nse_output:
        for token in nse_output.split():
            if token.startswith("claw_detect=") or token.startswith("signal="):
                evidence_list.append(f"NSE:{token}")
                if len(evidence_list) >= 8:
                    break

    for path in (
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
    ):
        response = raw.get(path)
        if not isinstance(response, dict):
            continue
        status = response.get("status") or response.get("status_code")
        if status:
            evidence_list.append(f"{path}:{status}")
        for hint in response.get("app_hint_list", [])[:2]:
            evidence_list.append(f"提示:{hint}")
        asset_list = response.get("asset_path_list", [])
        if asset_list:
            evidence_list.append(f"资源:{asset_list[0]}")
        body_hash = response.get("body_hash")
        if body_hash and path == "/favicon.ico":
            evidence_list.append(f"图标Hash:{body_hash}")
        if len(evidence_list) >= 10:
            break

    return evidence_list[:10]
