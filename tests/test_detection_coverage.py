import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.fingerprint.engine import FingerprintEngine
from app.fingerprint.exclusion_filter import ExclusionFilter
from app.fingerprint.rule import Condition, FingerprintRule
from app.services.change_detection import ChangeDetectionService
from app.scanner.deep_probe import DeepProbeScanner
from app.scanner.http_prober import HttpResponse, ProbeResult, _should_deep_probe
from app.scanner.mdns_scanner import MdnsScanner, MdnsService
from app.scanner.nmap_executor import NmapResult, OpenPort, _build_exclude_args, is_syn_privilege_error
from app.utils.ip_parser import IpRangeParser
from app.utils.port_parser import PortRangeParser
from app.utils.result_serializer import serialize_scan_result


class DetectionCoverageTest(unittest.TestCase):

    def test_port_parser_expands_known_claw_port_families(self):
        port_list = PortRangeParser.expand_claw_related([18789, 19000, 8789, 443])

        for port in (
            18791, 18792, 18800, 18805,
            19002, 19003, 19100, 19105,
            8791, 8792, 8800, 8805,
        ):
            self.assertIn(port, port_list)

        self.assertIn(443, port_list)

    def test_port_parser_infers_family_from_related_ports(self):
        port_list = PortRangeParser.expand_claw_related([18791, 18800, 19003, 8800])

        for port in (18789, 18792, 18805, 19000, 19002, 19100, 8789, 8791, 8792):
            self.assertIn(port, port_list)

    def test_openai_compatible_endpoint_triggers_deep_probe(self):
        response_list = [
            HttpResponse(path="/v1/chat/completions", status_code=405),
        ]

        self.assertTrue(_should_deep_probe(response_list))

    def test_legacy_openclaw_alias_triggers_deep_probe(self):
        response_list = [
            HttpResponse(path="/", status_code=200, body="<title>clawdbot gateway</title>"),
        ]

        self.assertTrue(_should_deep_probe(response_list))

    def test_findclaw_ui_does_not_trigger_deep_probe(self):
        response_list = [
            HttpResponse(
                path="/",
                status_code=200,
                title="君同·抓虾 FindClaw",
                body=(
                    "<html><body>"
                    "<img src='./openclaw-lobster.png' alt='OpenClaw 龙虾图标'>"
                    "<div>抓虾 FindClaw</div>"
                    "</body></html>"
                ),
                asset_path_list=["./openclaw-lobster.png"],
                app_hint_list=["openclaw"],
            ),
        ]

        self.assertFalse(_should_deep_probe(response_list))

    def test_reverse_proxy_header_is_not_excluded_when_claw_signal_exists(self):
        exclusion_filter = ExclusionFilter(
            [{"id": "exclude-nginx", "match": {"serverHeaderContains": "nginx"}}]
        )
        probe = ProbeResult(
            ip="192.168.1.10",
            port=443,
            response_list=[
                HttpResponse(
                    path="/tools/invoke",
                    status_code=405,
                    headers={"server": "nginx"},
                    body="",
                )
            ],
        )

        self.assertFalse(exclusion_filter.should_exclude(probe))

    def test_findclaw_ui_is_not_treated_as_claw_signal(self):
        exclusion_filter = ExclusionFilter(
            [{"id": "exclude-nginx", "match": {"serverHeaderContains": "nginx"}}]
        )
        probe = ProbeResult(
            ip="127.0.0.1",
            port=8080,
            response_list=[
                HttpResponse(
                    path="/",
                    status_code=200,
                    headers={"server": "nginx"},
                    title="君同·抓虾 FindClaw",
                    body=(
                        "<html><body>"
                        "<img src='./openclaw-lobster.png' alt='OpenClaw 龙虾图标'>"
                        "<div>抓虾 FindClaw</div>"
                        "</body></html>"
                    ),
                )
            ],
        )

        self.assertTrue(exclusion_filter.should_exclude(probe))

    def test_fingerprint_engine_matches_before_reverse_proxy_exclusion(self):
        engine = FingerprintEngine()
        engine.loader.rule_list[:] = [
            FingerprintRule(
                id="openclaw-header-version",
                name="OpenClaw",
                category="confirmed",
                priority=100,
                condition_list=[
                    Condition(
                        type="http_header",
                        header_name="X-Claw-Version",
                        match={"exists": True},
                    )
                ],
                condition_mode="allOf",
                confidence_score=90,
            )
        ]
        engine._exclusion_filter = ExclusionFilter(
            [{"id": "exclude-nginx", "match": {"serverHeaderContains": "nginx"}}]
        )

        probe = ProbeResult(
            ip="192.168.1.20",
            port=443,
            response_list=[
                HttpResponse(
                    path="/",
                    status_code=200,
                    headers={
                        "server": "nginx",
                        "X-Claw-Version": "2026.3.2",
                    },
                    body="",
                )
            ],
        )

        result = engine.match(probe)

        self.assertIsNotNone(result)
        self.assertEqual(result.claw_type, "OpenClaw")

    def test_default_fingerprint_engine_matches_legacy_openclaw_alias(self):
        engine = FingerprintEngine()
        engine.load()
        probe = ProbeResult(
            ip="192.168.1.21",
            port=18789,
            response_list=[
                HttpResponse(
                    path="/",
                    status_code=200,
                    headers={},
                    body="<html><body>moltbot control panel</body></html>",
                )
            ],
        )

        result = engine.match(probe)

        self.assertIsNotNone(result)
        self.assertEqual(result.claw_type, "OpenClaw")
        self.assertEqual(result.variant_hint, "moltbot")

    def test_default_fingerprint_engine_does_not_match_findclaw_ui(self):
        engine = FingerprintEngine()
        engine.load()
        probe = ProbeResult(
            ip="127.0.0.1",
            port=8080,
            response_list=[
                HttpResponse(
                    path="/",
                    status_code=200,
                    headers={},
                    title="君同·抓虾 FindClaw",
                    body=(
                        "<html><body>"
                        "<img src='./openclaw-lobster.png' alt='OpenClaw 龙虾图标'>"
                        "<div>抓虾 FindClaw</div>"
                        "<select><option>OpenClaw</option><option>AutoClaw</option></select>"
                        "</body></html>"
                    ),
                    asset_path_list=["./openclaw-lobster.png"],
                    app_hint_list=["openclaw"],
                )
            ],
        )

        result = engine.match(probe)

        self.assertIsNone(result)

    def test_syn_privilege_error_detection(self):
        error = "You requested a scan type which requires root privileges."
        self.assertTrue(is_syn_privilege_error(error))

    def test_fingerprint_engine_aggregates_rules_by_family(self):
        engine = FingerprintEngine()
        engine.loader.rule_list[:] = [
            FingerprintRule(
                id="openclaw-root",
                name="OpenClaw Root",
                family_name="OpenClaw",
                category="confirmed",
                priority=100,
                condition_list=[
                    Condition(
                        type="http_path_response",
                        path="/",
                        match={"bodyContains": ["openclaw"]},
                    )
                ],
                condition_mode="allOf",
                confidence_score=90,
            ),
            FingerprintRule(
                id="openclaw-tools",
                name="OpenClaw Tools",
                family_name="OpenClaw",
                category="confirmed",
                priority=90,
                condition_list=[
                    Condition(
                        type="http_path_response",
                        path="/tools/invoke",
                        match={"statusCode": 405},
                    )
                ],
                condition_mode="allOf",
                confidence_score=80,
            ),
            FingerprintRule(
                id="generic-claw",
                name="Unknown Claw Variant",
                family_name="Unknown Claw Variant",
                category="suspected",
                priority=95,
                condition_list=[
                    Condition(
                        type="http_path_response",
                        path="/",
                        match={"bodyContains": ["claw"]},
                    )
                ],
                condition_mode="allOf",
                confidence_score=60,
            ),
        ]

        probe = ProbeResult(
            ip="192.168.1.40",
            port=18789,
            response_list=[
                HttpResponse(path="/", status_code=200, body="openclaw gateway"),
                HttpResponse(path="/tools/invoke", status_code=405),
            ],
        )

        result = engine.match(probe)

        self.assertIsNotNone(result)
        self.assertEqual(result.claw_type, "OpenClaw")
        self.assertIn("openclaw-root", result.matched_rule_list)
        self.assertIn("openclaw-tools", result.matched_rule_list)

    def test_nmap_exclude_args_are_built(self):
        args = _build_exclude_args("192.168.1.10,192.168.1.20", "22,443")
        self.assertIn("--exclude 192.168.1.10,192.168.1.20", args)
        self.assertIn("--exclude-ports 22,443", args)

    def test_mdns_scanner_filters_by_target_and_exclusions(self):
        scanner = MdnsScanner()
        target = IpRangeParser.parse("192.168.1.0/24")
        exclude_target = IpRangeParser.parse("192.168.1.11")
        service_list = [
            MdnsService(
                ip="192.168.1.10",
                port=18789,
                service_type="_openclaw-gw._tcp.local.",
                service_name="OpenClaw A",
                properties={"gatewayPort": "18789"},
            ),
            MdnsService(
                ip="192.168.1.11",
                port=18789,
                service_type="_openclaw-gw._tcp.local.",
                service_name="OpenClaw B",
                properties={},
            ),
            MdnsService(
                ip="10.0.0.5",
                port=18789,
                service_type="_openclaw-gw._tcp.local.",
                service_name="OpenClaw C",
                properties={},
            ),
        ]

        with patch(
            "app.scanner.mdns_scanner._browse_services",
            return_value=service_list,
        ):
            result = asyncio.run(
                scanner.discover(
                    target,
                    exclude_target=exclude_target,
                    exclude_port_set={443},
                    timeout=0.1,
                )
            )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].ip, "192.168.1.10")
        self.assertEqual(result[0].port, 18789)

    def test_mdns_scanner_accepts_generic_http_service_with_claw_branding(self):
        scanner = MdnsScanner()
        target = IpRangeParser.parse("192.168.1.0/24")
        service_list = [
            MdnsService(
                ip="192.168.1.15",
                port=35689,
                service_type="_http._tcp.local.",
                service_name="clawdbot gateway",
                properties={"version": "1.2.3"},
            )
        ]

        with patch(
            "app.scanner.mdns_scanner._browse_services",
            return_value=service_list,
        ):
            result = asyncio.run(scanner.discover(target, timeout=0.1))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].service, "mdns-openclaw")
        self.assertEqual(result[0].version, "1.2.3")

    def test_deep_probe_preserves_mdns_seed_metadata(self):
        scanner = DeepProbeScanner()
        seed = OpenPort(
            ip="192.168.1.12",
            port=18789,
            service="mdns-openclaw",
            version="",
            script_output="mdns service=OpenClaw role=gateway gatewayPort=18789",
        )
        http_result = ProbeResult(ip="192.168.1.12", port=18789)
        nmap_result = NmapResult(open_port_list=[])

        async def run_case():
            with patch.object(scanner._http_prober, "probe", return_value=http_result), patch.object(
                scanner._nmap, "service_scan", return_value=nmap_result
            ):
                result_list = await scanner.probe_all([seed])
                return result_list[0]

        result = asyncio.run(run_case())

        self.assertEqual(result.nmap_service, "mdns-openclaw")
        self.assertIn("gatewayPort=18789", result.nse_output)

    def test_deep_probe_expands_non_standard_family_ports(self):
        scanner = DeepProbeScanner()
        seed = OpenPort(ip="192.168.1.30", port=35689, service="", version="", script_output="")

        def build_probe_result(port: int) -> ProbeResult:
            if port == 35689:
                return ProbeResult(
                    ip="192.168.1.30",
                    port=35689,
                    response_list=[
                        HttpResponse(path="/tools/invoke", status_code=405),
                    ],
                    is_suspect=True,
                )
            return ProbeResult(ip="192.168.1.30", port=port)

        async def run_case():
            with patch.object(
                scanner._http_prober,
                "probe",
                side_effect=lambda ip, port: build_probe_result(port),
            ), patch.object(
                scanner._nmap,
                "service_scan",
                return_value=NmapResult(open_port_list=[]),
            ), patch.object(
                scanner._nmap,
                "syn_scan",
                return_value=NmapResult(
                    open_port_list=[OpenPort(ip="192.168.1.30", port=35691)]
                ),
            ):
                return await scanner.probe_all([seed])

        result_list = asyncio.run(run_case())
        self.assertEqual(sorted(item.port for item in result_list), [35689, 35691])

    def test_result_serializer_exposes_sources_and_evidence(self):
        now = datetime.now(timezone.utc)
        row = SimpleNamespace(
            id=1,
            scan_id="scan-1",
            ip="192.168.1.10",
            port=18789,
            claw_type="OpenClaw",
            claw_version="2026.3.2",
            confidence="CONFIRMED",
            confidence_score=97,
            matched_keyword="openclaw",
            matched_rule="openclaw-control-ui",
            discovered_at=now,
            is_new=True,
            raw_response={
                "/tools/invoke": {"status": 405},
                "__meta__": {
                    "discovery_source_list": ["nmap", "mdns"],
                    "nmap_service": "mdns-openclaw",
                    "ws_available": True,
                    "nse_output": "claw_detect=openclaw signal=header:x-claw-version=2026.3.2",
                },
            },
        )

        payload = serialize_scan_result(row)

        self.assertEqual(payload["discovery_source_list"], ["mdns"])
        self.assertEqual(payload["family_hint"], "OpenClaw")
        self.assertIn("规则:openclaw-control-ui", payload["evidence_list"])
        self.assertIn("WebSocket:可用", payload["evidence_list"])

    def test_result_serializer_exposes_family_variant_and_rule_list(self):
        row = SimpleNamespace(
            id=2,
            scan_id="scan-2",
            ip="192.168.1.20",
            port=35689,
            claw_type="OpenClaw",
            claw_version=None,
            confidence="CONFIRMED",
            confidence_score=93,
            matched_keyword=None,
            matched_rule="openclaw-legacy-clawdbot-root",
            discovered_at=None,
            is_new=False,
            raw_response={
                "__meta__": {
                    "family_hint": "OpenClaw",
                    "variant_hint": "clawdbot",
                    "matched_rule_list": [
                        "openclaw-legacy-clawdbot-root",
                        "openclaw-nse-detect",
                    ],
                }
            },
        )

        payload = serialize_scan_result(row)

        self.assertEqual(payload["family_hint"], "OpenClaw")
        self.assertEqual(payload["variant_hint"], "clawdbot")
        self.assertEqual(
            payload["matched_rule_list"],
            ["openclaw-legacy-clawdbot-root", "openclaw-nse-detect"],
        )
        self.assertIsInstance(payload["evidence_summary"], str)

    def test_change_detection_treats_family_upgrade_as_change(self):
        service = ChangeDetectionService()

        async def run_case():
            service._get_result_set = AsyncMock(
                side_effect=[
                    {("192.168.1.9", 18789, "OpenClaw", "1.0.0", "openclaw-root"): 2},
                    {("192.168.1.9", 18789, "Unknown Claw Variant", None, "generic"): 1},
                ]
            )
            service._mark_new = AsyncMock()
            service._load_rows_by_ids = AsyncMock(return_value=["row-2"])
            return await service.detect(db=None, current_scan_id="cur", previous_scan_id="prev")

        report = asyncio.run(run_case())

        self.assertEqual(report["new_count"], 1)
        self.assertEqual(report["removed_count"], 1)
        self.assertEqual(report["unchanged_count"], 0)


if __name__ == "__main__":
    unittest.main()
