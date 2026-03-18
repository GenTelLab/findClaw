import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.api import asset as asset_api
from app.api import scan as scan_api
from app.database import get_db
from app.main import app
from app import main as main_module


class DummyDbSession:

    async def commit(self):
        return None


async def override_db():
    yield DummyDbSession()


class SmokeFlowTest(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self._patch_stack = ExitStack()
        self._patch_stack.enter_context(
            patch.object(main_module, "create_tables", new=AsyncMock())
        )
        self._patch_stack.enter_context(
            patch.object(main_module.fingerprint_engine, "load", MagicMock())
        )
        self._patch_stack.enter_context(
            patch.object(
                main_module.scan_service,
                "recover_incomplete_scans",
                new=AsyncMock(return_value=0),
            )
        )
        app.dependency_overrides[get_db] = override_db

    def tearDown(self):
        app.dependency_overrides.clear()
        self._patch_stack.close()

    def test_home_page_and_docs_are_accessible(self):
        with TestClient(app) as client:
            home_response = client.get("/")
            docs_response = client.get("/docs")

        self.assertEqual(home_response.status_code, 200)
        self.assertIn("君同·抓虾 FindClaw", home_response.text)
        self.assertIn("扫描配置", home_response.text)
        self.assertIn("startScan()", home_response.text)
        self.assertEqual(docs_response.status_code, 200)
        self.assertIn("Swagger UI", docs_response.text)

    def test_key_api_smoke_on_main_app(self):
        now = datetime.now(timezone.utc)
        asset = SimpleNamespace(
            id=1,
            scan_id="scan-1",
            ip="192.168.1.20",
            port=8080,
            claw_type="OpenClaw",
            claw_version="1.0.0",
            confidence="CONFIRMED",
            confidence_score=95,
            matched_keyword="openclaw",
            matched_rule="openclaw-header",
            discovered_at=now,
            is_new=True,
            first_seen_at=now,
            last_seen_at=now,
            seen_count=2,
            scan_count=2,
        )
        running_payload = {
            "scan_id": "scan-1",
            "target_ips": "192.168.1.0/24",
            "scan_ports": "8080,8888",
            "status": "SCANNING",
            "total_hosts": 256,
            "scanned_hosts": 64,
            "open_ports": 6,
            "confirmed_count": 1,
            "suspected_count": 0,
            "start_time": now.isoformat(),
            "end_time": None,
            "duration_ms": 5000,
            "error_message": None,
            "progress": 25.0,
            "current_phase": "PROBING",
            "phase_message": "深度探测中",
            "recent_result_list": [],
        }
        fake_scan_service = MagicMock()
        fake_scan_service.get_running = AsyncMock(
            return_value=SimpleNamespace(scan_id="scan-1")
        )
        fake_scan_service.get_status_payload = AsyncMock(return_value=running_payload)
        app.dependency_overrides[scan_api.get_scan_service] = lambda: fake_scan_service

        with patch.object(
            asset_api._asset_service,
            "list_assets",
            new=AsyncMock(return_value=([asset], 1)),
        ), patch.object(
            asset_api._asset_service,
            "get_summary",
            new=AsyncMock(
                return_value={
                    "total_assets": 1,
                    "total": 1,
                    "confirmed_count": 1,
                    "suspected_count": 0,
                    "open_port_count": 6,
                    "unique_ip_count": 1,
                }
            ),
        ), patch.object(
            asset_api._asset_service,
            "get_asset_timeline",
            new=AsyncMock(return_value=(asset, [])),
        ):
            with TestClient(app) as client:
                assets_response = client.get("/api/assets")
                summary_response = client.get("/api/assets/summary")
                running_response = client.get("/api/scan/running")
                timeline_response = client.get("/api/assets/192.168.1.20/8080/timeline")

        self.assertEqual(assets_response.status_code, 200)
        self.assertEqual(assets_response.json()["items"][0]["claw_type"], "OpenClaw")
        self.assertEqual(summary_response.status_code, 200)
        self.assertEqual(summary_response.json()["confirmed_count"], 1)
        self.assertEqual(running_response.status_code, 200)
        self.assertEqual(running_response.json()["current_phase"], "PROBING")
        self.assertEqual(timeline_response.status_code, 200)
        self.assertEqual(timeline_response.json()["asset"]["seen_count"], 2)


if __name__ == "__main__":
    unittest.main()
