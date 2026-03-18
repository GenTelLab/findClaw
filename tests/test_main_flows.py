import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import scan as scan_api
from app.database import get_db
from app.services.scan_service import ScanService


class DummyDbSession:

    async def flush(self):
        return None

    async def commit(self):
        return None


class DummyResult:

    def __init__(self, record_list):
        self._record_list = record_list

    def scalars(self):
        return self

    def all(self):
        return self._record_list


class DummyAsyncSessionContext:

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeRecoverySession:

    def __init__(self, record_list):
        self._record_list = record_list
        self.commit = AsyncMock()

    async def execute(self, stmt):
        return DummyResult(self._record_list)


async def override_db():
    yield DummyDbSession()


class MainFlowTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.maxDiff = None

    def test_scan_api_main_flow_start_status_cancel_retry(self):
        app = FastAPI()
        app.include_router(scan_api.router, prefix="/api")
        app.dependency_overrides[get_db] = override_db

        fake_service = MagicMock()
        started_record = SimpleNamespace(scan_id="scan-1", status="SCANNING")
        retried_record = SimpleNamespace(scan_id="scan-2", status="SCANNING")
        status_payload = {
            "scan_id": "scan-1",
            "target_ips": "192.168.1.0/24",
            "scan_ports": "8080,8888",
            "status": "SCANNING",
            "total_hosts": 256,
            "scanned_hosts": 32,
            "open_ports": 5,
            "confirmed_count": 1,
            "suspected_count": 1,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": None,
            "duration_ms": 2500,
            "error_message": None,
            "progress": 12.5,
            "current_phase": "DISCOVERY",
            "phase_message": "端口发现中",
            "recent_result_list": [],
        }

        fake_service.start_scan = AsyncMock(return_value=started_record)
        fake_service.get_status_payload = AsyncMock(return_value=status_payload)
        fake_service.cancel_scan = AsyncMock(return_value=True)
        fake_service.retry_scan = AsyncMock(return_value=retried_record)

        app.dependency_overrides[scan_api.get_scan_service] = lambda: fake_service

        with TestClient(app) as client:
            start_response = client.post(
                "/api/scan/start",
                json={
                    "target_ips": "192.168.1.0/24",
                    "scan_ports": "8080,8888",
                    "scan_rate": 1000,
                    "parallelism": 8,
                },
            )
            status_response = client.get("/api/scan/status/scan-1")
            cancel_response = client.post("/api/scan/cancel/scan-1")
            retry_response = client.post("/api/scan/retry/scan-1")

        self.assertEqual(start_response.status_code, 200)
        self.assertEqual(start_response.json()["scan_id"], "scan-1")
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["current_phase"], "DISCOVERY")
        self.assertEqual(cancel_response.status_code, 200)
        self.assertEqual(cancel_response.json()["message"], "Scan cancelled")
        self.assertEqual(retry_response.status_code, 200)
        self.assertEqual(retry_response.json()["scan_id"], "scan-2")
        fake_service.start_scan.assert_awaited_once()
        fake_service.get_status_payload.assert_awaited_once()
        fake_service.cancel_scan.assert_awaited_once()
        fake_service.retry_scan.assert_awaited_once()

    async def test_restart_recovery_marks_scanning_records_failed(self):
        from app.services import scan_service as scan_service_module

        start_time = datetime.now(timezone.utc) - timedelta(seconds=5)
        record = SimpleNamespace(
            status="SCANNING",
            start_time=start_time,
            end_time=None,
            duration_ms=None,
            error_message=None,
        )
        session = FakeRecoverySession([record])

        service = ScanService(MagicMock())

        with patch.object(
            scan_service_module,
            "async_session",
            return_value=DummyAsyncSessionContext(session),
        ):
            count = await service.recover_incomplete_scans()

        self.assertEqual(count, 1)
        self.assertEqual(record.status, "FAILED")
        self.assertEqual(record.error_message, "Scan interrupted by service restart.")
        self.assertIsNotNone(record.end_time)
        self.assertGreater(record.duration_ms, 0)
        session.commit.assert_awaited_once()

    async def test_stop_then_retry_starts_new_scan(self):
        service = ScanService(MagicMock())
        db = DummyDbSession()

        discovery = SimpleNamespace(cancel=AsyncMock())
        prober = SimpleNamespace(cancel=AsyncMock())

        running_record = SimpleNamespace(
            status="SCANNING",
            start_time=datetime.now(timezone.utc) - timedelta(seconds=2),
            end_time=None,
            duration_ms=None,
        )

        task = asyncio.create_task(asyncio.sleep(60))

        service._scanner_map["scan-1"] = {
            "discovery": discovery,
            "prober": prober,
        }
        service._running_scan_map["scan-1"] = task
        service.get_status = AsyncMock(return_value=running_record)

        cancelled = await service.cancel_scan(db, "scan-1")
        await asyncio.sleep(0)

        self.assertTrue(cancelled)
        self.assertEqual(running_record.status, "CANCELLED")
        discovery.cancel.assert_awaited_once()
        prober.cancel.assert_awaited_once()
        self.assertTrue(task.cancelled())

        cancelled_record = SimpleNamespace(
            status="CANCELLED",
            target_ips="192.168.1.0/24",
            scan_ports="8080",
            exclude_ips="192.168.1.10",
            exclude_ports="22",
            scan_rate=1000,
            parallelism=8,
            triggered_by=None,
        )

        service.get_status = AsyncMock(return_value=cancelled_record)
        service.start_scan = AsyncMock(
            return_value=SimpleNamespace(scan_id="scan-2", status="SCANNING")
        )

        retried = await service.retry_scan(db, "scan-1")

        self.assertEqual(retried.scan_id, "scan-2")
        service.start_scan.assert_awaited_once()
        request = service.start_scan.await_args.args[1]
        self.assertEqual(request.target_ips, "192.168.1.0/24")
        self.assertEqual(request.scan_ports, "8080")
        self.assertEqual(request.exclude_ips, "192.168.1.10")
        self.assertEqual(request.exclude_ports, "22")



if __name__ == "__main__":
    unittest.main()
