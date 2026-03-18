from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanRequest(BaseModel):
    target_ips: str
    scan_ports: str | None = None
    exclude_ips: str | None = None
    exclude_ports: str | None = None
    scan_rate: int = 1000
    parallelism: int = 8


class ScanResultDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: int
    scan_id: str
    ip: str
    port: int
    claw_type: str | None = None
    family_hint: str | None = None
    variant_hint: str | None = None
    claw_version: str | None = None
    confidence: str
    confidence_score: int
    matched_keyword: str | None = None
    matched_rule: str | None = None
    matched_rule_list: list[str] = []
    discovered_at: datetime | None = None
    is_new: bool
    discovery_source_list: list[str] = []
    evidence_list: list[str] = []
    evidence_summary: str | None = None
    service_hint: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    seen_count: int = 1
    scan_count: int = 1


class AssetTimelineDTO(BaseModel):
    asset: ScanResultDTO
    timeline: list[ScanResultDTO]


class ScanStatusDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    target_ips: str
    scan_ports: str | None = None
    status: str
    total_hosts: int
    scanned_hosts: int
    open_ports: int
    confirmed_count: int
    suspected_count: int
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_ms: int | None = None
    error_message: str | None = None
    progress: float = 0.0
    current_phase: str = "PENDING"
    phase_message: str = ""
    recent_result_list: list[ScanResultDTO] = []


class ScanHistoryDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    target_ips: str
    scan_ports: str | None = None
    status: str
    total_hosts: int
    open_ports: int
    confirmed_count: int
    suspected_count: int
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_ms: int | None = None
    triggered_by: str | None = None
    created_at: datetime | None = None


class ChangeReportDTO(BaseModel):
    new_count: int
    removed_count: int
    unchanged_count: int
    new_item_list: list[ScanResultDTO]
