from pydantic import BaseModel, ConfigDict


class AssetFilterRequest(BaseModel):
    keyword: str | None = None
    claw_type: str | None = None
    confidence: str | None = None
    scan_id: str | None = None
    page: int = 1
    size: int = 20


class AssetSummaryDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    confirmed_count: int
    suspected_count: int
    type_distribution: dict[str, int]
