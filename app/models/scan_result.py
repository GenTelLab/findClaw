from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scan_records.scan_id", ondelete="CASCADE"),
        nullable=False,
    )

    ip: Mapped[str] = mapped_column(String(45), nullable=False)

    port: Mapped[int] = mapped_column(Integer, nullable=False)

    claw_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    claw_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    confidence: Mapped[str] = mapped_column(String(20), nullable=False)

    confidence_score: Mapped[int] = mapped_column(Integer, default=0)

    matched_keyword: Mapped[str | None] = mapped_column(String(200), nullable=True)

    matched_rule: Mapped[str | None] = mapped_column(String(100), nullable=True)

    raw_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    discovered_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    is_new: Mapped[bool] = mapped_column(Boolean, default=False)

    scan_record = relationship("ScanRecord", back_populates="result_list")

    __table_args__ = (
        UniqueConstraint("scan_id", "ip", "port", name="uq_scan_result"),
        Index("idx_scan_results_scan_id", "scan_id"),
        Index("idx_scan_results_ip", "ip"),
        Index("idx_scan_results_claw_type", "claw_type"),
        Index("idx_scan_results_confidence", "confidence"),
    )
