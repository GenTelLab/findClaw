from sqlalchemy import BigInteger, DateTime, Index, Integer, String, Text, desc, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    scan_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)

    target_ips: Mapped[str] = mapped_column(Text, nullable=False)

    scan_ports: Mapped[str | None] = mapped_column(Text, nullable=True)

    exclude_ips: Mapped[str | None] = mapped_column(Text, nullable=True)

    exclude_ports: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan_rate: Mapped[int] = mapped_column(Integer, default=1000)

    parallelism: Mapped[int] = mapped_column(Integer, default=8)

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")

    total_hosts: Mapped[int] = mapped_column(Integer, default=0)

    scanned_hosts: Mapped[int] = mapped_column(Integer, default=0)

    open_ports: Mapped[int] = mapped_column(Integer, default=0)

    confirmed_count: Mapped[int] = mapped_column(Integer, default=0)

    suspected_count: Mapped[int] = mapped_column(Integer, default=0)

    start_time: Mapped[str | None] = mapped_column(DateTime(timezone=True), nullable=True)

    end_time: Mapped[str | None] = mapped_column(DateTime(timezone=True), nullable=True)

    duration_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    triggered_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    result_list = relationship(
        "ScanResult", back_populates="scan_record", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_scan_records_status", "status"),
        Index("idx_scan_records_created", desc("created_at")),
    )
