CREATE TABLE IF NOT EXISTS scan_records (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         VARCHAR(36) NOT NULL UNIQUE,
    target_ips      TEXT NOT NULL,
    scan_ports      TEXT,
    exclude_ips     TEXT,
    exclude_ports   TEXT,
    scan_rate       INTEGER DEFAULT 1000,
    parallelism     INTEGER DEFAULT 8,
    status          VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    total_hosts     INTEGER DEFAULT 0,
    scanned_hosts   INTEGER DEFAULT 0,
    open_ports      INTEGER DEFAULT 0,
    confirmed_count INTEGER DEFAULT 0,
    suspected_count INTEGER DEFAULT 0,
    start_time      TIMESTAMP WITH TIME ZONE,
    end_time        TIMESTAMP WITH TIME ZONE,
    duration_ms     BIGINT,
    error_message   TEXT,
    triggered_by    VARCHAR(36),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_records_status ON scan_records(status);
CREATE INDEX IF NOT EXISTS idx_scan_records_created ON scan_records(created_at DESC);

CREATE TABLE IF NOT EXISTS scan_results (
    id               BIGSERIAL PRIMARY KEY,
    scan_id          VARCHAR(36) NOT NULL,
    ip               VARCHAR(45) NOT NULL,
    port             INTEGER NOT NULL,
    claw_type        VARCHAR(50),
    claw_version     VARCHAR(50),
    confidence       VARCHAR(20) NOT NULL,
    confidence_score INTEGER DEFAULT 0,
    matched_keyword  VARCHAR(200),
    matched_rule     VARCHAR(100),
    raw_response     JSONB,
    discovered_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_new           BOOLEAN DEFAULT FALSE,

    CONSTRAINT uq_scan_result UNIQUE (scan_id, ip, port),
    CONSTRAINT fk_scan_record FOREIGN KEY (scan_id)
        REFERENCES scan_records(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(claw_type);
CREATE INDEX IF NOT EXISTS idx_scan_results_confidence ON scan_results(confidence);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id              BIGSERIAL PRIMARY KEY,
    task_id         VARCHAR(36) NOT NULL UNIQUE,
    task_name       VARCHAR(100) NOT NULL,
    target_ips      TEXT NOT NULL,
    scan_ports      TEXT,
    exclude_ips     TEXT,
    exclude_ports   TEXT,
    scan_rate       INTEGER DEFAULT 1000,
    parallelism     INTEGER DEFAULT 8,
    cron_expression VARCHAR(50) NOT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    last_run_at     TIMESTAMP WITH TIME ZONE,
    last_scan_id    VARCHAR(36),
    next_run_at     TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS system_settings (
    key             VARCHAR(100) PRIMARY KEY,
    value           TEXT NOT NULL,
    description     VARCHAR(200),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO system_settings (key, value, description) VALUES
    ('default.scan.ports', '18789,18791,18792,18800,18801,18802,18803,18804,18805,19000,8789,28789,80,443,3000,8000,8080,8443', '默认扫描端口（18个，核心 Claw 架构端口 + 常见反代端口）'),
    ('default.scan.rate', '1000', '默认扫描速率'),
    ('default.scan.parallelism', '8', '默认并发度')
ON CONFLICT (key) DO NOTHING;
