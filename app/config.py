from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://findclaw:findclaw123@localhost:5432/findclaw"

    server_host: str = "0.0.0.0"
    server_port: int = 8080

    nmap_path: str = "/usr/bin/nmap"
    nmap_nse_script_path: str = "docker/nmap-scripts/claw-detect.nse"
    default_scan_ports: str = (
        "18789,18791,18792,"
        "18800,18801,18802,18803,18804,18805,"
        "19000,8789,28789,"
        "80,443,3000,8000,8080,8443"
    )
    default_scan_rate: int = 1000
    default_parallelism: int = 8

    fingerprint_builtin_path: str = "config/fingerprints.json"
    fingerprint_external_path: str = ""

    scan_pool_size: int = 16
    http_probe_timeout: int = 8
    http_deep_probe_timeout: int = 20
    enable_mdns_discovery: bool = True
    mdns_discovery_timeout: float = 2.0

    model_config = {"env_prefix": "FINDCLAW_"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
