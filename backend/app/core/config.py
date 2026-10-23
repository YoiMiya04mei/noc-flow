import os
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "JDP Route Intelligence Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Security & Tokens
    SECRET_KEY: str = "jdp-super-secure-dev-secret-key-change-in-production-min-32-chars"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    # Application Database (PostgreSQL / SQLite fallback for lightweight tests)
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "jdp_route_intel"
    POSTGRES_USER: str = "jdp_user"
    POSTGRES_PASSWORD: str = "jdp_secure_password_dev"
    DATABASE_URL: str = "postgresql+asyncpg://jdp_user:jdp_secure_password_dev@localhost:5432/jdp_route_intel"

    # ClickHouse Analytics Database
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 8123
    CLICKHOUSE_DB: str = "jdp_flow_analytics"
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = "clickhouse_dev_pass"

    # =========================================================================
    # CRITICAL ROUTING & BGP SAFETY GUARDRAILS
    # Must remain False on default installations!
    # =========================================================================
    ROUTING_EXECUTION_ENABLED: bool = False
    MAX_PREFIX_CHANGE_LIMIT: int = 10
    BGP_LAB_MODE: bool = True

    # =========================================================================
    # PHASE 7: PRODUCTION EXECUTION GATES & MITIGATION FLAGS
    # All execution flags must remain False by default on all installations!
    # =========================================================================
    PRODUCTION_ROUTING_ENABLED: bool = False
    FLOWSPEC_EXECUTION_ENABLED: bool = False
    RTBH_EXECUTION_ENABLED: bool = False
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 3
    CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS: int = 300
    MAX_ROLLOUT_PREFIX_LIMIT: int = 5
    DEFAULT_RTBH_COMMUNITY: str = "65535:666"
    DEFAULT_MITIGATION_TTL_MINUTES: int = 60

    # =========================================================================
    # PHASE 6: ISOLATED BGP LAB CONFIGURATION
    # Default is disabled (False) for general safety!
    # =========================================================================
    BGP_LAB_ENABLED: bool = False
    BGP_LAB_SPEAKER_1_HOST: str = "127.0.0.1"
    BGP_LAB_SPEAKER_1_PORT: int = 50051
    BGP_LAB_SPEAKER_1_ASN: int = 65001
    BGP_LAB_SPEAKER_1_IP: str = "10.99.0.10"

    BGP_LAB_SPEAKER_2_HOST: str = "127.0.0.1"
    BGP_LAB_SPEAKER_2_PORT: int = 50052
    BGP_LAB_SPEAKER_2_ASN: int = 65002
    BGP_LAB_SPEAKER_2_IP: str = "10.99.0.20"

    BGP_LAB_ALLOWED_PREFIXES: List[str] = [
        "10.100.1.0/24",
        "10.100.2.0/24",
        "10.200.0.0/24",
    ]
    BGP_LAB_ALLOWED_PEERS: List[str] = [
        "10.99.0.10",
        "10.99.0.20",
    ]
    BGP_LAB_CONVERGENCE_TIMEOUT_SECONDS: int = 25
    BGP_LAB_COMMAND_TIMEOUT_SECONDS: int = 15

    # SNMP Polling Configuration
    SNMP_POLLING_ENABLED: bool = True
    SNMP_POLLING_INTERVAL_SECONDS: int = 30
    SNMP_CONCURRENCY_LIMIT: int = 10
    SNMP_STALE_THRESHOLD_SECONDS: int = 180

    # BGP & BMP (RFC 7854) Adapter Configuration
    BMP_ENABLED: bool = True
    BMP_HOST: str = "0.0.0.0"
    BMP_PORT: int = 11019
    BMP_ALLOWED_HOSTS: List[str] = [] # Empty list = allow any lab/dev peer; or restrict to CIDRs
    BMP_MAX_MESSAGE_SIZE: int = 1048576 # 1 MB maximum BMP frame size

    # Active Path Probing Configuration
    PROBE_ENABLED: bool = True
    PROBE_WORKER_INTERVAL_SECONDS: int = 15
    PROBE_CONCURRENCY_LIMIT: int = 20
    PROBE_PACKET_COUNT: int = 3
    PROBE_STALE_THRESHOLD_SECONDS: int = 120

    # Feature Toggles
    DEMO_MODE_ENABLED: bool = True

    model_config = SettingsConfigDict(
        env_file=os.getenv("ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
