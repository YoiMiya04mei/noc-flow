import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import engine
from app.models.base import Base
from app.api.v1.api import api_router
from app.core.clickhouse import clickhouse_service

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jdp_platform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing JDP Route Intelligence Platform backend...")
    logger.info("ROUTING_EXECUTION_ENABLED = %s", settings.ROUTING_EXECUTION_ENABLED)

    # Automatically create tables in development / test environments
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Check ClickHouse connectivity
    ch_connected = clickhouse_service.is_connected()
    logger.info("ClickHouse Analytics DB connected: %s", ch_connected)

    # Start SNMP scheduled background poller
    from app.services.snmp_service import snmp_background_worker
    await snmp_background_worker.start()

    # Start BGP BMP Adapter TCP listener (RFC 7854)
    from app.services.bmp_service import bmp_adapter_service
    await bmp_adapter_service.start()

    # Start Active Path Probing Background Worker
    from app.services.probe_service import probe_background_worker
    await probe_background_worker.start()

    yield

    logger.info("Shutting down JDP Route Intelligence Platform backend...")
    from app.services.probe_service import probe_background_worker
    await probe_background_worker.stop()

    from app.services.bmp_service import bmp_adapter_service
    await bmp_adapter_service.stop()

    from app.services.snmp_service import snmp_background_worker
    await snmp_background_worker.stop()
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Carrier-grade self-hosted route intelligence, flow analytics, and BGP optimization platform for ISP NOCs.",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# CORS Middleware
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "jdp-backend",
        "version": settings.VERSION,
        "routing_execution_enabled": settings.ROUTING_EXECUTION_ENABLED,
    }


@app.get("/ready", tags=["Health"])
async def readiness_check():
    return {
        "status": "ready",
        "clickhouse_connected": clickhouse_service.is_connected(),
        "routing_execution_enabled": settings.ROUTING_EXECUTION_ENABLED,
    }


# Include API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)
