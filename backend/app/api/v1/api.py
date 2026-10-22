from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    dashboard,
    devices,
    collectors,
    bgp,
    probes,
    recommendations,
    change_requests,
    alerts,
    audit,
    admin,
    flows,
    bgp_lab,
    mitigation,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(flows.router, prefix="/flows", tags=["Flow Analytics"])
api_router.include_router(devices.router, prefix="/devices", tags=["Devices & Interfaces"])
api_router.include_router(collectors.router, prefix="/collectors", tags=["Flow Collectors"])
api_router.include_router(bgp.router, prefix="/bgp", tags=["BGP Visibility"])
api_router.include_router(bgp_lab.router, prefix="/bgp-lab", tags=["Isolated BGP Lab"])
api_router.include_router(probes.router, prefix="/probes", tags=["Active Probes"])
api_router.include_router(recommendations.router, prefix="/recommendations", tags=["Route Recommendations"])
api_router.include_router(change_requests.router, prefix="/change-requests", tags=["Change Management"])
api_router.include_router(mitigation.router, prefix="/mitigation", tags=["Mitigation & Rollout"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts & Incidents"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Trail"])
api_router.include_router(admin.router, prefix="/admin", tags=["Administration & Policies"])
