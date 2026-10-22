import logging
from typing import Dict, Any, List
from fastapi import HTTPException, status
from app.core.config import settings

logger = logging.getLogger(__name__)


class ProductionAdapterError(Exception):
    pass


class ProductionBGPAdapter:
    """
    Production BGP & Routing Device Adapter Interface.
    Strictly separated from SimulationAdapter and BGPLabAdapter.
    
    Status: DISABLED BY DEFAULT.
    Protects production infrastructure by prohibiting direct shell/CLI command injection.
    All operations are strictly typed, allowlisted, and audited.
    """

    SUPPORTED_VENDORS = ["JUNIPER_JUNOS", "HUAWEI_VRP", "CISCO_IOSXR", "MIKROTIK_ROUTEROS"]
    ALLOWED_OPERATIONS = ["ANNOUNCE_UNICAST", "WITHDRAW_UNICAST", "FLOWSPEC_INSTALL", "FLOWSPEC_WITHDRAW", "RTBH_ACTIVATE", "RTBH_DEACTIVATE"]

    @classmethod
    def is_production_enabled(cls) -> bool:
        return settings.ROUTING_EXECUTION_ENABLED is True and settings.PRODUCTION_ROUTING_ENABLED is True

    @classmethod
    def get_adapter_status(cls) -> Dict[str, Any]:
        return {
            "adapter_name": "ProductionBGPAdapter",
            "is_enabled": cls.is_production_enabled(),
            "routing_execution_enabled": settings.ROUTING_EXECUTION_ENABLED,
            "production_routing_enabled": settings.PRODUCTION_ROUTING_ENABLED,
            "flowspec_execution_enabled": settings.FLOWSPEC_EXECUTION_ENABLED,
            "rtbh_execution_enabled": settings.RTBH_EXECUTION_ENABLED,
            "supported_vendors": cls.SUPPORTED_VENDORS,
            "allowed_operations": cls.ALLOWED_OPERATIONS,
            "safety_mode": "LOCKED_DRY_RUN",
        }

    @classmethod
    async def execute_dry_run_preview(
        cls,
        operation: str,
        target_device: str,
        target_peer: str,
        prefix: str,
        attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generates deterministic, vendor-safe CLI/API commands in dry-run mode
        WITHOUT transmitting anything to live physical routers.
        """
        if operation not in cls.ALLOWED_OPERATIONS:
            raise ProductionAdapterError(f"Operation '{operation}' not in ALLOWED_OPERATIONS: {cls.ALLOWED_OPERATIONS}")

        logger.info(
            "ProductionAdapter DRY-RUN PREVIEW generated for %s on %s (prefix: %s)",
            operation, target_device, prefix
        )

        return {
            "dry_run": True,
            "operation": operation,
            "target_device": target_device,
            "target_peer": target_peer,
            "prefix": prefix,
            "attributes": attributes,
            "simulated_commands": {
                "junos": f"set protocols bgp group ISP-EBGP neighbor {target_peer} export POLICY-{operation}-{prefix.replace('/', '_')}",
                "huawei": f"bgp 65000 \n peer {target_peer} route-policy POLICY-{operation} export",
                "cisco": f"router bgp 65000 \n neighbor {target_peer} route-policy POLICY-{operation} out",
            },
            "status": "SIMULATED_PREVIEW_SUCCESS",
            "message": "Production adapter is LOCKED. Command preview generated safely without network transmission.",
        }

    @classmethod
    async def transmit_live_operation(
        cls,
        operation: str,
        target_device: str,
        target_peer: str,
        prefix: str,
        attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Live execution gate enforcement. Permanently blocked on default installations.
        """
        if not cls.is_production_enabled():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "SAFETY LOCKOUT: Production routing execution is permanently DISABLED. "
                    "ROUTING_EXECUTION_ENABLED and PRODUCTION_ROUTING_ENABLED are FALSE. "
                    "Direct router mutations are blocked to protect live ISP traffic."
                ),
            )

        # In Phase 7, live execution remains blocked by design
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Phase 7 boundary: Physical router execution requires explicit operational authorization.",
        )
