from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.inventory import Device, Interface, Site, SNMPProfile, InterfaceMetricsHistory
from app.schemas.inventory import (
    DeviceCreate,
    DeviceResponse,
    InterfaceResponse,
    InterfaceCreate,
    SNMPProfileCreate,
    SNMPProfileUpdate,
    SNMPProfileResponse,
    InterfaceMetricsHistoryResponse,
    DevicePollResponse,
    SNMPWorkerStatusResponse,
)
from app.services.snmp_service import (
    encrypt_snmp_secret,
    poll_device_metrics,
    snmp_background_worker,
)
from app.api.deps import get_current_user, require_roles, record_audit_event

router = APIRouter()


# =============================================================================
# A. SNMP PROFILES MANAGEMENT
# =============================================================================

def _profile_to_response(profile: SNMPProfile) -> SNMPProfileResponse:
    """Format SNMPProfile model to response schema, strictly masking secrets."""
    return SNMPProfileResponse(
        id=profile.id,
        name=profile.name,
        version=profile.version,
        port=profile.port,
        timeout_sec=profile.timeout_sec,
        retries=profile.retries,
        security_name=profile.security_name,
        auth_protocol=profile.auth_protocol,
        priv_protocol=profile.priv_protocol,
        is_active=profile.is_active,
        has_auth_pass=bool(profile.auth_pass_encrypted),
        has_priv_pass=bool(profile.priv_pass_encrypted),
        has_community=bool(profile.community_encrypted),
        created_at=profile.created_at,
    )


@router.get("/snmp/profiles", response_model=List[SNMPProfileResponse])
async def list_snmp_profiles(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(SNMPProfile).order_by(SNMPProfile.id.asc())
    result = await db.execute(stmt)
    profiles = result.scalars().all()
    return [_profile_to_response(p) for p in profiles]


@router.post("/snmp/profiles", response_model=SNMPProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_snmp_profile(
    payload: SNMPProfileCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    # Check duplicate name
    stmt = select(SNMPProfile).where(SNMPProfile.name == payload.name)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Profile name already exists")

    # Encrypt secrets at rest
    enc_auth_pass = encrypt_snmp_secret(payload.auth_pass) if payload.auth_pass else None
    enc_priv_pass = encrypt_snmp_secret(payload.priv_pass) if payload.priv_pass else None
    enc_community = encrypt_snmp_secret(payload.community) if payload.community else None

    profile = SNMPProfile(
        name=payload.name,
        version=payload.version,
        port=payload.port,
        timeout_sec=payload.timeout_sec,
        retries=payload.retries,
        security_name=payload.security_name,
        auth_protocol=payload.auth_protocol,
        auth_pass_encrypted=enc_auth_pass,
        priv_protocol=payload.priv_protocol,
        priv_pass_encrypted=enc_priv_pass,
        community_encrypted=enc_community,
        is_active=payload.is_active,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_SNMP_PROFILE",
        resource_type="snmp_profile",
        resource_id=str(profile.id),
        details=f"Created SNMP profile '{profile.name}' (version {profile.version})",
        request=request,
    )

    return _profile_to_response(profile)


@router.get("/snmp/profiles/{profile_id}", response_model=SNMPProfileResponse)
async def get_snmp_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(SNMPProfile).where(SNMPProfile.id == profile_id)
    profile = (await db.execute(stmt)).scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SNMP profile not found")
    return _profile_to_response(profile)


@router.put("/snmp/profiles/{profile_id}", response_model=SNMPProfileResponse)
async def update_snmp_profile(
    profile_id: int,
    payload: SNMPProfileUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    stmt = select(SNMPProfile).where(SNMPProfile.id == profile_id)
    profile = (await db.execute(stmt)).scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SNMP profile not found")

    if payload.name is not None:
        profile.name = payload.name
    if payload.version is not None:
        profile.version = payload.version
    if payload.port is not None:
        profile.port = payload.port
    if payload.timeout_sec is not None:
        profile.timeout_sec = payload.timeout_sec
    if payload.retries is not None:
        profile.retries = payload.retries
    if payload.security_name is not None:
        profile.security_name = payload.security_name
    if payload.auth_protocol is not None:
        profile.auth_protocol = payload.auth_protocol
    if payload.priv_protocol is not None:
        profile.priv_protocol = payload.priv_protocol
    if payload.is_active is not None:
        profile.is_active = payload.is_active

    # Re-encrypt passwords only if explicitly provided in update
    if payload.auth_pass:
        profile.auth_pass_encrypted = encrypt_snmp_secret(payload.auth_pass)
    if payload.priv_pass:
        profile.priv_pass_encrypted = encrypt_snmp_secret(payload.priv_pass)
    if payload.community:
        profile.community_encrypted = encrypt_snmp_secret(payload.community)

    await db.commit()
    await db.refresh(profile)

    await record_audit_event(
        db=db,
        user=current_user,
        action="UPDATE_SNMP_PROFILE",
        resource_type="snmp_profile",
        resource_id=str(profile.id),
        details=f"Updated SNMP profile '{profile.name}'",
        request=request,
    )
    return _profile_to_response(profile)


@router.delete("/snmp/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_snmp_profile(
    profile_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    stmt = select(SNMPProfile).where(SNMPProfile.id == profile_id)
    profile = (await db.execute(stmt)).scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SNMP profile not found")

    await db.delete(profile)
    await db.commit()

    await record_audit_event(
        db=db,
        user=current_user,
        action="DELETE_SNMP_PROFILE",
        resource_type="snmp_profile",
        resource_id=str(profile_id),
        details=f"Deleted SNMP profile {profile_id}",
        request=request,
    )
    return None


# =============================================================================
# B. DEVICE INVENTORY & INTERFACES
# =============================================================================

@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Device).options(selectinload(Device.interfaces)).order_by(Device.id.asc())
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    payload: DeviceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    device = Device(
        hostname=payload.hostname,
        mgmt_ip=payload.mgmt_ip,
        vendor=payload.vendor,
        model=payload.model,
        site_id=payload.site_id,
        snmp_profile_id=payload.snmp_profile_id,
        status=payload.status,
    )
    db.add(device)
    await db.commit()
    await db.refresh(device)

    # Populate dummy default interfaces if created newly
    default_ifaces = [
        Interface(device_id=device.id, if_index=1, if_name="ge-0/0/0", alias="Uplink Provider A", speed_bps=10_000_000_000),
        Interface(device_id=device.id, if_index=2, if_name="ge-0/0/1", alias="Uplink Provider B", speed_bps=10_000_000_000),
        Interface(device_id=device.id, if_index=3, if_name="ge-0/0/2", alias="Core Downlink", speed_bps=40_000_000_000),
    ]
    for iface in default_ifaces:
        db.add(iface)
    await db.commit()

    # Re-fetch with interfaces
    stmt = select(Device).options(selectinload(Device.interfaces)).where(Device.id == device.id)
    refreshed = (await db.execute(stmt)).scalar_one()

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_DEVICE",
        resource_type="device",
        resource_id=str(device.id),
        details=f"Device {device.hostname} ({device.mgmt_ip}) added to site {device.site_id}.",
        request=request,
    )
    return refreshed


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Device).options(selectinload(Device.interfaces)).where(Device.id == device_id)
    device = (await db.execute(stmt)).scalars().first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    stmt = select(Device).where(Device.id == device_id)
    device = (await db.execute(stmt)).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    hostname = device.hostname
    mgmt_ip = device.mgmt_ip
    await db.delete(device)
    await db.commit()

    await record_audit_event(
        db=db,
        user=current_user,
        action="DELETE_DEVICE",
        resource_type="device",
        resource_id=str(device_id),
        details=f"Deleted device {hostname} ({mgmt_ip})",
        request=request,
    )
    return None


class DeviceProfileAssign(BaseModel):
    snmp_profile_id: Optional[int] = None


@router.put("/{device_id}/snmp-profile", response_model=DeviceResponse)
async def assign_snmp_profile(
    device_id: int,
    payload: DeviceProfileAssign,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    stmt = select(Device).options(selectinload(Device.interfaces)).where(Device.id == device_id)
    device = (await db.execute(stmt)).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if payload.snmp_profile_id is not None:
        p_stmt = select(SNMPProfile).where(SNMPProfile.id == payload.snmp_profile_id)
        profile = (await db.execute(p_stmt)).scalar_one_or_none()
        if not profile:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="SNMP profile does not exist")
        device.snmp_profile_id = profile.id
    else:
        device.snmp_profile_id = None

    await db.commit()
    await db.refresh(device)

    await record_audit_event(
        db=db,
        user=current_user,
        action="ASSIGN_SNMP_PROFILE",
        resource_type="device",
        resource_id=str(device.id),
        details=f"Assigned SNMP profile {payload.snmp_profile_id} to device {device.hostname}",
        request=request,
    )
    return device


@router.get("/{device_id}/interfaces", response_model=List[InterfaceResponse])
async def list_device_interfaces(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Interface).where(Interface.device_id == device_id).order_by(Interface.if_index.asc())
    interfaces = (await db.execute(stmt)).scalars().all()
    return interfaces


# =============================================================================
# C. INTERFACE METRICS HISTORY
# =============================================================================

@router.get("/{device_id}/interfaces/{interface_id}/history", response_model=List[InterfaceMetricsHistoryResponse])
async def get_interface_history(
    device_id: int,
    interface_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify interface belongs to device
    if_stmt = select(Interface).where(Interface.id == interface_id, Interface.device_id == device_id)
    iface = (await db.execute(if_stmt)).scalar_one_or_none()
    if not iface:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Interface not found on specified device")

    stmt = (
        select(InterfaceMetricsHistory)
        .where(
            InterfaceMetricsHistory.interface_id == interface_id,
            InterfaceMetricsHistory.device_id == device_id,
        )
        .order_by(desc(InterfaceMetricsHistory.timestamp))
        .limit(limit)
    )
    result = await db.execute(stmt)
    records = result.scalars().all()
    return list(reversed(records)) # Return in chronological order


# =============================================================================
# D. ON-DEMAND POLLING EXECUTION
# =============================================================================

class PollTriggerPayload(BaseModel):
    force_mock: bool = False


@router.post("/{device_id}/poll", response_model=DevicePollResponse)
async def trigger_device_poll(
    device_id: int,
    payload: Optional[PollTriggerPayload] = None,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Execute on-demand SNMP poll for a specifically registered device.
    CRITICAL SECURITY RULE: Target IP is strictly restricted to device.mgmt_ip.
    Arbitrary IP scanning is completely rejected.
    """
    stmt = select(Device).where(Device.id == device_id)
    device = (await db.execute(stmt)).scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    force_mock = payload.force_mock if payload else False
    poll_result = await poll_device_metrics(db, device.id, force_mock=force_mock)

    await record_audit_event(
        db=db,
        user=current_user,
        action="TRIGGER_SNMP_POLL",
        resource_type="device",
        resource_id=str(device.id),
        details=f"Triggered SNMP poll for {device.hostname} ({device.mgmt_ip}). Success={poll_result.success}",
        request=request,
    )

    return DevicePollResponse(
        device_id=device.id,
        hostname=device.hostname,
        mgmt_ip=device.mgmt_ip,
        success=poll_result.success,
        snmp_status=device.snmp_status,
        sys_uptime=poll_result.sys_uptime,
        sys_descr=poll_result.sys_descr,
        duration_ms=poll_result.duration_ms,
        error_message=poll_result.error_message,
        interfaces_polled=len(poll_result.interfaces),
    )


@router.get("/snmp/worker-status", response_model=SNMPWorkerStatusResponse)
async def get_snmp_worker_status(
    current_user: User = Depends(get_current_user),
):
    """
    Get live operational telemetry of the scheduled background SNMP polling worker:
    polling interval, total cycles, success/failure counts, active in-flight polls,
    and last cycle execution duration.
    """
    return snmp_background_worker.get_status()


@router.post("/snmp/worker-trigger", response_model=SNMPWorkerStatusResponse)
async def trigger_snmp_worker_cycle(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.NETWORK_ENGINEER, UserRole.SUPER_ADMIN)),
):
    """
    Trigger an immediate sweep cycle across all active inventory devices.
    Restricted to Network Engineers and Super Admins.
    """
    await snmp_background_worker.run_single_cycle()
    await record_audit_event(
        db=db,
        user=current_user,
        action="TRIGGER_SNMP_WORKER_CYCLE",
        resource_type="snmp_worker",
        resource_id="scheduler",
        details="Triggered manual background polling sweep cycle",
        request=request,
    )
    return snmp_background_worker.get_status()

