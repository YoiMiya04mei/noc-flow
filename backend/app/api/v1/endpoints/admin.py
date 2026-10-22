from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.policy import PrefixAllowlist, PeerAllowlist, ScoringPolicy
from app.schemas.auth import UserCreate, UserResponse, UserUpdate
from app.schemas.policy import (
    PrefixAllowlistCreate,
    PrefixAllowlistResponse,
    PeerAllowlistCreate,
    PeerAllowlistResponse,
    ScoringPolicyCreate,
    ScoringPolicyResponse,
)
from app.api.deps import require_roles, record_audit_event

router = APIRouter()


# Prefix Allowlists (Deny-by-default guardrail administration)
@router.get("/policies/prefixes", response_model=List[PrefixAllowlistResponse])
async def list_prefix_allowlists(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.NETWORK_ENGINEER)),
):
    stmt = select(PrefixAllowlist).order_by(PrefixAllowlist.id.asc())
    return (await db.execute(stmt)).scalars().all()


@router.post("/policies/prefixes", response_model=PrefixAllowlistResponse, status_code=status.HTTP_201_CREATED)
async def add_prefix_allowlist(
    payload: PrefixAllowlistCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    existing = await db.execute(select(PrefixAllowlist).where(PrefixAllowlist.prefix == payload.prefix))
    if existing.scalars().first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Prefix already allowlisted")

    allowlist_entry = PrefixAllowlist(
        prefix=payload.prefix,
        description=payload.description,
        is_active=payload.is_active,
    )
    db.add(allowlist_entry)
    await db.commit()
    await db.refresh(allowlist_entry)

    await record_audit_event(
        db=db,
        user=current_user,
        action="ADD_PREFIX_ALLOWLIST",
        resource_type="policy",
        resource_id=str(allowlist_entry.id),
        details=f"Prefix {allowlist_entry.prefix} added to allowlist.",
        request=request,
    )
    return allowlist_entry


# Peer Allowlists
@router.get("/policies/peers", response_model=List[PeerAllowlistResponse])
async def list_peer_allowlists(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN, UserRole.NETWORK_ENGINEER)),
):
    stmt = select(PeerAllowlist).order_by(PeerAllowlist.id.asc())
    return (await db.execute(stmt)).scalars().all()


@router.post("/policies/peers", response_model=PeerAllowlistResponse, status_code=status.HTTP_201_CREATED)
async def add_peer_allowlist(
    payload: PeerAllowlistCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    existing = await db.execute(select(PeerAllowlist).where(PeerAllowlist.peer_ip == payload.peer_ip))
    if existing.scalars().first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Peer IP already allowlisted")

    peer_entry = PeerAllowlist(
        peer_ip=payload.peer_ip,
        peer_asn=payload.peer_asn,
        description=payload.description,
        is_active=payload.is_active,
    )
    db.add(peer_entry)
    await db.commit()
    await db.refresh(peer_entry)

    await record_audit_event(
        db=db,
        user=current_user,
        action="ADD_PEER_ALLOWLIST",
        resource_type="policy",
        resource_id=str(peer_entry.id),
        details=f"Peer {peer_entry.peer_ip} (AS{peer_entry.peer_asn}) allowlisted.",
        request=request,
    )
    return peer_entry


# User Management
@router.get("/users", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    stmt = select(User).order_by(User.id.asc())
    return (await db.execute(stmt)).scalars().all()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.SUPER_ADMIN)),
):
    existing_user = await db.execute(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if existing_user.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username or email already exists",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        status=payload.status,
        is_active=payload.is_active,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await record_audit_event(
        db=db,
        user=current_user,
        action="CREATE_USER",
        resource_type="user",
        resource_id=str(user.id),
        details=f"User {user.username} (Role: {user.role}) created.",
        request=request,
    )
    return user
