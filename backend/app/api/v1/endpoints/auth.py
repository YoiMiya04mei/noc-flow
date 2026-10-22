from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import verify_password, create_access_token
from app.core.config import settings
from app.models.user import User, UserStatus
from app.schemas.auth import Token, UserResponse, LoginRequest
from app.api.deps import get_current_user, record_audit_event

router = APIRouter()


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(User.username == form_data.username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active or user.status != UserStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended",
        )

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token(subject=user.username, role=user.role)

    await record_audit_event(
        db=db,
        user=user,
        action="LOGIN",
        resource_type="auth",
        resource_id=str(user.id),
        details=f"User {user.username} logged in successfully.",
        request=request,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": user.role,
        "username": user.username,
    }


@router.post("/login-json", response_model=Token)
async def login_json(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).where(User.username == body.username)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active or user.status != UserStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended",
        )

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token(subject=user.username, role=user.role)

    await record_audit_event(
        db=db,
        user=user,
        action="LOGIN",
        resource_type="auth",
        resource_id=str(user.id),
        details=f"User {user.username} logged in via JSON endpoint.",
        request=request,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": user.role,
        "username": user.username,
    }


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await record_audit_event(
        db=db,
        user=current_user,
        action="LOGOUT",
        resource_type="auth",
        resource_id=str(current_user.id),
        details=f"User {current_user.username} logged out.",
        request=request,
    )
    return {"message": "Successfully logged out"}
