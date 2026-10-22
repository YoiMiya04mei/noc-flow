import pytest
import pytest_asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.main import app
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_password_hash, create_access_token
from app.models.base import Base
from app.models.user import User, UserRole, UserStatus
from app.models.policy import PrefixAllowlist

# SQLite in-memory test database
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
)

TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestAsyncSessionLocal() as session:
        # Seed test users
        users = [
            User(
                username="admin",
                email="admin@test.net",
                password_hash=get_password_hash("TestAdmin123!"),
                role=UserRole.SUPER_ADMIN.value,
                status=UserStatus.ACTIVE.value,
            ),
            User(
                username="engineer",
                email="engineer@test.net",
                password_hash=get_password_hash("TestEngineer123!"),
                role=UserRole.NETWORK_ENGINEER.value,
                status=UserStatus.ACTIVE.value,
            ),
            User(
                username="approver",
                email="approver@test.net",
                password_hash=get_password_hash("TestApprover123!"),
                role=UserRole.APPROVER.value,
                status=UserStatus.ACTIVE.value,
            ),
            User(
                username="operator",
                email="operator@test.net",
                password_hash=get_password_hash("TestOperator123!"),
                role=UserRole.NOC_OPERATOR.value,
                status=UserStatus.ACTIVE.value,
            ),
            User(
                username="auditor",
                email="auditor@test.net",
                password_hash=get_password_hash("TestAuditor123!"),
                role=UserRole.AUDITOR.value,
                status=UserStatus.ACTIVE.value,
            ),
        ]
        session.add_all(users)

        # Seed initial allowlisted prefix for tests
        allowlist = PrefixAllowlist(
            prefix="103.145.2.0/24",
            description="Test Allowed Prefix",
            is_active=True,
        )
        session.add(allowlist)
        await session.commit()

        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def admin_token() -> str:
    return create_access_token(subject="admin", role=UserRole.SUPER_ADMIN.value)


@pytest.fixture
def engineer_token() -> str:
    return create_access_token(subject="engineer", role=UserRole.NETWORK_ENGINEER.value)


@pytest.fixture
def approver_token() -> str:
    return create_access_token(subject="approver", role=UserRole.APPROVER.value)


@pytest.fixture
def operator_token() -> str:
    return create_access_token(subject="operator", role=UserRole.NOC_OPERATOR.value)


@pytest.fixture
def auditor_token() -> str:
    return create_access_token(subject="auditor", role=UserRole.AUDITOR.value)
