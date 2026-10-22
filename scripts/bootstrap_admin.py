#!/usr/bin/env python3
"""
Secure Administrator & Role Bootstrap CLI for JDP Route Intelligence Platform.
Enables initial account creation and zero-downtime password rotation without
exposing secrets in Git, logs, or command-line shell histories.
"""
import os
import sys
import argparse
import getpass
import secrets
import string
import re
import asyncio
from datetime import datetime, timezone

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole, UserStatus
from app.models.audit import AuditEvent


def generate_secure_password(length: int = 20) -> str:
    """Generate a high-entropy password meeting complexity requirements."""
    chars_upper = string.ascii_uppercase
    chars_lower = string.ascii_lowercase
    chars_digits = string.digits
    chars_special = "!@#$%^&*()-_=+"
    all_chars = chars_upper + chars_lower + chars_digits + chars_special

    # Ensure at least one of each category
    pwd = [
        secrets.choice(chars_upper),
        secrets.choice(chars_lower),
        secrets.choice(chars_digits),
        secrets.choice(chars_special),
    ]
    pwd += [secrets.choice(all_chars) for _ in range(length - 4)]
    # Shuffle cryptographically
    shuffled = "".join(secrets.SystemRandom().sample(pwd, len(pwd)))
    return shuffled


def validate_password_strength(password: str) -> bool:
    """Enforce NIST SP 800-63B / PCI-DSS password complexity."""
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*()_\-=+~`\[\]{}|:;\"'<>,.?/]", password):
        return False
    return True


async def bootstrap_user(
    username: str,
    email: str,
    full_name: str,
    role: str,
    password: str,
    is_generated: bool = False,
) -> bool:
    """Create or rotate user password and write security audit trail."""
    if not validate_password_strength(password):
        print(
            "ERROR: Password does not meet security requirements.\n"
            "Must be at least 12 characters long and contain uppercase, lowercase, numbers, and symbols.",
            file=sys.stderr,
        )
        return False

    valid_roles = [r.value for r in UserRole]
    if role not in valid_roles:
        print(f"ERROR: Invalid role '{role}'. Allowed roles: {valid_roles}", file=sys.stderr)
        return False

    async with AsyncSessionLocal() as session:
        query = select(User).where(User.username == username)
        result = await session.execute(query)
        user = result.scalars().first()

        hashed = get_password_hash(password)

        if user:
            # Password rotation
            user.password_hash = hashed
            user.status = UserStatus.ACTIVE.value
            user.updated_at = datetime.now(timezone.utc)
            action = "USER_PASSWORD_ROTATED"
            print(f"[BOOTSTRAP] Updating existing user '{username}' (Role: {user.role})...")
        else:
            # First-time bootstrap
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                password_hash=hashed,
                role=role,
                status=UserStatus.ACTIVE.value,
            )
            session.add(user)
            action = "USER_BOOTSTRAP_CREATED"
            print(f"[BOOTSTRAP] Creating new user '{username}' (Role: {role})...")

        # Append audit trail (strictly zero password logging)
        audit = AuditEvent(
            actor_username="system-bootstrap-cli",
            actor_role="super_admin",
            action=action,
            resource_type="user",
            resource_id=username,
            details=f'{{"username": "{username}", "role": "{role}", "status": "active", "timestamp": "{datetime.now(timezone.utc).isoformat()}"}}',
            ip_address="127.0.0.1",
        )
        session.add(audit)
        await session.commit()

    print(f"[SUCCESS] Action '{action}' completed successfully for user '{username}'.")
    if is_generated:
        print("\n" + "=" * 60)
        print("ATTENTION: GENERATED TEMPORARY / INITIAL PASSWORD:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print("STORE THIS PASSWORD SECURELY IMMEDIATELY. IT WILL NOT BE DISPLAYED AGAIN.")
        print("=" * 60 + "\n")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap or Rotate JDP Administrator / Role Credentials Securely."
    )
    parser.add_argument("--username", default="admin", help="Username to create or rotate (default: admin)")
    parser.add_argument("--email", default="admin@jdp-noc.net", help="Email address")
    parser.add_argument("--full-name", default="Super Administrator", help="Display name")
    parser.add_argument(
        "--role",
        default=UserRole.SUPER_ADMIN.value,
        choices=[r.value for r in UserRole],
        help="RBAC Role (default: super_admin)",
    )
    parser.add_argument("--password", help="Password string (NOT recommended on shared terminal histories)")
    parser.add_argument("--generate", action="store_true", help="Generate a secure random password")

    args = parser.parse_args()

    password = None
    is_generated = False

    if args.generate:
        password = generate_secure_password(22)
        is_generated = True
    elif args.password:
        password = args.password
    else:
        # Check environment variable first
        env_pwd = os.getenv("INITIAL_ADMIN_PASSWORD")
        if env_pwd:
            password = env_pwd
        else:
            # Interactive prompt without echo
            print(f"Enter new password for '{args.username}':")
            p1 = getpass.getpass("Password: ")
            p2 = getpass.getpass("Confirm Password: ")
            if p1 != p2:
                print("ERROR: Passwords do not match.", file=sys.stderr)
                sys.exit(1)
            password = p1

    success = asyncio.run(
        bootstrap_user(
            username=args.username,
            email=args.email,
            full_name=args.full_name,
            role=args.role,
            password=password,
            is_generated=is_generated,
        )
    )
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
