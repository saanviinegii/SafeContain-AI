"""SafeContain AI Persistent User Identity Store.

Provides ACID-compliant user account storage using SQLite with bcrypt password hashing.
Supports initial bootstrap from environment variables and administrative user management.
"""

from datetime import datetime, timezone
import logging
from pathlib import Path
import sqlite3
from typing import List, Optional
import uuid
import bcrypt
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.security.roles import AppRole, normalize_app_role

logger = logging.getLogger(__name__)


class UserRecord(BaseModel):
    """Internal user record containing credential hashes."""
    id: str
    username: str
    email: Optional[str] = None
    hashed_password: str
    role: AppRole
    is_active: bool = True
    full_name: Optional[str] = None
    created_at: str
    updated_at: str


class UserResponse(BaseModel):
    """Sanitized public user representation omitting credentials."""
    id: str
    username: str
    email: Optional[str] = None
    role: AppRole
    is_active: bool
    full_name: Optional[str] = None
    created_at: str
    updated_at: str


class UserCreateRequest(BaseModel):
    """Payload for administrative user creation."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    role: AppRole = AppRole.VIEWER
    email: Optional[str] = None
    full_name: Optional[str] = None


class UserUpdateRequest(BaseModel):
    """Payload for updating user metadata or role."""
    role: Optional[AppRole] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None
    email: Optional[str] = None


class UserStore:
    """ACID-compliant SQLite User Persistence Manager."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or settings.SQLITE_DB_PATH)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes schema and runs idempotent initial user bootstrap."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    full_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON app_users(username)")
            conn.commit()

        self._bootstrap_default_users()

    def _hash_password(self, password: str) -> str:
        """Generates a secure salted bcrypt hash."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verifies a plain password against the stored bcrypt hash."""
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception:
            return False

    def _bootstrap_default_users(self) -> None:
        """Bootstraps default administrative and demonstration accounts idempotently."""
        # 1. Admin account bootstrap
        admin_user = settings.INITIAL_ADMIN_USERNAME or "admin"
        admin_pass = settings.INITIAL_ADMIN_PASSWORD or "Admin@SafeContain2026!"
        
        if not self.get_user_by_username(admin_user):
            self.create_user(
                username=admin_user,
                password=admin_pass,
                role=AppRole.ADMIN,
                email=f"{admin_user}@safecontain.ai",
                full_name="Platform Security Administrator",
            )
            logger.info("Bootstrapped initial administrator account: '%s'", admin_user)

        # 2. Demonstration Analyst account
        if not self.get_user_by_username("analyst"):
            self.create_user(
                username="analyst",
                password="Analyst@SafeContain2026!",
                role=AppRole.ANALYST,
                email="analyst@safecontain.ai",
                full_name="Lead SOC Cyber Analyst",
            )

        # 3. Demonstration Viewer account
        if not self.get_user_by_username("viewer"):
            self.create_user(
                username="viewer",
                password="Viewer@SafeContain2026!",
                role=AppRole.VIEWER,
                email="viewer@safecontain.ai",
                full_name="Executive Dashboard Viewer",
            )

    def create_user(
        self,
        username: str,
        password: str,
        role: AppRole = AppRole.VIEWER,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
    ) -> UserRecord:
        """Creates a new user with a hashed password."""
        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        hashed = self._hash_password(password)
        clean_role = normalize_app_role(role).value

        with self._get_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO app_users (id, username, email, hashed_password, role, is_active, full_name, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (user_id, username.strip(), email.strip() if email else None, hashed, clean_role, full_name, now, now)
                )
                conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError(f"User with username '{username}' or email '{email}' already exists.") from e

        return self.get_user_by_id(user_id)  # type: ignore

    def get_user_by_username(self, username: str) -> Optional[UserRecord]:
        """Retrieves user by username."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM app_users WHERE username = ? COLLATE NOCASE",
                (username.strip(),)
            ).fetchone()
            if not row:
                return None
            return UserRecord(
                id=row["id"],
                username=row["username"],
                email=row["email"],
                hashed_password=row["hashed_password"],
                role=normalize_app_role(row["role"]),
                is_active=bool(row["is_active"]),
                full_name=row["full_name"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        """Retrieves user by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM app_users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                return None
            return UserRecord(
                id=row["id"],
                username=row["username"],
                email=row["email"],
                hashed_password=row["hashed_password"],
                role=normalize_app_role(row["role"]),
                is_active=bool(row["is_active"]),
                full_name=row["full_name"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def list_users(self) -> List[UserResponse]:
        """Lists all users without exposing password hashes."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM app_users ORDER BY created_at ASC").fetchall()
            return [
                UserResponse(
                    id=r["id"],
                    username=r["username"],
                    email=r["email"],
                    role=normalize_app_role(r["role"]),
                    is_active=bool(r["is_active"]),
                    full_name=r["full_name"],
                    created_at=r["created_at"],
                    updated_at=r["updated_at"],
                )
                for r in rows
            ]

    def update_user_role(self, user_id: str, new_role: AppRole) -> bool:
        """Updates a user's role."""
        clean_role = normalize_app_role(new_role).value
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE app_users SET role = ?, updated_at = ? WHERE id = ?",
                (clean_role, now, user_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def set_user_active(self, user_id: str, is_active: bool) -> bool:
        """Activates or deactivates an account."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE app_users SET is_active = ?, updated_at = ? WHERE id = ?",
                (1 if is_active else 0, now, user_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def update_password(self, user_id: str, new_password: str) -> bool:
        """Updates a user's password with a fresh hash."""
        hashed = self._hash_password(new_password)
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE app_users SET hashed_password = ?, updated_at = ? WHERE id = ?",
                (hashed, now, user_id)
            )
            conn.commit()
            return cursor.rowcount > 0


user_store = UserStore()
