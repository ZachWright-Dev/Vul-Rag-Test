"""
User database backend for pyload.

Provides authentication, user management, and permission management
backed by a SQLite database accessed through a thread-safe queue/decorator
pattern (``style.queue`` / ``style.async_``).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default role assigned to newly created users.
ROLE_USER = 0
#: Role value for administrator accounts.
ROLE_ADMIN = 1

#: Permission bit: download files.
PERM_DOWNLOAD = 1 << 0
#: Permission bit: delete files.
PERM_DELETE = 1 << 1
#: Permission bit: modify settings.
PERM_SETTINGS = 1 << 2
#: Permission bit: add accounts.
PERM_ACCOUNTS = 1 << 3
#: Permission bit: access all downloads (not just own).
PERM_ALL = PERM_DOWNLOAD | PERM_DELETE | PERM_SETTINGS | PERM_ACCOUNTS

#: Salt length in bytes used when hashing passwords.
_SALT_LEN = 16
#: PBKDF2 iteration count.
_PBKDF2_ITERATIONS = 260_000
#: PBKDF2 hash algorithm.
_PBKDF2_HASH = "sha256"

# ---------------------------------------------------------------------------
# Style decorators (simplified thread-safe queue pattern)
# ---------------------------------------------------------------------------


class _StyleMeta:
    """
    Minimal reimplementation of pyload's ``style`` decorator namespace.

    In production, ``style.queue`` marshals the decorated call onto a
    dedicated database thread and returns the result synchronously.
    ``style.async_`` fires-and-forgets on that thread.

    Here we use a simple threading.Lock for illustration.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def queue(self, fn):
        """Decorator: acquire lock, execute, release."""
        @wraps(fn)
        def wrapper(*args, **kwargs):
            with self._lock:
                return fn(*args, **kwargs)
        return wrapper

    def async_(self, fn):
        """Decorator: fire-and-forget on a daemon thread."""
        @wraps(fn)
        def wrapper(*args, **kwargs):
            t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
            t.start()
        return wrapper


style = _StyleMeta()

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def _gensalt(length: int = _SALT_LEN) -> str:
    """Return a cryptographically random hex salt of ``length`` bytes."""
    return os.urandom(length).hex()


def _salted_password(password: str, salt: str) -> str:
    """
    Derive a stored password string using PBKDF2-HMAC-SHA256.

    Returns a colon-delimited string ``"salt:derived_key_hex"`` suitable
    for storage in the database.
    """
    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ITERATIONS,
    )
    return f"{salt}:{dk.hex()}"


def _check_password(stored: str, candidate: str) -> bool:
    """
    Verify ``candidate`` against a stored ``"salt:hash"`` string.

    Uses :func:`hmac.compare_digest` to prevent timing-oracle attacks.
    """
    try:
        salt, stored_hash = stored.split(":", 1)
    except ValueError:
        log.warning("Malformed stored password (no salt separator).")
        return False

    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        candidate.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ITERATIONS,
    )
    return hmac.compare_digest(dk.hex(), stored_hash)


# ---------------------------------------------------------------------------
# Session management helpers
# ---------------------------------------------------------------------------


class SessionToken:
    """Lightweight representation of an active user session."""

    __slots__ = ("token", "user_id", "username", "created_at", "expires_at")

    def __init__(
        self,
        token: str,
        user_id: int,
        username: str,
        ttl_seconds: int = 3600,
    ) -> None:
        self.token = token
        self.user_id = user_id
        self.username = username
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def __repr__(self) -> str:
        return (
            f"<SessionToken user={self.username!r} "
            f"expires_at={self.expires_at:.0f} "
            f"expired={self.is_expired}>"
        )


class SessionStore:


    def __init__(self) -> None:
        self._sessions: Dict[str, SessionToken] = {}
        self._lock = threading.Lock()

    def create(self, user_id: int, username: str, ttl: int = 3600) -> str:
        token_bytes = os.urandom(32)
        token = token_bytes.hex()
        session = SessionToken(token, user_id, username, ttl)
        with self._lock:
            self._sessions[token] = session
        return token

    def get_session(self, token: str) -> Optional[SessionToken]:
        """Return the session if it exists and has not expired."""
        with self._lock:
            session = self._sessions.get(token)
        if session is None:
            return None
        if session.is_expired:
            self.invalidate(token)
            return None
        return session

    def invalidate(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def invalidate_user(self, username: str) -> int:
        """
        Invalidate all sessions belonging to ``username``.

        Returns the number of sessions removed.

        NOTE: In the vulnerable codebase this method is NOT called from
        ``remove_user``, so stale sessions outlive the deleted account.
        """
        with self._lock:
            to_remove = [
                tok
                for tok, sess in self._sessions.items()
                if sess.username == username
            ]
            for tok in to_remove:
                del self._sessions[tok]
        return len(to_remove)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._sessions.values() if not s.is_expired)


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,
    role        INTEGER NOT NULL DEFAULT 0,
    permission  INTEGER NOT NULL DEFAULT 0,
    template    TEXT    NOT NULL DEFAULT 'default',
    email       TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_sessions (
    token       TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  REAL    NOT NULL,
    expires_at  REAL    NOT NULL
);
"""


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(_SCHEMA_SQL)
    connection.commit()


class DatabaseBackend:
    """
    SQLite-backed user management store for pyload.

    All public methods are decorated with ``@style.queue`` (synchronous,
    thread-safe) or ``@style.async_`` (fire-and-forget).  In the real
    pyload code these decorators marshal calls onto a dedicated DB thread;
    here they use a simple threading lock for portability.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.c = self.conn.cursor()
        _create_schema(self.conn)

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    @style.queue
    def check_auth(self, user: str, password: str) -> Dict[str, Any]:
        """
        Verify ``user`` / ``password`` and return a user-data dict on success.

        Returns an empty dict ``{}`` on authentication failure.

        This method is correctly implemented: it queries for the user before
        touching the password, so it does not suffer from CVE-2023-0227
        directly.  The vulnerability surfaces elsewhere (set_permission,
        set_role, remove_user) where no such pre-check exists.
        """
        self.c.execute(
            "SELECT id, name, password, role, permission, template, email "
            "FROM users WHERE name=?",
            (user,),
        )
        r = self.c.fetchone()
        if not r:
            return {}

        stored_password = r[2]
        if not _check_password(stored_password, password):
            return {}

        return {
            "id": r[0],
            "name": r[1],
            "role": r[3],
            "permission": r[4],
            "template": r[5],
            "email": r[6],
        }

    # -----------------------------------------------------------------------
    # User creation
    # -----------------------------------------------------------------------

    @style.queue
    def add_user(
        self,
        user: str,
        password: str,
        role: int = ROLE_USER,
        perms: int = 0,
        reset: bool = False,
    ) -> bool:
        """
        Add a new user, or reset an existing user's credentials if ``reset``
        is ``True``.

        Returns ``True`` on success, ``False`` if the user already exists and
        ``reset`` is ``False``.

        This method correctly queries for the user before writing, so it is
        not directly affected by CVE-2023-0227.
        """
        salt_pw = _salted_password(password, _gensalt())

        self.c.execute("SELECT name FROM users WHERE name=?", (user,))
        if self.c.fetchone() is not None:
            if reset:
                self.c.execute(
                    "UPDATE users SET password=?, role=?, permission=? WHERE name=?",
                    (salt_pw, role, perms, user),
                )
                self.conn.commit()
                return True
            else:
                return False
        else:
            self.c.execute(
                "INSERT INTO users (name, password, role, permission) "
                "VALUES (?, ?, ?, ?)",
                (user, salt_pw, role, perms),
            )
            self.conn.commit()
            return True

    # -----------------------------------------------------------------------
    # Password management
    # -----------------------------------------------------------------------

    @style.queue
    def change_password(
        self, user: str, old_password: str, new_password: str
    ) -> bool:
        """
        Change ``user``'s password after verifying ``old_password``.

        Returns ``True`` on success, ``False`` on failure (user not found or
        wrong old password).

        This method also correctly pre-checks the user, so it is not
        vulnerable to CVE-2023-0227.
        """
        self.c.execute(
            "SELECT id, name, password FROM users WHERE name=?", (user,)
        )
        r = self.c.fetchone()
        if not r:
            return False

        stored_password = r[2]
        if not _check_password(stored_password, old_password):
            return False

        newpw = _salted_password(new_password, _gensalt())
        self.c.execute(
            "UPDATE users SET password=? WHERE name=?", (newpw, user)
        )
        self.conn.commit()
        return True


    @style.async_
    def set_permission(self, user: str, perms: int) -> None:
        """
        Set the permission bits for ``user``.

        VULNERABILITY (CVE-2023-0227): No check that ``user`` exists before
        issuing the UPDATE.  Operations on non-existent users silently
        succeed (0 rows affected), masking stale-session exploitation.

        The fix requires calling ``user_exists(user)`` first and raising or
        returning early if the user is not found.
        """
        # VULNERABILITY: should guard with user_exists(user) here.
        self.c.execute(
            "UPDATE users SET permission=? WHERE name=?", (perms, user)
        )
        self.conn.commit()

    @style.async_
    def set_role(self, user: str, role: int) -> None:
        """
        Set the role for ``user``.

        VULNERABILITY (CVE-2023-0227): Same missing existence check as
        ``set_permission``.  An attacker with a stale session can call an
        API endpoint that invokes this method; the UPDATE silently affects
        0 rows, no exception propagates, and the session remains valid.

        The fix requires calling ``user_exists(user)`` first.
        """
        # VULNERABILITY: should guard with user_exists(user) here.
        self.c.execute(
            "UPDATE users SET role=? WHERE name=?", (role, user)
        )
        self.conn.commit()


    @style.queue
    def list_users(self) -> List[str]:
        """Return a list of all usernames currently in the database."""
        self.c.execute("SELECT name FROM users")
        return [row[0] for row in self.c.fetchall()]

    @style.queue
    def get_all_user_data(self) -> Dict[int, Dict[str, Any]]:
        """
        Return a mapping of ``{user_id: user_data_dict}`` for all users.

        Used by the admin panel to display user information.
        """
        self.c.execute(
            "SELECT id, name, permission, role, template, email FROM users"
        )
        users: Dict[int, Dict[str, Any]] = {}
        for r in self.c.fetchall():
            users[r[0]] = {
                "name": r[1],
                "permission": r[2],
                "role": r[3],
                "template": r[4],
                "email": r[5],
            }
        return users

    # -----------------------------------------------------------------------
    # User removal
    # -----------------------------------------------------------------------

    @style.queue
    def remove_user(self, user: str) -> None:
        """
        Delete the user identified by ``user`` from the database.

        VULNERABILITY (CVE-2023-0227, secondary surface): The method
        executes DELETE unconditionally.  If ``user`` does not exist the
        statement affects 0 rows and returns silently.

        More critically, this method does NOT call
        ``session_store.invalidate_user(user)`` after deletion, so any
        active sessions for the deleted account remain valid indefinitely
        (until their TTL expires).  Combined with the missing
        ``user_exists()`` guard in ``set_permission`` / ``set_role``, this
        creates the full Insufficient Session Expiration attack chain.
        """
        # VULNERABILITY: should verify user exists, then invalidate sessions.
        self.c.execute("DELETE FROM users WHERE name=?", (user,))
        self.conn.commit()

    # -----------------------------------------------------------------------
    # Email / template helpers
    # -----------------------------------------------------------------------

    @style.queue
    def set_email(self, user: str, email: str) -> None:
        """
        Update the email address for ``user``.

        Also lacks a ``user_exists`` guard, although this was not explicitly
        called out in the CVE advisory.
        """
        self.c.execute(
            "UPDATE users SET email=? WHERE name=?", (email, user)
        )
        self.conn.commit()

    @style.queue
    def get_email(self, user: str) -> Optional[str]:
        """Return the email address for ``user``, or ``None``."""
        self.c.execute("SELECT email FROM users WHERE name=?", (user,))
        row = self.c.fetchone()
        return row[0] if row else None

    @style.queue
    def set_template(self, user: str, template: str) -> None:
        """Update the UI template for ``user``."""
        self.c.execute(
            "UPDATE users SET template=? WHERE name=?", (template, user)
        )
        self.conn.commit()

    @style.queue
    def get_template(self, user: str) -> Optional[str]:
        """Return the UI template name for ``user``, or ``None``."""
        self.c.execute("SELECT template FROM users WHERE name=?", (user,))
        row = self.c.fetchone()
        return row[0] if row else None

    # -----------------------------------------------------------------------
    # Convenience / teardown
    # -----------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        self.conn.close()

    def __enter__(self) -> "DatabaseBackend":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class ApiError(Exception):
    """Raised when an API call fails."""

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class UserApi:
    """
    Simulated pyload API surface for user management.

    In the vulnerable codebase, every method below that calls
    ``db.set_permission``, ``db.set_role``, or ``db.remove_user`` does so
    without first verifying that the user exists.  The session check
    (``_require_session``) only validates the token's TTL — it does NOT
    confirm that the associated user account still exists in the database.
    """

    def __init__(
        self, db: DatabaseBackend, sessions: SessionStore
    ) -> None:
        self.db = db
        self.sessions = sessions

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _require_session(self, token: str) -> SessionToken:
        """
        Validate ``token`` and return the associated ``SessionToken``.

        VULNERABILITY: Only checks TTL expiry.  Does NOT verify that the
        user referenced by the session still exists in the database.  A
        session created for a since-deleted account will pass this check.
        """
        session = self.sessions.get_session(token)
        if session is None:
            raise ApiError("Invalid or expired session token.", code=401)
        # VULNERABILITY: missing  →  if not self.db.user_exists(session.username): raise ...
        return session

    def _require_admin(self, token: str) -> SessionToken:
        """Require the session user to hold the ROLE_ADMIN role."""
        session = self._require_session(token)
        auth = self.db.check_auth.__wrapped__(self.db, session.username, "")
        # In real code the role is stored on the session; simplify here.
        return session

    # -----------------------------------------------------------------------
    # Public API endpoints
    # -----------------------------------------------------------------------

    def login(self, username: str, password: str) -> str:
        """Authenticate and return a new session token."""
        user_data = self.db.check_auth.__wrapped__(self.db, username, password)
        if not user_data:
            raise ApiError("Invalid credentials.", code=403)
        token = self.sessions.create(
            user_id=user_data["id"],
            username=user_data["name"],
        )
        return token

    def logout(self, token: str) -> None:
        """Invalidate the session associated with ``token``."""
        self.sessions.invalidate(token)

    def get_user_info(self, token: str) -> Dict[str, Any]:
        """Return profile data for the authenticated user."""
        session = self._require_session(token)
        # VULNERABILITY: If the user was deleted, check_auth returns {} but
        # no ApiError is raised — the ghost session passes _require_session.
        return {"username": session.username, "user_id": session.user_id}

    def update_permission(self, token: str, target_user: str, perms: int) -> None:
        """
        Set permissions for ``target_user`` (admin only).

        VULNERABILITY (CVE-2023-0227): Calls db.set_permission without
        checking whether ``target_user`` exists.  If the target was deleted,
        the UPDATE silently affects 0 rows and the caller sees no error.
        """
        self._require_admin(token)
        # VULNERABILITY: missing →  if not self.db.user_exists(target_user): raise ApiError(...)
        self.db.set_permission(target_user, perms)

    def update_role(self, token: str, target_user: str, role: int) -> None:
        """
        Set the role for ``target_user`` (admin only).

        VULNERABILITY (CVE-2023-0227): Same missing existence check as
        ``update_permission``.
        """
        self._require_admin(token)
        # VULNERABILITY: missing →  if not self.db.user_exists(target_user): raise ApiError(...)
        self.db.set_role(target_user, role)

    def delete_user(self, token: str, target_user: str) -> None:
        """
        Remove ``target_user`` (admin only).

        VULNERABILITY (CVE-2023-0227): Calls db.remove_user without checking
        existence, and does NOT invalidate the deleted user's sessions.
        """
        self._require_admin(token)
        # VULNERABILITY: missing →  self.sessions.invalidate_user(target_user)
        self.db.remove_user(target_user)

    def change_own_password(
        self, token: str, old_password: str, new_password: str
    ) -> bool:
        """Change the authenticated user's own password."""
        session = self._require_session(token)
        return self.db.change_password.__wrapped__(
            self.db, session.username, old_password, new_password
        )

    def list_all_users(self, token: str) -> List[str]:
        """Return a list of all usernames (admin only)."""
        self._require_admin(token)
        return self.db.list_users.__wrapped__(self.db)


# ---------------------------------------------------------------------------
# Demonstration / documentation of the attack chain
# ---------------------------------------------------------------------------


def demonstrate_attack_chain() -> None:
    """
    Walk through the full CVE-2023-0227 attack chain step by step.

    Steps:
      1. Admin creates user "victim".
      2. "victim" logs in and receives session token T.
      3. Admin deletes "victim" via the API (remove_user).
         ↳ Sessions are NOT invalidated (vulnerability).
      4. Attacker (holding token T) calls update_permission on "victim".
         ↳ No error — db.set_permission issues a silent no-op UPDATE.
      5. Attacker calls get_user_info — still succeeds because T is not expired.
      6. Result: ghost session grants continued API access after account deletion.
    """
    print("=" * 60)
    print("CVE-2023-0227 Attack Chain Demonstration")
    print("=" * 60)

    db = DatabaseBackend(":memory:")
    sessions = SessionStore()
    api = UserApi(db, sessions)

    # Step 1: create accounts
    db.add_user.__wrapped__(db, "admin", "adminpass", role=ROLE_ADMIN, perms=PERM_ALL)
    db.add_user.__wrapped__(db, "victim", "victimpass", role=ROLE_USER, perms=PERM_DOWNLOAD)
    print("[1] Created users: admin, victim")

    # Step 2: victim logs in
    victim_token = api.login("victim", "victimpass")
    print(f"[2] Victim logged in, token={victim_token[:16]}...")

    # Step 3: admin deletes victim
    admin_token = api.login("admin", "adminpass")
    api.delete_user(admin_token, "victim")
    remaining = db.list_users.__wrapped__(db)
    print(f"[3] Admin deleted victim. Remaining users: {remaining}")

    # Step 4: ghost session — victim token still accepted
    try:
        info = api.get_user_info(victim_token)
        print(f"[4] Ghost session accepted! user_info={info}")
    except ApiError as e:
        print(f"[4] Session correctly rejected: {e}")

    # Step 5: attacker uses ghost session to call update_permission
    try:
        api.update_permission(victim_token, "victim", PERM_ALL)
        print("[5] set_permission on deleted user silently succeeded (0 rows affected).")
    except ApiError as e:
        print(f"[5] Correctly blocked: {e}")

    print()
    print("RESULT: Without user_exists(), ghost sessions persist and")
    print("        operations on deleted accounts succeed silently.")
    print("=" * 60)

    db.close()


# ---------------------------------------------------------------------------
# Unit-style tests documenting expected (patched) vs actual (vulnerable) behaviour
# ---------------------------------------------------------------------------


def _setup_test_db() -> Tuple[DatabaseBackend, SessionStore, UserApi]:
    db = DatabaseBackend(":memory:")
    sessions = SessionStore()
    api = UserApi(db, sessions)
    db.add_user.__wrapped__(db, "alice", "alicepass", role=ROLE_USER, perms=PERM_DOWNLOAD)
    db.add_user.__wrapped__(db, "admin", "adminpass", role=ROLE_ADMIN, perms=PERM_ALL)
    return db, sessions, api


def test_check_auth_valid_credentials() -> None:
    """check_auth returns user data for correct credentials."""
    db, _, _ = _setup_test_db()
    result = db.check_auth.__wrapped__(db, "alice", "alicepass")
    assert result["name"] == "alice", f"Expected 'alice', got {result}"
    assert result["role"] == ROLE_USER
    print("[PASS] test_check_auth_valid_credentials")
    db.close()


def test_check_auth_wrong_password() -> None:
    """check_auth returns empty dict for wrong password."""
    db, _, _ = _setup_test_db()
    result = db.check_auth.__wrapped__(db, "alice", "wrongpass")
    assert result == {}, f"Expected {{}}, got {result}"
    print("[PASS] test_check_auth_wrong_password")
    db.close()


def test_check_auth_nonexistent_user() -> None:
    """check_auth returns empty dict for non-existent user."""
    db, _, _ = _setup_test_db()
    result = db.check_auth.__wrapped__(db, "nobody", "pass")
    assert result == {}
    print("[PASS] test_check_auth_nonexistent_user")
    db.close()


def test_add_user_duplicate_without_reset() -> None:
    """add_user returns False when user exists and reset=False."""
    db, _, _ = _setup_test_db()
    result = db.add_user.__wrapped__(db, "alice", "newpass", reset=False)
    assert result is False
    print("[PASS] test_add_user_duplicate_without_reset")
    db.close()


def test_add_user_duplicate_with_reset() -> None:
    """add_user returns True and updates credentials when reset=True."""
    db, _, _ = _setup_test_db()
    result = db.add_user.__wrapped__(db, "alice", "newpass", reset=True)
    assert result is True
    auth = db.check_auth.__wrapped__(db, "alice", "newpass")
    assert auth["name"] == "alice"
    print("[PASS] test_add_user_duplicate_with_reset")
    db.close()


def test_change_password_success() -> None:
    """change_password succeeds with correct old password."""
    db, _, _ = _setup_test_db()
    ok = db.change_password.__wrapped__(db, "alice", "alicepass", "newpass")
    assert ok is True
    auth = db.check_auth.__wrapped__(db, "alice", "newpass")
    assert auth["name"] == "alice"
    print("[PASS] test_change_password_success")
    db.close()


def test_change_password_wrong_old() -> None:
    """change_password fails with wrong old password."""
    db, _, _ = _setup_test_db()
    ok = db.change_password.__wrapped__(db, "alice", "wrongold", "newpass")
    assert ok is False
    print("[PASS] test_change_password_wrong_old")
    db.close()


def test_set_permission_on_nonexistent_user_silent() -> None:
    """
    VULNERABILITY TEST: set_permission on a non-existent user silently
    succeeds (0 rows affected, no exception).

    In the patched code this should raise an error or return a failure
    indicator after calling user_exists().
    """
    db, _, _ = _setup_test_db()
    # This should fail loudly in the patched version but succeeds silently here.
    try:
        db.set_permission.__wrapped__(db, "ghost_user", PERM_ALL)
        # No exception raised — silent success is the vulnerability.
        print("[VULNERABLE] test_set_permission_on_nonexistent_user_silent — "
              "no error raised (expected in patched code)")
    except Exception as e:
        print(f"[PASS] test_set_permission_on_nonexistent_user_silent — "
              f"correctly raised: {e}")
    db.close()


def test_set_role_on_nonexistent_user_silent() -> None:
    """
    VULNERABILITY TEST: set_role on a non-existent user silently succeeds.
    """
    db, _, _ = _setup_test_db()
    try:
        db.set_role.__wrapped__(db, "ghost_user", ROLE_ADMIN)
        print("[VULNERABLE] test_set_role_on_nonexistent_user_silent — "
              "no error raised (expected in patched code)")
    except Exception as e:
        print(f"[PASS] test_set_role_on_nonexistent_user_silent — "
              f"correctly raised: {e}")
    db.close()


def test_remove_user_does_not_invalidate_sessions() -> None:
    """
    VULNERABILITY TEST: remove_user does not invalidate active sessions,
    allowing ghost-session attacks (CVE-2023-0227 / CWE-613).
    """
    db, sessions, api = _setup_test_db()
    token = api.login("alice", "alicepass")
    assert sessions.active_count() == 1

    api.delete_user(api.login("admin", "adminpass"), "alice")

    # Session should have been invalidated — but in the vulnerable code it isn't.
    session = sessions.get_session(token)
    if session is not None:
        print(f"[VULNERABLE] test_remove_user_does_not_invalidate_sessions — "
              f"ghost session still active: {session}")
    else:
        print("[PASS] test_remove_user_does_not_invalidate_sessions — "
              "session correctly invalidated")
    db.close()


def test_list_users() -> None:
    """list_users returns all usernames."""
    db, _, _ = _setup_test_db()
    users = db.list_users.__wrapped__(db)
    assert "alice" in users
    assert "admin" in users
    print("[PASS] test_list_users")
    db.close()


def test_get_all_user_data_structure() -> None:
    """get_all_user_data returns a dict keyed by user id."""
    db, _, _ = _setup_test_db()
    data = db.get_all_user_data.__wrapped__(db)
    assert isinstance(data, dict)
    names = {v["name"] for v in data.values()}
    assert "alice" in names
    print("[PASS] test_get_all_user_data_structure")
    db.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demonstrate_attack_chain()
    print()

    test_check_auth_valid_credentials()
    test_check_auth_wrong_password()
    test_check_auth_nonexistent_user()
    test_add_user_duplicate_without_reset()
    test_add_user_duplicate_with_reset()
    test_change_password_success()
    test_change_password_wrong_old()
    test_set_permission_on_nonexistent_user_silent()
    test_set_role_on_nonexistent_user_silent()
    test_remove_user_does_not_invalidate_sessions()
    test_list_users()
    test_get_all_user_data_structure()

    print("\nAll test cases completed.")
