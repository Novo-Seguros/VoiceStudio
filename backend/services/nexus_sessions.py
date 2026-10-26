"""Process-local store for Nexus browser sessions and pending PKCE states.

Same shape as ``services.admin_sessions``: opaque 256-bit tokens indexed by a
keyed hash, bounded capacity, nothing on disk. A restart signs everyone out;
the next sign-in is silent while the Nexus SSO session lives.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import re
import secrets
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from types import ModuleType

from services.admin_sessions import IssuedSession
from services.nexus_auth import NexusIdentity

NEXUS_SESSION_PREFIX = "ovs_nexus_session_"
SESSION_TTL_SECONDS = 8 * 60 * 60
REFRESH_SKEW_SECONDS = 60
ACCESS_GRACE_SECONDS = 300
STATE_TTL_SECONDS = 600
MAX_SESSIONS = 256
MAX_STATES = 512
_TOKEN_BYTES = 32
_TOKEN_RE = re.compile(rf"^{NEXUS_SESSION_PREFIX}[A-Za-z0-9_-]{{43}}$")


@dataclass(frozen=True)
class NexusSessionRecord:
    credential_id: str
    sub: str
    email: str
    name: str
    capabilities: frozenset[str]
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_expires_at: float
    expires_at: float

    def needs_refresh(self, now: float) -> bool:
        return now >= self.access_expires_at - REFRESH_SKEW_SECONDS

    def access_usable(self, now: float) -> bool:
        return now < self.access_expires_at + ACCESS_GRACE_SECONDS


class NexusSessionStore:
    """Thread-safe, process-local store for Nexus sessions and PKCE states."""

    def __init__(
        self,
        *,
        wall_time: Callable[[], float] = time.time,
        token_bytes: Callable[[int], bytes] = secrets.token_bytes,
        pepper: bytes | None = None,
        session_ttl_seconds: int = SESSION_TTL_SECONDS,
        max_sessions: int = MAX_SESSIONS,
        max_states: int = MAX_STATES,
    ) -> None:
        if session_ttl_seconds <= 0 or max_sessions <= 0 or max_states <= 0:
            raise ValueError("session store bounds must be positive")
        self._now = wall_time
        self._token_bytes = token_bytes
        self._pepper = pepper if pepper is not None else secrets.token_bytes(32)
        self._ttl = session_ttl_seconds
        self._max_sessions = max_sessions
        self._max_states = max_states
        self._sessions: OrderedDict[str, NexusSessionRecord] = OrderedDict()
        self._states: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        with self._lock:
            return f"NexusSessionStore(sessions={len(self._sessions)}, states={len(self._states)})"

    def now(self) -> float:
        return self._now()

    def _hash(self, token: str) -> str:
        return hmac.digest(self._pepper, token.encode("utf-8"), "sha256").hex()

    def _drop_locked(self, credential_id: str) -> NexusSessionRecord | None:
        self._locks.pop(credential_id, None)
        return self._sessions.pop(credential_id, None)

    def _purge_locked(self, now: float) -> None:
        # Fixed TTL + insertion order = expiry order, so only the expired
        # prefix needs work.
        while self._sessions:
            credential_id = next(iter(self._sessions))
            if now < self._sessions[credential_id].expires_at:
                break
            self._drop_locked(credential_id)
        while self._states:
            state = next(iter(self._states))
            if now < self._states[state][1]:
                break
            self._states.pop(state)

    def issue(self, identity: NexusIdentity) -> IssuedSession:
        with self._lock:
            now = self._now()
            self._purge_locked(now)
            while len(self._sessions) >= self._max_sessions:
                self._drop_locked(next(iter(self._sessions)))
            raw = self._token_bytes(_TOKEN_BYTES)
            if not isinstance(raw, bytes) or len(raw) != _TOKEN_BYTES:
                raise RuntimeError("token source must return exactly 32 bytes")
            token = NEXUS_SESSION_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            credential_id = self._hash(token)
            expires_at = now + self._ttl
            self._sessions[credential_id] = NexusSessionRecord(
                credential_id=credential_id,
                sub=identity.sub,
                email=identity.email,
                name=identity.name,
                capabilities=identity.capabilities,
                access_token=identity.access_token,
                refresh_token=identity.refresh_token,
                access_expires_at=identity.access_expires_at,
                expires_at=expires_at,
            )
            return IssuedSession(token=token, expires_at=expires_at)

    def get(self, credential_id: str | None) -> NexusSessionRecord | None:
        with self._lock:
            self._purge_locked(self._now())
            return self._sessions.get(credential_id or "")

    def record_for_token(self, token: str | None) -> NexusSessionRecord | None:
        """The live session behind ``token``, whatever its access-token age."""
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            return None
        return self.get(self._hash(token))

    def resolve(self, token: str | None) -> NexusSessionRecord | None:
        """The session behind ``token`` while its Nexus access is honoured."""
        record = self.record_for_token(token)
        if record is None or not record.access_usable(self._now()):
            return None
        return record

    def update_identity(self, credential_id: str, identity: NexusIdentity) -> bool:
        with self._lock:
            record = self._sessions.get(credential_id)
            if record is None:
                return False
            self._sessions[credential_id] = replace(
                record,
                email=identity.email,
                name=identity.name,
                capabilities=identity.capabilities,
                access_token=identity.access_token,
                refresh_token=identity.refresh_token,
                access_expires_at=identity.access_expires_at,
            )
            return True

    def revoke_by_credential(self, credential_id: str | None) -> NexusSessionRecord | None:
        with self._lock:
            return self._drop_locked(credential_id or "")

    def refresh_lock(self, credential_id: str) -> asyncio.Lock:
        with self._lock:
            return self._locks.setdefault(credential_id, asyncio.Lock())

    def save_state(self, state: str, verifier: str) -> None:
        with self._lock:
            now = self._now()
            self._purge_locked(now)
            while len(self._states) >= self._max_states:
                self._states.popitem(last=False)
            self._states[state] = (verifier, now + STATE_TTL_SECONDS)

    def pop_state(self, state: str | None) -> str | None:
        """The verifier saved for ``state``, consumed on first use."""
        with self._lock:
            entry = self._states.pop(state or "", None)
            if entry is None or self._now() >= entry[1]:
                return None
            return entry[0]

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._states.clear()
            self._locks.clear()


_ANCHOR_MODULE_NAME = "_voicestudio_nexus_session_store_anchor"


def _process_store() -> NexusSessionStore:
    """One store per process, however this module was (re)imported — see
    ``services.admin_sessions._process_store`` for why."""
    anchor = sys.modules.get(_ANCHOR_MODULE_NAME)
    if not isinstance(anchor, ModuleType):
        anchor = ModuleType(_ANCHOR_MODULE_NAME)
        anchor.__doc__ = "Process-global anchor for the VoiceStudio Nexus session store."
        sys.modules[_ANCHOR_MODULE_NAME] = anchor
    store = getattr(anchor, "nexus_session_store", None)
    if store is None:
        store = NexusSessionStore()
        anchor.nexus_session_store = store
    return store


nexus_session_store = _process_store()
