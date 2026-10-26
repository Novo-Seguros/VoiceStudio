# Nexus Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Browser users of `https://voicestudio.novoapp.dev` sign in through Nexus (OAuth PKCE) and get `consume`/`admin` from their Nexus role; with no Nexus env vars VoiceStudio behaves exactly as upstream.

**Architecture:** The FastAPI backend is the OAuth client (BFF). Nexus tokens live in a process-local session store; the browser only holds the existing `ov_session` HttpOnly cookie, whose token prefix (`ovs_nexus_session_`) routes it to the new store. A pure-ASGI middleware refreshes expiring Nexus tokens before the auth gates run; another rewrites a loopback peer that carries proxy headers to a non-loopback address. The SPA's `WebAuthGate` gains a `nexus` mode, and a small session component loads the Nexus clock-out reminder (`lembrete.js`, mode B through `/api/nexus-ponto/*`).

**Tech Stack:** FastAPI/Starlette, PyJWT 2.15 (`PyJWKClient`), httpx 0.28 (`MockTransport` in tests), pytest; React 19 + react-i18next + Vitest.

**Spec:** `docs/superpowers/specs/2026-10-26-nexus-auth-design.md`

## Global Constraints

- Mode switch: `NEXUS_CLIENT_ID` non-blank ⇒ Nexus mode on. Also read: `NEXUS_SUPABASE_URL`, `NEXUS_SUPABASE_ANON_KEY`, `NEXUS_API_URL` (base, no `/v1`), `NEXUS_APP_URL` (no trailing slash), `NEXUS_SYSTEM_SLUG` (default `voicestudio`). Missing values with the switch on ⇒ fail closed (`nexus_error=configuracao`, remote requests still gated).
- Nexus mode implies server mode for the admin gates (`_server_mode()` true).
- Permission map: `usar` → `{consume}`; `admin` → `{consume, admin}`; neither ⇒ no session (`sem_acesso`).
- JWT: algorithms `ES256`/`RS256`, `iss = {NEXUS_SUPABASE_URL}/auth/v1`, `aud = NEXUS_APP_URL`, `exp`/`sub` required, `app_metadata.system_slug == NEXUS_SYSTEM_SLUG`; JWKS `{NEXUS_API_URL}/v1/auth/jwks`, cache 600 s.
- Session: prefix `ovs_nexus_session_` + 43 url-safe chars, max 256 sessions, TTL 8 h, refresh when access token expires in < 60 s, transient-failure grace 300 s. PKCE state TTL 600 s, max 512.
- Details (exact strings): `Nexus login required` (401), `Nexus admin permission required` (403).
- Callback error codes: `estado_invalido`, `troca_falhou`, `token_invalido`, `sem_acesso`, `nexus_indisponivel`, `configuracao`, `cancelado`.
- Ponto actions: `situacao`, `registrar`, `dispensar`; timeout 10 s; failure ⇒ `502 {}`; never log body or token.
- Never log tokens. Commits: Conventional Commits, no AI attribution trailers (repo rule `scripts/check_commit_identities.py`).
- Every new UI string goes through i18n in all 21 locales under `electron/src/renderer/src/i18n/locales/`.
- Docs: `docs/nexus-auth.md` (new) linked from `docs/api-auth.md`.

## File Structure

| File | Responsibility |
|---|---|
| `backend/services/nexus_auth.py` (new) | Config, PKCE, permission mapping, JWT verification, Nexus HTTP calls, session refresh |
| `backend/services/nexus_sessions.py` (new) | Process-local Nexus session + PKCE state store |
| `backend/core/nexus_middleware.py` (new) | Proxy-loopback rewrite + lazy refresh ASGI middlewares |
| `backend/api/routers/nexus_auth.py` (new) | `/auth/login`, `/auth/callback`, `/api/auth/nexus/me`, `/api/auth/nexus/logout`, `/api/nexus-ponto/{acao}` |
| `backend/core/auth.py` | `PrincipalKind.NEXUS_SESSION`, prefix dispatch, `presented_session_token` |
| `backend/api/dependencies.py` | capability-aware admin checks, Nexus 403 detail, server mode |
| `backend/main.py` | router registration, public paths, Bearer gate in Nexus mode, middleware wiring, CSP injection |
| `backend/core/spa_inject.py` | `allow_script_origin` |
| `electron/src/renderer/src/lib/api/client.ts` | `nexus` auth mode |
| `electron/src/renderer/src/components/web-auth-gate.tsx` | Nexus sign-in card |
| `electron/src/renderer/src/components/nexus-session.tsx` (new) | `/me`, reminder script, sign-out button |
| `electron/src/renderer/src/app.tsx`, `components/app-shell/workspace-sidebar.tsx` | mount points |
| `tests/test_nexus_auth_core.py`, `tests/test_nexus_sessions.py`, `tests/test_nexus_auth_flow.py` (new) | backend tests |
| `electron/src/renderer/src/components/web-auth-gate.test.tsx` (new) | gate test |

---

### Task 1: Nexus core (config, PKCE, permissions, JWT)

**Files:**
- Create: `backend/services/nexus_auth.py`
- Test: `tests/test_nexus_auth_core.py`

**Interfaces — Produces:**
- `nexus_enabled() -> bool`
- `load_config() -> NexusConfig` (raises `NexusConfigError`); `NexusConfig` fields `client_id, supabase_url, anon_key, api_url, app_url, system_slug`; properties `issuer, redirect_uri, authorize_url, token_url, jwks_url, logout_url, api_origin, ponto_script_url`; method `ponto_url(acao)`
- `pkce_pair() -> tuple[str, str]` (verifier, S256 challenge)
- `authorize_redirect(config, state, challenge) -> str`
- `capabilities_from_claims(claims: dict, system_slug: str) -> frozenset[str]`
- `verify_access_token(token, config, key_resolver=None) -> dict` (raises `NexusTokenError` / `NexusUnavailable`)
- `NexusIdentity` dataclass: `sub, email, name, capabilities, access_token, refresh_token, access_expires_at`
- `identity_from_tokens(config, tokens: dict, key_resolver=None) -> NexusIdentity` (raises `NexusForbidden` when no capability)
- Test seams: `set_key_resolver(fn | None)`, `set_transport(httpx.AsyncBaseTransport | None)`
- Exceptions: `NexusConfigError`, `NexusTokenError`, `NexusUnavailable`, `NexusRejected`, `NexusForbidden`

- [ ] **Step 1: Write failing tests** — `tests/test_nexus_auth_core.py` covering: `nexus_enabled` on/off/blank; `load_config` trims trailing slashes and raises on a missing var; `pkce_pair` challenge = b64url(sha256(verifier)) without padding; `authorize_redirect` carries `response_type=code`, `client_id`, `redirect_uri`, `code_challenge_method=S256`, `state`, `scope=openid email profile`; `capabilities_from_claims` for `"usar"`, `"usar|admin"`, `"admin"`, `""`, per-system dict, unknown slugs; `verify_access_token` accepts a token signed with a generated P-256 key and rejects wrong `aud`, wrong `iss`, expired, wrong `system_slug`, bad signature; `identity_from_tokens` raises `NexusForbidden` with no capability and builds name from `user_metadata.first_name/last_name`.

Helper used by every backend test file (inline in each file):

```python
from cryptography.hazmat.primitives.asymmetric import ec
import jwt, time

NEXUS_ENV = {
    "NEXUS_CLIENT_ID": "client-123",
    "NEXUS_SUPABASE_URL": "https://nexus-auth.example",
    "NEXUS_SUPABASE_ANON_KEY": "anon",
    "NEXUS_API_URL": "https://nexus.example",
    "NEXUS_APP_URL": "https://voicestudio.example",
}
_KEY = ec.generate_private_key(ec.SECP256R1())

def make_token(perms="usar", *, aud="https://voicestudio.example",
               iss="https://nexus-auth.example/auth/v1", slug="voicestudio",
               exp_in=3600, key=_KEY, sub="11111111-1111-1111-1111-111111111111"):
    now = int(time.time())
    return jwt.encode({
        "sub": sub, "email": "ana@novoseguros.com.br", "aud": aud, "iss": iss,
        "iat": now, "exp": now + exp_in,
        "app_metadata": {"permissions": perms, "system_slug": slug},
        "user_metadata": {"first_name": "Ana", "last_name": "Lima"},
    }, key, algorithm="ES256")

def resolver(_token):
    return _KEY.public_key()
```

- [ ] **Step 2: Run** `uv run pytest tests/test_nexus_auth_core.py -q` — expect ImportError.
- [ ] **Step 3: Implement `backend/services/nexus_auth.py`** (config, PKCE, mapping, verification; HTTP functions land in Task 4 but the `set_transport` seam and `_client()` are defined here):

```python
"""Nexus single sign-on for the Novo Seguros web deployment.

Inert unless ``NEXUS_CLIENT_ID`` is set. The backend is the OAuth client: it
runs the PKCE flow, keeps the Nexus tokens in process memory and hands the
browser only the opaque ``ov_session`` cookie. See docs/nexus-auth.md.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

DEFAULT_SYSTEM_SLUG = "voicestudio"
JWKS_CACHE_SECONDS = 600
HTTP_TIMEOUT_SECONDS = 10.0
PERMISSION_CAPABILITIES: dict[str, frozenset[str]] = {
    "usar": frozenset({"consume"}),
    "admin": frozenset({"consume", "admin"}),
}
_ALGORITHMS = ["ES256", "RS256"]


class NexusConfigError(RuntimeError):
    """Nexus mode is on but its configuration is incomplete."""


class NexusTokenError(ValueError):
    """A Nexus token failed verification."""


class NexusUnavailable(RuntimeError):
    """Nexus could not be reached or answered 5xx."""


class NexusRejected(RuntimeError):
    """Nexus definitively refused a grant (4xx)."""


class NexusForbidden(RuntimeError):
    """The token is valid but grants no VoiceStudio capability."""


def nexus_enabled() -> bool:
    return bool(os.environ.get("NEXUS_CLIENT_ID", "").strip())


def _env_url(name: str) -> str:
    value = os.environ.get(name, "").strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise NexusConfigError(f"{name} must be an absolute http(s) URL")
    return value


@dataclass(frozen=True)
class NexusConfig:
    client_id: str
    supabase_url: str
    anon_key: str = field(repr=False)
    api_url: str
    app_url: str
    system_slug: str

    @property
    def issuer(self) -> str:
        return f"{self.supabase_url}/auth/v1"

    @property
    def redirect_uri(self) -> str:
        return f"{self.app_url}/auth/callback"

    @property
    def authorize_url(self) -> str:
        return f"{self.supabase_url}/auth/v1/oauth/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.supabase_url}/auth/v1/oauth/token"

    @property
    def jwks_url(self) -> str:
        return f"{self.api_url}/v1/auth/jwks"

    @property
    def logout_url(self) -> str:
        return f"{self.api_url}/v1/auth/logout"

    @property
    def api_origin(self) -> str:
        parts = urlsplit(self.api_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def ponto_script_url(self) -> str:
        return f"{self.api_url}/v1/ponto/saida/lembrete.js"

    def ponto_url(self, acao: str) -> str:
        return f"{self.api_url}/v1/ponto/saida/{acao}"


def load_config() -> NexusConfig:
    client_id = os.environ.get("NEXUS_CLIENT_ID", "").strip()
    anon_key = os.environ.get("NEXUS_SUPABASE_ANON_KEY", "").strip()
    if not client_id or not anon_key:
        raise NexusConfigError("NEXUS_CLIENT_ID and NEXUS_SUPABASE_ANON_KEY are required")
    return NexusConfig(
        client_id=client_id,
        supabase_url=_env_url("NEXUS_SUPABASE_URL"),
        anon_key=anon_key,
        api_url=_env_url("NEXUS_API_URL"),
        app_url=_env_url("NEXUS_APP_URL"),
        system_slug=os.environ.get("NEXUS_SYSTEM_SLUG", "").strip() or DEFAULT_SYSTEM_SLUG,
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def authorize_redirect(config: NexusConfig, state: str, challenge: str) -> str:
    query = urlencode({
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": "openid email profile",
    })
    return f"{config.authorize_url}?{query}"


def capabilities_from_claims(claims: dict, system_slug: str) -> frozenset[str]:
    app_metadata = claims.get("app_metadata") or {}
    raw = app_metadata.get("permissions") if isinstance(app_metadata, dict) else None
    if isinstance(raw, dict):
        raw = raw.get(system_slug)
    if not isinstance(raw, str):
        return frozenset()
    capabilities: set[str] = set()
    for permission in raw.split("|"):
        capabilities |= PERMISSION_CAPABILITIES.get(permission.strip(), frozenset())
    return frozenset(capabilities)


KeyResolver = Callable[[str], object]
_key_resolver_override: KeyResolver | None = None
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def set_key_resolver(resolver: KeyResolver | None) -> None:
    """Test seam: replace JWKS lookups with a fixed key resolver."""
    global _key_resolver_override
    _key_resolver_override = resolver


def _jwks_resolver(config: NexusConfig) -> KeyResolver:
    client = _jwks_clients.get(config.jwks_url)
    if client is None:
        client = jwt.PyJWKClient(
            config.jwks_url, cache_jwk_set=True, lifespan=JWKS_CACHE_SECONDS,
            timeout=int(HTTP_TIMEOUT_SECONDS),
        )
        _jwks_clients[config.jwks_url] = client
    return lambda token: client.get_signing_key_from_jwt(token).key


def verify_access_token(token: str, config: NexusConfig, key_resolver: KeyResolver | None = None) -> dict:
    resolver = key_resolver or _key_resolver_override or _jwks_resolver(config)
    try:
        key = resolver(token)
    except jwt.PyJWKClientConnectionError as exc:
        raise NexusUnavailable("JWKS unreachable") from exc
    except jwt.PyJWTError as exc:
        raise NexusTokenError("signing key not found") from exc
    try:
        claims = jwt.decode(
            token, key, algorithms=_ALGORITHMS, audience=config.app_url,
            issuer=config.issuer, options={"require": ["exp", "sub", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise NexusTokenError(type(exc).__name__) from exc
    app_metadata = claims.get("app_metadata") or {}
    if not isinstance(app_metadata, dict) or app_metadata.get("system_slug") != config.system_slug:
        raise NexusTokenError("system_slug mismatch")
    return claims


@dataclass(frozen=True)
class NexusIdentity:
    sub: str
    email: str
    name: str
    capabilities: frozenset[str]
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    access_expires_at: float


def identity_from_tokens(config: NexusConfig, tokens: dict, key_resolver: KeyResolver | None = None) -> NexusIdentity:
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not isinstance(refresh_token, str) or not refresh_token:
        raise NexusTokenError("token response incomplete")
    claims = verify_access_token(access_token, config, key_resolver)
    capabilities = capabilities_from_claims(claims, config.system_slug)
    if not capabilities:
        raise NexusForbidden("no VoiceStudio permission")
    metadata = claims.get("user_metadata") or {}
    name = " ".join(
        str(part).strip() for part in (metadata.get("first_name"), metadata.get("last_name"))
        if isinstance(part, str) and part.strip()
    )
    return NexusIdentity(
        sub=str(claims["sub"]),
        email=str(claims.get("email") or ""),
        name=name,
        capabilities=capabilities,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_at=float(claims["exp"]),
    )


_transport: httpx.AsyncBaseTransport | None = None


def set_transport(transport: httpx.AsyncBaseTransport | None) -> None:
    """Test seam: route every Nexus HTTP call through ``transport``."""
    global _transport
    _transport = transport


def _client(timeout: float = HTTP_TIMEOUT_SECONDS) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_transport, timeout=timeout, follow_redirects=False)
```

- [ ] **Step 4: Run** `uv run pytest tests/test_nexus_auth_core.py -q` — PASS.
- [ ] **Step 5: Commit** `feat(nexus): token verification and permission mapping`

### Task 2: Session + PKCE state store

**Files:**
- Create: `backend/services/nexus_sessions.py`
- Test: `tests/test_nexus_sessions.py`

**Interfaces:**
- Consumes: `NexusIdentity` (Task 1).
- Produces: `NEXUS_SESSION_PREFIX = "ovs_nexus_session_"`, `NexusSessionRecord` (`credential_id, sub, email, name, capabilities, access_token, refresh_token, access_expires_at, expires_at`, methods `needs_refresh(now)`, `access_usable(now)`), `NexusSessionStore` with `issue(identity) -> IssuedSession`, `resolve(token) -> record|None` (respects access grace), `record_for_token(token)` (ignores access grace), `get(credential_id)`, `update_identity(credential_id, identity) -> bool`, `revoke_by_credential(credential_id) -> record|None`, `refresh_lock(credential_id) -> asyncio.Lock`, `save_state(state, verifier)`, `pop_state(state) -> str|None`, `clear()`; module global `nexus_session_store` (process-anchored like `admin_session_store`).

- [ ] **Step 1: Failing tests** — issue/resolve roundtrip; malformed or admin-prefixed tokens resolve to `None`; TTL expiry (inject `wall_time`); `resolve` returns `None` once `now > access_expires_at + 300` while `record_for_token` still returns it; `needs_refresh` at `exp - 59`; `update_identity` swaps tokens/capabilities and keeps `expires_at`; `revoke_by_credential` returns the record and removes it; capacity eviction drops the oldest; `pop_state` single-use and expires after 600 s; `refresh_lock` returns the same lock per credential; `repr` never contains tokens.
- [ ] **Step 2: Run** `uv run pytest tests/test_nexus_sessions.py -q` — fail.
- [ ] **Step 3: Implement**

```python
"""Process-local store for Nexus browser sessions and pending PKCE states.

Same shape as ``services.admin_sessions``: opaque 256-bit tokens indexed by a
keyed hash, bounded capacity, nothing on disk. A restart signs everyone out;
the next sign-in is silent while the Nexus SSO session lives.
"""

from __future__ import annotations

import asyncio
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
_TOKEN_RE = re.compile(r"^ovs_nexus_session_[A-Za-z0-9_-]{43}$")


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

    def _hash(self, token: str) -> str:
        return hmac.digest(self._pepper, token.encode("utf-8"), "sha256").hex()

    def _purge_locked(self, now: float) -> None:
        for credential_id in [c for c, r in self._sessions.items() if now >= r.expires_at]:
            self._drop_locked(credential_id)
        for state in [s for s, (_, exp) in self._states.items() if now >= exp]:
            self._states.pop(state, None)

    def _drop_locked(self, credential_id: str) -> NexusSessionRecord | None:
        self._locks.pop(credential_id, None)
        return self._sessions.pop(credential_id, None)

    def issue(self, identity: NexusIdentity) -> IssuedSession:
        with self._lock:
            now = self._now()
            self._purge_locked(now)
            while len(self._sessions) >= self._max_sessions:
                self._drop_locked(next(iter(self._sessions)))
            raw = self._token_bytes(32)
            token = NEXUS_SESSION_PREFIX + secrets.base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            credential_id = self._hash(token)
            expires_at = now + self._ttl
            self._sessions[credential_id] = NexusSessionRecord(
                credential_id=credential_id, sub=identity.sub, email=identity.email,
                name=identity.name, capabilities=identity.capabilities,
                access_token=identity.access_token, refresh_token=identity.refresh_token,
                access_expires_at=identity.access_expires_at, expires_at=expires_at,
            )
            return IssuedSession(token=token, expires_at=expires_at)

    def record_for_token(self, token: str | None) -> NexusSessionRecord | None:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            return None
        return self.get(self._hash(token))

    def get(self, credential_id: str | None) -> NexusSessionRecord | None:
        with self._lock:
            self._purge_locked(self._now())
            return self._sessions.get(credential_id or "")

    def resolve(self, token: str | None) -> NexusSessionRecord | None:
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
                record, email=identity.email, name=identity.name,
                capabilities=identity.capabilities, access_token=identity.access_token,
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
        sys.modules[_ANCHOR_MODULE_NAME] = anchor
    store = getattr(anchor, "nexus_session_store", None)
    if store is None:
        store = NexusSessionStore()
        anchor.nexus_session_store = store
    return store


nexus_session_store = _process_store()
```

(Use `import base64` and `base64.urlsafe_b64encode` instead of `secrets.base64` — `secrets` does not export it.)

- [ ] **Step 4: Run** tests — PASS.
- [ ] **Step 5: Commit** `feat(nexus): process-local session store`

### Task 3: Auth core wiring (principal, gates, proxy, refresh middleware)

**Files:**
- Modify: `backend/core/auth.py`, `backend/api/dependencies.py`, `backend/main.py` (BearerKeyMiddleware, `_is_public_path`, middleware registration)
- Create: `backend/core/nexus_middleware.py`
- Test: `tests/test_nexus_auth_flow.py` (gate part; flow tests are added in Task 4)

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: `PrincipalKind.NEXUS_SESSION`; `core.auth.presented_session_token(connection) -> str`; `refresh_session(record) -> NexusSessionRecord | None` in `services/nexus_auth.py` (async, defined here because the middleware needs it; `refresh_tokens` HTTP call defined in this task too); `ProxyLoopbackMiddleware`, `NexusRefreshMiddleware`.

Changes:

1. `core/auth.py`:
   - add `NEXUS_SESSION = "nexus_session"` to `PrincipalKind`;
   - `_active_nexus_store()` mirroring `_active_admin_session_store()` (`importlib.import_module("services.nexus_sessions").nexus_session_store`);
   - in `_candidate_principal`, before the admin `elif candidate.allow_session` branch:

```python
    elif candidate.allow_session and candidate.value.startswith(NEXUS_SESSION_PREFIX):
        if nexus_enabled():
            record = _active_nexus_store().resolve(candidate.value)
            if record is not None:
                principal = AuthPrincipal(
                    PrincipalKind.NEXUS_SESSION,
                    record.capabilities,
                    credential_id=record.credential_id,
                    transport=candidate.transport,
                )
```

   (`NEXUS_SESSION_PREFIX` is a plain string constant imported from `services.nexus_sessions`; `nexus_enabled` from `services.nexus_auth`. The existing `allow_master` branch runs first, so an API key still wins.)
   - `presented_session_token(connection)` returns `candidate.value` when the candidate allows sessions, else `""`.
   - `presents_valid_credential` keeps working (it calls `_candidate_principal`).

2. `api/dependencies.py`:
   - `_server_mode()` returns `True` when `nexus_enabled()` too;
   - `_admin_credential_configured`: `True` when `remote_api_key() or nexus_enabled()`;
   - `_request_presents_admin_credential`: accept `NEXUS_SESSION` only when `principal.allows("admin")`;
   - `ws_remote_authorized`: also `True` for `NEXUS_SESSION` with `consume`;
   - `_admin_gate_403(request=None)`: if the principal is `NEXUS_SESSION` → detail `"Nexus admin permission required"`; callers pass `request`.

3. `main.py`:
   - `_is_public_path`: add `path in {"/auth/login", "/auth/callback"}`;
   - `BearerKeyMiddleware.__call__`: `nexus = nexus_enabled()`; inert only when `not key and not nexus`; allowed kinds add `PrincipalKind.NEXUS_SESSION`; 401 detail `"Nexus login required" if nexus else "API key required"`;
   - register `NexusRefreshMiddleware` right after `BearerKeyMiddleware` and `ProxyLoopbackMiddleware` right after `BrowserGuardMiddleware`.

4. `core/nexus_middleware.py`:

```python
"""ASGI middlewares for Nexus mode. Both are inert unless NEXUS_CLIENT_ID is set."""

from __future__ import annotations

from starlette.requests import HTTPConnection

from core.auth import is_loopback, presented_session_token
from services.nexus_auth import nexus_enabled, refresh_session
from services.nexus_sessions import NEXUS_SESSION_PREFIX, nexus_session_store

_FORWARDING_HEADERS = (b"cf-connecting-ip", b"x-forwarded-for", b"x-real-ip", b"forwarded")


class ProxyLoopbackMiddleware:
    """A loopback peer that carries proxy headers is a relayed remote client.

    Uvicorn already rewrites the client from X-Forwarded-For for trusted
    proxies; this is the fail-closed backstop for a relay whose forwarded
    address is missing or claims loopback itself.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and nexus_enabled():
            client = scope.get("client")
            if client and is_loopback(client[0]):
                names = {name.lower() for name, _ in scope.get("headers", [])}
                if any(header in names for header in _FORWARDING_HEADERS):
                    scope = dict(scope, client=("0.0.0.0", client[1]))
        return await self.app(scope, receive, send)


class NexusRefreshMiddleware:
    """Refresh an expiring Nexus access token before the auth gates run."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and nexus_enabled():
            token = presented_session_token(HTTPConnection(scope))
            if token.startswith(NEXUS_SESSION_PREFIX):
                record = nexus_session_store.record_for_token(token)
                if record is not None and record.needs_refresh(nexus_session_store.now()):
                    await refresh_session(record)
        return await self.app(scope, receive, send)
```

   (Add a public `now()` method to `NexusSessionStore` returning `self._now()`.)

5. `services/nexus_auth.py` — add:

```python
async def _post_token(config: NexusConfig, form: dict[str, str]) -> dict:
    try:
        async with _client() as client:
            response = await client.post(
                config.token_url, data={**form, "client_id": config.client_id},
                headers={"apikey": config.anon_key},
            )
    except httpx.HTTPError as exc:
        raise NexusUnavailable("token endpoint unreachable") from exc
    if response.status_code >= 500:
        raise NexusUnavailable(f"token endpoint {response.status_code}")
    if response.status_code != 200:
        raise NexusRejected(f"token endpoint {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise NexusUnavailable("token endpoint returned non-JSON") from exc
    if not isinstance(payload, dict):
        raise NexusUnavailable("token endpoint returned non-object")
    return payload


async def exchange_code(config: NexusConfig, code: str, verifier: str) -> dict:
    return await _post_token(config, {
        "grant_type": "authorization_code", "code": code,
        "code_verifier": verifier, "redirect_uri": config.redirect_uri,
    })


async def refresh_tokens(config: NexusConfig, refresh_token: str) -> dict:
    return await _post_token(config, {"grant_type": "refresh_token", "refresh_token": refresh_token})


async def identity_from_tokens_async(config: NexusConfig, tokens: dict) -> NexusIdentity:
    # JWKS lookups block on the network at most once per cache window.
    return await asyncio.to_thread(identity_from_tokens, config, tokens)


async def refresh_session(record):
    from services.nexus_sessions import nexus_session_store as store

    async with store.refresh_lock(record.credential_id):
        current = store.get(record.credential_id)
        if current is None or not current.needs_refresh(store.now()):
            return current
        try:
            config = load_config()
            identity = await identity_from_tokens_async(config, await refresh_tokens(config, current.refresh_token))
        except NexusUnavailable:
            return current
        except (NexusRejected, NexusTokenError, NexusForbidden, NexusConfigError):
            store.revoke_by_credential(current.credential_id)
            logger.info("nexus session ended at refresh")
            return None
        store.update_identity(current.credential_id, identity)
        return store.get(current.credential_id)
```

   (`import asyncio, logging`; `logger = logging.getLogger("omnivoice.nexus")`.)

- [ ] **Step 1: Failing tests** in `tests/test_nexus_auth_flow.py` (fixture `nexus_env` sets `NEXUS_ENV` + `OMNIVOICE_DISABLE_FILE_LOG`, calls `set_key_resolver(resolver)`, clears `nexus_session_store`; teardown resets seams). Seed a session directly with `nexus_session_store.issue(identity_from_tokens(load_config(), {"access_token": make_token(perms), "refresh_token": "r1"}, resolver))` and set the cookie `ov_session`:
  - anonymous remote `GET /v1/audio/voices` → 401 `Nexus login required`;
  - `usar` session → `GET /v1/audio/voices` 200; `GET /api/settings/performance-profile` → 403 `Nexus admin permission required`;
  - `usar|admin` session → `GET /api/settings/performance-profile` 200;
  - API key still works in Nexus mode (`Authorization: Bearer <key>` with `OMNIVOICE_API_KEY` set);
  - loopback client with header `CF-Connecting-IP: 1.2.3.4` and no cookie → 401;
  - plain loopback without proxy headers → 200 (unchanged);
  - expired access token + `MockTransport` returning new tokens → request passes and the store holds the rotated refresh token;
  - refresh answered 400 → 401 and the session is gone;
  - refresh unreachable within grace → request passes;
  - Nexus disabled: `GET /auth/login` → 404 and remote `GET /v1/audio/voices` → 200 (gate inert).
- [ ] **Step 2: Run** `uv run pytest tests/test_nexus_auth_flow.py -q` — fail.
- [ ] **Step 3: Implement** the changes above.
- [ ] **Step 4: Run** the new file plus `tests/test_bearer_middleware.py tests/test_auth_principal.py tests/test_loopback_server_mode.py tests/test_auth_gate_detail_lockstep.py tests/test_auth_session_api.py tests/test_network_middleware.py tests/test_browser_guard.py tests/test_admin_sessions.py` — all PASS.
- [ ] **Step 5: Commit** `feat(nexus): Nexus sessions in the auth gates`

### Task 4: OAuth routes, logout, ponto proxy

**Files:**
- Create: `backend/api/routers/nexus_auth.py`
- Modify: `backend/main.py` (add module to `_router_modules`), `backend/services/nexus_auth.py` (logout + ponto HTTP)
- Test: `tests/test_nexus_auth_flow.py`

**Interfaces:**
- Consumes: Tasks 1–3; `api.routers.auth._set_session_cookie`, `_expire_cookie`, `_secure_cookie`.
- Produces: routes in the spec; `revoke_refresh_token(config, refresh_token) -> None`, `forward_ponto(config, acao, access_token, body, user_agent) -> tuple[int, object]`.

```python
"""Nexus sign-in routes (Novo Seguros fork). All 404 unless Nexus mode is on."""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from api.routers.auth import _expire_cookie, _secure_cookie, _set_session_cookie
from core.auth import CredentialTransport, PrincipalKind, principal_for
from core.csrf import cookie_csrf_allowed
from services import nexus_auth as nexus
from services.nexus_sessions import STATE_TTL_SECONDS, nexus_session_store as store

router = APIRouter(include_in_schema=False)
logger = logging.getLogger("omnivoice.nexus")

STATE_COOKIE = "ov_nexus_state"
PONTO_ACTIONS = frozenset({"situacao", "registrar", "dispensar"})
MAX_PONTO_BODY_BYTES = 16 * 1024


def _require_enabled() -> None:
    if not nexus.nexus_enabled():
        raise HTTPException(status_code=404)


def _fail(request: Request, code: str) -> RedirectResponse:
    response = RedirectResponse(f"/?nexus_error={code}", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/auth", secure=_secure_cookie(request), httponly=True, samesite="lax")
    return response


def _session(request: Request):
    principal = principal_for(request)
    if principal.kind is not PrincipalKind.NEXUS_SESSION:
        raise HTTPException(status_code=401, detail="Nexus login required")
    record = store.get(principal.credential_id)
    if record is None:
        raise HTTPException(status_code=401, detail="Nexus login required")
    return principal, record


@router.get("/auth/login")
def login(request: Request) -> Response:
    _require_enabled()
    try:
        config = nexus.load_config()
    except nexus.NexusConfigError:
        logger.error("Nexus mode is on but its configuration is incomplete")
        return _fail(request, "configuracao")
    state = secrets.token_urlsafe(32)
    verifier, challenge = nexus.pkce_pair()
    store.save_state(state, verifier)
    response = RedirectResponse(nexus.authorize_redirect(config, state, challenge), status_code=303)
    response.set_cookie(
        STATE_COOKIE, state, max_age=STATE_TTL_SECONDS, path="/auth",
        secure=_secure_cookie(request), httponly=True, samesite="lax",
    )
    return response


@router.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = "") -> Response:
    _require_enabled()
    verifier = store.pop_state(state) if state else None
    if error:
        return _fail(request, "cancelado")
    cookie_state = request.cookies.get(STATE_COOKIE, "")
    if not code or verifier is None or not cookie_state or not secrets.compare_digest(state, cookie_state):
        return _fail(request, "estado_invalido")
    try:
        config = nexus.load_config()
        tokens = await nexus.exchange_code(config, code, verifier)
        identity = await nexus.identity_from_tokens_async(config, tokens)
    except nexus.NexusConfigError:
        return _fail(request, "configuracao")
    except nexus.NexusUnavailable:
        return _fail(request, "nexus_indisponivel")
    except nexus.NexusRejected:
        return _fail(request, "troca_falhou")
    except nexus.NexusForbidden:
        return _fail(request, "sem_acesso")
    except nexus.NexusTokenError:
        return _fail(request, "token_invalido")
    issued = store.issue(identity)
    logger.info("nexus sign-in sub=%s", identity.sub)
    response = _fail(request, "")  # reuse the state-cookie deletion
    response.headers["location"] = "/"
    _set_session_cookie(response, request, issued.token, issued.expires_at)
    return response


@router.get("/api/auth/nexus/me")
def me(request: Request) -> dict:
    _require_enabled()
    _principal, record = _session(request)
    config = nexus.load_config()
    return {
        "email": record.email,
        "name": record.name,
        "admin": "admin" in record.capabilities,
        "system": config.system_slug,
        "ponto_script": config.ponto_script_url,
    }


@router.post("/api/auth/nexus/logout", status_code=204)
async def logout(request: Request) -> Response:
    _require_enabled()
    principal = principal_for(request)
    if principal.kind is PrincipalKind.NEXUS_SESSION:
        if principal.transport is CredentialTransport.COOKIE and not cookie_csrf_allowed(request):
            raise HTTPException(status_code=403, detail="browser origin rejected")
        record = store.revoke_by_credential(principal.credential_id)
        if record is not None:
            await nexus.revoke_refresh_token(nexus.load_config(), record.refresh_token)
    response = Response(status_code=204)
    _expire_cookie(response, request, "ov_session")
    return response


@router.post("/api/nexus-ponto/{acao}")
async def ponto(acao: str, request: Request) -> JSONResponse:
    _require_enabled()
    if acao not in PONTO_ACTIONS:
        raise HTTPException(status_code=404)
    _principal, record = _session(request)
    if record.needs_refresh(store.now()):
        record = await nexus.refresh_session(record)
        if record is None:
            raise HTTPException(status_code=401, detail="Nexus login required")
    body = await request.body()
    if len(body) > MAX_PONTO_BODY_BYTES:
        raise HTTPException(status_code=413)
    status, payload = await nexus.forward_ponto(
        nexus.load_config(), acao, record.access_token, body,
        request.headers.get("user-agent", ""),
    )
    return JSONResponse(payload, status_code=status)
```

(Write `callback`'s success response explicitly — `RedirectResponse("/", 303)`, delete `STATE_COOKIE`, set `ov_session` — instead of the `_fail` reuse shown; the reuse is only a sketch.)

`services/nexus_auth.py` additions:

```python
async def revoke_refresh_token(config: NexusConfig, refresh_token: str) -> None:
    """Best-effort server-side revocation; local sign-out never waits on it."""
    try:
        async with _client(timeout=5.0) as client:
            await client.post(config.logout_url, json={"refresh_token": refresh_token})
    except httpx.HTTPError:
        logger.info("nexus logout revocation failed")


async def forward_ponto(config: NexusConfig, acao: str, access_token: str, body: bytes, user_agent: str) -> tuple[int, object]:
    try:
        async with _client() as client:
            response = await client.post(
                config.ponto_url(acao), content=body or b"{}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "User-Agent": user_agent,
                },
            )
        return response.status_code, response.json()
    except (httpx.HTTPError, ValueError):
        return 502, {}
```

- [ ] **Step 1: Failing tests** (MockTransport handler routes by URL: token endpoint returns `{"access_token": make_token(...), "refresh_token": "r1"}`; logout records the body; ponto echoes `{"mostrar": false}` with 201):
  - `/auth/login` → 303 to `https://nexus-auth.example/auth/v1/oauth/authorize?...` with `client_id=client-123`, `redirect_uri=https%3A%2F%2Fvoicestudio.example%2Fauth%2Fcallback`, sets `ov_nexus_state`;
  - full flow: login → callback with the same `state` → 303 `/`, `ov_session` starts with `ovs_nexus_session_`, then `GET /api/auth/nexus/me` → `{"email": "ana@novoseguros.com.br", "name": "Ana Lima", "admin": false, "system": "voicestudio", "ponto_script": "https://nexus.example/v1/ponto/saida/lembrete.js"}`;
  - callback with wrong/reused state → `/?nexus_error=estado_invalido`; `error=access_denied` → `cancelado`; token endpoint 400 → `troca_falhou`; 503 → `nexus_indisponivel`; token without permissions → `sem_acesso`; wrong audience → `token_invalido`;
  - `/api/auth/nexus/me` anonymous remote → 401 `Nexus login required`;
  - logout with `X-VoiceStudio-CSRF: 1` and same origin → 204, cookie expired, Nexus logout got `{"refresh_token": "r1"}`, next `/me` → 401; logout without CSRF header → 403;
  - ponto: `situacao` forwards body and Bearer token, returns Nexus status + JSON; `foo` → 404; anonymous → 401; transport raising `httpx.ConnectError` → 502 `{}`.
- [ ] **Step 2: Run** — fail. **Step 3: Implement**, register `nexus_auth` in `_router_modules` (import `nexus_auth as nexus_auth_router` beside `auth as auth_router`). **Step 4: Run** the Task 3 test list again — PASS.
- [ ] **Step 5: Commit** `feat(nexus): sign-in, sign-out and clock-out reminder proxy routes`

### Task 5: CSP for the reminder script

**Files:**
- Modify: `backend/core/spa_inject.py`, `backend/main.py` (index routes)
- Test: `tests/test_spa_inject_nexus.py`

- [ ] **Step 1: Failing tests** — `allow_script_origin(doc, "https://nexus.example")` turns `script-src 'self'` into `script-src 'self' https://nexus.example` once; composes with `inject_api_base` (both hashes/origins present); invalid origin (`javascript:x`, path, quote) leaves the doc unchanged. App-level: with Nexus env and a temp `OMNIVOICE_FRONTEND_DIST` containing the renderer `index.html`, `GET /` HTML contains `script-src 'self' https://nexus.example`.
- [ ] **Step 2: Run** — fail.
- [ ] **Step 3: Implement**

```python
_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(?::\d{1,5})?$")


def allow_script_origin(html_doc: str, origin: str) -> str:
    """Allow one exact external script origin (the Nexus clock-out reminder)."""
    if not _ORIGIN_RE.match(origin or ""):
        return html_doc
    return html_doc.replace("script-src 'self'", f"script-src 'self' {origin}", 1)
```

`main.py`: compute `_nexus_script_origin` (`load_config().api_origin` when `nexus_enabled()`, `""` on `NexusConfigError`); register the `/` and `/index.html` routes when `_public_api_base or _nexus_script_origin`, rendering `inject_api_base` (if base) then `allow_script_origin` (if origin).
- [ ] **Step 4: Run** new test + `tests/test_spa_inject*.py` — PASS.
- [ ] **Step 5: Commit** `feat(nexus): allow the reminder script origin in the served CSP`

### Task 6: Web UI (gate, session, sign-out, i18n)

**Files:**
- Modify: `electron/src/renderer/src/lib/api/client.ts` (mode detection), `electron/src/renderer/src/components/web-auth-gate.tsx`, `electron/src/renderer/src/app.tsx`, `electron/src/renderer/src/components/app-shell/workspace-sidebar.tsx`
- Create: `electron/src/renderer/src/components/nexus-session.tsx`, `electron/src/renderer/src/components/web-auth-gate.test.tsx`
- Modify: all 21 `electron/src/renderer/src/i18n/locales/*.json` (new `nexus` object)

Behaviour:
- `client.ts`: `const mode = detail.includes('nexus login') ? 'nexus' : detail.includes('api key') ? 'apikey' : 'pin';` (`nexus` never clears an admin session).
- `WebAuthGate`: `AuthMode = 'apikey' | 'pin' | 'nexus'`; on mount read `nexus_error` from `window.location.search`, remove it with `history.replaceState`, and if present start in `nexus` mode with that error. The `nexus` card shows `t('nexus.sign_in_title')`, `t('nexus.sign_in_hint')`, the error `t('nexus.error_<code>')` (unknown code → `nexus.error_generic`) and a button `t('nexus.sign_in')` that runs `window.location.assign('/auth/login')`.
- `nexus-session.tsx`: zustand-free module state with `useSyncExternalStore`; `NexusSessionSync` (mounted inside `WebAuthGate` in `app.tsx`, only when `__WEB_DEPLOYMENT__`) fetches `/api/auth/nexus/me` with `apiFetch`, ignores 404, stores the result, injects `<script src={ponto_script} async>` once, and on load calls `window.NexusPonto?.iniciar({ endpoint: absoluteApiBase() + '/api/nexus-ponto', sistema: me.system, cabecalhos: () => ({ [CSRF_HEADER_NAME]: '1' }) })`. `NexusSignOutButton` renders nothing without a session; otherwise a ghost icon button (`LogOutIcon`, `title={t('nexus.sign_out', { email })}`) that calls `window.NexusPonto?.parar()`, `apiFetch('/api/auth/nexus/logout', { method: 'POST' })` and `window.location.assign('/')`.
- `workspace-sidebar.tsx`: render `<NexusSignOutButton compact={...} />` right after the Settings link in the rail footer.
- i18n keys (`nexus.*`): `sign_in_title`, `sign_in_hint`, `sign_in`, `sign_out`, `error_estado_invalido`, `error_troca_falhou`, `error_token_invalido`, `error_sem_acesso`, `error_nexus_indisponivel`, `error_configuracao`, `error_cancelado`, `error_generic` — translated in all 21 locales.

- [ ] **Step 1: Failing Vitest** `web-auth-gate.test.tsx`: with `?nexus_error=sem_acesso` the gate renders the Nexus card with the `sem_acesso` text and strips the query; an `ov:auth-required` event with `mode: 'nexus'` renders the button; clicking it calls `window.location.assign('/auth/login')`.
- [ ] **Step 2: Run** `cd electron && bun run vitest run src/renderer/src/components/web-auth-gate.test.tsx` — fail.
- [ ] **Step 3: Implement** + locales.
- [ ] **Step 4: Run** the Vitest file, `bun run typecheck` (or the repo's `tsc` script), `bun run locale:check`, `uv run pytest tests/test_locale_parity.py tests/test_no_hardcoded_cjk.py tests/test_auth_gate_detail_lockstep.py -q` — PASS.
- [ ] **Step 5: Commit** `feat(nexus): Nexus sign-in card, session chrome and clock-out reminder`

### Task 7: Docs + full verification

**Files:**
- Create: `docs/nexus-auth.md` (env vars, Nexus admin setup, permission map, proxy notes incl. `FORWARDED_ALLOW_IPS`, reminder, troubleshooting by `nexus_error` code)
- Modify: `docs/api-auth.md` (one paragraph linking it, in the gates overview)

- [ ] **Step 1:** Write docs.
- [ ] **Step 2:** Full backend auth suite: `uv run pytest tests -q -k "auth or bearer or loopback or network or browser_guard or nexus or spa or locale or cjk"`; frontend: `cd electron && bun run vitest run src/renderer/src/components src/renderer/src/lib/api`.
- [ ] **Step 3: Commit** `docs(nexus): document the Nexus sign-in for the web deployment`
