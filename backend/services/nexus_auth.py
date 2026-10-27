"""Nexus single sign-on for the Novo Seguros web deployment.

Inert unless ``NEXUS_CLIENT_ID`` is set. The backend is the OAuth client: it
runs the PKCE flow, keeps the Nexus tokens in process memory and hands the
browser only the opaque ``ov_session`` cookie. See docs/nexus-auth.md.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import secrets
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from types import ModuleType
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlsplit

import httpx
import jwt

if TYPE_CHECKING:
    from services.nexus_sessions import NexusSessionRecord

logger = logging.getLogger("omnivoice.nexus")

DEFAULT_SYSTEM_SLUG = "voicestudio"
JWKS_CACHE_SECONDS = 600
#: Shortest gap between JWKS fetches triggered by an unknown ``kid``.
JWKS_REFETCH_SECONDS = 30
HTTP_TIMEOUT_SECONDS = 10.0
LOGOUT_TIMEOUT_SECONDS = 5.0
#: Nexus permission slug → VoiceStudio capabilities (see core.auth).
PERMISSION_CAPABILITIES: dict[str, frozenset[str]] = {
    "usar": frozenset({"consume"}),
    "admin": frozenset({"consume", "admin"}),
}
_ALGORITHMS = ["ES256", "RS256"]
# Every Nexus call goes through httpx with this agent: Cloudflare in front of
# Nexus refuses urllib's default one, which PyJWKClient used to send.
_HEADERS = {"User-Agent": "VoiceStudio (Nexus sign-in)"}


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
    """Nexus mode switch. Read at call time so it stays testable."""
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
    api_url: str = ""
    app_url: str = ""
    system_slug: str = DEFAULT_SYSTEM_SLUG
    # Overrides only where Nexus sends the browser back (a local dev server);
    # app_url stays the token audience, which Nexus pins to the system URL.
    callback_url: str = ""

    @property
    def issuer(self) -> str:
        return f"{self.supabase_url}/auth/v1"

    @property
    def redirect_uri(self) -> str:
        return self.callback_url or f"{self.app_url}/auth/callback"

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


def _callback_override() -> str:
    if not os.environ.get("NEXUS_REDIRECT_URI", "").strip():
        return ""
    value = _env_url("NEXUS_REDIRECT_URI")
    if urlsplit(value).path != "/auth/callback":
        raise NexusConfigError("NEXUS_REDIRECT_URI must end in /auth/callback")
    return value


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
        callback_url=_callback_override(),
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    """A fresh ``(code_verifier, S256 code_challenge)`` pair."""
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
    """VoiceStudio capabilities granted by ``app_metadata.permissions``.

    System-scoped tokens carry a pipe-string; tokens minted for the Nexus
    admin itself carry one string per system, so a dict is read by slug.
    """
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
# JWKS URL → (monotonic fetch time, kid → public key).
_jwks_cache: dict[str, tuple[float, dict[str, object]]] = {}
_jwks_lock = threading.Lock()
_SEAMS_MODULE_NAME = "_voicestudio_nexus_auth_seams"


def _seams() -> ModuleType:
    """Process-wide test seams. Anchored outside this module (like the session
    store) so a test that reloads ``services.*`` cannot split them from the
    copies the app's middleware already imported."""
    seams = sys.modules.get(_SEAMS_MODULE_NAME)
    if not isinstance(seams, ModuleType):
        seams = ModuleType(_SEAMS_MODULE_NAME)
        seams.key_resolver = None
        seams.transport = None
        sys.modules[_SEAMS_MODULE_NAME] = seams
    return seams


def set_key_resolver(resolver: KeyResolver | None) -> None:
    """Test seam: replace JWKS lookups with a fixed key resolver."""
    _seams().key_resolver = resolver


def clear_jwks_cache() -> None:
    with _jwks_lock:
        _jwks_cache.clear()


def _fetch_jwks(url: str) -> dict[str, object]:
    try:
        with httpx.Client(
            transport=_seams().transport, timeout=HTTP_TIMEOUT_SECONDS, headers=_HEADERS
        ) as client:
            response = client.get(url)
        response.raise_for_status()
        key_set = jwt.PyJWKSet.from_dict(response.json())
    except (httpx.HTTPError, ValueError, jwt.PyJWTError) as exc:
        raise NexusUnavailable(f"JWKS fetch failed: {exc}") from exc
    return {key.key_id: key.key for key in key_set.keys if key.key_id}


def _signing_key(url: str, kid: object) -> object:
    with _jwks_lock:
        now = time.monotonic()
        fetched_at, keys = _jwks_cache.get(url, (None, {}))
        age = None if fetched_at is None else now - fetched_at
        expired = age is None or age >= JWKS_CACHE_SECONDS
        rotated = kid not in keys and (age is None or age >= JWKS_REFETCH_SECONDS)
        if expired or rotated:
            try:
                keys = _fetch_jwks(url)
                _jwks_cache[url] = (now, keys)
            except NexusUnavailable:
                if kid not in keys:
                    raise
                logger.warning("Nexus JWKS refresh failed; reusing the cached key")
    key = keys.get(kid)
    if key is None:
        raise NexusTokenError("signing key not found")
    return key


def _jwks_resolver(config: NexusConfig) -> KeyResolver:
    def resolve(token: str) -> object:
        kid = jwt.get_unverified_header(token).get("kid")
        return _signing_key(config.jwks_url, kid)

    return resolve


def verify_access_token(
    token: str,
    config: NexusConfig,
    key_resolver: KeyResolver | None = None,
) -> dict:
    """Claims of a Nexus access token minted for this system, or raise."""
    resolver = key_resolver or _seams().key_resolver or _jwks_resolver(config)
    try:
        key = resolver(token)
    except jwt.PyJWTError as exc:
        raise NexusTokenError("malformed token header") from exc
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=_ALGORITHMS,
            audience=config.app_url,
            issuer=config.issuer,
            options={"require": ["exp", "sub", "iss", "aud"]},
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


def identity_from_tokens(
    config: NexusConfig,
    tokens: dict,
    key_resolver: KeyResolver | None = None,
) -> NexusIdentity:
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not isinstance(refresh_token, str) or not refresh_token:
        raise NexusTokenError("token response incomplete")
    claims = verify_access_token(access_token, config, key_resolver)
    capabilities = capabilities_from_claims(claims, config.system_slug)
    if not capabilities:
        raise NexusForbidden("no VoiceStudio permission")
    metadata = claims.get("user_metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    name = " ".join(
        part.strip()
        for part in (metadata.get("first_name"), metadata.get("last_name"))
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


async def identity_from_tokens_async(config: NexusConfig, tokens: dict) -> NexusIdentity:
    # A JWKS lookup blocks on the network at most once per cache window.
    return await asyncio.to_thread(identity_from_tokens, config, tokens)


def set_transport(transport: httpx.MockTransport | None) -> None:
    """Test seam: route every Nexus HTTP call, sync or async, through ``transport``."""
    _seams().transport = transport


def _client(timeout: float = HTTP_TIMEOUT_SECONDS) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=_seams().transport, timeout=timeout, headers=_HEADERS, follow_redirects=False
    )


async def _post_token(config: NexusConfig, form: dict[str, str]) -> dict:
    try:
        async with _client() as client:
            response = await client.post(
                config.token_url,
                data={**form, "client_id": config.client_id},
                headers={"apikey": config.anon_key},
            )
    except httpx.HTTPError as exc:
        raise NexusUnavailable("token endpoint unreachable") from exc
    if response.status_code >= 500:
        raise NexusUnavailable(f"token endpoint answered {response.status_code}")
    if response.status_code != 200:
        raise NexusRejected(f"token endpoint answered {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise NexusUnavailable("token endpoint returned non-JSON") from exc
    if not isinstance(payload, dict):
        raise NexusUnavailable("token endpoint returned a non-object")
    return payload


async def exchange_code(config: NexusConfig, code: str, verifier: str) -> dict:
    return await _post_token(config, {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": config.redirect_uri,
    })


async def refresh_tokens(config: NexusConfig, refresh_token: str) -> dict:
    return await _post_token(config, {"grant_type": "refresh_token", "refresh_token": refresh_token})


async def refresh_session(record: NexusSessionRecord) -> NexusSessionRecord | None:
    """Renew a session's Nexus tokens; ``None`` when the session has ended.

    One refresh per session at a time: the refresh token rotates, so a second
    concurrent refresh would present an already-spent token and end the
    session. A transient Nexus outage keeps the session; ``resolve`` still
    stops honouring it once the access token is past its grace window.
    """
    from services.nexus_sessions import nexus_session_store as store

    async with store.refresh_lock(record.credential_id):
        current = store.get(record.credential_id)
        if current is None or not current.needs_refresh(store.now()):
            return current
        try:
            config = load_config()
            tokens = await refresh_tokens(config, current.refresh_token)
            identity = await identity_from_tokens_async(config, tokens)
        except NexusUnavailable:
            logger.warning("nexus token refresh unavailable; keeping the session for now")
            return current
        except (NexusRejected, NexusTokenError, NexusForbidden, NexusConfigError) as exc:
            store.revoke_by_credential(current.credential_id)
            logger.info("nexus session ended at refresh (%s)", type(exc).__name__)
            return None
        store.update_identity(current.credential_id, identity)
        return store.get(current.credential_id)


async def revoke_refresh_token(config: NexusConfig, refresh_token: str) -> None:
    """Best-effort server-side revocation; local sign-out never waits on it."""
    try:
        async with _client(timeout=LOGOUT_TIMEOUT_SECONDS) as client:
            await client.post(config.logout_url, json={"refresh_token": refresh_token})
    except httpx.HTTPError:
        logger.info("nexus logout revocation failed")


async def forward_ponto(
    config: NexusConfig,
    acao: str,
    access_token: str,
    body: bytes,
    user_agent: str,
) -> tuple[int, object]:
    """Relay one clock-out reminder call; any failure is ``(502, {})``."""
    try:
        async with _client() as client:
            response = await client.post(
                config.ponto_url(acao),
                content=body or b"{}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "User-Agent": user_agent,
                },
            )
        return response.status_code, response.json()
    except (httpx.HTTPError, ValueError):
        return 502, {}
