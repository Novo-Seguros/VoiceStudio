"""Nexus sign-in routes (Novo Seguros fork). All 404 unless Nexus mode is on.

``/auth/login`` and ``/auth/callback`` are public paths (see ``main.py``):
they validate their own PKCE state. Everything else needs a Nexus session.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from api.routers.auth import _expire_cookie, _secure_cookie, _set_session_cookie
from core.auth import CredentialTransport, PrincipalKind, principal_for
from core.csrf import cookie_csrf_allowed
from services import nexus_auth as nexus
from services.nexus_sessions import STATE_TTL_SECONDS, NexusSessionRecord
from services.nexus_sessions import nexus_session_store as store

router = APIRouter(include_in_schema=False)
logger = logging.getLogger("omnivoice.nexus")

STATE_COOKIE = "ov_nexus_state"
_STATE_COOKIE_PATH = "/auth"
PONTO_ACTIONS = frozenset({"situacao", "registrar", "dispensar"})
MAX_PONTO_BODY_BYTES = 16 * 1024
_LOGIN_REQUIRED = "Nexus login required"


def _require_enabled() -> None:
    if not nexus.nexus_enabled():
        raise HTTPException(status_code=404)


def _redirect(request: Request, location: str) -> RedirectResponse:
    response = RedirectResponse(location, status_code=303)
    response.delete_cookie(
        STATE_COOKIE,
        path=_STATE_COOKIE_PATH,
        secure=_secure_cookie(request),
        httponly=True,
        samesite="lax",
    )
    return response


def _fail(request: Request, code: str) -> RedirectResponse:
    return _redirect(request, f"/?nexus_error={code}")


def _session(request: Request) -> NexusSessionRecord:
    principal = principal_for(request)
    record = (
        store.get(principal.credential_id)
        if principal.kind is PrincipalKind.NEXUS_SESSION
        else None
    )
    if record is None:
        raise HTTPException(status_code=401, detail=_LOGIN_REQUIRED)
    return record


@router.get("/auth/login")
def login(request: Request) -> Response:
    _require_enabled()
    try:
        config = nexus.load_config()
    except nexus.NexusConfigError:
        logger.error("Nexus sign-in is on but its configuration is incomplete")
        return _fail(request, "configuracao")
    state = secrets.token_urlsafe(32)
    verifier, challenge = nexus.pkce_pair()
    store.save_state(state, verifier)
    response = RedirectResponse(nexus.authorize_redirect(config, state, challenge), status_code=303)
    # Lax, not Strict: Nexus sends the browser back here with a cross-site
    # top-level navigation, which must carry this cookie.
    response.set_cookie(
        STATE_COOKIE,
        state,
        max_age=STATE_TTL_SECONDS,
        path=_STATE_COOKIE_PATH,
        secure=_secure_cookie(request),
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = "") -> Response:
    _require_enabled()
    verifier = store.pop_state(state) if state else None
    if error:
        return _fail(request, "cancelado")
    cookie_state = request.cookies.get(STATE_COOKIE, "")
    if (
        not code
        or verifier is None
        or not cookie_state
        or not secrets.compare_digest(state.encode(), cookie_state.encode())
    ):
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
    response = _redirect(request, "/")
    _set_session_cookie(response, request, issued.token, issued.expires_at)
    return response


@router.get("/api/auth/nexus/me")
def me(request: Request) -> dict:
    _require_enabled()
    record = _session(request)
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
    """Relay for the Nexus clock-out reminder (mode B: the token stays here)."""
    _require_enabled()
    if acao not in PONTO_ACTIONS:
        raise HTTPException(status_code=404)
    record = _session(request)
    if record.needs_refresh(store.now()):
        record = await nexus.refresh_session(record)
        if record is None:
            raise HTTPException(status_code=401, detail=_LOGIN_REQUIRED)
    body = await request.body()
    if len(body) > MAX_PONTO_BODY_BYTES:
        raise HTTPException(status_code=413)
    status, payload = await nexus.forward_ponto(
        nexus.load_config(),
        acao,
        record.access_token,
        body,
        request.headers.get("user-agent", ""),
    )
    return JSONResponse(payload, status_code=status)
