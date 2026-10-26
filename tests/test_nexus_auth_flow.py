"""Nexus sign-in end to end: gates, OAuth routes, refresh, ponto relay.

Nexus itself is an ``httpx.MockTransport`` and its JWKS a fixed key, so the
whole flow runs offline against the real app.
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nexus_fixtures import NEXUS_ENV, make_token, resolver

ORIGIN = NEXUS_ENV["NEXUS_APP_URL"]
CSRF_HEADERS = {"Origin": ORIGIN, "X-VoiceStudio-CSRF": "1"}
CONSUMER_ROUTE = "/v1/audio/voices"
ADMIN_ROUTE = "/api/settings/performance-profile"


class FakeNexus:
    def __init__(self) -> None:
        self.token_responses: list[tuple[int, dict]] = []
        self.requests: list[httpx.Request] = []
        self.ponto: tuple[int, dict] = (201, {"mostrar": False})
        self.unreachable = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.unreachable:
            raise httpx.ConnectError("down", request=request)
        path = request.url.path
        if path == "/auth/v1/oauth/token":
            status, body = self.token_responses.pop(0)
            return httpx.Response(status, json=body)
        if path == "/v1/auth/logout":
            return httpx.Response(200, json={})
        if path.startswith("/v1/ponto/saida/"):
            return httpx.Response(self.ponto[0], json=self.ponto[1])
        return httpx.Response(404, json={})

    def form(self, index: int = -1) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.requests[index].content.decode()).items()}


@pytest.fixture
def fake_nexus(monkeypatch):
    from services import nexus_auth
    from services.admin_sessions import admin_session_store
    from services.nexus_sessions import nexus_session_store

    for name, value in NEXUS_ENV.items():
        monkeypatch.setenv(name, value)
    for name in ("OMNIVOICE_API_KEY", "OMNIVOICE_SERVER_MODE", "OMNIVOICE_TRUSTED_NETWORKS"):
        monkeypatch.delenv(name, raising=False)
    fake = FakeNexus()
    nexus_auth.set_key_resolver(resolver)
    nexus_auth.set_transport(httpx.MockTransport(fake))
    nexus_session_store.clear()
    admin_session_store.clear()
    yield fake
    nexus_auth.set_key_resolver(None)
    nexus_auth.set_transport(None)
    nexus_session_store.clear()
    admin_session_store.clear()


def _client(host: str = "10.0.0.5", headers: dict[str, str] | None = None):
    from fastapi.testclient import TestClient
    from main import app

    return TestClient(
        app, base_url=ORIGIN, client=(host, 1), headers=headers, follow_redirects=False
    )


def _seed(perms: str = "usar", *, refresh: str = "r1") -> str:
    from services.nexus_auth import identity_from_tokens, load_config
    from services.nexus_sessions import nexus_session_store

    identity = identity_from_tokens(
        load_config(), {"access_token": make_token(perms), "refresh_token": refresh}, resolver
    )
    return nexus_session_store.issue(identity).token


def _age_access(token: str, *, expires_in: float) -> str:
    """Move a seeded session's access-token expiry; returns its credential id."""
    from services.nexus_sessions import nexus_session_store

    record = nexus_session_store.record_for_token(token)
    with nexus_session_store._lock:
        nexus_session_store._sessions[record.credential_id] = replace(
            record, access_expires_at=time.time() + expires_in
        )
    return record.credential_id


def _signed_in(token: str):
    client = _client()
    client.cookies.set("ov_session", token)
    return client


# --- gates -----------------------------------------------------------------


def test_anonymous_remote_request_needs_nexus_login(fake_nexus):
    response = _client().get(CONSUMER_ROUTE)
    assert response.status_code == 401
    assert response.json()["detail"] == "Nexus login required"


def test_consumer_session_reaches_consumer_routes_only(fake_nexus):
    client = _signed_in(_seed("usar"))
    assert client.get(CONSUMER_ROUTE).status_code == 200
    response = client.get(ADMIN_ROUTE)
    assert response.status_code == 403
    assert response.json()["detail"] == "Nexus admin permission required"


def test_admin_session_reaches_admin_routes(fake_nexus):
    client = _signed_in(_seed("usar|admin"))
    assert client.get(ADMIN_ROUTE).status_code == 200


def test_api_key_still_works_in_nexus_mode(fake_nexus, monkeypatch):
    monkeypatch.setenv("OMNIVOICE_API_KEY", "break-glass-key")
    response = _client().get(ADMIN_ROUTE, headers={"Authorization": "Bearer break-glass-key"})
    assert response.status_code == 200


def test_forged_nexus_cookie_is_rejected(fake_nexus):
    client = _client()
    client.cookies.set("ov_session", "ovs_nexus_session_" + "A" * 43)
    assert client.get(CONSUMER_ROUTE).status_code == 401


def test_nexus_cookie_is_ignored_when_mode_is_off(fake_nexus, monkeypatch):
    token = _seed("usar|admin")
    monkeypatch.delenv("NEXUS_CLIENT_ID")
    monkeypatch.setenv("OMNIVOICE_API_KEY", "key")
    client = _client()
    client.cookies.set("ov_session", token)
    assert client.get(CONSUMER_ROUTE).status_code == 401


def test_relayed_loopback_request_is_not_trusted(fake_nexus):
    response = _client("127.0.0.1", {"CF-Connecting-IP": "203.0.113.9"}).get(ADMIN_ROUTE)
    assert response.status_code == 401


def test_plain_loopback_keeps_local_trust(fake_nexus):
    assert _client("127.0.0.1").get(ADMIN_ROUTE).status_code == 200


def test_mode_off_leaves_the_app_untouched(fake_nexus, monkeypatch):
    monkeypatch.delenv("NEXUS_CLIENT_ID")
    client = _client()
    assert client.get(CONSUMER_ROUTE).status_code == 200
    assert client.get("/auth/login").status_code == 404


# --- refresh -----------------------------------------------------------------


def test_expiring_access_token_is_refreshed_and_rotated(fake_nexus):
    from services.nexus_sessions import nexus_session_store

    token = _seed("usar")
    credential = _age_access(token, expires_in=10)
    fake_nexus.token_responses.append(
        (200, {"access_token": make_token("usar|admin"), "refresh_token": "r2"})
    )
    client = _signed_in(token)
    assert client.get(ADMIN_ROUTE).status_code == 200
    assert fake_nexus.form() == {
        "grant_type": "refresh_token",
        "refresh_token": "r1",
        "client_id": "client-123",
    }
    assert fake_nexus.requests[-1].headers["apikey"] == "anon"
    assert nexus_session_store.get(credential).refresh_token == "r2"


def test_rejected_refresh_ends_the_session(fake_nexus):
    from services.nexus_sessions import nexus_session_store

    token = _seed("usar")
    credential = _age_access(token, expires_in=10)
    fake_nexus.token_responses.append((400, {"error": "invalid_grant"}))
    assert _signed_in(token).get(CONSUMER_ROUTE).status_code == 401
    assert nexus_session_store.get(credential) is None


def test_refresh_losing_every_permission_ends_the_session(fake_nexus):
    token = _seed("usar")
    _age_access(token, expires_in=10)
    fake_nexus.token_responses.append((200, {"access_token": make_token(""), "refresh_token": "r2"}))
    assert _signed_in(token).get(CONSUMER_ROUTE).status_code == 401


def test_unreachable_nexus_keeps_the_session_within_grace(fake_nexus):
    token = _seed("usar")
    _age_access(token, expires_in=-100)
    fake_nexus.unreachable = True
    assert _signed_in(token).get(CONSUMER_ROUTE).status_code == 200


def test_unreachable_nexus_past_grace_signs_out(fake_nexus):
    token = _seed("usar")
    _age_access(token, expires_in=-400)
    fake_nexus.unreachable = True
    assert _signed_in(token).get(CONSUMER_ROUTE).status_code == 401


# --- sign-in -------------------------------------------------------------------


def _start_login(client):
    response = client.get("/auth/login")
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    return {k: v[0] for k, v in parse_qs(location.query).items()}, location


def test_login_redirects_to_nexus(fake_nexus):
    client = _client()
    query, location = _start_login(client)
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        "https://nexus-auth.example/auth/v1/oauth/authorize"
    )
    assert query["client_id"] == "client-123"
    assert query["redirect_uri"] == "https://voicestudio.example/auth/callback"
    assert query["code_challenge_method"] == "S256"
    assert client.cookies.get("ov_nexus_state") == query["state"]


def test_full_sign_in(fake_nexus):
    client = _client()
    query, _ = _start_login(client)
    fake_nexus.token_responses.append(
        (200, {"access_token": make_token("usar"), "refresh_token": "r1"})
    )
    response = client.get("/auth/callback", params={"code": "abc", "state": query["state"]})
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.cookies.get("ov_session", "").startswith("ovs_nexus_session_")
    assert not client.cookies.get("ov_nexus_state")
    form = fake_nexus.form()
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "abc"
    assert form["redirect_uri"] == "https://voicestudio.example/auth/callback"
    assert form["code_verifier"]

    me = client.get("/api/auth/nexus/me")
    assert me.status_code == 200
    assert me.json() == {
        "email": "ana@example.com",
        "name": "Ana Lima",
        "admin": False,
        "system": "voicestudio",
        "ponto_script": "https://nexus.example/v1/ponto/saida/lembrete.js",
    }
    assert client.get(CONSUMER_ROUTE).status_code == 200


def _callback_error(client, params) -> str:
    response = client.get("/auth/callback", params=params)
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert location.path == "/"
    assert "ov_session" not in client.cookies
    return parse_qs(location.query)["nexus_error"][0]


def test_callback_rejects_unknown_state(fake_nexus):
    client = _client()
    _start_login(client)
    assert _callback_error(client, {"code": "abc", "state": "forged"}) == "estado_invalido"


def test_callback_state_is_single_use(fake_nexus):
    client = _client()
    query, _ = _start_login(client)
    fake_nexus.token_responses.append((200, {"access_token": make_token(), "refresh_token": "r1"}))
    client.get("/auth/callback", params={"code": "abc", "state": query["state"]})
    client.cookies.clear()
    client.cookies.set("ov_nexus_state", query["state"])
    assert _callback_error(client, {"code": "abc", "state": query["state"]}) == "estado_invalido"


def test_callback_needs_the_browser_state_cookie(fake_nexus):
    query, _ = _start_login(_client())
    assert _callback_error(_client(), {"code": "abc", "state": query["state"]}) == "estado_invalido"


@pytest.mark.parametrize(
    ("token_response", "code"),
    [
        ((400, {"error": "invalid_grant"}), "troca_falhou"),
        ((503, {}), "nexus_indisponivel"),
        ((200, {"access_token": make_token(""), "refresh_token": "r1"}), "sem_acesso"),
        (
            (200, {"access_token": make_token(aud="https://other.example"), "refresh_token": "r1"}),
            "token_invalido",
        ),
    ],
)
def test_callback_failures(fake_nexus, token_response, code):
    client = _client()
    query, _ = _start_login(client)
    fake_nexus.token_responses.append(token_response)
    assert _callback_error(client, {"code": "abc", "state": query["state"]}) == code


def test_callback_cancelled_at_nexus(fake_nexus):
    client = _client()
    query, _ = _start_login(client)
    params = {"error": "access_denied", "state": query["state"]}
    assert _callback_error(client, params) == "cancelado"


def test_incomplete_configuration_fails_closed(fake_nexus, monkeypatch):
    monkeypatch.delenv("NEXUS_SUPABASE_URL")
    client = _client()
    response = client.get("/auth/login")
    assert response.status_code == 303
    assert response.headers["location"] == "/?nexus_error=configuracao"
    assert client.get(CONSUMER_ROUTE).status_code == 401


def test_me_requires_a_session(fake_nexus):
    response = _client().get("/api/auth/nexus/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Nexus login required"


# --- sign-out ------------------------------------------------------------------


def test_logout_revokes_locally_and_at_nexus(fake_nexus):
    client = _signed_in(_seed("usar"))
    response = client.post("/api/auth/nexus/logout", headers=CSRF_HEADERS)
    assert response.status_code == 204
    expired = response.headers["set-cookie"]
    assert expired.startswith("ov_session=") and "Max-Age=0" in expired
    assert json.loads(fake_nexus.requests[-1].content) == {"refresh_token": "r1"}
    assert client.get("/api/auth/nexus/me").status_code == 401


def test_logout_needs_the_csrf_header(fake_nexus):
    client = _signed_in(_seed("usar"))
    assert client.post("/api/auth/nexus/logout").status_code == 403
    assert client.get("/api/auth/nexus/me").status_code == 200


# --- clock-out reminder relay ---------------------------------------------------


def test_ponto_relays_to_nexus(fake_nexus):
    client = _signed_in(_seed("usar"))
    response = client.post(
        "/api/nexus-ponto/situacao",
        content=b'{"x":1}',
        headers={**CSRF_HEADERS, "User-Agent": "UA-test", "Content-Type": "application/json"},
    )
    assert response.status_code == 201
    assert response.json() == {"mostrar": False}
    sent = fake_nexus.requests[-1]
    assert str(sent.url) == "https://nexus.example/v1/ponto/saida/situacao"
    assert sent.headers["authorization"].startswith("Bearer ")
    assert sent.headers["user-agent"] == "UA-test"
    assert sent.content == b'{"x":1}'


def test_ponto_unknown_action_is_404(fake_nexus):
    client = _signed_in(_seed("usar"))
    assert client.post("/api/nexus-ponto/apagar", headers=CSRF_HEADERS).status_code == 404


def test_ponto_requires_a_session(fake_nexus):
    assert _client().post("/api/nexus-ponto/situacao", headers=CSRF_HEADERS).status_code == 401


def test_ponto_failure_is_502_empty(fake_nexus):
    client = _signed_in(_seed("usar"))
    fake_nexus.unreachable = True
    response = client.post("/api/nexus-ponto/registrar", headers=CSRF_HEADERS)
    assert response.status_code == 502
    assert response.json() == {}
