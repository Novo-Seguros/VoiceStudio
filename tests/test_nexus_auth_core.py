"""Nexus sign-in core: configuration, PKCE, permission mapping, JWT checks."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nexus_fixtures import NEXUS_ENV, OTHER_KEY, jwks, make_token, resolver
from services import nexus_auth as nexus


@pytest.fixture
def env(monkeypatch):
    for name, value in NEXUS_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("NEXUS_SYSTEM_SLUG", raising=False)
    monkeypatch.delenv("NEXUS_REDIRECT_URI", raising=False)


def test_enabled_follows_client_id(monkeypatch):
    monkeypatch.delenv("NEXUS_CLIENT_ID", raising=False)
    assert not nexus.nexus_enabled()
    monkeypatch.setenv("NEXUS_CLIENT_ID", "   ")
    assert not nexus.nexus_enabled()
    monkeypatch.setenv("NEXUS_CLIENT_ID", "abc")
    assert nexus.nexus_enabled()


def test_load_config_trims_trailing_slashes(env, monkeypatch):
    monkeypatch.setenv("NEXUS_API_URL", "https://nexus.example/")
    config = nexus.load_config()
    assert config.api_url == "https://nexus.example"
    assert config.system_slug == "voicestudio"
    assert config.issuer == "https://nexus-auth.example/auth/v1"
    assert config.redirect_uri == "https://voicestudio.example/auth/callback"
    assert config.jwks_url == "https://nexus.example/v1/auth/jwks"
    assert config.api_origin == "https://nexus.example"
    assert config.ponto_url("situacao") == "https://nexus.example/v1/ponto/saida/situacao"
    assert "anon" not in repr(config)


@pytest.mark.parametrize(
    "name", ["NEXUS_SUPABASE_URL", "NEXUS_SUPABASE_ANON_KEY", "NEXUS_API_URL", "NEXUS_APP_URL"]
)
def test_load_config_requires_every_value(env, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(nexus.NexusConfigError):
        nexus.load_config()


def test_redirect_uri_override_keeps_the_audience(env, monkeypatch):
    monkeypatch.setenv("NEXUS_REDIRECT_URI", "http://localhost:3901/auth/callback")
    config = nexus.load_config()
    assert config.redirect_uri == "http://localhost:3901/auth/callback"
    assert config.app_url == "https://voicestudio.example"
    claims = nexus.verify_access_token(make_token(), config, resolver)
    assert claims["aud"] == "https://voicestudio.example"


@pytest.mark.parametrize(
    "value", ["localhost:3901/auth/callback", "http://localhost:3901/", "http://localhost:3901/cb"]
)
def test_redirect_uri_override_must_reach_the_callback(env, monkeypatch, value):
    monkeypatch.setenv("NEXUS_REDIRECT_URI", value)
    with pytest.raises(nexus.NexusConfigError):
        nexus.load_config()


def test_load_config_rejects_non_http_url(env, monkeypatch):
    monkeypatch.setenv("NEXUS_APP_URL", "voicestudio.example")
    with pytest.raises(nexus.NexusConfigError):
        nexus.load_config()


def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = nexus.pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()
    assert 43 <= len(verifier) <= 128
    assert "=" not in verifier


def test_authorize_redirect_carries_the_oauth_parameters(env):
    url = nexus.authorize_redirect(nexus.load_config(), "st", "ch")
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == (
        "https://nexus-auth.example/auth/v1/oauth/authorize"
    )
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query == {
        "response_type": "code",
        "client_id": "client-123",
        "redirect_uri": "https://voicestudio.example/auth/callback",
        "code_challenge": "ch",
        "code_challenge_method": "S256",
        "state": "st",
        "scope": "openid email profile",
    }


@pytest.mark.parametrize(
    ("permissions", "expected"),
    [
        ("usar", {"consume"}),
        ("usar|admin", {"consume", "admin"}),
        ("admin", {"consume", "admin"}),
        ("", set()),
        ("vw_tk|cr_tk", set()),
        (None, set()),
        ({"voicestudio": "usar", "tarefas": "admin"}, {"consume"}),
        ({"tarefas": "admin"}, set()),
    ],
)
def test_capabilities_from_claims(permissions, expected):
    claims = {"app_metadata": {"permissions": permissions}}
    assert nexus.capabilities_from_claims(claims, "voicestudio") == frozenset(expected)


def test_verify_accepts_a_valid_token(env):
    claims = nexus.verify_access_token(make_token(), nexus.load_config(), resolver)
    assert claims["sub"]


@pytest.mark.parametrize(
    "token_kwargs",
    [
        {"aud": "https://other.example"},
        {"iss": "https://evil.example/auth/v1"},
        {"exp_in": -120},
        {"slug": "tarefas"},
        {"key": OTHER_KEY},
    ],
)
def test_verify_rejects_bad_tokens(env, token_kwargs):
    with pytest.raises(nexus.NexusTokenError):
        nexus.verify_access_token(make_token(**token_kwargs), nexus.load_config(), resolver)


def test_identity_from_tokens_maps_profile(env):
    identity = nexus.identity_from_tokens(
        nexus.load_config(),
        {"access_token": make_token("usar|admin"), "refresh_token": "r1"},
        resolver,
    )
    assert identity.email == "ana@example.com"
    assert identity.name == "Ana Lima"
    assert identity.capabilities == frozenset({"consume", "admin"})
    assert identity.refresh_token == "r1"
    assert "r1" not in repr(identity)


def test_identity_without_permission_is_forbidden(env):
    with pytest.raises(nexus.NexusForbidden):
        nexus.identity_from_tokens(
            nexus.load_config(), {"access_token": make_token(""), "refresh_token": "r1"}, resolver
        )


def test_identity_requires_a_refresh_token(env):
    with pytest.raises(nexus.NexusTokenError):
        nexus.identity_from_tokens(nexus.load_config(), {"access_token": make_token()}, resolver)


class JwksServer:
    """Nexus's JWKS endpoint behind the shared HTTP transport seam."""

    def __init__(self, status=200, document=None):
        self.status = status
        self.document = document if document is not None else jwks()
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.document)


@pytest.fixture
def jwks_server(env):
    server = JwksServer()
    nexus.set_key_resolver(None)
    nexus.set_transport(httpx.MockTransport(server))
    nexus.clear_jwks_cache()
    yield server
    nexus.set_transport(None)
    nexus.clear_jwks_cache()


def test_jwks_is_fetched_over_the_shared_client_and_cached(jwks_server):
    config = nexus.load_config()
    nexus.verify_access_token(make_token(), config)
    nexus.verify_access_token(make_token(), config)
    assert len(jwks_server.requests) == 1
    request = jwks_server.requests[0]
    assert str(request.url) == "https://nexus.example/v1/auth/jwks"
    # Cloudflare in front of Nexus answers 403 to Python-urllib (2026-10-27).
    assert "urllib" not in request.headers["user-agent"].lower()


def test_jwks_refusal_means_nexus_unavailable(jwks_server):
    jwks_server.status = 403
    with pytest.raises(nexus.NexusUnavailable):
        nexus.verify_access_token(make_token(), nexus.load_config())


def test_unknown_kid_refetches_once_then_rejects(jwks_server):
    config = nexus.load_config()
    nexus.verify_access_token(make_token(), config)
    with pytest.raises(nexus.NexusTokenError):
        nexus.verify_access_token(make_token(kid="rotated"), config)
    with pytest.raises(nexus.NexusTokenError):
        nexus.verify_access_token(make_token(kid="rotated"), config)
    assert len(jwks_server.requests) == 1


def test_rotated_key_is_picked_up_after_the_refetch_interval(jwks_server, monkeypatch):
    config = nexus.load_config()
    nexus.verify_access_token(make_token(), config)
    jwks_server.document = jwks(("rotated", OTHER_KEY))
    clock = nexus.time.monotonic() + nexus.JWKS_REFETCH_SECONDS
    monkeypatch.setattr(nexus.time, "monotonic", lambda: clock)
    claims = nexus.verify_access_token(make_token(key=OTHER_KEY, kid="rotated"), config)
    assert claims["sub"]
    assert len(jwks_server.requests) == 2
