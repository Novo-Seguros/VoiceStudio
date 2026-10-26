"""Nexus sign-in core: configuration, PKCE, permission mapping, JWT checks."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest

from nexus_fixtures import NEXUS_ENV, OTHER_KEY, make_token, resolver
from services import nexus_auth as nexus


@pytest.fixture
def env(monkeypatch):
    for name, value in NEXUS_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("NEXUS_SYSTEM_SLUG", raising=False)


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
    assert identity.email == "ana@novoseguros.com.br"
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
