"""Shared helpers for the Nexus sign-in tests (Novo Seguros fork)."""

from __future__ import annotations

import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

NEXUS_ENV = {
    "NEXUS_CLIENT_ID": "client-123",
    "NEXUS_SUPABASE_URL": "https://nexus-auth.example",
    "NEXUS_SUPABASE_ANON_KEY": "anon",
    "NEXUS_API_URL": "https://nexus.example",
    "NEXUS_APP_URL": "https://voicestudio.example",
}
APP_ORIGIN = NEXUS_ENV["NEXUS_APP_URL"]
SUB = "11111111-1111-1111-1111-111111111111"

KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = ec.generate_private_key(ec.SECP256R1())


def make_token(
    perms="usar",
    *,
    aud=APP_ORIGIN,
    iss="https://nexus-auth.example/auth/v1",
    slug="voicestudio",
    exp_in=3600,
    key=KEY,
    sub=SUB,
):
    now = int(time.time())
    return jwt.encode(
        {
            "sub": sub,
            "email": "ana@novoseguros.com.br",
            "aud": aud,
            "iss": iss,
            "iat": now,
            "exp": now + exp_in,
            "app_metadata": {"permissions": perms, "system_slug": slug},
            "user_metadata": {"first_name": "Ana", "last_name": "Lima"},
        },
        key,
        algorithm="ES256",
    )


def resolver(_token):
    return KEY.public_key()
