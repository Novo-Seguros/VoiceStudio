"""Digest authentication for SIP (RFC 2617, with RFC 7616's SHA-256).

A PBX answers an unauthenticated INVITE with 401 (``WWW-Authenticate``) or
407 (``Proxy-Authenticate``); the request is sent again with the matching
``Authorization`` / ``Proxy-Authorization`` header computed here.
"""
from __future__ import annotations

import hashlib
import re
import secrets

_PARAM_RE = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))')
_HASHES = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}


class DigestError(ValueError):
    pass


def parse_challenge(value: str) -> dict[str, str]:
    scheme, _, rest = (value or "").strip().partition(" ")
    if scheme.lower() != "digest":
        raise DigestError("only Digest authentication is supported")
    params = {m.group(1).lower(): m.group(2) if m.group(2) is not None else m.group(3) for m in _PARAM_RE.finditer(rest)}
    if "realm" not in params or "nonce" not in params:
        raise DigestError("the challenge has no realm or nonce")
    return params


def authorization(
    challenge: dict[str, str],
    *,
    method: str,
    uri: str,
    username: str,
    password: str,
    cnonce: str | None = None,
    nc: int = 1,
) -> str:
    """The credentials header value answering ``challenge``."""
    algorithm = (challenge.get("algorithm") or "MD5").upper()
    sess = algorithm.endswith("-SESS")
    base = algorithm[:-5] if sess else algorithm
    if base not in _HASHES:
        raise DigestError(f"unsupported digest algorithm {algorithm}")

    def h(text: str) -> str:
        return _HASHES[base](text.encode("utf-8")).hexdigest()

    realm, nonce = challenge["realm"], challenge["nonce"]
    qops = [q.strip() for q in (challenge.get("qop") or "").split(",") if q.strip()]
    if qops and "auth" not in qops:
        raise DigestError("only qop=auth is supported")
    cnonce = cnonce or secrets.token_hex(8)
    ha1 = h(f"{username}:{realm}:{password}")
    if sess:
        ha1 = h(f"{ha1}:{nonce}:{cnonce}")
    ha2 = h(f"{method}:{uri}")
    nc_text = f"{nc:08x}"
    if qops:
        response = h(f"{ha1}:{nonce}:{nc_text}:{cnonce}:auth:{ha2}")
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f"algorithm={algorithm if 'algorithm' in challenge else 'MD5'}",
    ]
    if "opaque" in challenge:
        parts.append(f'opaque="{challenge["opaque"]}"')
    if qops:
        parts += ["qop=auth", f"nc={nc_text}", f'cnonce="{cnonce}"']
    return "Digest " + ", ".join(parts)
