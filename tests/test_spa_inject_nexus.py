"""CSP for the Nexus clock-out reminder script (Novo Seguros fork)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.spa_inject import allow_script_origin, render_index_document

RENDERER_INDEX = Path(__file__).resolve().parents[1] / "electron" / "src" / "renderer" / "index.html"
CSP = '<meta http-equiv="Content-Security-Policy" content="script-src \'self\'; connect-src \'self\'">'


def test_allows_exactly_one_origin():
    out = allow_script_origin(CSP, "https://nexus.example")
    assert "script-src 'self' https://nexus.example;" in out
    assert out.count("https://nexus.example") == 1


@pytest.mark.parametrize(
    "origin",
    ["", "javascript:alert(1)", "https://nexus.example/v1", "https://x' 'unsafe-inline", "nexus.example"],
)
def test_rejects_anything_but_a_bare_origin(origin):
    assert allow_script_origin(CSP, origin) == CSP


def test_render_composes_api_base_and_script_origin():
    out = render_index_document(
        CSP, api_base="https://api.example.com", script_origin="https://nexus.example"
    )
    assert "window.__OMNIVOICE_API_BASE__" in out
    assert "https://nexus.example" in out
    assert "'sha256-" in out


def test_render_without_overrides_is_identity():
    assert render_index_document(CSP) == CSP


def test_renderer_csp_still_has_the_anchor_we_rewrite():
    doc = RENDERER_INDEX.read_text(encoding="utf-8")
    assert "script-src 'self'" in doc
    assert "https://nexus.example" in allow_script_origin(doc, "https://nexus.example")
