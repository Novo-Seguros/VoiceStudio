"""μ-law ⇄ A-law transcoding, as 256-byte ``bytes.translate`` tables.

The call loop speaks μ-law; a PBX may answer with A-law (common on E1 lines).
Each table is built once by decoding to 16-bit PCM and re-encoding with the
reference Sun ``g711.c`` algorithms (the ones ``audioop`` used), so a frame
converts with one C-level ``translate`` call and no dependencies.
"""
from __future__ import annotations

_SEG_AEND = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
_SEG_UEND = (0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF)


def _segment(value: int, ends: tuple[int, ...]) -> int:
    for i, end in enumerate(ends):
        if value <= end:
            return i
    return len(ends)


def ulaw_to_linear(code: int) -> int:
    u = ~code & 0xFF
    t = ((u & 0x0F) << 3) + 0x84
    t <<= (u & 0x70) >> 4
    return 0x84 - t if u & 0x80 else t - 0x84


def alaw_to_linear(code: int) -> int:
    a = code ^ 0x55
    t = (a & 0x0F) << 4
    seg = (a & 0x70) >> 4
    if seg == 0:
        t += 8
    else:
        t = (t + 0x108) << (seg - 1)
    return t if a & 0x80 else -t


def linear_to_alaw(pcm: int) -> int:
    pcm >>= 3
    if pcm >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        pcm = -pcm - 1
    seg = _segment(pcm, _SEG_AEND)
    if seg >= 8:
        return 0x7F ^ mask
    aval = seg << 4
    aval |= (pcm >> 1 if seg < 2 else pcm >> seg) & 0x0F
    return aval ^ mask


def linear_to_ulaw(pcm: int) -> int:
    pcm >>= 2
    if pcm < 0:
        pcm = -pcm
        mask = 0x7F
    else:
        mask = 0xFF
    pcm = min(pcm, 8159) + 0x21
    seg = _segment(pcm, _SEG_UEND)
    if seg >= 8:
        return 0x7F ^ mask
    return ((seg << 4) | ((pcm >> (seg + 1)) & 0x0F)) ^ mask


ULAW_TO_ALAW = bytes(linear_to_alaw(ulaw_to_linear(c)) for c in range(256))
ALAW_TO_ULAW = bytes(linear_to_ulaw(alaw_to_linear(c)) for c in range(256))
