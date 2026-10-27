"""The SDP offer we send and the answer we accept (RFC 4566 / 3264).

One audio stream of G.711 at 8 kHz in 20 ms packets: μ-law (payload type 0)
first, A-law (8) as the fallback a PBX may prefer.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

PCMU = 0
PCMA = 8
CODEC_NAMES = {PCMU: "PCMU", PCMA: "PCMA"}


@dataclass(frozen=True)
class Answer:
    address: str
    port: int
    payload_type: int


def offer(address: str, port: int, *, session_id: int, version: int = 1, payload_types=(PCMU, PCMA)) -> bytes:
    family = "IP6" if _is_ipv6(address) else "IP4"
    formats = " ".join(str(pt) for pt in payload_types)
    lines = [
        "v=0",
        f"o=- {session_id} {version} IN {family} {address}",
        "s=VoiceStudio",
        f"c=IN {family} {address}",
        "t=0 0",
        f"m=audio {port} RTP/AVP {formats}",
        *[f"a=rtpmap:{pt} {CODEC_NAMES[pt]}/8000" for pt in payload_types],
        "a=ptime:20",
        "a=sendrecv",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def parse_answer(body: bytes, offered=(PCMU, PCMA)) -> Answer | None:
    """The remote media address and the codec it chose; None when the answer
    has no usable audio stream (rejected, or none of our codecs)."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    session_addr = ""
    media_addr = ""
    port = None
    formats: list[int] = []
    in_audio = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("m="):
            parts = line[2:].split()
            in_audio = bool(parts) and parts[0] == "audio" and port is None
            if in_audio and len(parts) >= 4:
                try:
                    port = int(parts[1])
                    formats = [int(f) for f in parts[3:] if f.isdigit()]
                except ValueError:
                    return None
        elif line.startswith("c="):
            parts = line[2:].split()
            addr = parts[2].split("/", 1)[0] if len(parts) >= 3 else ""
            if in_audio:
                media_addr = addr
            elif port is None:
                session_addr = addr
    if not port:  # absent, or 0 = stream rejected
        return None
    chosen = next((pt for pt in formats if pt in offered), None)
    address = media_addr or session_addr
    if chosen is None or not address:
        return None
    return Answer(address=address, port=port, payload_type=chosen)


def _is_ipv6(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).version == 6
    except ValueError:
        return False
