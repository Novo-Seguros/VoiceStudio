"""The RTP leg of a call (RFC 3550): one UDP socket, G.711 in and out.

Symmetric RTP: we send from the same port we advertise, so a PBX behind or in
front of NAT (``comedia``) learns where to send the caller's audio from our
first packet. Packets are accepted only from the PBX's media address host, and
only with the negotiated payload type.
"""
from __future__ import annotations

import asyncio
import random
import secrets
import socket
import struct
from collections.abc import Callable

from . import g711
from .sdp import PCMA, PCMU

_HEADER = struct.Struct("!BBHII")
#: One 20 ms frame of 8 kHz G.711.
FRAME_BYTES = 160


class RtpError(OSError):
    pass


def build_packet(payload_type: int, seq: int, timestamp: int, ssrc: int, payload: bytes, *, marker: bool = False) -> bytes:
    return _HEADER.pack(0x80, (0x80 if marker else 0) | payload_type, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc) + payload


def parse_packet(data: bytes) -> tuple[int, bytes] | None:
    """``(payload_type, payload)`` of an RTP packet; None if it is not one."""
    if len(data) < 12 or data[0] >> 6 != 2:
        return None
    first, second = data[0], data[1]
    offset = 12 + 4 * (first & 0x0F)  # CSRC list
    if first & 0x10:  # header extension
        if len(data) < offset + 4:
            return None
        offset += 4 + 4 * struct.unpack_from("!H", data, offset + 2)[0]
    end = len(data)
    if first & 0x20:  # padding
        end -= data[-1]
    if offset > end:
        return None
    return second & 0x7F, data[offset:end]


class RtpEndpoint(asyncio.DatagramProtocol):
    """Send μ-law frames, receive the caller's audio as μ-law.

    ``remote`` and ``payload_type`` are set once the SDP answer arrives; until
    then ``send`` is a no-op. The wire codec may be A-law: conversion happens
    here so callers only ever see μ-law.
    """

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.local_port = 0
        self.remote: tuple[str, int] | None = None
        self.payload_type = PCMU
        self.on_audio: Callable[[bytes], None] | None = None
        self.packets_in = 0
        self.packets_out = 0
        self._seq = random.randrange(0x10000)
        self._timestamp = random.randrange(0x100000000)
        self._ssrc = secrets.randbits(32)
        self._marker = True

    # ── asyncio.DatagramProtocol ──

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if self.remote is None or addr[0] != self.remote[0]:
            return
        parsed = parse_packet(data)
        if parsed is None or parsed[0] != self.payload_type or not parsed[1]:
            return  # comfort noise, DTMF events, or a stray codec
        self.packets_in += 1
        payload = parsed[1]
        if self.payload_type == PCMA:
            payload = payload.translate(g711.ALAW_TO_ULAW)
        if self.on_audio is not None:
            self.on_audio(payload)

    def error_received(self, exc) -> None:  # ICMP port unreachable and friends
        pass

    # ── API ──

    def start_media(self, address: str, port: int, payload_type: int) -> None:
        self.remote = (address, port)
        self.payload_type = payload_type

    def send(self, ulaw: bytes) -> None:
        if self.transport is None or self.remote is None or self.transport.is_closing():
            return
        payload = ulaw.translate(g711.ULAW_TO_ALAW) if self.payload_type == PCMA else ulaw
        self.transport.sendto(
            build_packet(self.payload_type, self._seq, self._timestamp, self._ssrc, payload, marker=self._marker),
            self.remote,
        )
        self._marker = False
        self._seq = (self._seq + 1) & 0xFFFF
        self._timestamp = (self._timestamp + len(payload)) & 0xFFFFFFFF
        self.packets_out += 1

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


async def open_endpoint(host: str, port_min: int, port_max: int) -> RtpEndpoint:
    """Bind an even port in ``[port_min, port_max]`` (RTP convention, §11)."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    candidates = list(range(port_min + port_min % 2, port_max + 1, 2))
    random.shuffle(candidates)
    for port in candidates[:64]:
        try:
            _transport, endpoint = await loop.create_datagram_endpoint(
                RtpEndpoint, local_addr=(host, port), family=family
            )
        except OSError:
            continue
        endpoint.local_port = port
        return endpoint
    raise RtpError(f"No free RTP port between {port_min} and {port_max}")
