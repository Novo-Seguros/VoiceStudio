"""The RTP leg of a SIP call, dressed as a Media Streams WebSocket.

The provider-agnostic call loop (``services.telephony.session.run_call``)
drives a WebSocket that speaks the Twilio Media Streams envelope: a ``start``
event, base64 μ-law ``media`` frames both ways, ``mark`` echoes once audio
before them has played, ``clear`` to drop unplayed audio on barge-in, and
``stop``. :class:`MediaStreamBridge` implements exactly the four methods the
loop calls (``accept``, ``receive_text``, ``send_json``, ``close``) on top of
an :class:`~.rtp.RtpEndpoint`, so the call agent runs over SIP unchanged.

Playout is paced here: Twilio buffers whatever the loop sends and plays it in
real time; a PBX expects one 20 ms packet every 20 ms. A clock-driven pump
sends the next queued frame (or silence, which also keeps the NAT binding
open) and echoes a mark when playout reaches it.
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from collections import deque
from collections.abc import Awaitable, Callable

from .rtp import FRAME_BYTES, RtpEndpoint

ULAW_SILENCE = b"\xff" * FRAME_BYTES
_FRAME_S = 0.020
#: Further behind than this (a stalled loop), restart the clock instead of
#: bursting the backlog at the PBX.
_MAX_LAG_S = 0.2


class _Mark:
    __slots__ = ("name",)

    def __init__(self, name: str):
        self.name = name


class MediaStreamBridge:
    def __init__(
        self,
        rtp: RtpEndpoint,
        *,
        call_id: str,
        account_id: str,
        params: dict[str, str],
        on_close: Callable[[], Awaitable[object]] | None = None,
    ):
        self._rtp = rtp
        self._stream_id = "MZ" + secrets.token_hex(16)
        self._inbound: asyncio.Queue[str | None] = asyncio.Queue()
        self._outbound: deque[bytes | _Mark] = deque()
        self._pending = b""
        self._on_close = on_close
        self._closed = False
        self._ended = False
        self._pump_task: asyncio.Task | None = None
        self._inbound.put_nowait(
            json.dumps(
                {
                    "event": "start",
                    "streamSid": self._stream_id,
                    "start": {
                        "streamSid": self._stream_id,
                        "callSid": call_id,
                        "accountSid": account_id,
                        "customParameters": params,
                        "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1},
                    },
                }
            )
        )
        rtp.on_audio = self._on_audio

    # ── The WebSocket surface run_call uses ──

    async def accept(self) -> None:
        self._pump_task = asyncio.ensure_future(self._pump())

    async def receive_text(self) -> str:
        message = await self._inbound.get()
        if message is None:
            raise RuntimeError("the call ended")  # run_call reads this as a closed socket
        return message

    async def send_json(self, message: dict) -> None:
        event = message.get("event")
        if event == "media":
            try:
                payload = base64.b64decode((message.get("media") or {}).get("payload") or "")
            except ValueError:
                return
            self._queue_audio(payload)
        elif event == "mark":
            self._flush_partial()
            self._outbound.append(_Mark(str((message.get("mark") or {}).get("name") or "")))
        elif event == "clear":
            # Unplayed audio is dropped; its marks are reported as reached, as
            # Twilio does, so nothing waits forever on audio that will not play.
            self._pending = b""
            marks = [item for item in self._outbound if isinstance(item, _Mark)]
            self._outbound.clear()
            for mark in marks:
                self._emit_mark(mark.name)

    async def close(self, code: int = 1000) -> None:
        if self._closed:
            return
        self._closed = True
        self.end()
        if self._pump_task is not None:
            self._pump_task.cancel()
        if self._on_close is not None:
            await self._on_close()

    # ── The SIP side ──

    def end(self) -> None:
        """The call is over (either side hung up): the loop sees ``stop``."""
        if self._ended:
            return
        self._ended = True
        self._inbound.put_nowait(json.dumps({"event": "stop", "streamSid": self._stream_id}))
        self._inbound.put_nowait(None)

    def _on_audio(self, ulaw: bytes) -> None:
        if self._ended:
            return
        self._inbound.put_nowait(
            json.dumps(
                {
                    "event": "media",
                    "streamSid": self._stream_id,
                    "media": {"track": "inbound", "payload": base64.b64encode(ulaw).decode("ascii")},
                }
            )
        )

    def _emit_mark(self, name: str) -> None:
        if not self._ended:
            self._inbound.put_nowait(
                json.dumps({"event": "mark", "streamSid": self._stream_id, "mark": {"name": name}})
            )

    def _queue_audio(self, payload: bytes) -> None:
        data = self._pending + payload
        whole = len(data) - len(data) % FRAME_BYTES
        for i in range(0, whole, FRAME_BYTES):
            self._outbound.append(data[i : i + FRAME_BYTES])
        self._pending = data[whole:]

    def _flush_partial(self) -> None:
        if self._pending:
            self._outbound.append(self._pending + ULAW_SILENCE[len(self._pending) :])
            self._pending = b""

    async def _pump(self) -> None:
        # perf_counter, not the loop clock: on Windows before Python 3.13 the
        # monotonic clock ticks every ~15.6 ms, too coarse for 20 ms packets.
        next_at = time.perf_counter()
        while not self._closed:
            while self._outbound and isinstance(self._outbound[0], _Mark):
                self._emit_mark(self._outbound.popleft().name)
            frame = self._outbound.popleft() if self._outbound else ULAW_SILENCE
            self._rtp.send(frame)
            next_at += _FRAME_S
            delay = next_at - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            elif delay < -_MAX_LAG_S:
                next_at = time.perf_counter()
                await asyncio.sleep(0)
            else:
                await asyncio.sleep(0)
