"""Outbound calls through a SIP trunk: the INVITE transaction and the dialog.

:class:`OutboundCall` is one call from INVITE to BYE:

    call = OutboundCall(account, "+5527999990000", on_ringing=...)
    await call.start()             # INVITE sent (raises SipError if unreachable)
    if await call.answered():      # True on 200 OK, False when it ended first
        call.rtp.send(frame)       # 20 ms of μ-law; caller audio → call.rtp.on_audio
    await call.hangup()            # CANCEL while ringing, BYE once answered
    end = await call.ended()       # CallEnd(status, code, reason)

The PBX sees an ordinary trunk peer: digest-authenticated INVITE (401 and 407
both handled), symmetric RTP, ``rport`` in Via. Every socket is opened from
this side, so a NATed machine needs no inbound port forwarding as long as the
PBX treats the peer as NATed (Asterisk: ``nat=force_rport,comedia``).
"""
from __future__ import annotations

import asyncio
import logging
import secrets
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import digest, rtp, sdp
from .message import (
    SipMessage,
    SipParseError,
    StreamFramer,
    name_addr_uri,
    new_branch,
    new_call_id,
    new_tag,
    parse,
    response_to,
)

logger = logging.getLogger("omnivoice.telephony.sip")

T1 = 0.5
#: INVITE transaction timeout (64·T1, RFC 3261 Timer B).
TIMER_B = 32.0
#: How long a BYE or CANCEL waits for its answer before giving up.
_REQUEST_TIMEOUT_S = 4.0
#: CRLF keep-alive on UDP so the NAT binding for the PBX's BYE stays open.
KEEPALIVE_S = 20.0
USER_AGENT = "VoiceStudio-SIP"
ALLOW = "INVITE, ACK, CANCEL, BYE, OPTIONS"
TRANSPORTS = ("udp", "tcp")


class SipError(Exception):
    """The call could not be started; ``code`` is a stable, UI-mappable id."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SipAccount:
    """A trunk peer on the PBX."""

    server: str
    username: str
    password: str = ""
    port: int = 5060
    transport: str = "udp"
    #: When the PBX authenticates a different name than the From user.
    auth_username: str = ""
    #: The host in From/To/Request-URI; the server when empty.
    domain: str = ""
    display_name: str = ""
    #: Address advertised in Via/Contact/SDP; the interface that routes to
    #: the server when empty.
    local_address: str = ""
    rtp_port_min: int = 10000
    rtp_port_max: int = 10999
    #: Dial ``5527…`` instead of ``+5527…`` (most PBX dial plans match digits).
    strip_plus: bool = True

    @property
    def sip_domain(self) -> str:
        return self.domain or self.server

    @property
    def auth_user(self) -> str:
        return self.auth_username or self.username


@dataclass(frozen=True)
class CallEnd:
    status: str  # completed | busy | no_answer | failed | canceled
    code: int = 0
    reason: str = ""


def status_for(code: int) -> str:
    """A final SIP failure response → the call status shown to people."""
    if code in (486, 600, 603):
        return "busy"
    if code in (408, 480):
        return "no_answer"
    if code == 487:
        return "canceled"
    return "failed"


# ── Transports ──────────────────────────────────────────────────────────────


class _UdpTransport(asyncio.DatagramProtocol):
    name = "UDP"

    def __init__(self, on_message: Callable[[SipMessage], None], on_closed: Callable[[], None]):
        self.on_message = on_message
        self.on_closed = on_closed
        self.local: tuple[str, int] = ("", 0)
        self._transport: asyncio.DatagramTransport | None = None

    async def open(self, ip: str, port: int) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(lambda: self, remote_addr=(ip, port))
        self.local = tuple(self._transport.get_extra_info("sockname")[:2])

    def datagram_received(self, data: bytes, addr) -> None:
        if not data.strip(b"\r\n"):
            return  # keep-alive
        try:
            msg = parse(data)
        except SipParseError:
            return
        self.on_message(msg)

    def error_received(self, exc) -> None:
        pass

    def send(self, data: bytes) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.sendto(data)

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()


class _TcpTransport:
    name = "TCP"

    def __init__(self, on_message: Callable[[SipMessage], None], on_closed: Callable[[], None]):
        self.on_message = on_message
        self.on_closed = on_closed
        self.local: tuple[str, int] = ("", 0)
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task | None = None

    async def open(self, ip: str, port: int) -> None:
        reader, self._writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=10.0)
        self.local = tuple(self._writer.get_extra_info("sockname")[:2])
        self._task = asyncio.create_task(self._read(reader))

    async def _read(self, reader: asyncio.StreamReader) -> None:
        framer = StreamFramer()
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                for msg in framer.feed(data):
                    self.on_message(msg)
        except (OSError, SipParseError):
            pass
        finally:
            self.on_closed()

    def send(self, data: bytes) -> None:
        if self._writer is not None and not self._writer.is_closing():
            self._writer.write(data)

    def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
        if self._task is not None and self._task is not asyncio.current_task():
            self._task.cancel()


async def _connect(account: SipAccount, on_message, on_closed):
    if account.transport not in TRANSPORTS:
        raise SipError("invalid_transport", f"Unknown SIP transport {account.transport!r}")
    loop = asyncio.get_running_loop()
    kind = socket.SOCK_STREAM if account.transport == "tcp" else socket.SOCK_DGRAM
    try:
        infos = await loop.getaddrinfo(account.server, account.port, type=kind)
    except OSError as exc:
        raise SipError("unreachable", f"Cannot resolve the SIP server {account.server}") from exc
    ip = infos[0][4][0]
    transport = (_TcpTransport if account.transport == "tcp" else _UdpTransport)(on_message, on_closed)
    try:
        await transport.open(ip, account.port)
    except (TimeoutError, OSError) as exc:
        raise SipError(
            "unreachable", f"Cannot reach the SIP server {account.server}:{account.port} ({type(exc).__name__})"
        ) from exc
    return transport


# ── The call ────────────────────────────────────────────────────────────────


class OutboundCall:
    def __init__(
        self,
        account: SipAccount,
        number: str,
        *,
        ring_timeout_s: float = 60.0,
        on_ringing: Callable[[], None] | None = None,
        on_hangup: Callable[[CallEnd], None] | None = None,
    ):
        self.account = account
        self.number = number
        self.user = number.lstrip("+") if account.strip_plus else number
        self.ring_timeout_s = ring_timeout_s
        self.on_ringing = on_ringing
        #: Called once when an answered call ends, whoever hung up.
        self.on_hangup = on_hangup
        self.call_id = new_call_id("voicestudio")
        self.rtp: rtp.RtpEndpoint | None = None
        self.state = "idle"  # calling → answered → ended
        self._transport = None
        self._local = ("", 0)
        self._local_tag = new_tag()
        self._sdp_session = secrets.randbelow(2**31)
        self._sdp_version = 1
        self._cseq = 0
        self._invite: SipMessage | None = None
        self._invite_bytes = b""
        self._invite_sent_at = 0.0
        self._ack_bytes = b""
        self._remote_to = ""
        self._remote_target = ""
        self._route_set: list[str] = []
        self._auth_attempts = 0
        self._provisional = False
        self._rang = False
        self._cancel_requested = False
        self._cancel_sent = False
        self._no_answer = False
        self._hanging_up = False
        self._pending: dict[tuple[int, str], asyncio.Future] = {}
        self._tasks: set[asyncio.Task] = set()
        self._answered: asyncio.Future | None = None
        self._ended: asyncio.Future | None = None

    # ── Public surface ──

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._answered = loop.create_future()
        self._ended = loop.create_future()
        self._transport = await _connect(self.account, self._on_message, self._on_transport_closed)
        bind_host = self._transport.local[0]
        self._local = (self.account.local_address or bind_host, self._transport.local[1])
        try:
            self.rtp = await rtp.open_endpoint(bind_host, self.account.rtp_port_min, self.account.rtp_port_max)
        except OSError as exc:
            self._transport.close()
            raise SipError("no_rtp_port", str(exc)) from exc
        self.state = "calling"
        self._send_invite()
        self._spawn(self._invite_timer())
        self._spawn(self._ring_timer())
        if self.account.transport == "udp":
            self._spawn(self._keepalive())

    async def answered(self) -> bool:
        return await asyncio.shield(self._answered)

    async def ended(self) -> CallEnd:
        return await asyncio.shield(self._ended)

    async def hangup(self) -> CallEnd:
        """Cancel a ringing call or end an answered one; safe to call twice."""
        if self._ended is None:
            raise RuntimeError("the call was never started")
        if self._ended.done() or self._hanging_up:
            return await self.ended()
        self._hanging_up = True
        if self.state == "answered":
            await self._send_bye()
            self._finish(CallEnd("completed", 0, "Hung up"))
        else:
            self._cancel_requested = True
            if self._provisional:
                self._send_cancel()
            try:
                await asyncio.wait_for(self.ended(), timeout=_REQUEST_TIMEOUT_S * 2)
            except TimeoutError:
                self._finish(CallEnd("no_answer" if self._no_answer else "canceled", 0, "Canceled"))
        return await self.ended()

    # ── Building requests ──

    def _via(self) -> str:
        host, port = self._local
        return f"SIP/2.0/{self._transport.name} {_host(host)}:{port};branch={new_branch()};rport"

    def _from(self) -> str:
        name = f'"{self.account.display_name}" ' if self.account.display_name else ""
        return f"{name}<sip:{self.account.username}@{self.account.sip_domain}>;tag={self._local_tag}"

    def _contact(self) -> str:
        host, port = self._local
        suffix = ";transport=tcp" if self.account.transport == "tcp" else ""
        return f"<sip:{self.account.username}@{_host(host)}:{port}{suffix}>"

    def _send(self, msg: SipMessage) -> bytes:
        data = msg.to_bytes()
        self._transport.send(data)
        return data

    def _send_invite(self, credentials: tuple[str, str] | None = None) -> None:
        uri = f"sip:{self.user}@{self.account.sip_domain}"
        self._cseq += 1
        invite = SipMessage(method="INVITE", uri=uri)
        invite.headers = [
            ("Via", self._via()),
            ("Max-Forwards", "70"),
            ("From", self._from()),
            ("To", f"<{uri}>"),
            ("Call-ID", self.call_id),
            ("CSeq", f"{self._cseq} INVITE"),
            ("Contact", self._contact()),
            ("Allow", ALLOW),
            ("User-Agent", USER_AGENT),
            ("Content-Type", "application/sdp"),
        ]
        if credentials:
            invite.headers.append(credentials)
        invite.body = sdp.offer(self._local[0], self.rtp.local_port, session_id=self._sdp_session)
        self._invite = invite
        self._provisional = False
        self._invite_sent_at = time.monotonic()
        self._invite_bytes = self._send(invite)

    def _in_dialog(self, method: str) -> SipMessage:
        self._cseq += 1
        msg = SipMessage(method=method, uri=self._remote_target or self._invite.uri)
        msg.headers = [("Via", self._via()), ("Max-Forwards", "70")]
        msg.headers += [("Route", r) for r in self._route_set]
        msg.headers += [
            ("From", self._from()),
            ("To", self._remote_to),
            ("Call-ID", self.call_id),
            ("CSeq", f"{self._cseq} {method}"),
            ("User-Agent", USER_AGENT),
        ]
        return msg

    def _send_ack(self, response: SipMessage) -> None:
        num, _ = response.cseq
        if 200 <= response.status < 300:
            # A 2xx ACK is its own transaction, sent within the dialog (§13.2.2.4).
            ack = self._in_dialog("ACK")
            self._cseq -= 1
            ack.set("CSeq", f"{num} ACK")
            self._ack_bytes = self._send(ack)
            return
        # A failure ACK belongs to the INVITE transaction: same branch (§17.1.1.3).
        ack = SipMessage(method="ACK", uri=self._invite.uri)
        ack.headers = [
            ("Via", self._invite.get("Via")),
            ("Max-Forwards", "70"),
            ("From", self._invite.get("From")),
            ("To", response.get("To")),
            ("Call-ID", self.call_id),
            ("CSeq", f"{num} ACK"),
        ]
        self._send(ack)

    def _send_cancel(self) -> None:
        if self._cancel_sent:
            return
        self._cancel_sent = True
        num, _ = self._invite.cseq
        cancel = SipMessage(method="CANCEL", uri=self._invite.uri)
        cancel.headers = [
            ("Via", self._invite.get("Via")),
            ("Max-Forwards", "70"),
            ("From", self._invite.get("From")),
            ("To", self._invite.get("To")),
            ("Call-ID", self.call_id),
            ("CSeq", f"{num} CANCEL"),
            ("User-Agent", USER_AGENT),
        ]
        self._spawn(self._request(cancel))

    async def _send_bye(self) -> None:
        credentials = None
        for _attempt in range(2):
            bye = self._in_dialog("BYE")
            if credentials:
                bye.headers.append(credentials)
            response = await self._request(bye)
            if response is None or response.status not in (401, 407):
                return
            try:
                credentials = self._credentials(response, "BYE", bye.uri)
            except digest.DigestError:
                return

    async def _request(self, msg: SipMessage) -> SipMessage | None:
        """Send a non-INVITE request and wait for its final response
        (retransmitted on UDP per Timer E); None on timeout."""
        future = asyncio.get_running_loop().create_future()
        key = msg.cseq
        self._pending[key] = future
        data = self._send(msg)
        deadline = time.monotonic() + _REQUEST_TIMEOUT_S
        interval = T1
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                try:
                    return await asyncio.wait_for(asyncio.shield(future), timeout=min(interval, remaining))
                except TimeoutError:
                    if self.account.transport == "udp":
                        self._transport.send(data)
                    interval = min(interval * 2, 4.0)
        finally:
            self._pending.pop(key, None)

    def _credentials(self, challenge_response: SipMessage, method: str, uri: str) -> tuple[str, str]:
        proxy = challenge_response.status == 407
        challenge = digest.parse_challenge(
            challenge_response.get("Proxy-Authenticate" if proxy else "WWW-Authenticate")
        )
        value = digest.authorization(
            challenge,
            method=method,
            uri=uri,
            username=self.account.auth_user,
            password=self.account.password,
        )
        return ("Proxy-Authorization" if proxy else "Authorization", value)

    # ── Incoming messages ──

    def _on_message(self, msg: SipMessage) -> None:
        if msg.is_request:
            self._on_request(msg)
            return
        if msg.get("Call-ID") != self.call_id:
            return
        num, method = msg.cseq
        if method == "INVITE":
            self._on_invite_response(msg)
            return
        future = self._pending.get((num, method))
        if future is not None and not future.done() and msg.status >= 200:
            future.set_result(msg)

    def _on_invite_response(self, resp: SipMessage) -> None:
        num, _ = resp.cseq
        code = resp.status
        if num != self._invite.cseq[0] or self.state == "ended":
            if 200 <= code < 300 and self._ack_bytes:
                self._transport.send(self._ack_bytes)
            return
        if code < 200:
            self._provisional = True
            if code in (180, 183) and not self._rang:
                self._rang = True
                if self.on_ringing is not None:
                    self.on_ringing()
            if self._cancel_requested:
                self._send_cancel()
            return
        if code < 300:
            self._on_invite_ok(resp)
            return
        self._send_ack(resp)
        if code in (401, 407) and not self._cancel_requested and self._may_retry_auth(resp):
            self._auth_attempts += 1
            try:
                credentials = self._credentials(resp, "INVITE", self._invite.uri)
            except digest.DigestError as exc:
                self._finish(CallEnd("failed", code, str(exc)))
                return
            self._send_invite(credentials)
            return
        if code in (401, 407):
            self._finish(CallEnd("failed", code, "The SIP server refused the trunk credentials"))
            return
        status = "no_answer" if self._no_answer else status_for(code)
        self._finish(CallEnd(status, code, resp.reason))

    def _may_retry_auth(self, resp: SipMessage) -> bool:
        if self._auth_attempts == 0:
            return True
        # A second challenge only means "try again" when the nonce went stale.
        header = resp.get("Proxy-Authenticate" if resp.status == 407 else "WWW-Authenticate")
        return self._auth_attempts < 3 and "stale=true" in header.replace(" ", "").lower()

    def _on_invite_ok(self, resp: SipMessage) -> None:
        if self.state == "answered":
            if self._ack_bytes:  # a retransmitted 200: ACK again
                self._transport.send(self._ack_bytes)
            return
        self._remote_to = resp.get("To")
        contacts = resp.get_all("Contact")
        self._remote_target = name_addr_uri(contacts[0]) if contacts else self._invite.uri
        self._route_set = list(reversed(resp.get_all("Record-Route")))
        self.state = "answered"
        self._send_ack(resp)
        answer = sdp.parse_answer(resp.body)
        if answer is None:
            self._end_after_bye(CallEnd("failed", 488, "The PBX answered without a usable audio codec"))
            return
        if self._cancel_requested:  # answered while we were canceling
            self._end_after_bye(CallEnd("no_answer" if self._no_answer else "canceled", 0, "Canceled"))
            return
        self.rtp.start_media(answer.address, answer.port, answer.payload_type)
        if not self._answered.done():
            self._answered.set_result(True)

    def _end_after_bye(self, end: CallEnd) -> None:
        async def _bye() -> None:
            await self._send_bye()
            self._finish(end)

        self._hanging_up = True
        self._spawn(_bye())

    def _on_request(self, req: SipMessage) -> None:
        method = req.method
        if method == "ACK":
            return
        if req.get("Call-ID") != self.call_id:
            # A qualify ping is fine; anything else is not for us.
            self._respond(req, 200 if method == "OPTIONS" else 481)
            return
        if method == "BYE":
            self._respond(req, 200)
            answered = self.state == "answered"
            self._finish(CallEnd("completed" if answered else "canceled", 0, "The other side hung up"))
            return
        if method in ("INVITE", "UPDATE") and req.body:
            # Session refresh or media change: follow it, keep our codec.
            offered = sdp.parse_answer(req.body, offered=(self.rtp.payload_type,))
            if offered is None:
                self._respond(req, 488)
                return
            self.rtp.start_media(offered.address, offered.port, offered.payload_type)
            self._sdp_version += 1
            body = sdp.offer(
                self._local[0],
                self.rtp.local_port,
                session_id=self._sdp_session,
                version=self._sdp_version,
                payload_types=(self.rtp.payload_type,),
            )
            self._respond(req, 200, body=body)
            return
        if method in ("INVITE", "UPDATE", "OPTIONS", "INFO", "NOTIFY", "CANCEL"):
            self._respond(req, 200)
            return
        self._respond(req, 501)

    def _respond(self, req: SipMessage, status: int, *, body: bytes = b"") -> None:
        reasons = {200: "OK", 481: "Call/Transaction Does Not Exist", 488: "Not Acceptable Here", 501: "Not Implemented"}
        resp = response_to(req, status, reasons.get(status, ""), to_tag=self._local_tag)
        resp.headers.append(("User-Agent", USER_AGENT))
        if req.method in ("INVITE", "UPDATE") and status == 200:
            resp.headers.append(("Contact", self._contact()))
        if body:
            resp.headers.append(("Content-Type", "application/sdp"))
            resp.body = body
        self._send(resp)

    def _on_transport_closed(self) -> None:
        if self._ended is not None and not self._ended.done():
            answered = self.state == "answered"
            self._finish(
                CallEnd("completed" if answered else "failed", 0, "The connection to the SIP server closed")
            )

    # ── Timers ──

    async def _invite_timer(self) -> None:
        """Retransmit the INVITE on UDP until something answers (Timer A);
        fail the call when nothing does within Timer B."""
        interval = T1
        while self.state == "calling":
            await asyncio.sleep(interval)
            if self.state != "calling" or self._provisional:
                if self.state != "calling":
                    return
                interval = T1
                continue
            if time.monotonic() - self._invite_sent_at >= TIMER_B:
                self._finish(CallEnd("failed", 408, "The SIP server did not answer"))
                return
            if self.account.transport == "udp":
                self._transport.send(self._invite_bytes)
            interval = min(interval * 2, 4.0)

    async def _ring_timer(self) -> None:
        await asyncio.sleep(self.ring_timeout_s)
        if self.state == "calling":
            self._no_answer = True
            await self.hangup()

    async def _keepalive(self) -> None:
        while self.state != "ended":
            await asyncio.sleep(KEEPALIVE_S)
            if self.state != "ended":
                self._transport.send(b"\r\n\r\n")

    # ── Teardown ──

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _finish(self, end: CallEnd) -> None:
        if self._ended is None or self._ended.done():
            return
        was_answered = self.state == "answered"
        self.state = "ended"
        if not self._answered.done():
            self._answered.set_result(False)
        self._ended.set_result(end)
        current = asyncio.current_task()
        for task in list(self._tasks):
            if task is not current:
                task.cancel()
        if self.rtp is not None:
            self.rtp.close()
        if self._transport is not None:
            self._transport.close()
        logger.info("SIP call ended: %s (%s)", end.status, end.code or "-")
        if was_answered and self.on_hangup is not None:
            self.on_hangup(end)


async def options_ping(account: SipAccount, timeout: float = 5.0) -> int:
    """Send OPTIONS to the PBX and return the response code. Any response —
    even 401/404 — proves the server is reachable over this transport.
    Raises SipError when nothing answers."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def on_message(msg: SipMessage) -> None:
        if not msg.is_request and msg.status >= 200 and not future.done():
            future.set_result(msg.status)

    transport = await _connect(account, on_message, lambda: None)
    try:
        host, port = account.local_address or transport.local[0], transport.local[1]
        uri = f"sip:{account.sip_domain}"
        msg = SipMessage(method="OPTIONS", uri=uri)
        msg.headers = [
            ("Via", f"SIP/2.0/{transport.name} {_host(host)}:{port};branch={new_branch()};rport"),
            ("Max-Forwards", "70"),
            ("From", f"<sip:{account.username}@{account.sip_domain}>;tag={new_tag()}"),
            ("To", f"<{uri}>"),
            ("Call-ID", new_call_id("voicestudio")),
            ("CSeq", "1 OPTIONS"),
            ("Accept", "application/sdp"),
            ("User-Agent", USER_AGENT),
        ]
        data = msg.to_bytes()
        transport.send(data)
        deadline = time.monotonic() + timeout
        interval = T1
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SipError("no_response", f"The SIP server {account.server} did not answer")
            try:
                return await asyncio.wait_for(asyncio.shield(future), timeout=min(interval, remaining))
            except TimeoutError:
                interval = min(interval * 2, 4.0)
                if account.transport == "udp":  # TCP is reliable: never resend
                    transport.send(data)
    finally:
        transport.close()


def _host(address: str) -> str:
    return f"[{address}]" if ":" in address else address
