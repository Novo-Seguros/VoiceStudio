"""SIP trunk dialer: wire formats, the call against a fake PBX, and the bridge
that runs the call loop over RTP.

The fake PBX is a real UDP/TCP SIP server on loopback, so the user agent's
transactions (digest challenge, provisional responses, ACK, CANCEL, BYE) and
its RTP leg are exercised end to end without a phone line.
"""
import os

os.environ.setdefault("OMNIVOICE_MODEL", "test")
os.environ.setdefault("OMNIVOICE_DISABLE_FILE_LOG", "1")

import asyncio
import base64
import hashlib
import importlib
import json

import pytest
from services.telephony import session as session_mod
from services.telephony.sip import digest, g711, message, rtp, sdp
from services.telephony.sip.bridge import MediaStreamBridge
from services.telephony.sip.ua import (
    CallEnd,
    OutboundCall,
    SipAccount,
    SipError,
    options_ping,
    status_for,
)

PASSWORD = "s3cret"
NUMBER = "+5527999990000"


# ── Messages ────────────────────────────────────────────────────────────────


def test_parse_expands_compact_headers_and_reads_the_body():
    raw = (
        b"SIP/2.0 200 OK\r\n"
        b"v: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK1, SIP/2.0/UDP 10.0.0.3;branch=z9hG4bK2\r\n"
        b"f: <sip:a@b>;tag=1\r\nt: <sip:c@d>;tag=2\r\ni: abc@x\r\nCSeq: 2 INVITE\r\n"
        b"l: 4\r\n\r\nbodyEXTRA"
    )
    msg = message.parse(raw)
    assert (msg.status, msg.reason) == (200, "OK")
    assert msg.get("call-id") == "abc@x"
    assert len(msg.get_all("Via")) == 2
    assert msg.cseq == (2, "INVITE")
    assert msg.body == b"body"
    assert message.header_param(msg.get("To"), "tag") == "2"


def test_build_sets_content_length_and_round_trips():
    msg = message.SipMessage(method="OPTIONS", uri="sip:pbx")
    msg.headers = [("Call-ID", "x"), ("CSeq", "1 OPTIONS"), ("Content-Length", "99")]
    msg.body = b"abc"
    back = message.parse(msg.to_bytes())
    assert back.method == "OPTIONS" and back.body == b"abc"
    assert back.get_all("Content-Length") == ["3"]


def test_stream_framer_splits_messages_and_skips_keepalives():
    one = message.SipMessage(status=200, reason="OK", headers=[("CSeq", "1 BYE")]).to_bytes()
    two = message.SipMessage(method="BYE", uri="sip:x", headers=[("CSeq", "2 BYE")], body=b"xy").to_bytes()
    framer = message.StreamFramer()
    stream = b"\r\n\r\n" + one + two
    out = framer.feed(stream[:30]) + framer.feed(stream[30:-1]) + framer.feed(stream[-1:])
    assert [m.cseq for m in out] == [(1, "BYE"), (2, "BYE")]
    assert out[1].body == b"xy"


def test_list_split_ignores_commas_in_quotes_and_uris():
    assert message.split_list('"Doe, J" <sip:a@b;x=1,2>, <sip:c@d>') == ['"Doe, J" <sip:a@b;x=1,2>', "<sip:c@d>"]


def test_response_echoes_the_transaction_and_adds_our_tag():
    req = message.parse(
        b"OPTIONS sip:me@1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/UDP 5.6.7.8;branch=z9hG4bKa\r\n"
        b"From: <sip:pbx@5.6.7.8>;tag=p\r\nTo: <sip:me@1.2.3.4>\r\nCall-ID: q\r\nCSeq: 7 OPTIONS\r\n\r\n"
    )
    resp = message.response_to(req, 200, "OK", to_tag="mine")
    assert resp.get("Via") == "SIP/2.0/UDP 5.6.7.8;branch=z9hG4bKa"
    assert resp.get("To").endswith(";tag=mine")
    assert resp.cseq == (7, "OPTIONS")


# ── Digest ──────────────────────────────────────────────────────────────────


def test_digest_matches_rfc_2617_example():
    challenge = digest.parse_challenge(
        'Digest realm="testrealm@host.com", qop="auth,auth-int", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"'
    )
    header = digest.authorization(
        challenge, method="GET", uri="/dir/index.html", username="Mufasa",
        password="Circle Of Life", cnonce="0a4f113b", nc=1,
    )
    assert 'response="6629fae49393a05397450978507c4ef1"' in header
    assert "qop=auth" in header and "nc=00000001" in header and 'opaque="5ccc069c403ebaf9f0171e9517f40e41"' in header


def test_digest_without_qop_is_the_rfc_2069_form():
    challenge = digest.parse_challenge('Digest realm="asterisk", nonce="abc", algorithm=MD5')
    header = digest.authorization(challenge, method="INVITE", uri="sip:1@pbx", username="u", password="p")
    ha1 = hashlib.md5(b"u:asterisk:p").hexdigest()
    ha2 = hashlib.md5(b"INVITE:sip:1@pbx").hexdigest()
    assert f'response="{hashlib.md5(f"{ha1}:abc:{ha2}".encode()).hexdigest()}"' in header
    assert "qop" not in header


def test_digest_refuses_what_it_cannot_answer():
    with pytest.raises(digest.DigestError):
        digest.parse_challenge('Basic realm="x"')
    with pytest.raises(digest.DigestError):
        digest.authorization(
            digest.parse_challenge('Digest realm="r", nonce="n", qop="auth-int"'),
            method="INVITE", uri="sip:x", username="u", password="p",
        )


# ── SDP ─────────────────────────────────────────────────────────────────────


def test_offer_lists_pcmu_then_pcma():
    text = sdp.offer("192.168.1.5", 10002, session_id=7).decode()
    assert "c=IN IP4 192.168.1.5" in text
    assert "m=audio 10002 RTP/AVP 0 8" in text
    assert "a=rtpmap:8 PCMA/8000" in text


def test_answer_picks_the_first_codec_we_offered_and_the_media_address():
    body = (
        b"v=0\r\no=- 1 1 IN IP4 38.0.0.1\r\ns=-\r\nc=IN IP4 38.0.0.1\r\nt=0 0\r\n"
        b"m=audio 17000 RTP/AVP 8 0 101\r\nc=IN IP4 38.0.0.9\r\na=rtpmap:101 telephone-event/8000\r\n"
    )
    assert sdp.parse_answer(body) == sdp.Answer("38.0.0.9", 17000, sdp.PCMA)


def test_answer_without_a_usable_stream_is_none():
    rejected = b"v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 0 RTP/AVP 0\r\n"
    foreign = b"v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/AVP 18\r\n"
    assert sdp.parse_answer(rejected) is None
    assert sdp.parse_answer(foreign) is None


# ── G.711 transcoding ───────────────────────────────────────────────────────


def test_g711_reference_codecs_are_bit_identical_to_audioop():
    audioop = pytest.importorskip("audioop")  # removed in Python 3.13
    for code in range(256):
        assert g711.alaw_to_linear(code) == int.from_bytes(audioop.alaw2lin(bytes([code]), 2), "little", signed=True)
        assert g711.ulaw_to_linear(code) == int.from_bytes(audioop.ulaw2lin(bytes([code]), 2), "little", signed=True)
    for pcm in range(-32768, 32768, 7):
        sample = pcm.to_bytes(2, "little", signed=True)
        assert g711.linear_to_alaw(pcm) == audioop.lin2alaw(sample, 2)[0]
        assert g711.linear_to_ulaw(pcm) == audioop.lin2ulaw(sample, 2)[0]


def test_transcoding_round_trip_keeps_the_signal():
    for code in range(256):
        back = bytes([code]).translate(g711.ULAW_TO_ALAW).translate(g711.ALAW_TO_ULAW)[0]
        before, after = g711.ulaw_to_linear(code), g711.ulaw_to_linear(back)
        assert abs(before - after) <= max(64, abs(before) // 8)


# ── RTP ─────────────────────────────────────────────────────────────────────


def test_rtp_packet_round_trip_with_csrc_extension_and_padding():
    packet = rtp.build_packet(0, 65535, 2**32 - 1, 0xDEADBEEF, b"\x01\x02", marker=True)
    assert rtp.parse_packet(packet) == (0, b"\x01\x02")
    fancy = bytearray(rtp.build_packet(8, 1, 160, 1, b""))
    fancy[0] |= 0x10 | 0x20 | 0x01  # extension, padding, one CSRC
    fancy += b"\x00\x00\x00\x01" + b"\xbe\xde\x00\x01" + b"\x00\x00\x00\x00" + b"\xaa\xbb" + b"\x00\x02"
    assert rtp.parse_packet(bytes(fancy)) == (8, b"\xaa\xbb")
    assert rtp.parse_packet(b"\x00" * 12) is None


def test_status_mapping():
    assert [status_for(c) for c in (486, 603, 480, 408, 487, 404, 503)] == [
        "busy", "busy", "no_answer", "no_answer", "canceled", "failed", "failed",
    ]


# ── A fake PBX ──────────────────────────────────────────────────────────────


class FakePbx:
    """A loopback SIP server that answers like an Asterisk trunk peer."""

    def __init__(self, *, transport="udp", final=200, ring_s=0.0, challenge=True, password=PASSWORD,
                 bye_after_s=None, codec=sdp.PCMU, answer_rtp=True):
        self.transport_name = transport
        self.final = final
        self.ring_s = ring_s
        self.challenge = challenge
        self.password = password
        self.bye_after_s = bye_after_s
        self.codec = codec
        self.answer_rtp = answer_rtp
        self.requests: list[message.SipMessage] = []
        self.rtp_in: list[bytes] = []
        self.port = 0
        self.rtp_port = 0
        self._send = None
        self._peer_rtp = None
        self._invite = None
        self._tag = "pbx" + message.new_tag()
        self._tasks = []
        self.rtp_sock = None

    async def start(self):
        loop = asyncio.get_running_loop()
        outer = self

        class _Rtp(asyncio.DatagramProtocol):
            def connection_made(self, t):
                outer.rtp_sock = t

            def datagram_received(self, data, addr):
                parsed = rtp.parse_packet(data)
                if parsed:
                    outer.rtp_in.append(parsed[1])

        await loop.create_datagram_endpoint(_Rtp, local_addr=("127.0.0.1", 0))
        self.rtp_port = self.rtp_sock.get_extra_info("sockname")[1]
        if self.transport_name == "udp":
            class _Udp(asyncio.DatagramProtocol):
                def connection_made(self, t):
                    outer._udp = t

                def datagram_received(self, data, addr):
                    if not data.strip(b"\r\n"):
                        return
                    outer._send = lambda b: outer._udp.sendto(b, addr)
                    outer.on_message(message.parse(data))

            await loop.create_datagram_endpoint(_Udp, local_addr=("127.0.0.1", 0))
            self.port = self._udp.get_extra_info("sockname")[1]
        else:
            async def handle(reader, writer):
                self._send = writer.write
                framer = message.StreamFramer()
                while data := await reader.read(4096):
                    for msg in framer.feed(data):
                        self.on_message(msg)

            self._server = await asyncio.start_server(handle, "127.0.0.1", 0)
            self.port = self._server.sockets[0].getsockname()[1]
        return self

    def account(self, **kw):
        return SipAccount(server="127.0.0.1", port=self.port, transport=self.transport_name,
                          username="voicestudio", password=kw.pop("password", PASSWORD),
                          rtp_port_min=31000, rtp_port_max=31999, **kw)

    def methods(self):
        return [m.method for m in self.requests]

    def respond(self, req, status, reason, *, body=b"", tag=True):
        resp = message.response_to(req, status, reason, to_tag=self._tag if tag else "")
        if status == 401:
            resp.headers.append(("WWW-Authenticate", 'Digest algorithm=MD5, realm="asterisk", nonce="n0nce"'))
        if 200 <= status < 300 and req.method == "INVITE":
            resp.headers.append(("Contact", f"<sip:{req.uri.split(':', 1)[1].split('@')[0]}@127.0.0.1:{self.port}>"))
            resp.headers.append(("Content-Type", "application/sdp"))
            resp.body = body
        self._send(resp.to_bytes())

    def on_message(self, msg):
        if not msg.is_request:
            return
        self.requests.append(msg)
        if msg.method == "INVITE":
            self._invite = msg
            if self.challenge and not msg.get("Authorization"):
                self.respond(msg, 401, "Unauthorized", tag=True)
                return
            if self.challenge:
                expected = digest.authorization(
                    digest.parse_challenge('Digest realm="asterisk", nonce="n0nce"'),
                    method="INVITE", uri=msg.uri, username="voicestudio", password=self.password,
                )
                got = message.header_param(";" + msg.get("Authorization").replace(", ", ";"), "response")
                want = message.header_param(";" + expected.replace(", ", ";"), "response")
                if got != want:
                    self.respond(msg, 401, "Unauthorized")
                    return
            offer = sdp.parse_answer(msg.body)
            self._peer_rtp = (offer.address, offer.port)
            self.respond(msg, 100, "Trying", tag=False)
            self.respond(msg, 180, "Ringing")
            self._tasks.append(asyncio.ensure_future(self._final(msg)))
        elif msg.method == "CANCEL":
            self.respond(msg, 200, "OK")
            self.respond(self._invite, 487, "Request Terminated")
        elif msg.method == "BYE":
            self.respond(msg, 200, "OK")

    async def _final(self, invite):
        await asyncio.sleep(self.ring_s)
        if self.final != 200:
            self.respond(invite, self.final, "Busy Here" if self.final == 486 else "Nope")
            return
        body = sdp.offer("127.0.0.1", self.rtp_port, session_id=1, payload_types=(self.codec,))
        self.respond(invite, 200, "OK", body=body)
        if self.bye_after_s is not None:
            await asyncio.sleep(self.bye_after_s)
            bye = message.SipMessage(method="BYE", uri="sip:voicestudio@127.0.0.1")
            bye.headers = [
                ("Via", f"SIP/2.0/{self.transport_name.upper()} 127.0.0.1:{self.port};branch={message.new_branch()}"),
                ("From", f"{invite.get('To')};tag={self._tag}"),
                ("To", invite.get("From")),
                ("Call-ID", invite.get("Call-ID")),
                ("CSeq", "1 BYE"),
            ]
            self._send(bye.to_bytes())

    def send_rtp(self, payload: bytes, pt=None):
        self.rtp_sock.sendto(rtp.build_packet(self.codec if pt is None else pt, 1, 0, 9, payload), self._peer_rtp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=20))


# ── The call against the fake PBX ───────────────────────────────────────────


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_call_authenticates_rings_answers_carries_audio_and_hangs_up(transport):
    async def scenario():
        pbx = await FakePbx(transport=transport).start()
        rang = []
        call = OutboundCall(pbx.account(), NUMBER, on_ringing=lambda: rang.append(True))
        await call.start()
        assert await call.answered() is True
        heard = []
        call.rtp.on_audio = heard.append
        call.rtp.send(b"\x11" * 160)
        pbx.send_rtp(b"\x22" * 160)
        pbx.send_rtp(b"\x33" * 160, pt=101)  # DTMF event: ignored
        await asyncio.sleep(0.2)
        end = await call.hangup()
        await asyncio.sleep(0.05)
        return pbx, rang, heard, end

    pbx, rang, heard, end = run(scenario())
    assert rang == [True]
    assert pbx.methods() == ["INVITE", "ACK", "INVITE", "ACK", "BYE"]
    invite = pbx.requests[2]
    assert invite.uri == "sip:5527999990000@127.0.0.1"  # digits, no plus
    assert invite.get("Authorization").startswith("Digest ")
    assert invite.cseq[0] == pbx.requests[0].cseq[0] + 1
    ack = pbx.requests[3]
    assert message.header_param(ack.get("To"), "tag", ) is not None
    assert pbx.rtp_in == [b"\x11" * 160]
    assert heard == [b"\x22" * 160]
    assert end == CallEnd("completed", 0, "Hung up")


def test_a_law_line_is_transcoded_both_ways():
    async def scenario():
        pbx = await FakePbx(codec=sdp.PCMA).start()
        call = OutboundCall(pbx.account(), NUMBER)
        await call.start()
        assert await call.answered()
        heard = []
        call.rtp.on_audio = heard.append
        ulaw = bytes(range(160))
        call.rtp.send(ulaw)
        pbx.send_rtp(ulaw.translate(g711.ULAW_TO_ALAW))
        await asyncio.sleep(0.2)
        await call.hangup()
        return pbx, heard, ulaw

    pbx, heard, ulaw = run(scenario())
    assert pbx.rtp_in == [ulaw.translate(g711.ULAW_TO_ALAW)]
    assert heard == [ulaw.translate(g711.ULAW_TO_ALAW).translate(g711.ALAW_TO_ULAW)]


def test_busy_line_ends_busy_with_an_ack():
    async def scenario():
        pbx = await FakePbx(final=486).start()
        call = OutboundCall(pbx.account(), NUMBER)
        await call.start()
        answered = await call.answered()
        await asyncio.sleep(0.05)
        return pbx, answered, await call.ended()

    pbx, answered, end = run(scenario())
    assert answered is False
    assert end.status == "busy" and end.code == 486
    assert pbx.methods()[-1] == "ACK"


def test_wrong_password_fails_without_looping():
    async def scenario():
        pbx = await FakePbx(password="other").start()
        call = OutboundCall(pbx.account(), NUMBER)
        await call.start()
        await call.answered()
        return pbx, await call.ended()

    pbx, end = run(scenario())
    assert end.status == "failed" and end.code == 401
    assert pbx.methods().count("INVITE") == 2


def test_hangup_while_ringing_sends_cancel():
    async def scenario():
        pbx = await FakePbx(ring_s=30).start()
        call = OutboundCall(pbx.account(), NUMBER)
        await call.start()
        await asyncio.sleep(0.2)  # 180 arrives
        return pbx, await call.hangup()

    pbx, end = run(scenario())
    assert "CANCEL" in pbx.methods()
    assert end.status == "canceled" and end.code == 487


def test_ring_timeout_ends_as_no_answer():
    async def scenario():
        pbx = await FakePbx(ring_s=30).start()
        call = OutboundCall(pbx.account(), NUMBER, ring_timeout_s=0.3)
        await call.start()
        return await call.ended()

    assert run(scenario()).status == "no_answer"


def test_remote_bye_ends_the_call_and_notifies():
    async def scenario():
        pbx = await FakePbx(bye_after_s=0.2).start()
        ended = []
        call = OutboundCall(pbx.account(), NUMBER, on_hangup=ended.append)
        await call.start()
        assert await call.answered()
        end = await call.ended()
        return end, ended

    end, ended = run(scenario())
    assert end.status == "completed"
    assert ended == [end]


def test_unreachable_server_raises_a_mappable_error():
    async def scenario():
        account = SipAccount(server="127.0.0.1", port=9, transport="tcp", username="u", password="p")
        with pytest.raises(SipError) as info:
            await OutboundCall(account, NUMBER).start()
        return info.value.code

    assert run(scenario()) == "unreachable"


def test_options_ping_reports_the_status():
    async def scenario():
        pbx = await FakePbx().start()
        original = pbx.on_message

        def on_message(msg):
            if msg.method == "OPTIONS":
                pbx.respond(msg, 200, "OK")
            else:
                original(msg)

        pbx.on_message = on_message
        return await options_ping(pbx.account())

    assert run(scenario()) == 200


# ── The bridge: the call loop over RTP ──────────────────────────────────────


class _FakeRtp:
    def __init__(self):
        self.sent: list[bytes] = []
        self.on_audio = None

    def send(self, frame):
        self.sent.append(frame)


class _Responder:
    """Speaks two frames and a mark, then ends; records what it hears."""

    def __init__(self):
        self.heard = []
        self.marks = []

    async def speak(self):
        yield b"\x01" * 200  # not a whole frame: the bridge re-frames it
        yield session_mod.Mark("agent-1")
        yield b"\x02" * 120

    async def on_inbound_audio(self, ulaw):
        self.heard.append(ulaw)

    async def on_mark(self, name):
        self.marks.append(name)


def test_bridge_runs_the_call_loop_paced_with_marks_and_inbound_audio():
    from services.telephony import twilio as wire

    async def scenario():
        fake = _FakeRtp()
        closed = []

        async def on_close():
            closed.append(True)

        token = session_mod.tokens.issue(session_mod.token_subject("call-1", "s1"))
        bridge = MediaStreamBridge(fake, call_id="call-1", account_id="sip",
                                   params={"token": token, "call": "s1"}, on_close=on_close)
        responder = _Responder()
        fake.on_audio(b"\x7f" * 160)  # caller audio before the loop starts is queued
        outcome = await session_mod.run_call(
            bridge, wire, account_id="sip", responder_factory=lambda start: responder,
            max_calls=2, max_seconds=10,
        )
        return outcome, fake.sent, responder, closed

    outcome, sent, responder, closed = run(scenario())
    assert outcome == "completed"
    frames = [f for f in sent if f != b"\xff" * 160]
    assert frames[0] == b"\x01" * 160
    assert frames[1] == b"\x01" * 40 + b"\xff" * 120  # padded before the mark
    assert frames[2] == b"\x02" * 120 + b"\xff" * 40
    assert all(len(f) == 160 for f in sent)
    assert responder.marks == ["agent-1"]
    assert responder.heard == [b"\x7f" * 160]
    assert closed == [True]


def test_bridge_clear_drops_audio_and_releases_its_marks():
    async def scenario():
        fake = _FakeRtp()
        bridge = MediaStreamBridge(fake, call_id="c", account_id="sip", params={})
        await bridge.receive_text()  # start
        payload = base64.b64encode(b"\x05" * 1600).decode()
        await bridge.send_json({"event": "media", "media": {"payload": payload}})
        await bridge.send_json({"event": "mark", "mark": {"name": "m1"}})
        await bridge.send_json({"event": "clear"})
        echoed = json.loads(await bridge.receive_text())
        bridge.end()
        stop = json.loads(await bridge.receive_text())
        with pytest.raises(RuntimeError):
            await bridge.receive_text()
        return echoed, stop

    echoed, stop = run(scenario())
    assert echoed["event"] == "mark" and echoed["mark"]["name"] == "m1"
    assert stop["event"] == "stop"


def test_bridge_paces_one_frame_per_20_ms():
    async def scenario():
        fake = _FakeRtp()
        bridge = MediaStreamBridge(fake, call_id="c", account_id="sip", params={})
        await bridge.accept()
        await asyncio.sleep(0.5)
        await bridge.close()
        return len(fake.sent)

    # 25 packets in 0.5 s; generous bounds for a loaded CI box.
    assert 18 <= run(scenario()) <= 30


# ── VoiceStudio glue: a call-agent session over the trunk ───────────────────


@pytest.fixture()
def sip_store(monkeypatch):
    import services

    settings_store = importlib.import_module("services.settings_store")
    monkeypatch.setattr(services, "settings_store", settings_store, raising=False)
    text, secrets_ = {}, {}
    monkeypatch.setattr(settings_store, "get_text", lambda k, d=None: text.get(k, d))
    monkeypatch.setattr(settings_store, "set_text", lambda k, v: text.__setitem__(k, v))
    monkeypatch.setattr(settings_store, "get_secret", lambda n: secrets_.get(n))
    monkeypatch.setattr(
        settings_store, "set_secret",
        lambda n, v: secrets_.__setitem__(n, v) if v else secrets_.pop(n, None),
    )
    monkeypatch.setattr(settings_store, "list_secret_names", lambda: list(secrets_))
    return text


def test_config_round_trip_and_carrier_switch(sip_store):
    from services.telephony import config

    assert config.outbound_carrier() == "twilio"
    cfg = config.SipConfig(enabled=True, server="sip01.example.com", port=5060, transport="tcp",
                           username="voicestudio")
    config.save_sip(cfg)
    config.set_sip_password("pw")
    assert config.load_sip() == cfg
    assert config.sip_password() == "pw"
    assert config.sip_missing(cfg, True) == []
    assert config.outbound_carrier() == "sip"
    assert config.normalize_sip_host("203.0.113.10") == "203.0.113.10"
    with pytest.raises(config.ConfigError):
        config.normalize_sip_host("bad host!")
    with pytest.raises(config.ConfigError):
        config.normalize_rtp_range(20000, 20001)


def test_readiness_over_sip_has_no_twilio_items(sip_store, monkeypatch):
    from services.telephony import calls, config

    config.save_sip(config.SipConfig(enabled=True, server="pbx", username="vs"))
    monkeypatch.setattr(calls, "llm_status", lambda: (True, "ok"))
    monkeypatch.setattr(calls, "asr_status", lambda: (True, "ok"))
    monkeypatch.setattr(calls, "count_eligible_profiles", lambda: 1)
    items = calls.readiness()
    assert [i["id"] for i in items] == ["sip", "llm", "asr", "voice"]
    assert items[0]["ok"] is False and "password" in items[0]["detail"]
    config.set_sip_password("pw")
    assert calls.readiness()[0]["ok"] is True


def test_agent_call_over_the_trunk_end_to_end(sip_store, monkeypatch):
    from services.telephony import calls, config

    finished = []

    def fake_connect(session_id, call_id):
        live = calls.get_live(session_id)
        assert live.provider_call_id == call_id
        live.stream_connected = True
        live.set_status("in_progress")
        responder = _Responder()
        responder.call = live
        return responder

    async def fake_finish(call_session, outcome, agent=None):
        finished.append((outcome, call_session.status))
        calls._complete(call_session, "completed")

    monkeypatch.setattr(calls, "connect_stream", fake_connect)
    monkeypatch.setattr(calls, "finish", fake_finish)
    monkeypatch.setattr(calls, "store_save", lambda s: None)

    async def scenario():
        pbx = await FakePbx(transport="tcp").start()
        config.save_sip(config.SipConfig(enabled=True, server="127.0.0.1", port=pbx.port, transport="tcp",
                                         username="voicestudio", rtp_port_min=32000, rtp_port_max=32999))
        config.set_sip_password(PASSWORD)
        live = calls._register(calls.CallSession(
            id="sess1", direction="outbound", remote_number=NUMBER, from_number="",
            brief="test", profile_id="p",
        ))
        statuses = []
        live.publish = lambda event: statuses.append(event.get("status"))
        await calls.place(live)
        for _ in range(200):
            if live.finalized:
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.1)
        return pbx, live, statuses

    pbx, live, statuses = run(scenario())
    assert finished == [("completed", "in_progress")]
    assert live.status == "completed"
    assert "ringing" in statuses
    assert pbx.methods() == ["INVITE", "ACK", "INVITE", "ACK", "BYE"]
    assert any(p.startswith(b"\x01") for p in pbx.rtp_in)


def test_unreachable_trunk_fails_the_session(sip_store, monkeypatch):
    from services.telephony import calls, config

    monkeypatch.setattr(calls, "store_save", lambda s: None)
    config.save_sip(config.SipConfig(enabled=True, server="127.0.0.1", port=9, transport="tcp", username="vs"))
    config.set_sip_password("pw")
    live = calls._register(calls.CallSession(
        id="sess2", direction="outbound", remote_number=NUMBER, from_number="", brief="b", profile_id="p",
    ))
    with pytest.raises(calls.CallError) as info:
        run(calls.place(live))
    assert info.value.code == "sip_error"
    assert live.finalized and live.status == "failed"
