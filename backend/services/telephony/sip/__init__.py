"""A small SIP user agent that places outbound calls through a PBX trunk.

It exists so the call agent can dial through a company's own PBX (Asterisk,
Issabel, FreePBX…) instead of a cloud carrier. The PBX authenticates the
INVITE with digest auth, as it does for any SIP trunk peer, and routes the
call out through its own lines, so no public webhook or tunnel is needed:
every connection is opened from this machine.

Self-contained on purpose — stdlib only, nothing imported from the rest of
VoiceStudio — so the dialer can be reused by other services:

- ``message`` — SIP message parsing, building and stream framing (RFC 3261)
- ``digest``  — HTTP digest authentication for SIP (RFC 2617 / 7616)
- ``sdp``     — the audio offer and the answer parser (RFC 4566)
- ``g711``    — μ-law ⇄ A-law transcoding tables
- ``rtp``     — the RTP endpoint (RFC 3550): packets in and out
- ``ua``      — :class:`OutboundCall`: INVITE, CANCEL, BYE and the dialog
- ``bridge``  — the RTP leg dressed as a Media Streams WebSocket, so the
  provider-agnostic call loop (``services.telephony.session``) runs unchanged

Scope: outbound calls, G.711 audio, UDP or TCP signalling. No registration,
no inbound calls, no TLS/SRTP, no DTMF.
"""
