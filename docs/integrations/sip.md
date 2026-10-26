# SIP trunk: place calls through your own PBX

The [call agent](calls.md) can dial through a PBX you already run (Asterisk,
Issabel, FreePBX…) instead of Twilio. VoiceStudio connects to the PBX as a SIP
trunk peer, the PBX authenticates it like any other trunk and sends the call out
through its own lines. Calls leave with the caller ID and the line costs your PBX
already has.

Every connection is opened from this computer: there is no webhook, no tunnel
and no port to forward. When the SIP trunk is enabled it places every outbound
call; Twilio, if configured, keeps answering incoming calls.

## What you need

- A trunk peer on the PBX for VoiceStudio: a peer name, a password, and a dial
  plan context that sends the numbers it dials out through an outgoing route.
- The PBX reachable from this computer on its SIP port (UDP or TCP 5060), and
  the PBX firewall accepting this computer's address.
- Everything else the [call agent](calls.md#what-you-need) needs: an LLM, a
  speech recognition model and a voice that may place calls.

## Setup

The settings live in the API for now (there is no Integrations page yet):

```http
PUT /api/integrations/sip/config
{
  "server": "pbx.example.com",
  "port": 5060,
  "transport": "tcp",
  "username": "voicestudio",
  "password": "…",
  "enabled": true
}
```

| Field | Meaning |
| --- | --- |
| `server`, `port` | The PBX address and SIP port. |
| `transport` | `udp` or `tcp`. Prefer `tcp` when this computer is behind NAT: the signalling stays on one connection for the whole call. |
| `username`, `password` | The peer name and secret. `password` is stored encrypted and never returned; `""` clears it. |
| `auth_username` | Only when the PBX authenticates a different name than the peer. |
| `domain` | The host in the SIP URIs; the server when empty. |
| `local_address` | The address advertised to the PBX; the interface that routes to it when empty. |
| `rtp_port_min`, `rtp_port_max` | The UDP ports used for call audio (default 10000–10999). |

`GET /api/integrations/sip/state` shows the settings (without the password) and
what is missing. `POST /api/integrations/sip/test` sends an OPTIONS ping and
returns the PBX's answer; it proves the PBX is reachable, not that the password
is right. The first call proves that.

With the trunk enabled, `GET /calls/readiness` returns `sip`, `llm`, `asr` and
`voice`.

## The PBX side (Asterisk `chan_sip`)

A peer for VoiceStudio and a context that dials out:

```ini
; sip_custom.conf
[voicestudio]
type=friend
host=dynamic
secret=<a long random password>
context=from-voicestudio
insecure=no
nat=force_rport,comedia
transport=tcp,udp
disallow=all
allow=ulaw,alaw
directmedia=no
qualify=no
```

```ini
; extensions_custom.conf
[from-voicestudio]
exten => _X.,1,Set(CALLERID(num)=<the line's number>)
 same => n,Dial(SIP/<outgoing trunk>/${EXTEN},60)
 same => n,Hangup()
```

`nat=force_rport,comedia` lets the PBX reply to the address the packets come
from, so a computer behind NAT needs no port forwarding. `directmedia=no` keeps
the audio flowing through the PBX, where the caller's audio is sent to the
address VoiceStudio sends from.

## How a call works

1. `POST /calls` creates the session and VoiceStudio sends an INVITE with an
   offer of G.711 μ-law and A-law. The PBX challenges it (401 or 407) and it
   answers with digest credentials.
2. Ringing (180/183) shows as `ringing`. A busy line, no answer, a decline or a
   failure ends the call with the matching status. After 60 seconds of ringing
   VoiceStudio cancels the call as unanswered.
3. On 200 OK the audio starts in 20 ms RTP packets, and the call agent runs
   exactly as it does for a Twilio call: same disclosure, turns, barge-in,
   transcript, recording rules and summary.
4. Whoever hangs up, the other side gets a BYE, and the call is finalized.

## Limits

- Outbound calls only: incoming calls still come through Twilio.
- G.711 only (μ-law or A-law). No TLS or SRTP, no DTMF, no registration.
- The same call limits as Twilio calls (`max_concurrent`, the call length cap).

## Troubleshooting

- **`unreachable`**: the PBX does not answer on that address, port and
  transport. Check the firewall on both sides.
- **The call fails with 401 or 407**: the PBX refused the peer name or password.
- **The call connects but nobody hears anything**: the PBX is sending audio to
  the advertised address instead of the source address. Set
  `nat=force_rport,comedia` on the peer, or set `local_address` to the address
  the PBX sees.
- **The call fails with 404 or 503**: the context does not route the number.
  VoiceStudio dials the E.164 digits without the plus, such as `5527999990000`.
