"""Outbound call-agent calls through the SIP trunk.

The Twilio path is webhook-driven: Twilio answers, calls our voice webhook,
then opens the media WebSocket. Over SIP we own the whole call, so this module
plays both parts on the main event loop: it places the INVITE, maps SIP
progress onto the same session statuses (:func:`calls.on_provider_status`),
and once the PBX answers runs the same provider-agnostic call loop
(:func:`session.run_call`) over a :class:`~sip.bridge.MediaStreamBridge`.
Everything after that — the agent, transcript, summary, record — is shared
with Twilio calls.
"""
from __future__ import annotations

import asyncio
import logging
import threading

from services.telephony import calls, config, session
from services.telephony import twilio as wire
from services.telephony.sip.bridge import MediaStreamBridge
from services.telephony.sip.ua import OutboundCall, SipError

logger = logging.getLogger("omnivoice.telephony.sip")

#: The stream's account id. The bridge is created here, so this only has to
#: match itself; the per-call token is what binds the stream to the session.
ACCOUNT_ID = "sip"
#: Ring time before the call is given up as unanswered.
RING_TIMEOUT_S = 60.0

_live: dict[str, tuple[OutboundCall, asyncio.AbstractEventLoop]] = {}
_live_lock = threading.Lock()
_tasks: set[asyncio.Task] = set()


async def place(call_session: calls.CallSession) -> None:
    """Send the INVITE; the rest of the call runs in the background.

    Raises CallError when the PBX cannot be reached at all (the session is
    finalized as failed first), mirroring a Twilio REST error.
    """
    cfg = config.load_sip()
    call = OutboundCall(
        cfg.account(config.sip_password()),
        call_session.remote_number,
        ring_timeout_s=RING_TIMEOUT_S,
        on_ringing=lambda: calls.on_provider_status(call_session.id, call.call_id, "ringing"),
    )
    with call_session._lock:
        call_session.provider_call_id = call.call_id
    try:
        await call.start()
    except SipError as exc:
        calls.finish_unconnected(call_session, "failed", error=str(exc))
        raise calls.CallError(502, "sip_error", str(exc), sip_code=exc.code) from exc
    call_session.set_status("initiated")
    with _live_lock:
        _live[call_session.id] = (call, asyncio.get_running_loop())
    task = asyncio.ensure_future(_run(call_session, call))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def cancel(session_id: str) -> bool:
    """Thread-safe hang-up for a call that is not connected to the agent yet
    (the agent hangs up a connected one). False when no SIP call is live."""
    with _live_lock:
        entry = _live.get(session_id)
    if entry is None:
        return False
    call, loop = entry
    if loop.is_closed():
        return False
    loop.call_soon_threadsafe(lambda: asyncio.ensure_future(call.hangup()))
    return True


async def _run(call_session: calls.CallSession, call: OutboundCall) -> None:
    try:
        if not await call.answered():
            end = await call.ended()
            calls.on_provider_status(call_session.id, call.call_id, end.status)
            if not call_session.finalized:  # a status on_provider_status ignores
                calls.finish_unconnected(call_session, "failed", error=end.reason)
            return
        await _converse(call_session, call)
    except Exception:
        logger.exception("SIP call failed")
        if not call_session.finalized:
            calls.finish_unconnected(call_session, "failed", error="The SIP call failed")
    finally:
        await call.hangup()
        with _live_lock:
            _live.pop(call_session.id, None)


async def _converse(call_session: calls.CallSession, call: OutboundCall) -> None:
    token = session.tokens.issue(session.token_subject(call.call_id, call_session.id))
    bridge = MediaStreamBridge(
        call.rtp,
        call_id=call.call_id,
        account_id=ACCOUNT_ID,
        params={"token": token or "", "call": call_session.id},
        on_close=call.hangup,
    )
    call.on_hangup = lambda _end: bridge.end()
    agent_call: dict = {}

    def _responder(start):
        agent = calls.connect_stream(start.params.get("call", ""), start.call_id)
        if agent is not None:
            agent_call["agent"] = agent
        return agent

    outcome = "error"
    try:
        outcome = await session.run_call(
            bridge,
            wire,
            account_id=ACCOUNT_ID,
            responder_factory=_responder,
            max_calls=config.max_concurrent_calls(),
            max_seconds=config.max_call_seconds(),
        )
    finally:
        agent = agent_call.get("agent")
        if agent is not None:
            await asyncio.shield(calls.finish(agent.call, outcome, agent))
        elif not call_session.finalized:
            calls.finish_unconnected(call_session, "failed", error=outcome)
