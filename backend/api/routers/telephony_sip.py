"""SIP trunk integration: outbound calls through a company PBX.

Admin-only, main backend. Nothing here listens on the network: the trunk is
used only when a call is placed (``POST /calls``), and every connection is
opened from this machine. The password is stored encrypted and never returned.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from services.telephony import config
from services.telephony.sip.ua import SipError, options_ping

from api.dependencies import require_admin

router = APIRouter(
    prefix="/api/integrations/sip",
    tags=["integrations"],
    dependencies=[Depends(require_admin)],
)


def _state() -> dict:
    cfg = config.load_sip()
    password = config.has_sip_password()
    return {
        **cfg.as_dict(),
        "has_password": password,
        "missing": config.sip_missing(cfg, password),
        "carrier": config.outbound_carrier(),
    }


class _ConfigBody(BaseModel):
    enabled: bool | None = None
    server: str | None = Field(None, max_length=253)
    port: int | None = None
    transport: str | None = Field(None, max_length=8)
    username: str | None = Field(None, max_length=64)
    password: str | None = Field(None, max_length=256, description="'' clears, None keeps")
    auth_username: str | None = Field(None, max_length=64)
    domain: str | None = Field(None, max_length=253)
    local_address: str | None = Field(None, max_length=253)
    rtp_port_min: int | None = None
    rtp_port_max: int | None = None


@router.get("/state")
def get_state():
    return _state()


@router.put("/config")
def put_config(body: _ConfigBody):
    current = config.load_sip()

    def pick(name: str, normalize):
        value = getattr(body, name)
        return getattr(current, name) if value is None else normalize(value)

    try:
        rtp_min, rtp_max = config.normalize_rtp_range(
            pick("rtp_port_min", int), pick("rtp_port_max", int)
        )
        updated = config.SipConfig(
            enabled=current.enabled if body.enabled is None else body.enabled,
            server=pick("server", config.normalize_sip_host),
            port=pick("port", config.normalize_port),
            transport=pick("transport", config.normalize_sip_transport),
            username=pick("username", config.normalize_sip_user),
            auth_username=pick("auth_username", config.normalize_sip_user),
            domain=pick("domain", lambda v: config.normalize_sip_host(v, code="invalid_sip_domain")),
            local_address=pick(
                "local_address", lambda v: config.normalize_sip_host(v, code="invalid_local_address")
            ),
            rtp_port_min=rtp_min,
            rtp_port_max=rtp_max,
        )
    except config.ConfigError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": str(exc)}) from exc
    if body.password is not None:
        config.set_sip_password(body.password)
    missing = config.sip_missing(updated, config.has_sip_password())
    if updated.enabled and missing:
        # Save the fields, but never route calls to a half-configured trunk.
        config.save_sip(config.SipConfig(**{**updated.__dict__, "enabled": False}))
        raise HTTPException(
            status_code=400,
            detail={"code": "incomplete", "missing": missing, "message": "Complete the setup first"},
        )
    config.save_sip(updated)
    return _state()


@router.post("/test")
async def test_trunk():
    """OPTIONS ping to the PBX: proves the server answers on this transport.
    It does not prove the password (PBXs do not challenge OPTIONS); the first
    call does."""
    cfg = config.load_sip()
    if not cfg.server:
        raise HTTPException(400, detail={"code": "missing_server", "message": "Enter the SIP server first"})
    try:
        status = await options_ping(cfg.account(""))
    except SipError as exc:
        raise HTTPException(502, detail={"code": exc.code, "message": str(exc)}) from exc
    return {"ok": True, "status": status}
