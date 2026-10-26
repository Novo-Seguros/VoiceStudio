"""Process-local Nexus session and PKCE state store."""

from __future__ import annotations

import pytest

from services.nexus_auth import NexusIdentity
from services.nexus_sessions import (
    ACCESS_GRACE_SECONDS,
    NEXUS_SESSION_PREFIX,
    REFRESH_SKEW_SECONDS,
    SESSION_TTL_SECONDS,
    STATE_TTL_SECONDS,
    NexusSessionStore,
)


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def identity(*, access_exp: float, refresh: str = "r1", caps=("consume",)) -> NexusIdentity:
    return NexusIdentity(
        sub="sub-1",
        email="ana@novoseguros.com.br",
        name="Ana Lima",
        capabilities=frozenset(caps),
        access_token="access-secret",
        refresh_token=refresh,
        access_expires_at=access_exp,
    )


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return NexusSessionStore(wall_time=clock)


def test_issue_and_resolve(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 3600))
    assert issued.token.startswith(NEXUS_SESSION_PREFIX)
    assert issued.expires_at == clock.now + SESSION_TTL_SECONDS
    record = store.resolve(issued.token)
    assert record is not None
    assert record.email == "ana@novoseguros.com.br"
    assert record.capabilities == frozenset({"consume"})
    assert len(record.credential_id) == 64


@pytest.mark.parametrize(
    "token",
    [None, "", "ovs_nexus_session_short", "ovs_admin_session_" + "a" * 43, "x" * 61],
)
def test_malformed_tokens_resolve_to_none(store, token):
    assert store.resolve(token) is None


def test_session_expires_after_ttl(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 10 * 3600))
    clock.now += SESSION_TTL_SECONDS
    assert store.resolve(issued.token) is None
    assert store.record_for_token(issued.token) is None


def test_access_grace_window(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 60))
    clock.now += 60 + ACCESS_GRACE_SECONDS - 1
    assert store.resolve(issued.token) is not None
    clock.now += 2
    assert store.resolve(issued.token) is None
    # Still reachable for a late refresh until the session TTL ends.
    assert store.record_for_token(issued.token) is not None


def test_needs_refresh_inside_the_skew(store, clock):
    issued = store.issue(identity(access_exp=clock.now + REFRESH_SKEW_SECONDS + 1))
    record = store.record_for_token(issued.token)
    assert not record.needs_refresh(clock.now)
    assert record.needs_refresh(clock.now + 1)


def test_update_identity_swaps_tokens_and_keeps_expiry(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 60))
    record = store.record_for_token(issued.token)
    assert store.update_identity(
        record.credential_id,
        identity(access_exp=clock.now + 3600, refresh="r2", caps=("consume", "admin")),
    )
    updated = store.get(record.credential_id)
    assert updated.refresh_token == "r2"
    assert updated.capabilities == frozenset({"consume", "admin"})
    assert updated.access_expires_at == clock.now + 3600
    assert updated.expires_at == record.expires_at
    assert not store.update_identity("0" * 64, identity(access_exp=0))


def test_revoke_returns_the_record(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 3600))
    record = store.record_for_token(issued.token)
    revoked = store.revoke_by_credential(record.credential_id)
    assert revoked.refresh_token == "r1"
    assert store.resolve(issued.token) is None
    assert store.revoke_by_credential(record.credential_id) is None


def test_capacity_evicts_the_oldest(clock):
    store = NexusSessionStore(wall_time=clock, max_sessions=2)
    first = store.issue(identity(access_exp=clock.now + 3600))
    second = store.issue(identity(access_exp=clock.now + 3600))
    third = store.issue(identity(access_exp=clock.now + 3600))
    assert store.resolve(first.token) is None
    assert store.resolve(second.token) is not None
    assert store.resolve(third.token) is not None


def test_state_is_single_use_and_expires(store, clock):
    store.save_state("s1", "v1")
    assert store.pop_state("s1") == "v1"
    assert store.pop_state("s1") is None
    store.save_state("s2", "v2")
    clock.now += STATE_TTL_SECONDS
    assert store.pop_state("s2") is None
    assert store.pop_state(None) is None


def test_refresh_lock_is_per_credential(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 3600))
    credential = store.record_for_token(issued.token).credential_id
    assert store.refresh_lock(credential) is store.refresh_lock(credential)
    assert store.refresh_lock(credential) is not store.refresh_lock("other")


def test_repr_never_leaks_tokens(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 3600))
    record = store.record_for_token(issued.token)
    assert "access-secret" not in repr(record)
    assert "r1" not in repr(record)
    assert issued.token not in repr(store)


def test_clear_drops_everything(store, clock):
    issued = store.issue(identity(access_exp=clock.now + 3600))
    store.save_state("s", "v")
    store.clear()
    assert store.resolve(issued.token) is None
    assert store.pop_state("s") is None
