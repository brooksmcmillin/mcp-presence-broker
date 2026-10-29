import concurrent.futures
import json
import sqlite3
from pathlib import Path

import pyotp
import pytest

from presence_broker.store import CAPABILITY, LOCKOUT_SECONDS, MAX_FAILURES, Denied, Store


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Store:
    monkeypatch.setattr("presence_broker.store.time.time", lambda: 1_800_000_000.0)
    return Store.initialize(tmp_path / "state")


def code(store: Store, offset: int = 0) -> str:
    return pyotp.TOTP(store.secret).at(1_800_000_000 + offset)


def test_lifecycle(store: Store) -> None:
    token = store.create_session("a")
    other = store.create_session("b")
    with pytest.raises(Denied, match="capability_denied"):
        store.increment(token)
    with pytest.raises(Denied, match="presence_check_failed"):
        store.request_grant(token, None)
    assert store.grants(token) == []
    grant = store.request_grant(token, code(store))
    assert grant["capability"] == CAPABILITY
    assert store.increment(token) == 1
    with pytest.raises(Denied, match="capability_denied"):
        store.increment(other)
    with pytest.raises(Denied, match="replayed_code"):
        store.request_grant(other, code(store))
    store.revoke(token)
    assert store.grants(token) == []
    with pytest.raises(Denied, match="capability_denied"):
        store.increment(token)
    events = store.audit()
    issued = [row for row in events if row["event"] == "grant_issued"]
    assert len(issued) == 1
    assert issued[0]["session_id"] == 1
    assert json.loads(str(issued[0]["detail"]))["totp_verified"] is True
    serialized = json.dumps(events)
    assert token not in serialized and store.secret not in serialized
    assert code(store) not in serialized


def test_expiry_is_checked_on_execution(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    token = store.create_session("a")
    store.request_grant(token, code(store), ttl=1)
    monkeypatch.setattr("presence_broker.store.time.time", lambda: 1_800_000_001.0)
    assert store.grants(token) == []
    with pytest.raises(Denied, match="capability_denied"):
        store.increment(token)


def test_revoked_session_cannot_use_existing_grant(store: Store) -> None:
    token = store.create_session("a")
    store.request_grant(token, code(store))
    store.revoke_session(1)
    with pytest.raises(Denied, match="invalid_session"):
        store.increment(token)
    with pytest.raises(Denied, match="invalid_session"):
        store.authenticate(token)


@pytest.mark.parametrize("ttl", [0, -1, 301])
def test_invalid_ttl_does_not_consume_code(store: Store, ttl: int) -> None:
    token = store.create_session("a")
    with pytest.raises(Denied, match="invalid_request"):
        store.request_grant(token, code(store), ttl=ttl)
    assert store.request_grant(token, code(store))


def test_unknown_capability(store: Store) -> None:
    token = store.create_session("a")
    with pytest.raises(Denied, match="invalid_request"):
        store.request_grant(token, code(store), capability="shell.exec")
    assert store.grants(token) == []


@pytest.mark.parametrize("bad", [None, "", "accept", "１２３４５６", "0000000"])
def test_missing_or_malformed_code_commits_failure(store: Store, bad: str | None) -> None:
    token = store.create_session("a")
    with pytest.raises(Denied, match="presence_check_failed"):
        store.request_grant(token, bad)
    with store.transaction() as conn:
        assert conn.execute("SELECT failures FROM factor").fetchone()[0] == 1
    assert store.audit()[-1]["event"] == "approval_denied"


def test_global_lockout_survives_restart(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    for index in range(MAX_FAILURES):
        token = store.create_session(str(index))
        with pytest.raises(Denied, match="presence_check_failed"):
            store.request_grant(token, None)
    restarted = Store(store.directory)
    token = restarted.create_session("new")
    with pytest.raises(Denied, match="locked_out"):
        restarted.request_grant(token, code(store))
    monkeypatch.setattr(
        "presence_broker.store.time.time", lambda: 1_800_000_000.0 + LOCKOUT_SECONDS
    )
    assert restarted.request_grant(token, code(store, LOCKOUT_SECONDS))


def test_replay_survives_restart(store: Store) -> None:
    token = store.create_session("a")
    store.request_grant(token, code(store))
    restarted = Store(store.directory)
    with pytest.raises(Denied, match="replayed_code"):
        restarted.request_grant(token, code(store))
    with pytest.raises(Denied, match="replayed_code"):
        restarted.request_grant(token, code(store, -30))


def test_parallel_replay_has_exactly_one_winner(store: Store) -> None:
    tokens = [store.create_session(str(i)) for i in range(4)]
    fresh = code(store)

    def attempt(token: str) -> str:
        try:
            store.request_grant(token, fresh)
            return "granted"
        except Denied as exc:
            return str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, tokens))
    assert results.count("granted") == 1
    assert results.count("replayed_code") == 3


def test_parallel_failures_are_not_lost(store: Store) -> None:
    token = store.create_session("a")

    def attempt(_: int) -> None:
        with pytest.raises(Denied, match="presence_check_failed"):
            store.request_grant(token, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_FAILURES) as pool:
        list(pool.map(attempt, range(MAX_FAILURES)))
    with pytest.raises(Denied, match="locked_out"):
        store.request_grant(token, code(store))


def test_no_reenrollment_over_existing_state(store: Store) -> None:
    with pytest.raises(FileExistsError):
        Store.initialize(store.directory)
    assert Store(store.directory).secret == store.secret


def test_missing_factor_prevents_startup(store: Store) -> None:
    store.seed_file.unlink()
    with pytest.raises(FileNotFoundError):
        Store(store.directory)


def test_world_readable_seed_prevents_startup(store: Store) -> None:
    store.seed_file.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        Store(store.directory)


def test_symlink_seed_prevents_startup(store: Store) -> None:
    original = store.seed_file.with_suffix(".original")
    store.seed_file.rename(original)
    store.seed_file.symlink_to(original)
    with pytest.raises(ValueError, match="service user"):
        Store(store.directory)


def test_unknown_schema_refused_without_modification(store: Store) -> None:
    # This project starts at v1: reject unknown shapes rather than pretend the
    # private broker's historical migrations have been ported and validated.
    with sqlite3.connect(store.database) as conn:
        conn.execute("PRAGMA user_version = 99")
    before = store.database.read_bytes()
    with pytest.raises(ValueError, match="unsupported database version"):
        Store(store.directory)
    assert store.database.read_bytes() == before
