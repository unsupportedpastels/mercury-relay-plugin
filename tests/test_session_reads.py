from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from conftest import contract_import

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.session_lease import SessionLease  # noqa: E402
from mercury_relay_plugin.session_reads import (  # noqa: E402
    MAX_TRANSCRIPT_LIMIT,
    SessionReads,
    SessionReadsError,
)
from mercury_relay_plugin.virtual_ws import VirtualWebSocket  # noqa: E402

FIXTURES = Path(__file__).parents[1] / "protocol" / "fixtures" / "hermes" / "rest.json"


class FakeSessionDB:
    """Minimal SessionDB read surface with close tracking."""

    def __init__(self, log: list[str], *, fail: str | None = None) -> None:
        self._log = log
        self._fail = fail
        self.rows = [
            {
                "id": "fixture-durable-001",
                "title": "fixture title",
                "preview": "fixture preview",
                "message_count": 2,
                "profile": "fixture_profile",
            }
        ]
        self.messages = [
            {"role": "user", "content": "fixture prompt"},
            {"role": "assistant", "content": "fixture answer"},
        ]

    def list_sessions_rich(self, **kwargs):
        self._log.append(f"list:{kwargs['limit']}:{kwargs['offset']}")
        if self._fail == "lock":
            raise RuntimeError("database is locked (secret path detail)")
        if self._fail == "malformed":
            return [{"id": object()}]
        return list(self.rows)

    def session_count(self, **kwargs):
        assert kwargs.get("exclude_children") is True
        return len(self.rows)

    def resolve_session_id(self, session_id):
        self._log.append(f"resolve:{session_id}")
        return "fixture-durable-001" if session_id.startswith("fixture") else None

    def resolve_resume_session_id(self, session_id):
        self._log.append(f"resume:{session_id}")
        return "fixture-compression-tip"

    def get_messages(self, session_id, *, limit, offset, latest):
        self._log.append(f"messages:{session_id}:{limit}:{offset}:{latest}")
        if self._fail == "oversize":
            return [{"role": "assistant", "content": "x" * 20_000_000}]
        return list(self.messages)

    def close(self):
        self._log.append("close")


def _reads(log: list[str], *, fail: str | None = None, authorizer=None) -> SessionReads:
    def opener(profile: str):
        log.append(f"open:{profile}")
        if fail == "open":
            raise RuntimeError("no such file: /secret/path/state.db")
        return FakeSessionDB(log, fail=fail)

    return SessionReads(
        profile_authorizer=authorizer or (lambda profile: profile in {"default", "researcher"}),
        db_opener=opener,
        status_snapshot=lambda: {"installed": True, "runtime": "ready"},
    )


def test_reads_match_retained_fixture_envelopes_and_close_every_handle() -> None:
    fixture_records = {
        record["id"]: json.loads(record["response"]["body_utf8"])
        for record in json.loads(FIXTURES.read_text())["records"]
    }

    async def exercise() -> None:
        log: list[str] = []
        reads = _reads(log)

        status = await reads.dispatch("relay.status", {})
        assert status["installed"] is True
        assert status["runtime"] == "ready"

        listed = await reads.dispatch(
            "relay.sessions.list", {"profile": "researcher", "limit": 20, "offset": 0}
        )
        assert set(listed) == set(fixture_records["session-list"])
        assert listed["total"] == 1
        assert listed["sessions"][0]["id"] == "fixture-durable-001"

        transcript = await reads.dispatch(
            "relay.session.transcript",
            {"profile": "default", "session_id": "fixture-durable-001"},
        )
        assert set(transcript) == set(fixture_records["transcript"])
        assert set(transcript["pagination"]) >= {"limit", "offset", "order", "returned"}
        assert transcript["messages"] == [
            {"role": "user", "content": "fixture prompt"},
            {"role": "assistant", "content": "fixture answer"},
        ]
        # Durable-ID preference and compression-tip resolution ran in order,
        # the default page is the latest, and the handle closed both times.
        assert "resolve:fixture-durable-001" in log
        assert "resume:fixture-durable-001" in log
        assert f"messages:fixture-compression-tip:{MAX_TRANSCRIPT_LIMIT}:0:True" in log
        assert log.count("close") == 2

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", [1, 2])
def test_session_list_paginates_pins_without_backfilling_other_pages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: int,
) -> None:
    SessionDB = contract_import("hermes_state").SessionDB
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db_path = tmp_path / "state.db"
    expected = {f"fixture-page-{index}" for index in range(5)}
    db = SessionDB(db_path)
    try:
        for index, session_id in enumerate(sorted(expected)):
            db.create_session(session_id, source="mercury")
            db.append_message(session_id, "user", content="Synthetic pagination fixture")
            db.set_session_pinned(session_id, index % 2 == 0)
    finally:
        db.close()

    async def exercise() -> None:
        reads = SessionReads(db_opener=lambda _: SessionDB(db_path, read_only=True))
        seen: list[str] = []
        for offset in range(0, len(expected) + limit, limit):
            result = await reads.dispatch("relay.sessions.list", {
                "limit": limit, "offset": offset,
            })
            rows = result["sessions"]
            assert result["total"] == len(expected)
            assert len(rows) <= limit
            seen.extend(row["id"] for row in rows)
        assert len(seen) == len(expected)
        assert set(seen) == expected
        end = await reads.dispatch("relay.sessions.list", {
            "limit": limit, "offset": len(expected),
        })
        assert end["sessions"] == []

    asyncio.run(exercise())


@pytest.mark.parametrize("order", ["oldest", "latest"])
def test_transcript_filters_stored_internal_kinds_without_losing_page_positions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    order: str,
) -> None:
    SessionDB = contract_import("hermes_state").SessionDB
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    db_path = tmp_path / "state.db"
    db = SessionDB(db_path)
    # Both ends are hidden-only pages; the middle pages mix hidden and visible
    # rows. Identical control-looking text from a real user must survive.
    text = "[Internal notification] delegation_closeout: wait for delegates"
    kinds = [
        "internal_notification",
        "delegation_closeout",
        None,
        "delegation_waiting",
        "delegation_closeout_provisional",
        None,
        "hidden",
        "internal_notification",
    ]
    try:
        db.create_session("fixture-controls", source="mercury")
        for kind in kinds:
            db.append_message(
                "fixture-controls",
                "user",
                content=text,
                display_kind=kind,
            )
        expected = [
            m["id"] for m in db.get_messages("fixture-controls") if m.get("display_kind") is None
        ]
    finally:
        db.close()

    async def exercise() -> None:
        reads = SessionReads(db_opener=lambda _: SessionDB(db_path, read_only=True))
        offset = 0
        visible_ids = []
        page_sizes = []
        for _ in range(5):
            page = await reads.dispatch(
                "relay.session.transcript",
                {
                    "session_id": "fixture-controls",
                    "limit": 2,
                    "offset": offset,
                    "order": order,
                },
            )
            messages = page["messages"]
            assert all(m.get("display_kind") is None for m in messages)
            assert all(m["content"] == text for m in messages)
            pagination = page["pagination"]
            assert pagination["returned"] == len(messages)
            assert pagination["raw_returned"] == (2 if offset < len(kinds) else 0)
            assert pagination["next_offset"] == offset + pagination["raw_returned"]
            page_sizes.append(len(messages))
            ids = [m["id"] for m in messages]
            visible_ids[:] = ids + visible_ids if order == "latest" else visible_ids + ids
            offset = pagination["next_offset"]
            if pagination["raw_returned"] < pagination["limit"]:
                break
        assert page_sizes == [0, 1, 1, 0, 0]
        assert offset == len(kinds)
        assert visible_ids == expected  # exactly once, in insertion order

    asyncio.run(exercise())


def test_reads_fail_closed_with_stable_reasons() -> None:
    async def exercise() -> None:
        log: list[str] = []
        reads = _reads(log)

        cases = [
            ("relay.sessions.list", {"profile": "missing"}, "profile_not_available"),
            ("relay.sessions.list", {"profile": "../etc"}, "profile_not_available"),
            ("relay.sessions.list", {"profile": "default", "limit": 0}, "invalid_params"),
            ("relay.sessions.list", {"profile": "default", "limit": 101}, "invalid_params"),
            ("relay.sessions.list", {"profile": "default", "extra": 1}, "invalid_params"),
            ("relay.session.transcript", {"profile": "default"}, "invalid_params"),
            (
                "relay.session.transcript",
                {"profile": "default", "session_id": "x", "order": "sideways"},
                "invalid_params",
            ),
            ("relay.status", {"unexpected": True}, "invalid_params"),
            ("relay.unknown", {}, "method_not_allowed"),
        ]
        for method, params, reason in cases:
            with pytest.raises(SessionReadsError) as caught:
                await reads.dispatch(method, params)
            assert caught.value.reason == reason

        with pytest.raises(SessionReadsError) as caught:
            await reads.dispatch(
                "relay.session.transcript",
                {"profile": "default", "session_id": "unknown-session"},
            )
        assert caught.value.reason == "session_not_found"
        assert log.count("close") == 1  # the handle closed even on not-found

        for fail, reason in [
            ("open", "read_failed"),
            ("lock", "read_failed"),
            ("malformed", "read_failed"),
            ("oversize", "response_too_large"),
        ]:
            failing = _reads(log, fail=fail)
            with pytest.raises(SessionReadsError) as caught:
                if fail == "oversize":
                    await failing.dispatch(
                        "relay.session.transcript",
                        {"profile": "default", "session_id": "fixture-durable-001"},
                    )
                else:
                    await failing.dispatch("relay.sessions.list", {"profile": "default"})
            assert caught.value.reason == reason
            assert "secret" not in str(caught.value)
            assert "/secret/path" not in str(caught.value)

    asyncio.run(exercise())


def test_lease_serves_reads_without_touching_hermes() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []

        async def close_controller(controller_id: str) -> bool:
            closed.append(controller_id)
            return True

        log: list[str] = []
        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=close_controller,
            read_dispatcher=_reads(log).dispatch,
        )
        lease.start()
        attachment = lease.attach(0)
        status = json.loads(await attachment.next_text(timeout=1.0))
        assert status["method"] == "relay.lease.attached"

        await attachment.feed_text(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "read-1",
                    "method": "relay.sessions.list",
                    "params": {"profile": "default", "limit": 5},
                }
            )
        )
        response = json.loads(await attachment.next_text(timeout=1.0))
        assert response["id"] == "read-1"
        assert response["result"]["sessions"][0]["id"] == "fixture-durable-001"
        # The read never reached the Hermes-bound virtual WebSocket and was
        # not retained as a lease event.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
        assert lease.last_seq == 0

        await attachment.feed_text(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "read-2",
                    "method": "relay.session.transcript",
                    "params": {"profile": "default", "session_id": "nope"},
                }
            )
        )
        failure = json.loads(await attachment.next_text(timeout=1.0))
        assert failure["id"] == "read-2"
        assert failure["error"] == {"code": -32000, "message": "session_not_found"}

        await lease.release("test_finished")

    asyncio.run(exercise())


def test_real_session_db_reads_are_bounded_and_shape_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_import("hermes_state")

    async def exercise() -> None:
        from hermes_state import SessionDB

        root = tmp_path / "hermes"
        (root / "profiles" / "researcher").mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(root))

        db = SessionDB(root / "profiles" / "researcher" / "state.db")
        try:
            db.create_session("real-session-001", source="mercury")
            db.append_message("real-session-001", "user", content="real prompt")
            db.append_message("real-session-001", "assistant", content="real answer")
        finally:
            db.close()

        reads = SessionReads(
            profile_authorizer=lambda profile: profile in {"default", "researcher"},
            status_snapshot=lambda: {"runtime": "ready"},
        )
        listed = await reads.dispatch("relay.sessions.list", {"profile": "researcher"})
        assert listed["total"] == 1
        assert listed["sessions"][0]["id"] == "real-session-001"
        assert listed["sessions"][0]["message_count"] == 2

        transcript = await reads.dispatch(
            "relay.session.transcript",
            {"profile": "researcher", "session_id": "real-session-001", "limit": 10},
        )
        assert transcript["session_id"] == "real-session-001"
        contents = [message.get("content") for message in transcript["messages"]]
        assert contents == ["real prompt", "real answer"]
        assert transcript["pagination"]["returned"] == 2

        with pytest.raises(SessionReadsError) as missing:
            await reads.dispatch("relay.sessions.list", {"profile": "deleted-profile"})
        assert missing.value.reason == "profile_not_available"

    asyncio.run(exercise())
