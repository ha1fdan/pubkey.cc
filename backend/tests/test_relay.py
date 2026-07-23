import asyncio

from app import relay as relay_module
from app import storage
from app.relay import ConnectionManager


class FakeWebSocket:
    def __init__(self, fail_at: int | None = None):
        self.sent: list[dict] = []
        self.closed = False
        self.fail_at = fail_at

    async def send_json(self, data: dict) -> None:
        if self.fail_at is not None and len(self.sent) == self.fail_at:
            raise RuntimeError("send failed")
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True


async def test_connect_replaces_and_closes_old_socket_for_same_pubkey():
    manager = ConnectionManager()
    old_ws = FakeWebSocket()
    new_ws = FakeWebSocket()

    await manager.connect("alice", old_ws)
    await manager.connect("alice", new_ws)

    assert old_ws.closed
    assert manager._connections["alice"] is new_ws


async def test_disconnect_ignores_stale_websocket_reference():
    manager = ConnectionManager()
    old_ws = FakeWebSocket()
    new_ws = FakeWebSocket()

    await manager.connect("alice", old_ws)
    await manager.connect("alice", new_ws)

    # A late disconnect() for the OLD (already-replaced) socket must not
    # evict the new, live connection.
    manager.disconnect("alice", old_ws)
    assert manager._connections.get("alice") is new_ws

    manager.disconnect("alice", new_ws)
    assert "alice" not in manager._connections


async def test_flush_queue_requeues_remaining_envelopes_on_send_failure():
    await storage.enqueue_message("bob", {"from": "a", "to": "bob", "ciphertext": "1", "nonce": "1", "ts": None})
    await storage.enqueue_message("bob", {"from": "a", "to": "bob", "ciphertext": "2", "nonce": "2", "ts": None})
    await storage.enqueue_message("bob", {"from": "a", "to": "bob", "ciphertext": "3", "nonce": "3", "ts": None})

    manager = ConnectionManager()
    fake_ws = FakeWebSocket(fail_at=1)  # fails sending the 2nd envelope

    ok = await manager.flush_queue("bob", fake_ws)

    assert ok is False
    assert len(fake_ws.sent) == 1

    remaining = await storage.drain_queue("bob")
    assert [envelope["ciphertext"] for envelope in remaining] == ["2", "3"]


async def test_flush_queue_returns_true_when_all_sends_succeed():
    await storage.enqueue_message("bob", {"from": "a", "to": "bob", "ciphertext": "1", "nonce": "1", "ts": None})

    manager = ConnectionManager()
    fake_ws = FakeWebSocket()

    ok = await manager.flush_queue("bob", fake_ws)

    assert ok is True
    assert len(fake_ws.sent) == 1
    assert await storage.drain_queue("bob") == []


async def test_authenticate_times_out_on_silent_client(monkeypatch):
    monkeypatch.setattr(relay_module, "CHALLENGE_TTL_SECONDS", 0.05)

    class SilentWebSocket:
        async def send_json(self, data: dict) -> None:
            pass

        async def receive_json(self) -> dict:
            await asyncio.sleep(10)
            raise AssertionError("should have been cancelled by the timeout")

    manager = ConnectionManager()
    pubkey = await manager.authenticate(SilentWebSocket())

    assert pubkey is None
