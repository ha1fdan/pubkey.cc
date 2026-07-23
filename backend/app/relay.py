"""The blind relay: routes opaque ciphertext envelopes between connected
clients by recipient pubkey, falling back to an ephemeral TTL'd queue when
the recipient is offline. The server never inspects message content."""

import asyncio

from fastapi import WebSocket, WebSocketDisconnect

from . import storage
from .auth import new_challenge, verify_challenge_signature
from .config import CHALLENGE_TTL_SECONDS

# Close code used when a newer connection for the same pubkey takes over
# (e.g. the same identity opened in a second tab). Distinct from a network
# failure so the client knows *not* to auto-reconnect -- reconnecting here
# would just close the new connection in turn, ping-ponging between tabs
# forever. See ws.js's close handler, which checks for this exact code.
REPLACED_CLOSE_CODE = 4000


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}

    async def authenticate(self, websocket: WebSocket) -> str | None:
        challenge = new_challenge()
        await websocket.send_json({"type": "challenge", "nonce": challenge})
        try:
            reply = await asyncio.wait_for(websocket.receive_json(), timeout=CHALLENGE_TTL_SECONDS)
        except (asyncio.TimeoutError, WebSocketDisconnect, ValueError, RuntimeError):
            # An unauthenticated client that never replies would otherwise
            # hold the accepted connection open indefinitely.
            return None

        pubkey = reply.get("pubkey")
        signature = reply.get("signature")
        if not pubkey or not signature:
            return None
        if not verify_challenge_signature(pubkey, challenge, signature):
            return None
        return pubkey

    async def connect(self, pubkey: str, websocket: WebSocket) -> None:
        # A second connection authenticating as the same pubkey (e.g. a
        # client reconnecting before its old socket has been noticed as
        # dead) must not be silently shadowed -- close the old one so it
        # can't later evict the new one out from under disconnect().
        existing = self._connections.get(pubkey)
        if existing is not None and existing is not websocket:
            await existing.close(code=REPLACED_CLOSE_CODE, reason="replaced by a new connection")
        self._connections[pubkey] = websocket

    def disconnect(self, pubkey: str, websocket: WebSocket) -> None:
        # Only remove the mapping if it still points at *this* websocket.
        # Without this check, an old connection's belated disconnect could
        # remove a newer, live connection for the same pubkey from the map.
        if self._connections.get(pubkey) is websocket:
            self._connections.pop(pubkey, None)

    async def deliver_or_queue(self, envelope: dict) -> None:
        recipient = envelope["to"]
        websocket = self._connections.get(recipient)
        if websocket is not None:
            try:
                await websocket.send_json({"type": "message", **envelope})
                return
            except Exception:
                self.disconnect(recipient, websocket)
        await storage.enqueue_message(recipient, envelope)

    async def flush_queue(self, pubkey: str, websocket: WebSocket) -> bool:
        """Returns False if delivery failed partway through, having
        re-enqueued the failed envelope and everything after it so nothing
        drained from storage is lost. drain_queue() deletes as it reads, so
        a naive send-then-forget loop would silently drop the rest of the
        queue on the first failed send."""
        envelopes = await storage.drain_queue(pubkey)
        for index, envelope in enumerate(envelopes):
            try:
                await websocket.send_json({"type": "message", **envelope})
            except Exception:
                for remaining in envelopes[index:]:
                    await storage.enqueue_message(pubkey, remaining)
                return False
        return True


manager = ConnectionManager()


async def handle_connection(websocket: WebSocket) -> None:
    await websocket.accept()
    pubkey = await manager.authenticate(websocket)
    if pubkey is None:
        await websocket.close(code=4001, reason="authentication failed")
        return

    await manager.connect(pubkey, websocket)
    await websocket.send_json({"type": "ready", "pubkey": pubkey})
    if not await manager.flush_queue(pubkey, websocket):
        manager.disconnect(pubkey, websocket)
        return

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") != "message":
                continue
            envelope = {
                "from": pubkey,
                "to": data["to"],
                "ciphertext": data["ciphertext"],
                "nonce": data["nonce"],
                "ts": data.get("ts"),
            }
            await manager.deliver_or_queue(envelope)
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(pubkey, websocket)
