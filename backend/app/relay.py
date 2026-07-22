"""The blind relay: routes opaque ciphertext envelopes between connected
clients by recipient pubkey, falling back to an ephemeral TTL'd queue when
the recipient is offline. The server never inspects message content."""

from fastapi import WebSocket, WebSocketDisconnect

from . import storage
from .auth import new_challenge, verify_challenge_signature


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}

    async def authenticate(self, websocket: WebSocket) -> str | None:
        challenge = new_challenge()
        await websocket.send_json({"type": "challenge", "nonce": challenge})
        try:
            reply = await websocket.receive_json()
        except Exception:
            return None

        pubkey = reply.get("pubkey")
        signature = reply.get("signature")
        if not pubkey or not signature:
            return None
        if not verify_challenge_signature(pubkey, challenge, signature):
            return None
        return pubkey

    async def connect(self, pubkey: str, websocket: WebSocket) -> None:
        self._connections[pubkey] = websocket

    def disconnect(self, pubkey: str) -> None:
        self._connections.pop(pubkey, None)

    async def deliver_or_queue(self, envelope: dict) -> None:
        recipient = envelope["to"]
        websocket = self._connections.get(recipient)
        if websocket is not None:
            try:
                await websocket.send_json({"type": "message", **envelope})
                return
            except Exception:
                self.disconnect(recipient)
        await storage.enqueue_message(recipient, envelope)

    async def flush_queue(self, pubkey: str, websocket: WebSocket) -> None:
        for envelope in await storage.drain_queue(pubkey):
            await websocket.send_json({"type": "message", **envelope})


manager = ConnectionManager()


async def handle_connection(websocket: WebSocket) -> None:
    await websocket.accept()
    pubkey = await manager.authenticate(websocket)
    if pubkey is None:
        await websocket.close(code=4001, reason="authentication failed")
        return

    await manager.connect(pubkey, websocket)
    await websocket.send_json({"type": "ready", "pubkey": pubkey})
    await manager.flush_queue(pubkey, websocket)

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
        manager.disconnect(pubkey)
