from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import storage
from .config import CORS_ORIGINS
from .relay import handle_connection

app = FastAPI(title="pubkey.cc relay")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DirectoryEntry(BaseModel):
    identity_pub: str
    exchange_pub: str
    handle: str | None = None


class RecoveryBlob(BaseModel):
    version: int
    kdf: str
    iterations: int
    salt: str
    iv: str
    ciphertext: str


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.post("/register")
async def register(entry: DirectoryEntry) -> dict:
    """Publish the public identity/exchange keys behind /u/<key_or_handle>.
    No private key material ever reaches the server."""
    await storage.publish_directory_entry(entry.identity_pub, entry.exchange_pub, entry.handle)
    return {"status": "registered"}


@app.get("/u/{key_or_handle}")
async def lookup(key_or_handle: str) -> dict:
    result = await storage.lookup_directory_entry(key_or_handle)
    if result is None:
        raise HTTPException(status_code=404, detail="not found")
    return result


@app.put("/recovery/{recovery_id}")
async def save_recovery(recovery_id: str, blob: RecoveryBlob) -> dict:
    """Store an encrypted identity backup under a hash of its paper key.
    recovery_id is unguessable (a SHA-256 of the paper key), so possession of
    the id is the only access control, same trust model as a secret URL."""
    await storage.save_recovery_blob(recovery_id, blob.model_dump())
    return {"status": "saved"}


@app.get("/recovery/{recovery_id}")
async def load_recovery(recovery_id: str) -> dict:
    blob = await storage.load_recovery_blob(recovery_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="not found")
    return blob


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await handle_connection(websocket)
