import json

import redis.asyncio as redis

from .config import MESSAGE_TTL_SECONDS, REDIS_URL

_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(REDIS_URL, decode_responses=True)
    return _client


def _queue_key(pubkey: str) -> str:
    return f"queue:{pubkey}"


def _directory_key_by_pubkey(identity_pub: str) -> str:
    return f"directory:key:{identity_pub}"


def _directory_key_by_handle(handle: str) -> str:
    return f"directory:handle:{handle}"


def _recovery_key(recovery_id: str) -> str:
    return f"recovery:{recovery_id}"


async def enqueue_message(recipient: str, envelope: dict) -> None:
    """Buffer an envelope for an offline recipient with a strict TTL."""
    client = get_client()
    key = _queue_key(recipient)
    await client.rpush(key, json.dumps(envelope))
    await client.expire(key, MESSAGE_TTL_SECONDS)


async def drain_queue(recipient: str) -> list[dict]:
    """Atomically read and clear all buffered envelopes for a recipient."""
    client = get_client()
    key = _queue_key(recipient)
    async with client.pipeline(transaction=True) as pipe:
        pipe.lrange(key, 0, -1)
        pipe.delete(key)
        raw, _ = await pipe.execute()
    return [json.loads(item) for item in raw]


async def publish_directory_entry(identity_pub: str, exchange_pub: str, handle: str | None) -> None:
    client = get_client()
    payload = json.dumps({"identity_pub": identity_pub, "exchange_pub": exchange_pub})
    await client.set(_directory_key_by_pubkey(identity_pub), payload)
    if handle:
        await client.set(_directory_key_by_handle(handle), payload)


async def lookup_directory_entry(key_or_handle: str) -> dict | None:
    """Identity keys and handles live in separate namespaces so a handle
    can never collide with (and overwrite/shadow) someone else's identity
    key entry. Identity-key lookups take priority over handles."""
    client = get_client()
    raw = await client.get(_directory_key_by_pubkey(key_or_handle))
    if raw is None:
        raw = await client.get(_directory_key_by_handle(key_or_handle))
    return json.loads(raw) if raw else None


async def save_recovery_blob(recovery_id: str, blob: dict) -> None:
    """Store an encrypted identity backup keyed by a hash of the paper key
    (recovery_id) that produced it. The server only ever sees this hash and
    the ciphertext, never the paper key or the private keys it protects."""
    client = get_client()
    await client.set(_recovery_key(recovery_id), json.dumps(blob))


async def load_recovery_blob(recovery_id: str) -> dict | None:
    client = get_client()
    raw = await client.get(_recovery_key(recovery_id))
    return json.loads(raw) if raw else None
