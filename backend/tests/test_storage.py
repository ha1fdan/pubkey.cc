from app import storage


async def test_enqueue_and_drain_round_trip():
    envelope = {"from": "alice", "to": "bob", "ciphertext": "abc", "nonce": "123"}
    await storage.enqueue_message("bob", envelope)

    drained = await storage.drain_queue("bob")

    assert drained == [envelope]
    assert await storage.drain_queue("bob") == []


async def test_directory_lookup_by_key_and_handle():
    await storage.publish_directory_entry("pk123", "ek456", "alice")

    by_key = await storage.lookup_directory_entry("pk123")
    by_handle = await storage.lookup_directory_entry("alice")

    assert by_key == {"identity_pub": "pk123", "exchange_pub": "ek456"}
    assert by_handle == by_key


async def test_lookup_missing_entry_returns_none():
    assert await storage.lookup_directory_entry("nobody") is None


async def test_recovery_blob_round_trip():
    blob = {"version": 1, "kdf": "PBKDF2-SHA256", "iterations": 250000, "salt": "s", "iv": "i", "ciphertext": "c"}
    await storage.save_recovery_blob("recovery-id-123", blob)

    assert await storage.load_recovery_blob("recovery-id-123") == blob


async def test_recovery_blob_missing_returns_none():
    assert await storage.load_recovery_blob("nonexistent") is None
