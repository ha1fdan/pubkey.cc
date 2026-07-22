from starlette.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_register_and_lookup_round_trip():
    resp = client.post("/register", json={"identity_pub": "pk1", "exchange_pub": "ek1", "handle": "alice"})
    assert resp.status_code == 200

    by_key = client.get("/u/pk1")
    by_handle = client.get("/u/alice")
    assert by_key.status_code == 200
    assert by_key.json() == {"identity_pub": "pk1", "exchange_pub": "ek1"}
    assert by_handle.json() == by_key.json()


def test_lookup_missing_returns_404():
    resp = client.get("/u/nobody")
    assert resp.status_code == 404


def test_recovery_save_and_load_round_trip():
    blob = {"version": 1, "kdf": "PBKDF2-SHA256", "iterations": 250000, "salt": "s", "iv": "i", "ciphertext": "c"}
    put_resp = client.put("/recovery/some-recovery-id", json=blob)
    assert put_resp.status_code == 200

    get_resp = client.get("/recovery/some-recovery-id")
    assert get_resp.status_code == 200
    assert get_resp.json() == blob


def test_recovery_missing_returns_404():
    resp = client.get("/recovery/nonexistent")
    assert resp.status_code == 404
