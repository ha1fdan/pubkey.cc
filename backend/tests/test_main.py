import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from starlette.testclient import TestClient

from app.auth import registration_payload
from app.main import app

client = TestClient(app)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_raw(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Mimic Web Crypto's raw r||s ECDSA output from a DER signature."""
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    size = (private_key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _identity_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, _b64url(spki)


def _register(private_key: ec.EllipticCurvePrivateKey, identity_pub: str, exchange_pub: str, handle: str | None = None):
    payload = registration_payload(identity_pub, exchange_pub, handle)
    signature = _b64url(_sign_raw(private_key, payload.encode()))
    return client.post(
        "/register",
        json={"identity_pub": identity_pub, "exchange_pub": exchange_pub, "handle": handle, "signature": signature},
    )


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_register_and_lookup_round_trip():
    private_key, identity_pub = _identity_keypair()
    resp = _register(private_key, identity_pub, "ek1", "alice")
    assert resp.status_code == 200

    by_key = client.get(f"/u/{identity_pub}")
    by_handle = client.get("/u/alice")
    assert by_key.status_code == 200
    assert by_key.json() == {"identity_pub": identity_pub, "exchange_pub": "ek1"}
    assert by_handle.json() == by_key.json()


def test_register_rejects_invalid_signature():
    _, identity_pub = _identity_keypair()
    resp = client.post(
        "/register",
        json={"identity_pub": identity_pub, "exchange_pub": "ek1", "signature": "not-a-real-signature"},
    )
    assert resp.status_code == 401


def test_register_rejects_hijack_attempt():
    # Victim registers legitimately.
    victim_key, victim_pub = _identity_keypair()
    assert _register(victim_key, victim_pub, "victim-exchange-key").status_code == 200

    # Attacker signs with their OWN key over the victim's identity_pub,
    # trying to overwrite the victim's directory entry with an
    # attacker-controlled exchange key. Must be rejected since the
    # signature doesn't verify against victim_pub.
    attacker_key, _ = _identity_keypair()
    payload = registration_payload(victim_pub, "attacker-exchange-key", None)
    forged_signature = _b64url(_sign_raw(attacker_key, payload.encode()))
    resp = client.post(
        "/register",
        json={
            "identity_pub": victim_pub,
            "exchange_pub": "attacker-exchange-key",
            "signature": forged_signature,
        },
    )
    assert resp.status_code == 401

    # Victim's entry must be untouched.
    assert client.get(f"/u/{victim_pub}").json() == {
        "identity_pub": victim_pub,
        "exchange_pub": "victim-exchange-key",
    }


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
