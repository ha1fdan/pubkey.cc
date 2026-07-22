import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import auth


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_raw(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Mimic Web Crypto's raw r||s ECDSA output from a DER signature."""
    der_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    size = (private_key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def test_verify_challenge_signature_accepts_valid_signature():
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_b64url = _b64url(spki)

    challenge = auth.new_challenge()
    signature_b64url = _b64url(_sign_raw(private_key, challenge.encode()))

    assert auth.verify_challenge_signature(pubkey_b64url, challenge, signature_b64url)


def test_verify_challenge_signature_rejects_wrong_key():
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    other_spki = other.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    challenge = auth.new_challenge()
    signature_b64url = _b64url(_sign_raw(signer, challenge.encode()))

    assert not auth.verify_challenge_signature(_b64url(other_spki), challenge, signature_b64url)


def test_verify_challenge_signature_rejects_tampered_challenge():
    private_key = ec.generate_private_key(ec.SECP256R1())
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pubkey_b64url = _b64url(spki)

    challenge = auth.new_challenge()
    signature_b64url = _b64url(_sign_raw(private_key, challenge.encode()))

    assert not auth.verify_challenge_signature(pubkey_b64url, challenge + "x", signature_b64url)
