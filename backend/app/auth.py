"""Connection-ownership proof: clients sign a server-issued nonce with their
identity key (ECDSA P-256, matching what the Web Crypto API supports natively
in-browser). The server never sees a private key or message plaintext."""

import base64
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def new_challenge() -> str:
    return secrets.token_urlsafe(32)


def _pad(b64url: str) -> str:
    return b64url + "=" * (-len(b64url) % 4)


def _raw_to_der_signature(raw: bytes) -> bytes:
    """Web Crypto's ECDSA output is raw fixed-width r||s; `cryptography`
    expects DER-encoded (r, s)."""
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)


def load_public_key(spki_b64url: str) -> ec.EllipticCurvePublicKey:
    der = base64.urlsafe_b64decode(_pad(spki_b64url))
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected an EC public key")
    return key


def verify_challenge_signature(pubkey_b64url: str, challenge: str, signature_b64url: str) -> bool:
    try:
        public_key = load_public_key(pubkey_b64url)
        # Restrict to exactly the curve/signature shape the client is
        # supposed to produce. Without this, a key on a different curve (or
        # an oversized raw signature) would either fail confusingly deep in
        # _raw_to_der_signature or, worse, be accepted with a different
        # security level than intended.
        if not isinstance(public_key.curve, ec.SECP256R1):
            return False
        raw_signature = base64.urlsafe_b64decode(_pad(signature_b64url))
        if len(raw_signature) != 64:
            return False
        der_signature = _raw_to_der_signature(raw_signature)
        public_key.verify(der_signature, challenge.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def registration_payload(identity_pub: str, exchange_pub: str, handle: str | None) -> str:
    """Canonical message the client signs to prove it controls identity_pub
    before the server will publish a directory entry for it. Without this,
    anyone could POST someone else's identity_pub with an attacker-chosen
    exchange_pub and hijack their directory record."""
    return f"{identity_pub}|{exchange_pub}|{handle or ''}"
