from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_MARKER = b"ENC1"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_TEST_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)


def decrypt_if_needed(body: bytes) -> bytes | None:
    """Return plaintext for an authenticated ENC1 container."""
    if not body.startswith(_MARKER):
        return None

    nonce_end = len(_MARKER) + _NONCE_SIZE
    if len(body) < nonce_end + _TAG_SIZE:
        raise ValueError("The ENC1 container is too short")

    nonce = body[len(_MARKER):nonce_end]
    ciphertext_and_tag = body[nonce_end:]
    return AESGCM(_TEST_KEY).decrypt(nonce, ciphertext_and_tag, None)
