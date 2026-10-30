import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


FRONTIER_KEY_ENV = "XSS_SENTINEL_FRONTIER_KEY"


def frontier_cipher() -> Fernet:
    raw = os.getenv(FRONTIER_KEY_ENV, "").strip()
    if not raw:
        raise ValueError(f"{FRONTIER_KEY_ENV} must be set before starting crawl jobs.")
    try:
        return Fernet(raw.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{FRONTIER_KEY_ENV} must be a valid Fernet key.") from exc


def encrypt_frontier_value(value: str) -> str:
    return frontier_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_frontier_value(value: str) -> str:
    try:
        return frontier_cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise ValueError("Unable to decrypt a saved crawl frontier item; check the configured frontier key.") from exc


def request_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
