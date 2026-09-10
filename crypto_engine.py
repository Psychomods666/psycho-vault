import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"PSYCHOVAULT"
VERSION = 1

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# Argon2id parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4


class VaultError(Exception):
    """Base exception for vault errors."""


class InvalidPasswordError(VaultError):
    """Raised when authentication/decryption fails."""


class InvalidVaultError(VaultError):
    """Raised when the encrypted file format is invalid."""


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from the user's password using Argon2id.
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def encrypt_bytes(data: bytes, original_filename: str, password: str) -> bytes:
    """
    Encrypt file data using AES-256-GCM.

    File format:

    MAGIC
    VERSION
    SALT
    NONCE
    METADATA_LENGTH
    METADATA
    CIPHERTEXT
    """

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    original_hash = sha256_bytes(data)

    metadata = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id",
        "original_filename": Path(original_filename).name,
        "original_size": len(data),
        "sha256": original_hash,
    }

    metadata_bytes = json.dumps(
        metadata,
        separators=(",", ":"),
    ).encode("utf-8")

    # Authenticate metadata as Additional Authenticated Data.
    aad = MAGIC + bytes([VERSION]) + metadata_bytes

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        data,
        aad,
    )

    metadata_length = len(metadata_bytes).to_bytes(4, "big")

    package = (
        MAGIC
        + bytes([VERSION])
        + salt
        + nonce
        + metadata_length
        + metadata_bytes
        + ciphertext
    )

    return package


def decrypt_bytes(package: bytes, password: str):
    """
    Decrypt a PSYCHO VAULT encrypted package.

    Returns:
        metadata, plaintext
    """

    minimum_size = (
        len(MAGIC)
        + 1
        + SALT_SIZE
        + NONCE_SIZE
        + 4
    )

    if len(package) < minimum_size:
        raise InvalidVaultError("Encrypted file is too small or corrupted.")

    position = 0

    magic = package[position:position + len(MAGIC)]
    position += len(MAGIC)

    if magic != MAGIC:
        raise InvalidVaultError("Not a valid PSYCHO VAULT file.")

    version = package[position]
    position += 1

    if version != VERSION:
        raise InvalidVaultError(
            f"Unsupported vault version: {version}"
        )

    salt = package[position:position + SALT_SIZE]
    position += SALT_SIZE

    nonce = package[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    metadata_length = int.from_bytes(
        package[position:position + 4],
        "big",
    )
    position += 4

    if metadata_length <= 0:
        raise InvalidVaultError("Invalid metadata.")

    metadata_end = position + metadata_length

    if metadata_end > len(package):
        raise InvalidVaultError("Metadata is truncated.")

    metadata_bytes = package[position:metadata_end]
    position = metadata_end

    try:
        metadata = json.loads(
            metadata_bytes.decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidVaultError("Invalid vault metadata.")

    ciphertext = package[position:]

    if not ciphertext:
        raise InvalidVaultError("Encrypted payload is empty.")

    aad = MAGIC + bytes([VERSION]) + metadata_bytes

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            aad,
        )
    except InvalidTag:
        # Deliberately do not distinguish wrong password
        # from tampered ciphertext.
        raise InvalidPasswordError(
            "Authentication failed. Wrong password or modified file."
        )

    expected_hash = metadata.get("sha256")

    if not expected_hash:
        raise InvalidVaultError(
            "Encrypted file does not contain an integrity hash."
        )

    actual_hash = sha256_bytes(plaintext)

    if not hmac.compare_digest(
        expected_hash,
        actual_hash,
    ):
        raise InvalidPasswordError(
            "Integrity verification failed."
        )

    return metadata, plaintext


def encrypt_file(input_path: Path, output_path: Path, password: str):
    data = input_path.read_bytes()

    encrypted = encrypt_bytes(
        data,
        input_path.name,
        password,
    )

    output_path.write_bytes(encrypted)

    return {
        "filename": input_path.name,
        "encrypted_size": len(encrypted),
        "sha256": sha256_bytes(data),
    }


def decrypt_file(input_path: Path, output_dir: Path, password: str):
    package = input_path.read_bytes()

    metadata, plaintext = decrypt_bytes(
        package,
        password,
    )

    original_filename = Path(
        metadata["original_filename"]
    ).name

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = output_dir / original_filename

    # Prevent accidental overwriting.
    if output_path.exists():
        stem = output_path.stem
        suffix = output_path.suffix

        counter = 1

        while output_path.exists():
            output_path = (
                output_dir
                / f"{stem}_decrypted_{counter}{suffix}"
            )

            counter += 1

    output_path.write_bytes(plaintext)

    return {
        "filename": output_path.name,
        "size": len(plaintext),
        "sha256": sha256_bytes(plaintext),
    }