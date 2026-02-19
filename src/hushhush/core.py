from __future__ import annotations

import os
from collections import OrderedDict

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

from hushhush.utils import (
    base64_to_bytes,
    bytes_to_base64,
    ensure_bytes,
    ensure_unicode,
)

HASH_LENGTH = 32
SALT_LENGTH = 32
THREADS = 1

SECURITY_LEVELS: OrderedDict[int, tuple[int, int]] = OrderedDict(
    [
        (0, (8, 1)),  # 8 KB, 1 iteration — testing only
        (1, (2**12, 10)),  # 4 MB
        (2, (2**13, 10)),  # 8 MB (default)
        (3, (2**15, 10)),  # 32 MB
        (4, (2**17, 10)),  # 128 MB
        (5, (2**18, 10)),  # 256 MB
        (6, (2**19, 10)),  # 512 MB
        (7, (2**20, 10)),  # 1 GB
        (8, (2**20, 10)),  # 1 GB
        (9, (2**20, 10)),  # 1 GB
        (10, (2**21, 20)),  # 2 GB
        (11, (2**21, 30)),  # 2 GB
        (12, (2**22, 30)),  # 4 GB
        (13, (2**22, 40)),  # 4 GB
        (14, (2**23, 40)),  # 8 GB
        (15, (2**23, 50)),  # 8 GB
        (16, (2**24, 60)),  # 16 GB
        (17, (2**24, 70)),  # 16 GB
        (18, (2**24, 80)),  # 16 GB
        (19, (2**24, 90)),  # 16 GB
        (20, (2**24, 100)),  # 16 GB
    ]
)


def _derive_key(
    password: bytes,
    salt: bytes,
    security: int,
    server: bool,
) -> bytes:
    memory_cost, time_cost = SECURITY_LEVELS[security]
    argon2_type = Type.I if server else Type.D
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=THREADS,
        hash_len=HASH_LENGTH,
        type=argon2_type,
    )
    return raw


def hide(
    secret: bytes,
    password: str | bytes,
    security: int = 2,
    salt: bytes | None = None,
    server: bool = True,
) -> str:
    """Encrypt *secret* with *password*.

    Returns a self-describing unicode string that can later be decrypted
    with :func:`peek`.
    """
    if security not in SECURITY_LEVELS:
        raise ValueError(f"security must be between 0 and 20, got {security}")

    password_bytes = ensure_bytes(password)

    if salt is None:
        salt = os.urandom(SALT_LENGTH)

    key = _derive_key(password_bytes, salt, security, server)
    fernet_key = bytes_to_base64(key)
    f = Fernet(fernet_key.encode("ascii"))
    token = f.encrypt(secret)

    server_flag = "1" if server else "0"
    return f"{server_flag}${security}${bytes_to_base64(salt)}${ensure_unicode(token)}"


def peek(
    hidden: str | bytes,
    password: str | bytes,
    expires: int | None = None,
) -> bytes:
    """Decrypt a secret previously encrypted with :func:`hide`.

    Raises :class:`ValueError` if the password is wrong, the data has been
    tampered with, or the token has expired.
    """
    hidden_str = ensure_unicode(hidden)
    password_bytes = ensure_bytes(password)

    try:
        server_flag, security_str, salt_b64, token = hidden_str.split("$")
    except ValueError:
        raise ValueError("Invalid hidden value format") from None

    server = server_flag == "1"
    security = int(security_str)

    if security not in SECURITY_LEVELS:
        raise ValueError(f"Invalid security level: {security}")

    salt = base64_to_bytes(salt_b64)
    key = _derive_key(password_bytes, salt, security, server)
    fernet_key = bytes_to_base64(key)
    f = Fernet(fernet_key.encode("ascii"))

    try:
        return f.decrypt(token.encode("ascii"), ttl=expires)
    except InvalidToken:
        raise ValueError("Wrong password, tampered data, or expired token") from None
