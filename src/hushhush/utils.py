from __future__ import annotations

import base64


def ensure_bytes(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        return s
    return s.encode("utf-8")


def ensure_unicode(s: str | bytes) -> str:
    if isinstance(s, str):
        return s
    return s.decode("utf-8")


def bytes_to_base64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def base64_to_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))
