# hushhush

Password-protect your data. A modern, drop-in replacement for [privy](https://github.com/ofek/privy).

## Installation

```bash
pip install hushhush
```

## Usage

```python
import hushhush

# Encrypt a secret with a password
hidden = hushhush.hide(b"my secret data", "my-password")

# Decrypt it later
secret = hushhush.peek(hidden, "my-password")
# b"my secret data"
```

## API

### `hide(secret, password, security=2, salt=None, server=True)`

Encrypts `secret` (bytes) with `password` (str or bytes).

- **security** (int, 0–20): Controls Argon2 memory/time cost. Default `2`.
- **salt** (bytes or None): Custom 32-byte salt. Random by default.
- **server** (bool): Use Argon2i (True, side-channel resistant) or Argon2d (False, faster).

Returns a self-describing unicode string.

### `peek(hidden, password, expires=None)`

Decrypts a value produced by `hide()`.

- **expires** (int or None): Max age in seconds. `None` means no expiry.

Returns the original secret as bytes.

Raises `ValueError` on wrong password, tampered data, or expired token.

## Compatibility

hushhush is a drop-in replacement for privy. The encrypted output format is identical, so data encrypted with privy can be decrypted with hushhush and vice versa.
