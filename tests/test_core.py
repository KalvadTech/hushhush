from __future__ import annotations

import time

import pytest

import hushhush


class TestHideAndPeek:
    def test_roundtrip_bytes_password(self):
        secret = b"my secret data"
        password = b"strong-password"
        hidden = hushhush.hide(secret, password, security=0)
        assert hushhush.peek(hidden, password) == secret

    def test_roundtrip_str_password(self):
        secret = b"my secret data"
        password = "strong-password"
        hidden = hushhush.hide(secret, password, security=0)
        assert hushhush.peek(hidden, password) == secret

    def test_wrong_password_raises(self):
        secret = b"my secret data"
        hidden = hushhush.hide(secret, "correct", security=0)
        with pytest.raises(ValueError):
            hushhush.peek(hidden, "wrong")

    def test_tampered_data_raises(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        tampered = hidden[:-5] + "XXXXX"
        with pytest.raises(ValueError):
            hushhush.peek(tampered, "pass")

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            hushhush.peek("not-a-valid-hidden-string", "pass")

    def test_server_flag_true(self):
        hidden = hushhush.hide(b"secret", "pass", security=0, server=True)
        assert hidden.startswith("1$")
        assert hushhush.peek(hidden, "pass") == b"secret"

    def test_server_flag_false(self):
        hidden = hushhush.hide(b"secret", "pass", security=0, server=False)
        assert hidden.startswith("0$")
        assert hushhush.peek(hidden, "pass") == b"secret"

    def test_custom_salt(self):
        salt = b"a" * 32
        hidden = hushhush.hide(b"secret", "pass", security=0, salt=salt)
        assert hushhush.peek(hidden, "pass") == b"secret"

    def test_deterministic_with_same_salt(self):
        salt = b"a" * 32
        h1 = hushhush.hide(b"secret", "pass", security=0, salt=salt)
        h2 = hushhush.hide(b"secret", "pass", security=0, salt=salt)
        # Fernet includes a timestamp, so tokens differ even with same salt/key
        # But both should decrypt to the same secret
        assert hushhush.peek(h1, "pass") == b"secret"
        assert hushhush.peek(h2, "pass") == b"secret"

    def test_invalid_security_level(self):
        with pytest.raises(ValueError):
            hushhush.hide(b"secret", "pass", security=21)
        with pytest.raises(ValueError):
            hushhush.hide(b"secret", "pass", security=-1)

    def test_hidden_is_unicode_string(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        assert isinstance(hidden, str)

    def test_peek_returns_bytes(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        result = hushhush.peek(hidden, "pass")
        assert isinstance(result, bytes)

    def test_peek_accepts_bytes_hidden(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        hidden_bytes = hidden.encode("utf-8")
        assert hushhush.peek(hidden_bytes, "pass") == b"secret"

    def test_empty_secret(self):
        hidden = hushhush.hide(b"", "pass", security=0)
        assert hushhush.peek(hidden, "pass") == b""

    def test_large_secret(self):
        secret = b"x" * 10_000
        hidden = hushhush.hide(secret, "pass", security=0)
        assert hushhush.peek(hidden, "pass") == secret


class TestExpiry:
    def test_not_expired(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        result = hushhush.peek(hidden, "pass", expires=10)
        assert result == b"secret"

    def test_expired_raises(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        time.sleep(2)
        with pytest.raises(ValueError):
            hushhush.peek(hidden, "pass", expires=1)


class TestSecurityLevels:
    def test_level_0(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        assert hushhush.peek(hidden, "pass") == b"secret"

    def test_level_1(self):
        hidden = hushhush.hide(b"secret", "pass", security=1)
        assert hushhush.peek(hidden, "pass") == b"secret"

    def test_level_2_default(self):
        hidden = hushhush.hide(b"secret", "pass")
        assert hushhush.peek(hidden, "pass") == b"secret"


class TestOutputFormat:
    def test_format_has_four_dollar_separated_parts(self):
        hidden = hushhush.hide(b"secret", "pass", security=0)
        parts = hidden.split("$")
        assert len(parts) == 4

    def test_format_server_flag(self):
        hidden = hushhush.hide(b"secret", "pass", security=0, server=True)
        parts = hidden.split("$")
        assert parts[0] == "1"

    def test_format_security_level(self):
        hidden = hushhush.hide(b"secret", "pass", security=3)
        parts = hidden.split("$")
        assert parts[1] == "3"
