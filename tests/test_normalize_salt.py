# -*- encoding: utf-8 -*-
"""
Tests for _normalize_salt helper in locksmith.core.habbing.

Validates that the extracted helper produces identical results
for all input variants: None, raw hex string, valid qb64, raw str,
and raw bytes.
"""

import sys
import types


# Shim missing keri.app submodules so habbing.py's transitive imports
# succeed on environments where only keri 2.x is installed.
# _normalize_salt itself only depends on keri.core.signing and keri.kering.
for _mod in ("keri.app.connecting",):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

from keri.core import signing  # noqa: E402

from locksmith.core.habbing import _normalize_salt  # noqa: E402


# The default salt that None and the raw hex string should both produce
DEFAULT_SALT = signing.Salter(raw=b"0123456789abcdef").qb64


class TestNormalizeSalt:
    """Tests for the _normalize_salt helper."""

    def test_none_returns_default(self):
        """None input produces the default qb64 salt."""
        assert _normalize_salt(None) == DEFAULT_SALT

    def test_raw_hex_string_returns_default(self):
        """The literal hex string '0123456789abcdef' is treated as raw bytes."""
        assert _normalize_salt("0123456789abcdef") == DEFAULT_SALT

    def test_valid_qb64_passes_through(self):
        """A valid qb64 salt round-trips cleanly."""
        valid_qb64 = signing.Salter().qb64  # random valid salt
        assert _normalize_salt(valid_qb64) == valid_qb64

    def test_raw_string_fallback(self):
        """A non-qb64 string falls back to raw-bytes encoding."""
        raw = "some_custom_salt_val"
        result = _normalize_salt(raw)
        expected = signing.Salter(raw=raw.encode("utf-8")).qb64
        assert result == expected

    def test_raw_bytes_fallback(self):
        """Raw bytes that aren't a valid qb64 string fall through to Salter(raw=...)."""
        raw = b"raw_bytes_salt_value"
        result = _normalize_salt(raw)
        expected = signing.Salter(raw=raw).qb64
        assert result == expected

    def test_none_and_hex_are_identical(self):
        """None and the hex string must produce the exact same output."""
        assert _normalize_salt(None) == _normalize_salt("0123456789abcdef")
