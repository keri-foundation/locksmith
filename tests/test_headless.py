# -*- encoding: utf-8 -*-
"""
Tests for locksmith.core.headless — Qt-free Habery/Regery lifecycle.

Validates that open_headless_hby can open a temporary Habery/Regery
pair without importing PySide6 or any vault/tasking code.
"""

import sys
import types

# Shim missing keri.app submodules so locksmith imports succeed on
# environments where only keri 2.x is installed.
for _mod in ("keri.app.connecting",):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

import uuid  # noqa: E402

import pytest  # noqa: E402
from keri.app import habbing  # noqa: E402
from keri.vdr import credentialing  # noqa: E402

from locksmith.core.headless import open_headless_hby  # noqa: E402


@pytest.fixture
def tmp_keystore():
    """Provide a unique keystore name and base dir for each test.

    hio requires ``base`` to be a *relative* path segment (it joins it
    under ``~/.keri/``), so we use an empty string.  Each test gets a
    unique ``name`` so LMDB doesn't collide within the same process.
    """
    return {
        "name": f"test-headless-{uuid.uuid4().hex[:8]}",
        "base": "",
        "bran": "0123456789abcdefghijk",  # 21-char minimum
    }


class TestOpenHeadlessHby:
    """open_headless_hby returns (Habery, Regery) without Qt."""

    def test_returns_habery_and_regery(self, tmp_keystore):
        hby, rgy = open_headless_hby(**tmp_keystore)
        try:
            assert isinstance(hby, habbing.Habery)
            assert isinstance(rgy, credentialing.Regery)
        finally:
            hby.close()

    def test_habery_name_matches(self, tmp_keystore):
        hby, rgy = open_headless_hby(**tmp_keystore)
        try:
            assert hby.name == tmp_keystore["name"]
        finally:
            hby.close()

    def test_custom_salt_accepted(self, tmp_keystore):
        from keri.core.signing import Salter

        custom_salt = Salter().qb64
        hby, rgy = open_headless_hby(**tmp_keystore, salt=custom_salt)
        try:
            assert isinstance(hby, habbing.Habery)
        finally:
            hby.close()

    def test_no_pyside6_imported(self, tmp_keystore):
        """Confirm PySide6 is not in sys.modules after opening headless."""
        hby, rgy = open_headless_hby(**tmp_keystore)
        try:
            pyside_mods = [m for m in sys.modules if m.startswith("PySide6")]
            assert pyside_mods == [], f"PySide6 leaked into imports: {pyside_mods}"
        finally:
            hby.close()
