# -*- encoding: utf-8 -*-
"""
locksmith.core.headless module

Qt-free Habery/Regery lifecycle for headless environments (iOS/Pyodide, CLI, tests).
Does NOT import PySide6 or any locksmith.core.vaulting / locksmith.core.tasking code.
"""

from keri import help
from keri import kering
from keri.app import habbing
from keri.vdr import credentialing

from locksmith.core.habbing import _normalize_salt

logger = help.ogler.getLogger(__name__)


def open_headless_hby(name, base, bran, salt=None):
    """Open a Habery and Regery without any Qt or Vault dependencies.

    This is the headless equivalent of ``open_hby``.  It returns the raw
    KERI objects so the caller can drive the event loop however it likes
    (hio coroutines, asyncio, manual ticking, etc.).

    Args:
        name: Keystore / habery name.
        base: Base directory for KERI databases.
        bran: Passcode (will be formatted internally by Habery).
        salt: Optional salt for signing keys (see ``_normalize_salt``).

    Returns:
        tuple[habbing.Habery, credentialing.Regery]

    Raises:
        kering.AuthError: If the passcode is incorrect.
        ValueError: If habery opening fails.
    """
    salt = _normalize_salt(salt)

    try:
        hby = habbing.Habery(
            name=name, bran=bran, free=True, cf=None, base=base, salt=salt
        )
    except kering.AuthError:
        logger.error(f"Passcode incorrect for {name}")
        raise
    except ValueError:
        logger.error(f"Open Habery failed on ValueError for {name}")
        raise

    rgy = credentialing.Regery(hby=hby, name=hby.name, base=base, temp=False)
    return hby, rgy
