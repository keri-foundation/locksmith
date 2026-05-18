# -*- encoding: utf-8 -*-
"""
locksmith.plugins.base module

Plugin contracts for Locksmith extensions.

Three base classes:
- ``PluginCore``: shared minimum (plugin_id + initialize).
- ``AppPlugin``: app/window lifecycle hooks (run pre-vault-unlock).
- ``VaultPlugin``: vault lifecycle hooks (the original surface).

A plugin can inherit one, the other, or both. PluginManager dispatches
hooks based on isinstance() checks against AppPlugin / VaultPlugin.

``PluginBase`` is kept as a deprecated alias for VaultPlugin so existing
in-tree imports continue to resolve while Task 3 migrates them. Remove
the alias once kerifoundation has been migrated.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from hio.base import doing
    from PySide6.QtGui import QKeySequence
    from PySide6.QtWidgets import QWidget
    from locksmith.ui.vault.menu import MenuButton


class PluginCore(ABC):
    """Shared minimum every plugin must implement."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Unique namespace key for this plugin (e.g. 'your_plugin')."""

    @abstractmethod
    def initialize(self, app: Any) -> None:
        """Called once at startup after plugin discovery, before any hooks fire."""


class AppPlugin(PluginCore):
    """Plugin that hooks into app/window lifecycle.

    Inherit this for plugins that need to do work before any vault is
    opened — e.g., install global shortcuts, run a background service
    that owns a window-attached resource. No abstractmethods beyond the
    PluginCore minimum; all hooks default to no-ops.
    """

    def on_app_started(self, app: Any, window: Any) -> None:
        """Called once after LocksmithWindow.__init__ completes."""

    def on_app_stopping(self, app: Any) -> None:
        """Called once during LocksmithWindow.closeEvent, before services stop."""

    def get_app_shortcuts(self) -> list[tuple["QKeySequence", Callable[[], None]]]:
        """Global keyboard shortcuts to install on the main window.

        Each tuple is (sequence, callback). PluginManager installs them
        with Qt.ApplicationShortcut context.
        """
        return []

    def get_app_services(self) -> list[Any]:
        """Long-lived services owned by the plugin.

        Each service is duck-typed: must have ``start() -> None`` and
        ``stop() -> None``. PluginManager calls start() in discovery order
        after on_app_started, and stop() in reverse order before
        on_app_stopping.
        """
        return []


class VaultPlugin(PluginCore):
    """Plugin that hooks into vault lifecycle (the original surface)."""

    @abstractmethod
    def on_vault_opened(self, vault: Any) -> None:
        """Called when a vault is opened. Start doers, open plugin DB, etc."""

    @abstractmethod
    def on_vault_closed(self, vault: Any, *, clear: bool = False) -> None:
        """Called when a vault is closed. Cleanup, close DB, etc.

        When ``clear`` is True, plugin-local durable state tied to the
        vault should also be deleted from disk.
        """

    @abstractmethod
    def get_menu_entry(self) -> "MenuButton":
        """Entry button shown in the main vault sidebar."""

    @abstractmethod
    def get_menu_section(self) -> list["QWidget"]:
        """Submenu items shown when the plugin menu is pushed."""

    @abstractmethod
    def get_pages(self) -> dict[str, "QWidget"]:
        """page_key -> widget mappings to register in VaultPage."""

    # Optional hooks — defaults are no-ops.

    def get_doers(self) -> list["doing.Doer"]:
        return []

    def prepare_vault_deletion(self, vault: Any) -> None:
        pass

    def get_witness_batches(self, vault: Any, hab_pre: str) -> Any | None:
        return None

    def get_witness_state(self, vault: Any, wit_eid: str) -> Any | None:
        return None

    def update_witness_state(self, vault: Any, wit_eid: str) -> None:
        pass

    def update_witness_state_after_auth(self, vault: Any, wit_eid: str) -> None:
        pass

    async def after_identifier_authenticated(self, vault: Any, hab: Any) -> None:
        pass


# Backward-compat alias. Remove after Task 3 (kerifoundation migration).
PluginBase = VaultPlugin


# Existing capability mixins — keep their shape; they now apply only to VaultPlugin.

class AccountProviderPlugin(ABC):
    """Mixin for plugins with a setup/account creation flow."""

    @abstractmethod
    def is_setup_complete(self, vault: Any) -> bool: ...

    @abstractmethod
    def get_setup_page(self, vault: Any) -> tuple[str, bool]: ...

    def on_account_created(self, vault: Any, account: Any) -> None:
        pass


class IdentifierUploadProviderPlugin(ABC):
    """Contract for plugins that upload/sync local identifiers to a platform."""


class WitnessProviderPlugin(ABC):
    """Contract for plugins that provision witness services."""


class WatcherProviderPlugin(ABC):
    """Contract for plugins that provision watcher services."""


class CredentialProviderPlugin(ABC):
    """Contract for plugins that manage published credentials."""
