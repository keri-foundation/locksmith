"""Keep credential inventory rows in sync with their vault and signing keys."""
from PySide6.QtCore import QTimer

from locksmith.ui.vault.shared.base_list_page import BaseListPage


class CredentialInventoryPage(BaseListPage):

    """Subclasses load their rows and name the events that change inventory."""

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.app = parent.app
        self._vault = None
        self._signers = {}
        self._pending_refresh = None  # A hidden refresh retains its reset_page option.
        self._timer = QTimer(self, interval=1000)
        self._timer.timeout.connect(self._check_signers)

    def set_vault_name(self, vault_name):
        self._unbind()
        vault = getattr(self.app, 'vault', None)
        if vault and vault.hby and not getattr(vault, 'closed', False):
            self._vault = vault
            if signals := getattr(vault, 'signals', None):
                signals.doer_event.connect(self._on_doer_event)
            self._refresh_rows(reset_page=True)

    def _unbind(self):
        if self._vault is not None:
            if signals := getattr(self._vault, 'signals', None):
                signals.doer_event.disconnect(self._on_doer_event)
            self._vault = None
            self.table.set_static_data([])
        self._signers.clear()
        self._pending_refresh = None

    def _current_vault(self):
        if self._vault is not None and (self._vault is not getattr(self.app, 'vault', None)
                                        or getattr(self._vault, 'closed', False)):
            self._unbind()
        return self._vault

    def _refresh_rows(self, *, reset_page=False):
        if self._current_vault() is None:
            return
        reset_page = reset_page or bool(self._pending_refresh)
        if not self.isVisibleTo(self.window()):
            self._pending_refresh = reset_page
            return
        self._pending_refresh = None
        self._load_rows(reset_page=reset_page)

    def _on_doer_event(self, name, event, data):
        if ((name, event) in self.inventory_events
                or (name, event) == ('RegistrySync', 'registry_loaded') and data['changed']):
            self._refresh_rows()

    def _watch_signers(self, credentials):
        # A signature-only credential requires the issuer's current signing keys.
        issuers = {item['sad']['i'] for item in credentials if item['status'].get('auth') == 'signature'}
        self._signers = {pre: self.app.vault.hby.kevers[pre].lastEst for pre in issuers}

    def _check_signers(self):
        vault = self._current_vault()
        if not vault or not self._signers:
            return
        if any((kever := vault.hby.kevers.get(pre)) is None or kever.lastEst != last
               for pre, last in self._signers.items()):
            self._signers.clear()
            self._load_rows()

    def showEvent(self, event):
        super().showEvent(event)
        if self._pending_refresh is not None:
            self._refresh_rows()
        else:
            self._check_signers()
        self._timer.start()

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)
