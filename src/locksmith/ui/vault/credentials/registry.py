"""Create a holder-controlled registry and export its public identifier."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from keri.app.habbing import GroupHab

from locksmith.core.registries import CreateRegistryDoer
from locksmith.ui.toolkit.widgets import LocksmithDialog, LocksmithButton, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel


class RegistryDialog(LocksmithDialog):
    def __init__(self, app, parent=None, *, controller=None):
        self.app, self.vault, self._doer = app, app.vault, None
        self._auth_panel, self._closed = None, False
        self._pending_names = {rip.said: '.'.join(keys)
                               for keys, rip in self.vault.db.registry_creations.getTopItemIter()
                               if controller is None or rip.israid == controller}
        content = QWidget()
        layout = QVBoxLayout(content)
        description = QLabel('Create a registry before giving its public identifier to an issuer. '
                             'An issuer can declare it in a credential to require your approval of later disclosures.')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.existing = FloatingLabelComboBox('Registries and pending requests')
        self.existing.addItem('Choose a registry', None)
        for name, registry in self.vault.rgy.names.items():
            if (self.vault.rgy.store.head(registry.regk) and registry.regk not in self._pending_names
                    and (controller is None or registry.hab.pre == controller)):
                self.existing.addItem(name, registry.regk)
        for regk, name in self._pending_names.items():
            self.existing.addItem(f'{name} (creation pending)', regk)
        layout.addWidget(self.existing)
        self.controller = FloatingLabelComboBox('Controller')
        for hab in self.vault.hby.habs.values():
            if not isinstance(hab, GroupHab) and (controller is None or hab.pre == controller):
                self.controller.addItem(hab.name, hab.pre)
        self.controller.setEnabled(controller is None)
        self._controller = controller
        layout.addWidget(self.controller)
        self.name = FloatingLabelLineEdit('New registry name')
        layout.addWidget(self.name)
        self.identifier = QLabel('')
        self.identifier.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.identifier.setWordWrap(True)
        layout.addWidget(self.identifier)
        self._layout = layout
        buttons = QHBoxLayout()
        close = LocksmithInvertedButton('Close')
        self.create = LocksmithButton('Create registry')
        buttons.addWidget(close)
        buttons.addWidget(self.create)
        super().__init__(parent=parent, title='Presentation registry', content=content, buttons=buttons,
                         show_close_button=True, show_overlay=False)
        self.setFixedSize(700, 640)
        close.clicked.connect(self.close)
        self.existing.currentIndexChanged.connect(self._existing_changed)
        self.controller.currentIndexChanged.connect(self._controller_changed)
        self.create.clicked.connect(self._create)
        self.vault.signals.doer_event.connect(self._event)
        self.finished.connect(self._finished)
        self._controller_changed()

    def _existing_changed(self, *_):
        regk = self.existing.currentData()
        if regk in self._pending_names:
            name = self._pending_names[regk]
            rip = self.vault.db.registry_creations.get((name,))
            self.controller.setCurrentIndex(self.controller.combo_box.findData(rip.israid))
            self.name.setText(name)
            self.controller.setEnabled(False)
            self.name.setEnabled(False)
            self.identifier.setText('')
            authenticated = bool(self.vault.rgy.store.head(regk))
            self.create.setText('Retry publication' if authenticated else 'Retry creation')
            if self._auth_panel:
                self._auth_panel.setVisible(not authenticated)
        else:
            self.identifier.setText(regk or '')
            self.controller.setEnabled(self._controller is None)
            self.name.setEnabled(True)
            if self._auth_panel:
                self._auth_panel.show()

    def _finished(self, *_):
        if self._closed:
            return
        self._closed = True
        self.vault.signals.doer_event.disconnect(self._event)
        if self._doer is not None and self._doer in self.vault.doers:
            self.vault.remove([self._doer])

    def closeEvent(self, event):
        self._finished()
        super().closeEvent(event)

    def _controller_changed(self, *_):
        if self._auth_panel is not None:
            self._auth_panel.setParent(None)
            self._auth_panel.deleteLater()
            self._auth_panel = None
        hab = self.vault.hby.habByPre(self.controller.currentData())
        self._estate = hab.kever.lastEst.d if hab else None
        if hab and hab.kever.wits:
            self._auth_panel = WitnessAuthenticationPanel(self.app, hab, list(hab.kever.wits), self)
            self._layout.addWidget(self._auth_panel)

    def _create(self):
        try:
            if self._closed or (self._doer is not None and not self._doer.done):
                return
            if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
                raise ValueError('This vault is closed')
            hab = self.vault.hby.habByPre(self.controller.currentData())
            if hab is None:
                raise ValueError('Choose a local controller')
            if self._estate != hab.kever.lastEst.d:
                self._controller_changed()
                raise ValueError('Identifier key state changed. Review witness authentication again.')
            codes = []
            name = self.name.text().strip()
            pending = self.vault.db.registry_creations.get((name,))
            authenticated = bool(pending and self.vault.rgy.store.head(pending.said))
            if self._auth_panel and not authenticated:
                valid, codes, error = self._auth_panel.validate_authentication_codes()
                if not valid:
                    raise ValueError(error)
            if (not name or (name in self.vault.rgy.names
                             and self.vault.db.registry_creations.get((name,)) is None)):
                raise ValueError('Choose an unused registry name')
            self.clear_error()
            self.identifier.setText('')
            self._doer = CreateRegistryDoer(self.vault, hab, name, codes=codes)
            self.vault.extend([self._doer])
            if self._auth_panel:
                for field in self._auth_panel.passcode_fields.values():
                    field.setText('')
            for field in (self.create, self.controller, self.name, self.existing):
                field.setEnabled(False)
            if self._auth_panel:
                self._auth_panel.setEnabled(False)
            self.create.setText('Anchoring and publishing…')
        except Exception as ex:
            self.show_error(str(ex))

    def _event(self, name, event, data):
        if name != 'CreateRegistry' or self._doer is None or data.get('operation') != self._doer.operation:
            return
        if self._closed or self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            return
        if event == 'created':
            self.identifier.setText(data['registry'])
            self._pending_names.pop(data['registry'], None)
            index = self.existing.combo_box.findData(data['registry'])
            if index < 0:
                self.existing.addItem(self._doer.name, data['registry'])
            else:
                self.existing.combo_box.setItemText(index, self._doer.name)
            self.show_success('Registry anchored and published')
            self.create.setText('Registry created')
            self.existing.setEnabled(True)
        else:
            self.show_error(data['error'])
            self.create.setText('Retry creation')
            self.create.setEnabled(True)
            self.existing.setEnabled(True)
            if self._auth_panel:
                self._auth_panel.setEnabled(True)
            rip = self.vault.db.registry_creations.get((self._doer.name,))
            if rip is None:
                self.controller.setEnabled(self._controller is None)
                self.name.setEnabled(True)
            if rip and self.vault.rgy.store.head(rip.said):
                self.create.setText('Retry publication')
                if self._auth_panel:
                    self._auth_panel.hide()
            if rip and rip.said not in self._pending_names:
                self._pending_names[rip.said] = self._doer.name
                self.existing.addItem(f'{self._doer.name} (creation pending)', rip.said)
