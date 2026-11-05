"""OOB citizen challenge and IAR binding dialog."""
import json
from datetime import datetime, timezone
from time import time

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from keri.core import SealEvent

from locksmith.core import proofing
from locksmith.ui.toolkit.tables import PaginatedTableWidget
from locksmith.ui.vault.credentials.presentation import identifier_name
from locksmith.ui.vault.shared.base_list_page import BaseListPage
from locksmith.ui.toolkit.widgets import LocksmithDialog, LocksmithButton, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.buttons import LocksmithCopyButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel, witness_auth_dialog_height


class ProofingDialog(LocksmithDialog):
    def __init__(self, app, parent=None):
        self.app, self.vault = app, app.vault
        self._pending = False
        self._doer = None
        self._auth_dialog = None
        self._auth_panel = None
        content = QWidget()
        layout = QVBoxLayout(content)
        description = QLabel('Exchange the citizen AID and challenge out of band. '
                             'This checks control and receipt binding. State proofing authority '
                             'and identity attributes remain unapproved.')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.sessions = FloatingLabelComboBox('Resume session')
        self.sessions.addItem('New session', None)
        for (nonce,), record in self.vault.db.proofing.getTopItemIter():
            self.sessions.addItem(f'{record.citizen[:12]}… {nonce}', nonce)
        layout.addWidget(self.sessions)
        self.citizen = FloatingLabelLineEdit('Citizen AID received out of band')
        self.proofer = FloatingLabelLineEdit('Proofer AID')
        self.nonce = FloatingLabelLineEdit('Challenge (blank to generate as proofer)')
        self.sn = FloatingLabelLineEdit('Citizen anchor sequence number (decimal)')
        self.receipt = FloatingLabelLineEdit('Authenticated received IAR SAID (optional)')
        for field in (self.citizen, self.proofer, self.nonce, self.sn, self.receipt):
            layout.addWidget(field)
        self.anchor_reference = FloatingLabelLineEdit('Verified citizen anchor reference')
        self.anchor_reference.line_edit.setReadOnly(True)
        self.copy_anchor = LocksmithCopyButton(tooltip='Copy citizen anchor reference')
        self.copy_anchor.setEnabled(False)
        anchor_row = QHBoxLayout()
        anchor_row.addWidget(self.anchor_reference, 1)
        anchor_row.addWidget(self.copy_anchor)
        layout.addLayout(anchor_row)
        self.status = QLabel('New session')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        actions = QHBoxLayout()
        self.start_button = LocksmithButton('Save challenge')
        self.anchor_button = LocksmithButton('Anchor as citizen')
        self.verify_button = LocksmithButton('Check binding')
        self.issue_button = LocksmithButton('Issue IAR…')
        for button in (self.start_button, self.anchor_button, self.verify_button, self.issue_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        buttons = QHBoxLayout()
        close = LocksmithInvertedButton('Close')
        buttons.addWidget(close)
        super().__init__(parent=parent, title='Proofing', content=content, buttons=buttons,
                         show_close_button=True, show_overlay=False)
        self.setFixedSize(740, 710)
        close.clicked.connect(self.close)
        self.sessions.currentIndexChanged.connect(self._load)
        self.start_button.clicked.connect(lambda: self._run(self._start))
        self.anchor_button.clicked.connect(lambda: self._run(self._anchor))
        self.verify_button.clicked.connect(lambda: self._run(self._verify))
        self.issue_button.clicked.connect(lambda: self._run(self._issue))
        self.vault.signals.doer_event.connect(self._event)
        self.finished.connect(self._finished)
        self._actions_for_session()

    def _run(self, action):
        try:
            if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
                raise ValueError('This vault is closed')
            if self._pending:
                raise ValueError('Citizen anchor is still collecting witness receipts')
            self.clear_error()
            action()
        except Exception as error:
            self.show_error(str(error))

    def _load(self, *_):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.show_error('This vault is closed')
            return
        nonce = self.sessions.currentData()
        self.anchor_reference.setText('')
        self.copy_anchor.set_copy_content('')
        self.copy_anchor.setEnabled(False)
        for field in (self.citizen, self.proofer, self.nonce):
            field.setEnabled(nonce is None)
        self.start_button.setEnabled(nonce is None)
        if nonce is None:
            for field in (self.citizen, self.proofer, self.nonce, self.sn, self.receipt):
                field.setText('')
            self.status.setText('New session')
            self._actions_for_session()
            return
        record = proofing.session(self.vault, nonce)
        self.citizen.setText(record.citizen)
        self.proofer.setText(record.proofer)
        self.nonce.setText(nonce)
        self.sn.setText(str(record.anchor_sn) if record.anchor_sn >= 0 else '')
        self.receipt.setText(record.receipt)
        self.status.setText(f'{record.status}. State authority has not been established.')
        self._actions_for_session(record)
        if record.anchor_said:
            try:
                anchor = proofing.binding(self.vault, nonce, record.anchor_sn)
                if anchor.said != record.anchor_said:
                    raise ValueError('Saved citizen anchor is no longer canonical')
            except Exception as error:
                self.show_error(str(error))
                return
            reference = json.dumps(SealEvent(i=anchor.pre, s=anchor.snh, d=anchor.said)._asdict())
            self.anchor_reference.setText(reference)
            self.copy_anchor.set_copy_content(reference)
            self.copy_anchor.setEnabled(True)

    def _actions_for_session(self, record=None):
        citizen = bool(record and record.citizen in self.vault.hby.prefixes)
        proofer = bool(record and record.proofer in self.vault.hby.prefixes)
        self.start_button.setVisible(record is None)
        self.anchor_button.setVisible(citizen)
        self.anchor_button.setEnabled(not record or not record.anchor_said)
        self.verify_button.setVisible(record is not None)
        self.verify_button.setEnabled(record is not None)
        self.verify_button.setText('Check receipt binding' if citizen and not proofer else 'Check binding')
        self.issue_button.setVisible(proofer)
        self.issue_button.setEnabled(bool(record and record.anchor_said))
        self.sn.setVisible(record is not None)
        self.receipt.setVisible(record is not None)
        self.anchor_reference.setVisible(record is not None)
        self.copy_anchor.setVisible(record is not None)

    def _selected(self):
        nonce = self.sessions.currentData()
        if not nonce:
            raise ValueError('Save a challenge or resume a session first')
        return nonce

    def _start(self):
        record = proofing.start(self.vault, self.citizen.text().strip(), self.proofer.text().strip(),
                                self.nonce.text().strip() or None)
        self.sessions.addItem(f'{record.citizen[:12]}… {record.nonce}', record.nonce)
        self.sessions.setCurrentIndex(self.sessions.combo_box.count() - 1)

    def _anchor(self):
        nonce = self._selected()
        record = proofing.session(self.vault, nonce)
        hab = self.vault.hby.habByPre(record.citizen)
        if hab is None:
            raise ValueError('Only the local citizen can anchor this challenge')
        if self._auth_dialog is not None:
            raise ValueError('Finish or cancel witness authentication first')
        sn = record.anchor_sn if record.anchor_sn >= 0 else hab.kever.sn
        witness_ids = [wit.qb64 for wit in hab.kvy.fetchWitnessState(hab.pre, sn)]
        if not witness_ids:
            self._queue_anchor(nonce)
            return
        self._auth_panel = WitnessAuthenticationPanel(self.app, hab, witness_ids, self)
        buttons = QHBoxLayout()
        cancel = LocksmithInvertedButton('Cancel')
        submit = LocksmithButton('Authenticate and anchor')
        buttons.addWidget(cancel)
        buttons.addWidget(submit)
        self._auth_dialog = LocksmithDialog(parent=self, title='Authenticate Citizen Witnesses',
                                           content=self._auth_panel, buttons=buttons,
                                           show_close_button=True, show_overlay=False)
        self._auth_dialog.setFixedSize(700, witness_auth_dialog_height(
            self._auth_panel.individual_witnesses, self._auth_panel.batch_groups))
        cancel.clicked.connect(self._auth_dialog.close)
        submit.clicked.connect(lambda: self._run(lambda: self._submit_anchor_auth(nonce)))
        self._auth_dialog.finished.connect(self._auth_finished)
        self.sessions.setEnabled(False)
        self._auth_dialog.open()

    def _submit_anchor_auth(self, nonce):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            raise ValueError('This vault is closed')
        if nonce != self._selected() or self._auth_panel is None:
            raise ValueError('This proofing session changed')
        valid, codes, error = self._auth_panel.validate_authentication_codes()
        if not valid:
            self._auth_dialog.show_error(error)
            return
        self._queue_anchor(nonce, codes)
        self._auth_dialog.accept()

    def _auth_finished(self, _result):
        dialog = self._auth_dialog
        if self._auth_panel is not None:
            for field in self._auth_panel.passcode_fields.values():
                field.setText('')
        self._auth_dialog = None
        self._auth_panel = None
        if not self._pending:
            self.sessions.setEnabled(True)
        if dialog is not None:
            dialog.deleteLater()

    def _queue_anchor(self, nonce, codes=None):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            raise ValueError('This vault is closed')
        self._doer = proofing.AnchorChallengeDoer(self.app, nonce, codes=codes)
        self._pending = True
        self.sessions.setEnabled(False)
        self.status.setText('Anchoring challenge and collecting witness receipts…')
        try:
            self.vault.extend([self._doer])
        except Exception:
            self._pending = False
            self._doer = None
            self.sessions.setEnabled(True)
            raise

    def _verify(self):
        proofing.verify(self.vault, self._selected(), int(self.sn.text()), self.receipt.text().strip() or None)
        self._load()

    def _issue(self):
        nonce = self._selected()
        record = proofing.verify(self.vault, nonce, int(self.sn.text()))
        if self.vault.db.issuers.get((proofing.IAR_SCHEMA,)) != record.proofer:
            raise ValueError('Configure the IAR schema with this session proofer as local issuer')
        dialog = IssueCredentialDialog(self.app, self, nonce=nonce)
        schema = dialog.schema_dropdown.combo_box.findData(proofing.IAR_SCHEMA)
        if schema < 0:
            raise ValueError('Load and configure the IAR schema first')
        dialog.schema_dropdown.setCurrentIndex(schema)
        dialog.schema_dropdown.setEnabled(False)
        modes = dialog.authentication_dropdown.combo_box
        modes.setCurrentIndex(modes.findData('signature'))
        dialog.local_radio.setChecked(record.citizen in self.vault.hby.prefixes)
        dialog.remote_radio.setChecked(record.citizen not in self.vault.hby.prefixes)
        if dialog.recipient_dropdown.combo_box.findData(record.citizen) < 0:
            dialog.recipient_dropdown.addItem(record.citizen, record.citizen)
        dialog.recipient_dropdown.setCurrentIndex(dialog.recipient_dropdown.combo_box.findData(record.citizen))
        dialog.recipient_dropdown.setEnabled(False)
        dialog.local_radio.setEnabled(False)
        dialog.remote_radio.setEnabled(False)
        self._issue_dialog = dialog
        dialog.open()

    def _event(self, name, event, data):
        if name != 'Proofing' or data.get('nonce') != self.sessions.currentData():
            return
        self._pending = False
        self._doer = None
        self.sessions.setEnabled(True)
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            return
        self._load()
        if event == 'failed':
            self.show_error(data.get('error', 'Proofing failed'))

    def _finished(self, _result):
        if self._auth_dialog is not None:
            self._auth_dialog.close()
        self.vault.signals.doer_event.disconnect(self._event)
        if self._doer is not None and not getattr(self.vault, 'closed', False):
            self.vault.remove([self._doer])
        self._doer = None


class ProofingSessionsPage(BaseListPage):
    """Resume an out-of-band proofing ceremony without an existing credential."""

    def __init__(self, parent):
        super().__init__(parent)
        self.app = parent.app
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.table = PaginatedTableWidget(
            columns=['Citizen', 'Proofer', 'Status', 'Expires', 'Actions'], title='Proofing',
            icon_path=':/assets/material-icons/badge.svg', add_button_text='New session',
            row_actions=['Resume'])
        layout.addWidget(self.table)
        self.table.add_clicked.connect(lambda: self._open_session())
        self.table.row_clicked.connect(lambda row: self._open_session(row['nonce']))
        self.table.row_action_triggered.connect(lambda row, action: self._open_session(row['nonce']))

    def set_vault_name(self, vault_name):
        self.refresh()

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh()

    def refresh(self):
        vault = self.app.vault
        rows = []
        if vault and not getattr(vault, 'closed', False):
            for (nonce,), record in vault.db.proofing.getTopItemIter():
                status = ('Expired' if time() >= record.expires_at and not record.anchor_said
                          else record.status.replace('_', ' ').capitalize())
                rows.append({'Citizen': identifier_name(vault, record.citizen),
                             'Proofer': identifier_name(vault, record.proofer), 'Status': status,
                             'Expires': datetime.fromtimestamp(record.expires_at, timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
                             'nonce': nonce})
        self.table.set_static_data(rows)

    def _open_session(self, nonce=None):
        vault = self.app.vault
        if not vault or getattr(vault, 'closed', False):
            return
        self._dialog = ProofingDialog(self.app, self)
        if nonce is not None:
            self._dialog.sessions.setCurrentIndex(self._dialog.sessions.combo_box.findData(nonce))
        self._dialog.finished.connect(self.refresh)
        self._dialog.open()
