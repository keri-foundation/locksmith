"""Start a credential exchange from its schema or inventory."""
from PySide6.QtCore import Qt, Signal, QSignalBlocker
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel

from locksmith.core import credentialing, ipexing
from locksmith.ui.vault.shared.messaging import prepare_messaging
from locksmith.core.habbing import list_eligible_local_identifiers
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.credentials.disclosure import DisclosureFields, DisclosureSelection
from locksmith.ui.vault.credentials.presentation import credential_name, identifier_name, disclosure_fields
from locksmith.ui.vault.credentials.schema.catalog import request_schemas
from locksmith.ui.vault.remotes.add import AddRemoteIdentifierDialog
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel


class RequestDisclosure(QWidget):
    """Request attributes from a credential and its declared source links."""

    changed = Signal()

    def __init__(self, vault, schema, schemas, parent=None):
        super().__init__(parent)
        self.vault, self.schema, self.schemas = vault, schema, schemas
        self.links = {}
        edges = credentialing.schema_detail(schema.get('properties', {}).get('e')) or {}
        self.slots = {name: detail for name, definition in edges.get('properties', {}).items()
                      if (detail := credentialing.schema_detail(definition))
                      and 'n' in detail.get('properties', {})}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.fields = DisclosureFields(vault, schema)
        self.fields.changed.connect(self.changed)
        layout.addWidget(self.fields)
        self.link_rows = QVBoxLayout()
        layout.addLayout(self.link_rows)
        self.add_information = FloatingLabelComboBox('Add information from a linked credential')
        layout.addWidget(self.add_information)
        self._available_links()
        self.add_information.currentIndexChanged.connect(self._add_link)

    def _available_links(self):
        with QSignalBlocker(self.add_information):
            self.add_information.clear()
            self.add_information.addItem('Choose information', None)
            for name, definition in self.slots.items():
                if name not in self.links:
                    label = definition.get('description', name).removesuffix(' Edge Block')
                    self.add_information.addItem(label, name)
        self.add_information.setVisible(len(self.links) < len(self.slots))

    def _add_link(self, *_):
        name = self.add_information.currentData()
        if name is None:
            return
        definition = self.slots[name]
        row = QWidget()
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        heading = QHBoxLayout()
        selector = FloatingLabelComboBox(definition.get('description', name).removesuffix(' Edge Block'))
        selector.addItem('Choose credential type', None)
        fixed = definition.get('properties', {}).get('s', {}).get('const')
        for said, schemer in self.schemas.items():
            if fixed is None or said == fixed:
                selector.addItem(credential_name(schemer.sed), said)
        remove = LocksmithInvertedButton('Remove')
        remove.setAccessibleName('Remove ' + name)
        heading.addWidget(selector, 1)
        heading.addWidget(remove)
        layout.addLayout(heading)
        self.links[name] = {'row': row, 'selector': selector, 'fields': {}, 'fixed': fixed}
        self.link_rows.addWidget(row)
        selector.currentIndexChanged.connect(lambda *_: self._select_link(name))
        remove.clicked.connect(lambda: self._remove_link(name))
        if fixed and selector.count() == 2:
            selector.setCurrentIndex(1)
            selector.setEnabled(False)
        self._available_links()
        self.changed.emit()

    def _select_link(self, name):
        link = self.links[name]
        said = link['selector'].currentData()
        for fields in link['fields'].values():
            fields.hide()
        if said:
            if said not in link['fields']:
                fields = DisclosureFields(self.vault, self.schemas[said].sed)
                fields.changed.connect(self.changed)
                link['fields'][said] = fields
                link['row'].layout().addWidget(fields)
            link['fields'][said].show()
        self.changed.emit()

    def _remove_link(self, name):
        row = self.links.pop(name)['row']
        self.link_rows.removeWidget(row)
        row.deleteLater()
        self._available_links()
        self.changed.emit()

    @staticmethod
    def _requested_fields(widget, schema):
        selected = widget.selected_fields()
        if selected:
            selected.extend(field['path'] for field in disclosure_fields(schema) if field['required'])
        return selected

    def disclosure_plan(self, said):
        graph = [[said, '/', self._requested_fields(self.fields, self.schema)]]
        for name in self.slots:
            if name not in self.links:
                continue
            link = self.links[name]
            source = link['selector'].currentData()
            if not source:
                if link['fixed'] and link['fixed'] not in self.schemas:
                    raise ValueError('Load the linked credential schema before requesting this information.')
                raise ValueError('Choose a credential type for the linked information.')
            graph.append([source, f'/e/{name}/_/',
                          self._requested_fields(link['fields'][source], self.schemas[source].sed)])
        return [graph]


class StartExchangeDialog(LocksmithDialog):
    """Start a credential request or offer with a compact preview."""

    submitted = Signal(str)

    def __init__(self, app, parent, action, *, schema=None, credential_said=None, received=False,
                 intent='issuance'):
        self.app, self.vault, self.action = app, app.vault, action
        self.received = received
        self.intent = intent
        self._offer_error = ''
        self._requests = {}
        self._offers = {}
        self._request_doer = None
        self._repair_dialog = None
        self._request_submitted = False
        self._closed = False
        self._auth_panel = None
        self._auth_controller = None
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(16)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        if action == 'Apply':
            explanation = QLabel(
                'Ask an issuer for a new credential.' if intent == 'issuance' else
                'Ask a holder to share information from a credential they already have.')
            explanation.setWordWrap(True)
            layout.addWidget(explanation)
        if action == 'Offer':
            explanation = QLabel('Choose what you are willing to share. Optional fields start unselected. '
                                 'The offer names your choices; values are shared after agreement.')
            explanation.setWordWrap(True)
            layout.addWidget(explanation)
        self.sender = FloatingLabelComboBox('Your identifier')
        for identifier in list_eligible_local_identifiers(app):
            self.sender.addItem(self._name(identifier['prefix']), identifier['prefix'])
        if self.sender.count() != 1:
            self.sender.setCurrentIndex(-1)
            layout.addWidget(self.sender)
        else:
            self.sender.hide()
        self.recipient = FloatingLabelComboBox('To')
        layout.addWidget(self.recipient)
        self.selection = FloatingLabelComboBox('Credential type' if action == 'Apply' else 'Credential')
        if action == 'Apply':
            self.schemas = request_schemas(self.vault)
            self.selection.addItem('Choose credential type', None)
            for said, schemer in self.schemas.items():
                self.selection.addItem(credential_name(schemer.sed), said)
        else:
            for view in credentialing.credentials(self.vault, received=True if received else None):
                if view['status']['et'] in ('issued', 'authenticated'):
                    self.selection.addItem(credential_name(view['schema']) + ' · ' + view['sad']['d'][:8] + '…',
                                           view['sad']['d'])
        selected = schema if action == 'Apply' else credential_said
        if selected:
            self.selection.setCurrentIndex(self.selection.combo_box.findData(selected))
            self.selection.setEnabled(False)
        layout.addWidget(self.selection)
        self.preview = QWidget()
        preview_layout = QVBoxLayout(self.preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        self.preview.setVisible(action != 'Apply' or intent == 'presentation')
        layout.addWidget(self.preview)
        self.registry_notice = QLabel()
        self.registry_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.registry_notice.setWordWrap(True)
        self.registry_notice.hide()
        layout.addWidget(self.registry_notice)
        self.auth_notice = QLabel('Enter the witness code to approve registry setup. '
                                 'Locksmith then publishes the registry and sends your request automatically.')
        self.auth_notice.setWordWrap(True)
        self.auth_notice.hide()
        layout.addWidget(self.auth_notice)
        self.authentication = QVBoxLayout()
        layout.addLayout(self.authentication)
        self.progress = QLabel()
        self.progress.setWordWrap(True)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        self.error.hide()
        layout.addWidget(self.error)
        self.repair_button = LocksmithInvertedButton('Import delivery details')
        self.repair_button.clicked.connect(self._repair_route)
        layout.addWidget(self.repair_button)
        cancel = LocksmithInvertedButton('Cancel')
        self.send_button = LocksmithButton('Send request' if action == 'Apply' else 'Send offer')
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(self.send_button)
        title = 'Offer credential'
        if action == 'Apply':
            title = 'Request credential' if intent == 'issuance' else 'Request presentation'
        super().__init__(parent, title=title,
                         content=content, buttons=buttons, show_title_divider=False)
        self.fit_content(640 if action == 'Apply' and intent == 'issuance' else 540)
        cancel.clicked.connect(self.close)
        self.send_button.clicked.connect(self._send)
        self.sender.currentIndexChanged.connect(self._update_recipients)
        self.recipient.currentIndexChanged.connect(self._check_route)
        self.selection.currentIndexChanged.connect(self._select_sender)
        self.vault.signals.doer_event.connect(self._request_event)
        self.finished.connect(self._finished)
        self._select_sender()
        self._update_recipients()

    def _name(self, pre):
        return identifier_name(self.vault, pre)

    def _update_recipients(self, *_):
        """Keep the recipient choice when it remains valid for the sender."""
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.send_button.setEnabled(False)
            return
        selected = self.recipient.currentData()
        peers = {contact['id'] for contact in self.vault.org.list()}
        peers.update(self.vault.hby.prefixes)
        peers.discard(self.sender.currentData())
        with QSignalBlocker(self.recipient):
            self.recipient.clear()
            self.recipient.addItem('Choose a contact', None)
            for pre in sorted(peers, key=lambda pre: (self._name(pre).casefold(), pre)):
                self.recipient.addItem(self._name(pre), pre)
            self.recipient.setCurrentIndex(max(0, self.recipient.combo_box.findData(selected)))
        self._check_route()

    def _select_sender(self, *_):
        if self._closed or self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.send_button.setEnabled(False)
            return
        if self.action == 'Apply' and self.intent == 'presentation':
            for request in self._requests.values():
                request.hide()
            said = self.selection.currentData()
            self._offer_error = ''
            try:
                if said:
                    if said not in self._requests:
                        request = RequestDisclosure(self.vault, self.schemas[said].sed, self.schemas)
                        request.changed.connect(self._request_changed)
                        self._requests[said] = request
                        self.preview.layout().addWidget(request)
                    self._requests[said].show()
            except ValueError as error:
                self._offer_error = str(error)
        if self.action == 'Offer' and self.selection.currentData() and self.sender.currentData() is None:
            said = self.selection.currentData()
            view = credentialing.credential(self.vault, said, received=self.received)
            pre = (view['sad']['i'] if not self.received and self.vault.db.issued.get((said,))
                   else view['subject'])
            index = self.sender.combo_box.findData(pre)
            if index >= 0:
                self.sender.setCurrentIndex(index)
        if self.action == 'Offer':
            for offer in self._offers.values():
                offer.hide()
            self._offer_error = ''
            try:
                said = self.selection.currentData()
                if said:
                    if said not in self._offers:
                        offer = DisclosureSelection(self.vault, said)
                        offer.changed.connect(self._request_changed)
                        self._offers[said] = offer
                        self.preview.layout().addWidget(offer)
                    self._offers[said].show()
            except Exception as error:
                self._offer_error = str(error)
        self._check_route()

    def _request_changed(self):
        self._check_route()

    def _check_route(self, *_):
        if self._request_doer is not None and not self._request_doer.done:
            return
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.send_button.setEnabled(False)
            return
        hab = self.vault.hby.habByPre(self.sender.currentData())
        needs_registry = self._needs_registry()
        if needs_registry:
            controller_name = self._name(hab.pre) if hab else 'your selected identifier'
            self.registry_notice.setText(
                'Sending this request creates and publishes a presentation registry '
                f'controlled by {controller_name}. Setup finishes before Locksmith contacts the issuer. '
                'The issuer includes this registry in your new credential. '
                'Retrying an unfinished request reuses its registry.')
        authenticated = needs_registry and self._request_authenticated()
        self.registry_notice.setVisible(needs_registry and not authenticated)
        if self.action == 'Apply' and self._request_doer is None:
            self.progress.setText('Registry already created. Sending resumes setup and sends your request.'
                                  if authenticated else '')
            self.progress.setVisible(bool(authenticated))
        controller = hab.pre if hab and needs_registry and hab.kever.wits and not authenticated else None
        self.auth_notice.setVisible(bool(controller))
        if controller != self._auth_controller:
            if self._auth_panel is not None:
                self.authentication.removeWidget(self._auth_panel)
                self._auth_panel.deleteLater()
                self._auth_panel = None
            self._auth_controller = controller
            if controller:
                self._auth_panel = WitnessAuthenticationPanel(self.app, hab, list(hab.kever.wits), self)
                self.authentication.addWidget(self._auth_panel)
                self._auth_panel.show()
        recipient = self.recipient.currentData()
        error = self._offer_error
        if self.action == 'Apply' and not error and self.selection.currentData() in self._requests:
            try:
                self._requests[self.selection.currentData()].disclosure_plan(self.selection.currentData())
            except ValueError as ex:
                error = str(ex)
        missing_recipient = False
        if hab is not None and recipient and recipient != hab.pre and not error:
            try:
                ipexing._require_route(hab, recipient)
            except ipexing.MissingRouteError as ex:
                error = str(ex)
                missing_recipient = True
            except Exception as ex:
                error = str(ex)
        self.error.setText(error)
        self.error.setVisible(bool(error))
        self.repair_button.setVisible(missing_recipient)
        self.send_button.setEnabled(bool(hab and recipient and recipient != hab.pre
                                         and self.selection.currentData() and not error))
        self.fit_content(self.width())

    def _repair_route(self):
        if self._closed or self.app.vault is not self.vault:
            return
        if self._repair_dialog is None:
            self._repair_dialog = AddRemoteIdentifierDialog(self.app, self.parentWidget())
            self._repair_dialog.finished.connect(self._return_from_repair)
        self.hide()
        self._repair_dialog.open()

    def _return_from_repair(self, *_):
        if not self._closed and self.app.vault is self.vault and not getattr(self.vault, 'closed', False):
            self._update_recipients()
            self.open()

    def _needs_registry(self):
        if self.action != 'Apply' or self.intent != 'issuance' or not self.selection.currentData():
            return False
        schemer = self.schemas.get(self.selection.currentData())
        return bool(schemer and ipexing.requests_presentation_registry(schemer.sed))

    def _request_authenticated(self):
        schema = self.selection.currentData()
        for (request_id,), record in self.vault.db.requests.getTopItemIter():
            if not record.submitted and (record.sender, record.recipient, record.schema, record.plan, record.ax) == (
                    self.sender.currentData(), self.recipient.currentData(), schema, [[[schema, '/', []]]], None):
                registry = self.vault.rgy.registryByName('request-' + request_id)
                return bool(record.stream or (registry and self.vault.rgy.store.head(registry.regk)))
        return False

    def _finished(self, *_):
        if self._closed:
            return
        self._closed = True
        if self._repair_dialog is not None:
            self._repair_dialog.reject()
        self.vault.signals.doer_event.disconnect(self._request_event)
        if (not self._request_submitted and self._request_doer is not None
                and self._request_doer in self.vault.doers):
            self.vault.remove([self._request_doer])

    def _request_event(self, name, event, data):
        if (name != 'RequestCredential' or self._request_doer is None
                or data.get('request') != self._request_doer.request_id):
            return
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            return
        if event == 'submitted':
            self._request_submitted = True
            self.accept()
            self.submitted.emit(data['said'])
        elif event == 'progress':
            self.progress.setText({
                'creating': 'Creating your presentation registry…',
                'witnessing': 'Waiting for the witness to approve registry setup…',
                'publishing': 'Registry created. Publishing and verifying your registry…',
                'sending': 'Registry setup complete. Sending your request…',
            }[data['stage']])
            self.progress.show()
            self.fit_content(self.width())
        elif event == 'failed':
            authenticated = self._request_authenticated()
            self.progress.setText(
                'Registry created. Your credential request has not been sent. Retry to finish setup and send it.'
                if authenticated else 'Registry setup is incomplete. Your credential request has not been sent.')
            self.progress.show()
            if self._auth_panel:
                self._auth_panel.setEnabled(True)
                self._auth_panel.setVisible(not authenticated)
                self.auth_notice.setVisible(not authenticated)
            self.error.setText(data['error'])
            self.error.show()
            self.send_button.setText('Retry request')
            self.send_button.setEnabled(True)
            self.fit_content(self.width())

    def _send(self):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.error.setText('This vault is closed.')
            self.error.show()
            return
        self.send_button.setEnabled(False)
        try:
            hab = self.vault.hby.habByPre(self.sender.currentData())
            if hab is None:
                raise ValueError('Choose your identifier')
            if prepare_messaging(self, self.app, hab, self._send, self._messaging_error):
                return
            selection = {'schema' if self.action == 'Apply' else 'credential_said': self.selection.currentData()}
            if self.action == 'Apply':
                said = self.selection.currentData()
                selection['disclosure_plan'] = (self._requests[said].disclosure_plan(said)
                                                if self.intent == 'presentation' else [[[said, '/', []]]])
                # Save requested schemas only once the user commits to sending.
                for said, _, _ in selection['disclosure_plan'][0]:
                    if self.vault.hby.db.schema.get((said,)) is None:
                        self.vault.hby.db.schema.pin((said,), self.schemas[said])
                if self._needs_registry():
                    codes = []
                    if self._auth_panel and not self._request_authenticated():
                        valid, codes, error = self._auth_panel.validate_authentication_codes()
                        if not valid:
                            raise ValueError(error)
                    self._request_doer = ipexing.RequestCredentialDoer(
                        self.vault, hab, self.recipient.currentData(), codes=codes, **selection)
                    for field in (self.sender, self.recipient, self.selection, self.preview):
                        field.setEnabled(False)
                    self.send_button.setText('Preparing request…')
                    self.error.clear()
                    self.error.hide()
                    self.progress.clear()
                    self.progress.hide()
                    self.registry_notice.hide()
                    self.auth_notice.hide()
                    if self._auth_panel:
                        self._auth_panel.setEnabled(False)
                        self._auth_panel.hide()
                        for field in self._auth_panel.passcode_fields.values():
                            field.setText('')
                    self.vault.extend([self._request_doer])
                    return
            else:
                plan, message, _ = self._offers[self.selection.currentData()].prepare()
                selection.update(disclosure_plan=plan, message=message)
            said = ipexing.start(self.vault, hab, self.recipient.currentData(), self.action, **selection)
            self.accept()
            self.submitted.emit(said)
        except Exception as error:
            self.error.setText(str(error))
            self.error.show()
            self.send_button.setEnabled(True)
            self.fit_content(self.width())

    def _messaging_error(self, message):
        self.error.setText(message)
        self.error.show()
        self.send_button.setEnabled(True)
        self.fit_content(self.width())
