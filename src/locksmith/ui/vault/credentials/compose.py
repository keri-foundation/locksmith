"""Combine held credentials into a self-issued presentation."""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel

from locksmith.core import credentialing, ipexing
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, LocksmithPlainTextEdit
from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection
from locksmith.ui.vault.credentials.presentation import (
    attribute_label, credential_details, credential_name, identifier_name, request_details,
    identity_context, consent_action,
)


def can_compose(schema):
    """Accept identity-only roots with simple issuer-to-issuee source edges."""
    properties = schema.get('properties', {})
    attributes = credentialing.schema_detail(properties.get('a'))
    edges = credentialing.schema_detail(properties.get('e'))
    rules = credentialing.schema_detail(properties.get('r'))
    if (not attributes or not edges or 'rd' in schema.get('required', [])
            or set(attributes.get('properties', {})) - {'d', 'u', 'i'}
            or 'i' not in attributes.get('properties', {})):
        return False
    if 'r' in properties and (not rules or set(rules.get('properties', {})) - {'d', 'u', 'l'}
                              or rules.get('properties', {}).get('l', {}).get('type') != 'string'):
        return False
    slots = {name: definition for name, definition in edges.get('properties', {}).items()
             if name not in ('d', 'u')}
    return bool(slots) and all(
        definition.get('type') == 'object'
        and 'n' in definition.get('properties', {})
        and not set(definition.get('properties', {})) - {'d', 'u', 'n', 's', 'o'}
        and definition.get('properties', {}).get('o', {}).get('const', 'I2I') == 'I2I'
        for definition in slots.values())


class ComposePresentationDialog(LocksmithDialog):
    """Choose source credentials, then return to the disclosure review."""

    credential_created = Signal(str)

    def __init__(self, page, request_said, *, draft=None):
        self.app, self.vault = page.app, page.vault
        self.request_said = request_said
        self._issuance_id = None
        self._draft = draft if draft is not None else {}
        request = self.vault.hby.db.exns.get((request_said,))
        self.schema_said = ipexing.request_schema(request)
        schemer = self.vault.hby.db.schema.get((self.schema_said,)) if self.schema_said else None
        if schemer is None or not can_compose(schemer.sed):
            raise ValueError('This request does not support combining held credentials.')
        self.schema = schemer.sed
        self.presenter = request.sad['ri']
        self._sources = {}
        self._edge_schema = credentialing.schema_detail(self.schema['properties']['e'])
        self._rules_schema = credentialing.schema_detail(self.schema['properties'].get('r'))
        content = self.form = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(12)
        layout.addWidget(identity_context(self.vault, self.presenter, request.pre))
        layout.addWidget(request_details(self.vault, request))
        explanation = QLabel('Choose credentials to combine, then choose what to share.')
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        candidates = [view for view in credentialing.credentials(self.vault)
                      if view['subject'] == self.presenter
                      and view['status']['et'] in ('issued', 'authenticated')]
        requested = {path: schema for graph in request.sad['q'].get('dp', [])
                     for schema, path, _ in graph}
        for name, definition in self._edge_schema['properties'].items():
            if name in ('d', 'u'):
                continue
            label = attribute_label(name, definition).removesuffix(' Edge Block')
            field = FloatingLabelComboBox(label)
            field.addItem('Choose a credential' if name in self._edge_schema.get('required', [])
                          else 'Not included', None)
            fields = definition['properties']
            wanted = requested.get(f'/e/{name}/_/')
            for view in candidates:
                said, schema = view['sad']['d'], view['schema'].get('$id')
                if wanted and schema != wanted:
                    continue
                if fields['n'].get('const', said) != said:
                    continue
                constraint = fields.get('s', {})
                if constraint.get('const', schema) != schema or schema not in constraint.get('enum', [schema]):
                    continue
                source_label = (f"{credential_name(view['schema'])} · Issued by "
                                f"{identifier_name(self.vault, view['sad']['i'])} · {said[:8]}…")
                field.addItem(source_label, said)
                field.combo_box.setItemData(field.count() - 1,
                    f"Issuer: {view['sad']['i']}\nSubject: {view['subject']}\nCredential: {said}\nSchema: {schema}",
                    Qt.ItemDataRole.ToolTipRole)
            field.setAccessibleName(label)
            layout.addWidget(field)
            self._sources[name] = field
            selected = field.combo_box.findData(self._draft.get('sources', {}).get(name))
            field.setCurrentIndex(max(0, selected))
        self.source_review = CollapsibleSection(title='Review selected credentials')
        self.source_review.set_content_layout(QVBoxLayout())
        layout.addWidget(self.source_review)
        self.terms = None
        if self._rules_schema:
            layout.addWidget(QLabel('Terms for this presentation'))
            self.terms = LocksmithPlainTextEdit('Enter the terms to include with this presentation.')
            self.terms.setAccessibleName('Terms for this presentation')
            self.terms.setFixedHeight(100)
            constant = self._rules_schema['properties']['l'].get('const')
            if constant is not None:
                self.terms.setPlainText(constant)
                self.terms.setReadOnly(True)
            else:
                self.terms.setPlainText(self._draft.get('terms', ''))
            layout.addWidget(self.terms)
        self.create_button = LocksmithButton('Continue to disclosure')
        self.cancel_button = LocksmithInvertedButton('Back')
        consent_action(self.create_button)
        consent_action(self.cancel_button)
        buttons = QHBoxLayout()
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.create_button)
        super().__init__(page, title='Combine credentials', content=content, buttons=buttons,
                         show_overlay=False)
        self.register_collapsible_section(self.source_review)
        for field in self._sources.values():
            field.currentIndexChanged.connect(self._preview_sources)
        self._preview_sources()
        self.cancel_button.clicked.connect(self.close)
        self.create_button.clicked.connect(self._create)
        self.vault.signals.doer_event.connect(self._on_doer_event)
        self.finished.connect(self._disconnect)
        self.finished.connect(self._save_draft)

    def _save_draft(self, *_):
        self._draft['sources'] = {name: field.currentData() for name, field in self._sources.items()}
        if self.terms is not None:
            self._draft['terms'] = self.terms.toPlainText()

    def _preview_sources(self, *_):
        layout = self.source_review.content_area.layout()
        while layout.count():
            widget = layout.takeAt(0).widget()
            widget.setParent(None)
            widget.deleteLater()
        for field in self._sources.values():
            if said := field.currentData():
                try:
                    if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
                        raise ValueError('This vault is closed.')
                    view = credentialing.credential(self.vault, said)
                    layout.addWidget(credential_details(self.vault, view['sad']))
                except Exception as error:
                    notice = QLabel(f'Cannot review {field.accessibleName()}: {error}')
                    notice.setTextFormat(Qt.TextFormat.PlainText)
                    notice.setWordWrap(True)
                    layout.addWidget(notice)
        self.source_review.setVisible(layout.count() > 0)
        self.source_review.update_content_height()
        self.fit_content(640)

    def _create(self):
        if self._issuance_id is not None:
            return
        try:
            if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
                raise ValueError('This vault is closed.')
            request = self.vault.hby.db.exns.get((self.request_said,))
            if request is None or 'Offer' not in ipexing.responses(self.vault, request):
                raise ValueError('This request has changed. Return to Activity to review it.')
            if error := ipexing.expiry_error(self.vault, request):
                raise ValueError(error)
            if self.vault.db.issuers.get((self.schema_said,)) != self.presenter:
                raise ValueError('Enable issuance for this schema with your presenting identifier first.')
            hab = self.vault.hby.habByPre(self.presenter)
            if hab is None:
                raise ValueError('The presenting identifier is not in this wallet.')
            edges = {}
            for name, field in self._sources.items():
                said = field.currentData()
                if said is None:
                    if name in self._edge_schema.get('required', []):
                        raise ValueError(f'Choose a credential for {field.accessibleName()}.')
                    continue
                source, _, _, _ = ipexing._credential_evidence(self.vault, said, hab)
                if source['subject'] != self.presenter:
                    raise ValueError('Each source credential must belong to your presenting identifier.')
                definition = self._edge_schema['properties'][name]
                values = {'n': said}
                if 's' in definition['properties']:
                    values['s'] = source['schema']['$id']
                if 'o' in definition['properties']:
                    values['o'] = 'I2I'
                edges[name] = values
            if not edges:
                raise ValueError('Choose at least one credential to combine.')
            rules = None
            if self.terms is not None:
                text = self.terms.toPlainText().strip()
                rules = {'l': text}
            doer = credentialing.IssueCredentialDoer(
                self.app, self.schema_said, self.presenter, {}, edges=edges, rules=rules,
                authentication='signature', signal_bridge=self.vault.signals)
            self._issuance_id = doer.issuance_id
            self.form.setEnabled(False)
            self.create_button.setEnabled(False)
            self.cancel_button.setEnabled(False)
            self.create_button.setText('Preparing presentation…')
            self.vault.extend([doer])
        except Exception as error:
            self._issuance_id = None
            self.form.setEnabled(True)
            self.create_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.create_button.setText('Continue to disclosure')
            self.show_error(str(error))

    def _on_doer_event(self, name, event, data):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self._disconnect()
            return
        if name != 'IssueCredentialDoer' or self._issuance_id is None or data.get('issuance_id') != self._issuance_id:
            return
        if event == 'credential_issued':
            self._issuance_id = None
            self.credential_created.emit(data['credential_said'])
            self.accept()
        elif event == 'credential_issuance_failed':
            self._issuance_id = None
            self.form.setEnabled(True)
            self.create_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.create_button.setText('Continue to disclosure')
            self.show_error(data.get('error', 'Could not prepare this presentation.'))

    def _disconnect(self, *_):
        try:
            self.vault.signals.doer_event.disconnect(self._on_doer_event)
        except RuntimeError:
            pass
