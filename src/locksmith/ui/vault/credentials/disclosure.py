"""Choose credential information without editing the retained credential."""
from collections.abc import Mapping
import json

from PySide6.QtCore import QObject, Qt, Signal, Slot
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from locksmith.core import credentialing, ipexing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets.buttons import LocksmithButton, LocksmithCheckbox
from locksmith.ui.vault.credentials.presentation import (
    attribute_view, credential_name, identifier_name, rules_text, disclosure_fields, disclosure_paths,
    attribute_label, consent_action, details_section, display_claims, requested_field_paths,
)


class RegistryCheckWait(QObject):
    """Resume an approved send after its pending registry check completes."""

    def __init__(self, dialog, form, send, failed, *, decline=None):
        super().__init__(dialog)
        self.dialog, self.form, self.send, self.failed, self.decline = dialog, form, send, failed, decline
        self.pending = None
        self._completed = None
        self._label = ''
        dialog.finished.connect(self.cancel)

    def wait(self, check):
        if self._completed == (check.registry, check.operation):
            # That check just completed and its evidence is still not current. Let the user decide when to retry.
            self.failed(str(check))
            self.dialog.send_button.setEnabled(True)
            return
        # A different check, such as the registrar after the observer, waits in turn.
        self.pending = (check.registry, check.operation)
        self._label = self.dialog.send_button.text()
        self.form.setEnabled(False)
        if self.decline is not None:
            self.decline.setEnabled(False)
        self.dialog.send_button.setEnabled(False)
        self.dialog.send_button.setText('Checking observer…' if check.operation == 'fetch' else 'Waiting for registrar…')
        self.dialog.vault.signals.doer_event.connect(self.checked, Qt.ConnectionType.QueuedConnection)

    def cancel(self):
        if self.pending is not None:
            self.pending = None
            self.dialog.vault.signals.doer_event.disconnect(self.checked)

    @Slot(str, str, dict)
    def checked(self, name, event, data):
        if (name != 'RegistryEvidence' or event != 'status_checked'
                or self.pending != (data.get('registry'), data.get('operation'))):
            return
        completed = self.pending
        self.cancel()
        self.form.setEnabled(True)
        if self.decline is not None:
            self.decline.setEnabled(True)
        self.dialog.send_button.setText(self._label)
        self.dialog.send_button.setEnabled(True)
        if not data['success']:
            self.failed(data['error'])
            return
        self._completed = completed
        try:
            self.send()
        finally:
            self._completed = None


class DisclosureFields(QWidget):
    """One choice per independently disclosable field or attribute block."""

    changed = Signal()

    def __init__(self, schema, sad=None, selected=None, parent=None, *, requested=None,
                 expand_additional=False, select_available=False):
        super().__init__(parent)
        self.checkboxes = {}
        self.select_all = None
        self.request_notice = None
        self.descriptions = disclosure_fields(schema, sad)
        selected = set(selected or ())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        requested_paths = requested_field_paths(self.descriptions, requested or (), sad)
        groups = {name: QVBoxLayout() for name in ('Requested fields', 'Additional fields', 'Always shared')}
        for field in self.descriptions:
            required = field['required']
            wanted = field['path'] in requested_paths
            content = QVBoxLayout()
            content.setContentsMargins(0, 0, 0, 0)
            content.setSpacing(4)
            definition = credentialing.schema_detail(field['schema']) or field['schema']
            definition = definition if isinstance(definition, Mapping) else {}
            properties = (field['value'] if isinstance(field['value'], Mapping)
                          else definition.get('properties', {}))
            claims = display_claims(field['value'], field['schema']) if sad is not None else None
            if required:
                if sad is not None:
                    # Mapping children already carry their schema labels.
                    label = None if isinstance(field['value'], Mapping) and field['value'] else field['name']
                    group = attribute_view(label, claims, field['schema'])
                else:
                    group = self._explanation(field['name'])
                group.setAccessibleName('Required information: ' + field['name'])
                content.addWidget(group)
            else:
                checkbox = LocksmithCheckbox(field['name'])
                checkbox.setAccessibleName(field['name'])
                checkbox.setAccessibleDescription(
                    'Request this field. The holder decides whether to offer it.' if sad is None else
                    ('Requested; ' if wanted else 'Optional; ') + 'not shared unless selected. ' +
                    str(claims))
                checkbox.setChecked(field['path'] in selected)
                self.checkboxes[field['path']] = checkbox
                checkbox.toggled.connect(self._selection_changed)
                content.addWidget(checkbox)
                if sad is not None:
                    content.addWidget(attribute_view(None, claims, field['schema']))
            if len(properties.keys() - {'d', 'u'}) > 1:
                content.addWidget(self._explanation(
                    'Shared together; individual values cannot be omitted.'))
            if sad is None:
                layout.addLayout(content)
            else:
                groups['Always shared' if required else 'Requested fields' if wanted else 'Additional fields'].addLayout(content)
        if sad is not None:
            for name, group in groups.items():
                if not group.count():
                    continue
                widget = QWidget()
                widget.setLayout(group)
                if name == 'Requested fields' or (select_available and name == 'Additional fields'):
                    self.select_all = LocksmithButton('Select all' if select_available else 'Select all requested')
                    self.select_all.setToolTip(
                        'Use this when issuing a credential with all its available fields. '
                        'Choose fields from linked credentials separately.' if select_available else
                        'Select the requested fields shown for this credential.')
                    consent_action(self.select_all)
                    group.insertWidget(0, self.select_all)
                    choices = widget.findChildren(LocksmithCheckbox)
                    self.select_all.clicked.connect(lambda checked=False, boxes=choices: self._select_fields(boxes))
                if name == 'Requested fields':
                    layout.addWidget(self._explanation(name + ' · choose what to offer'))
                    layout.addWidget(widget)
                else:
                    additional = name == 'Additional fields'
                    title = 'Additional fields (not requested)' if additional and requested is not None else name
                    if additional and select_available and requested is not None:
                        title = 'Available fields'
                    layout.addWidget(details_section(title, widget, expanded=additional and
                        (expand_additional or bool(selected - requested_paths))))
        if sad is None and self.checkboxes:
            self.request_notice = self._explanation('No specific fields requested; the holder chooses what to offer.')
            self.request_notice.setVisible(not self.has_selection())
            layout.addWidget(self.request_notice)

    def _selection_changed(self):
        if self.request_notice is not None:
            self.request_notice.setVisible(not self.has_selection())
        self.changed.emit()

    @staticmethod
    def _explanation(text):
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        label.setStyleSheet(f'color: {colors.TEXT_SECONDARY};')
        return label

    def selected_fields(self):
        """Return the optional canonical paths selected by the user."""
        return [path for path, checkbox in self.checkboxes.items() if checkbox.isChecked()]

    def has_selection(self):
        return any(checkbox.isChecked() for checkbox in self.checkboxes.values())

    @staticmethod
    def _select_fields(checkboxes):
        for checkbox in checkboxes:
            checkbox.setChecked(True)


class DisclosureSelection(QWidget):
    """Review and select data from retained credential evidence before an Offer."""

    changed = Signal()

    def __init__(self, vault, credential_said, selections=None, parent=None, *, requested=None, issuer_delivery=False):
        super().__init__(parent)
        self.vault, self.credential_said = vault, credential_said
        self.selections = selections if selections is not None else {}
        self.field_widgets = {}
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        self.summary.setAccessibleName('Selected disclosure summary')
        _, _, plan, nodes = ipexing._credential_evidence(vault, credential_said)
        self.plan, self.nodes, self.schemas = plan, nodes, {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.overview = QWidget()
        overview = QVBoxLayout(self.overview)
        overview.setContentsMargins(0, 0, 0, 0)
        overview.addWidget(self.summary)
        layout.addWidget(self.overview)
        graph = requested[0] if requested and len(requested) == 1 else []
        requests = {}
        if graph and graph[0][:2] == plan[0][0][:2]:
            requests = {(schema, prefix): paths for schema, prefix, paths in graph}
        specific_request = any(requests.values())
        opened_additional = False
        self.required_summary = QLabel()
        self.required_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.required_summary.setWordWrap(True)
        self.required_summary.setAccessibleName('Always shared with these sources')
        self.required_summary.setStyleSheet(f'background-color: {colors.BACKGROUND_SELECTION}; '
            f'color: {colors.TEXT_PRIMARY}; padding: 10px; border-radius: 4px;')
        required_lines = []
        supporting = QWidget()
        support_layout = QVBoxLayout(supporting)
        for schema_said, prefix, _ in plan[0]:
            node = ipexing.disclosure_node(nodes, credential_said, prefix)
            schemer = vault.hby.db.schema.get((schema_said,))
            schema = node['s'] if isinstance(node['s'], Mapping) else schemer.sed if schemer else None
            if schema is None:
                raise ValueError('Load the credential schema before choosing information to share.')
            self.schemas[prefix] = schema
            card = QWidget()
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(0, 0, 0, 0)
            card_layout.addWidget(attribute_view(credential_name(schema),
                'Issued by ' + identifier_name(vault, node['i'])))
            select_available = prefix == '/' and (requested is None or
                (issuer_delivery and requested == [[[schema_said, '/', []]]]))
            fields = DisclosureFields(schema, node, self.selections.get(prefix),
                                      requested=requests.get((schema_said, prefix), ()) if requested is not None else None,
                                      expand_additional=not specific_request and not opened_additional,
                                      select_available=select_available)
            opened_additional = opened_additional or bool(fields.checkboxes)
            self.field_widgets[prefix] = fields
            fields.changed.connect(self._changed)
            card_layout.addWidget(fields)
            required = [field for field in fields.descriptions if field['required']]
            if required:
                parts = [field['name'] + ': ' + self._compact(
                    display_claims(field['value'], field['schema']), field['schema']) for field in required]
                required_lines.append(credential_name(schema) + ' — ' + '; '.join(parts))
            technical = QWidget()
            technical_layout = QVBoxLayout(technical)
            technical_layout.addWidget(attribute_view('Identifiers and original values', json.dumps(node, indent=2)))
            technical_layout.addWidget(attribute_view('Terms', rules_text(node['r']) if node.get('r') else 'No rules attached.'))
            card_layout.addWidget(details_section('Source and technical details', technical))
            (layout if fields.checkboxes else support_layout).addWidget(card)
        self.required_summary.setText('\n\n'.join(required_lines))
        if required_lines:
            overview.addWidget(details_section(f'Always shared ({len(required_lines)} credentials)', self.required_summary))
        if support_layout.count():
            layout.addWidget(details_section(f'Supporting credentials ({support_layout.count()})', supporting))
        self._changed()

    @staticmethod
    def _compact(value, schema=None):
        schema = schema if isinstance(schema, Mapping) else {}
        schema = credentialing.schema_detail(schema) or schema or {}
        if isinstance(value, Mapping):
            properties = schema.get('properties', {})
            return ', '.join(attribute_label(key, properties.get(key, {})) + ': ' +
                             DisclosureSelection._compact(item, properties.get(key, {}))
                             for key, item in value.items() if not ('d' in value and key in ('d', 'u'))) or '{}'
        if isinstance(value, list):
            return ', '.join(DisclosureSelection._compact(item, schema.get('items', {})) for item in value) or '[]'
        return ('Yes' if value else 'No') if isinstance(value, bool) else '—' if value is None else str(value)

    def _changed(self):
        selections = self.selected_fields()
        names = [field['name']
                 for prefix, widget in self.field_widgets.items()
                 for field in widget.descriptions if field['path'] in selections[prefix]]
        self.summary.setText('Optional fields selected: ' + (', '.join(names) if names else
            'None') + ' · shared after agreement')
        self.changed.emit()

    def selected_fields(self):
        """Keep optional choices per node without changing the retained data."""
        self.selections.update({prefix: fields.selected_fields() for prefix, fields in self.field_widgets.items()})
        return dict(self.selections)

    def prepare(self):
        """Return native disclosure choices and a value-free summary of the Offer."""
        selections = self.selected_fields()
        plan = [[[schema, prefix, disclosure_paths(
            self.schemas[prefix], ipexing.disclosure_node(self.nodes, self.credential_said, prefix),
            selections[prefix])] for schema, prefix, _ in self.plan[0]]]
        _, _, plan, nodes = ipexing.disclosure(self.vault, self.credential_said, plan=plan)
        lines = []
        for node in nodes.values():
            schema = node['s'] if isinstance(node['s'], Mapping) else self.vault.hby.db.schema.get((node['s'],)).sed
            names = ', '.join(field['name'] for field in disclosure_fields(schema, node))
            lines.append(f'{credential_name(schema)}: {names or "supporting evidence"}')
        return plan, '\n'.join(lines), nodes
