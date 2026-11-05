"""Credential labels and read-only attributes shared by wallet views."""
from collections.abc import Mapping
import json
import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QHBoxLayout, QWidget, QSizePolicy
from keri.help import helping
from keri.core import Saider

from locksmith.core import credentialing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection


def credential_name(schema):
    schema = schema or {}
    return schema.get('title', 'Credential')


def attribute_label(name, schema):
    """Use the same readable field names in forms and credential reviews."""
    schema = schema if isinstance(schema, Mapping) else {}
    description = schema.get('title') or schema.get('description', 'Date' if name == 'dt' else name)
    # Timestamp annotations describe wire encoding, not part of the field label.
    return description.split(' RFC-3339')[0].split(' RFC3339')[0]


def identifier_name(vault, pre):
    if not pre:
        return 'Not specified'
    hab = vault.hby.habByPre(pre)
    contact = vault.org.get(pre) or {}
    name = hab.name if hab else contact.get('alias')
    if not name:
        return pre[:10] + '…' + pre[-6:]
    peers = {h.pre for h in vault.hby.habs.values() if h.name == name}
    peers.update(c['id'] for c in vault.org.list() if c.get('alias') == name)
    return f'{name} ({pre[:8]}…)' if len(peers) > 1 else name


def date_label(stamp):
    if not stamp:
        return '—'
    try:
        return helping.fromIso8601(stamp).astimezone().strftime('%b %d, %Y %H:%M')
    except (ValueError, TypeError):
        return stamp


def identity_context(vault, presenter, recipient, *, compact=False):
    """Keep local names alongside inspectable identifiers, without implying trust."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    identities = QHBoxLayout()
    for label, pre in (('Presenting as', presenter), ('Recipient', recipient)):
        if compact:
            row = QLabel(label + ': ' + identifier_name(vault, pre))
            row.setTextFormat(Qt.TextFormat.PlainText)
            row.setWordWrap(True)
        else:
            row = attribute_view(label, identifier_name(vault, pre))
        row.setToolTip(pre)
        identities.addWidget(row, 1)
    layout.addLayout(identities)
    widget.identifier_details = details_section('Identifier details', attribute_view(
        'Names are local labels; verify the identifiers',
        {'Presenting identifier': presenter, 'Recipient identifier': recipient}))
    layout.addWidget(widget.identifier_details)
    return widget


def details_section(title, content, *, expanded=False):
    """Use the existing disclosure widget with natural, wrapping content height."""
    section = CollapsibleSection(title=title)
    layout = QVBoxLayout()
    layout.setContentsMargins(12, 4, 0, 8)
    layout.addWidget(content)
    section.set_content_layout(layout)
    section.content_area.setMaximumHeight(16777215)
    section.content_area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    section.toggle_button.setMinimumHeight(36)
    section.toggle_button.setAccessibleName(title)
    section.toggle_button.setStyleSheet(section.toggle_button.styleSheet() +
        f'QToolButton:focus {{ border: 2px solid {colors.TEXT_PRIMARY}; border-radius: 4px; }}')
    section.toggle_button.setChecked(expanded)
    return section


def consent_action(button):
    """Keep the existing action style with readable text and a visible focus ring."""
    button.setStyleSheet(button.styleSheet() +
        f'QPushButton:enabled {{ color: {colors.TEXT_DARK}; }} '
        f'QPushButton:focus {{ border: 2px solid {colors.TEXT_PRIMARY}; }}')


def display_claims(value, schema=None):
    """Format only schema-declared timestamps; preserve untyped values exactly."""
    schema = schema if isinstance(schema, Mapping) else {}
    if isinstance(value, Mapping):
        properties = (credentialing.schema_detail(schema) or schema).get('properties', {})
        return {name: display_claims(item, properties.get(name)) for name, item in value.items()}
    if isinstance(value, list):
        definition = credentialing.schema_detail(schema, 'array') or schema
        return [display_claims(item, definition.get('items')) for item in value]
    if isinstance(value, str) and schema.get('format') == 'date-time':
        return date_label(value)
    return value


def status_label(status):
    return {'issued': 'Active', 'revoked': 'Revoked', 'pending': 'Pending verification',
            'authenticated': 'Authenticated'}.get(status.get('et'), 'Unknown state')


def rules_text(rules):
    """Keep disclosed terms readable without treating a commitment as rule text."""
    if not isinstance(rules, Mapping):
        try:
            if Saider(qb64=rules).qb64 == rules:
                return 'Rule text has not been disclosed.'
        except Exception:
            pass
        return rules
    values = {('Legal terms' if key == 'l' else key): value if key == 'l' else rules_text(value)
              for key, value in rules.items() if key not in ('d', 'u')}
    if list(values) == ['Legal terms']:
        return values['Legal terms']
    return values or 'Rule text has not been disclosed.'


def plan_summary(vault, plan, *, request=False):
    """Name schema-resolved requests without guessing aggregate positions."""
    lines = []
    for graph in plan:
        for schema, _, paths in graph:
            schemer = vault.hby.db.schema.get((schema,))
            definition = schemer.sed if schemer else {}
            try:
                labels = {field['path']: field['name'] for field in disclosure_fields(definition)}
            except ValueError:
                labels = {}
            names = [labels.get(path, 'Selected information') for path in paths if path not in ('e/', 'r/')]
            unspecified = ('No specific fields requested; you choose what to offer' if request
                           else 'Required supporting information only')
            text = (unspecified if not paths else 'Whole credential' if paths == ['']
                    else ', '.join(dict.fromkeys(names)) or 'Supporting evidence')
            lines.append(f'{credential_name(definition)}: {text}')
    return '\n'.join(lines)


def request_details(vault, request):
    """Keep the request visible before a matching credential exists."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(attribute_view('Requested information', plan_summary(vault, request.sad['q'].get('dp', []), request=True)))
    if request.sad['a'].get('m'):
        layout.addWidget(attribute_view('Requester’s message', request.sad['a']['m']))
    return widget


def offer_details(vault, plan):
    """Show the references and credential types disclosed by a native Offer."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(attribute_view('Proposed disclosure', plan_summary(vault, plan)))
    layout.addWidget(attribute_view('Disclosure',
        'Credential contents are not disclosed in this offer. Review the proposed disclosure before requesting it.'))
    return widget


def credential_details(vault, sad, *, identity=True):
    """Show a retained credential's identity, disclosed attributes, and terms."""
    schema = sad.get('s', {})
    if isinstance(schema, str):
        schemer = vault.hby.db.schema.get((schema,))
        schema = schemer.sed if schemer else {}
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 12)
    if identity:
        layout.addWidget(attribute_view(credential_name(schema), 'Issued by ' + identifier_name(vault, sad.get('i'))))
    attrs = sad.get('a')
    if isinstance(attrs, Mapping):
        if identity:
            layout.addWidget(attribute_view('Credential subject', identifier_name(vault, attrs.get('i'))))
        definition = schema.get('properties', {}).get('a', {})
        definition = definition if isinstance(definition, Mapping) else {}
        definition = next((item for item in definition.get('oneOf', [definition])
                           if isinstance(item, Mapping) and item.get('type') == 'object'), {})
        for name, value in attrs.items():
            if name in ('d', 'i', 'u'):
                continue
            prop = definition.get('properties', {}).get(name, {})
            prop = prop if isinstance(prop, Mapping) else {}
            layout.addWidget(attribute_view(attribute_label(name, prop), display_claims(value, prop), prop))
    elif attrs is not None:
        layout.addWidget(attribute_view('Attributes', 'Withheld until the Grant.' if attrs == '' else 'Only a commitment is disclosed.'))
    if 'A' in sad:
        try:
            definitions = credentialing.attribute_schemas(schema, aggregate=True)
        except ValueError:
            definitions = []
        blocks = sad['A'][1:] if isinstance(sad['A'], list) else [sad['A']]
        for block in blocks:
            if not isinstance(block, Mapping):
                layout.addWidget(attribute_view('Undisclosed attributes', 'Only a commitment is disclosed.'))
                continue
            definition = next((item for item in definitions
                               if set(block) - {'d', 'u'} <= item.get('properties', {}).keys()), {})
            for name, value in block.items():
                if name in ('d', 'u'):
                    continue
                if name == 'i':
                    if identity:
                        layout.addWidget(attribute_view('Credential subject', identifier_name(vault, value)))
                    continue
                prop = definition.get('properties', {}).get(name, {})
                prop = prop if isinstance(prop, Mapping) else {}
                layout.addWidget(attribute_view(attribute_label(name, prop), display_claims(value, prop), prop))
    layout.addWidget(attribute_view('Terms', rules_text(sad['r']) if sad.get('r') else 'No rules attached.'))
    layout.addWidget(details_section('Source and original values', attribute_view(
        'Credential data', json.dumps(sad, indent=2))))
    return widget


def attribute_view(label, value, schema=None):
    """Display disclosed values without editable controls or JSON syntax."""
    schema = schema if isinstance(schema, Mapping) else {}
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 8)
    if label:
        title = QLabel(label)
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setStyleSheet(f'font-weight: bold; color: {colors.TEXT_SECONDARY};')
        title.setWordWrap(True)
        layout.addWidget(title)
    if isinstance(value, Mapping):
        properties = (credentialing.schema_detail(schema) or schema).get('properties', {})
        for name, item in value.items():
            if 'd' in value and name in ('d', 'u'):
                continue
            prop = properties.get(name, {})
            prop = prop if isinstance(prop, Mapping) else {}
            child = attribute_view(attribute_label(name, prop), item, prop)
            child.layout().setContentsMargins(16, 0, 0, 8)
            layout.addWidget(child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            layout.addWidget(attribute_view(str(index + 1) if isinstance(item, (Mapping, list)) else None, item, schema.get('items', {})))
    else:
        text = ('Yes' if value else 'No') if isinstance(value, bool) else str(value if value is not None else '')
        detail = credentialing.schema_detail(schema)
        if isinstance(value, str) and detail and 'd' in detail.get('properties', {}):
            try:
                if Saider(qb64=value).qb64 == value:
                    text = 'Not disclosed'
            except Exception:
                pass
        content = QLabel(text or '—')
        content.setTextFormat(Qt.TextFormat.PlainText)
        content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse |
                                        Qt.TextInteractionFlag.TextSelectableByKeyboard)
        content.setWordWrap(True)
        layout.addWidget(content)
    return widget


def _disclosure_name(names, definitions):
    labels = []
    for name in names:
        definition = definitions.get(name, {})
        definition = definition if isinstance(definition, Mapping) else {}
        label = definition.get('title') or definition.get('description')
        if label:
            labels.append(attribute_label(name, {'description': label}))
            continue
        label = re.sub(r'(?<=[a-z])(?=[A-Z0-9])', ' ', name).replace('_', ' ')
        labels.append({'i': 'Subject', 'rd': 'Registry'}.get(name, label.capitalize()))
    return ' / '.join(labels)


def disclosure_fields(schema, sad=None):
    """Describe atomic attribute choices, including mandatory identity information.

    Schema-only aggregate paths use the proposed unique field selector. Once a
    credential exists, paths use its actual aggregate positions.
    """
    result = []
    definitions = credentialing.attribute_schemas(schema, aggregate=bool(sad and 'A' in sad))

    def add(path, names, properties, values):
        if not names:
            return
        definition = {'type': 'object', 'properties': {name: properties.get(name, {}) for name in names}}
        value = {name: values[name] for name in names} if values is not None else None
        if len(names) == 1:
            definition = properties.get(names[0], {})
            value = value[names[0]] if value is not None else None
        result.append(dict(path=path, name=_disclosure_name(names, properties), schema=definition,
                           value=value, required=bool(set(names) & {'i', 'rd'})))

    def mapping(definition, values, prefix, label=None):
        properties = definition.get('properties', {})
        names = list(values if values is not None else properties)
        direct, nested = [], []
        for name in names:
            if name in ('d', 'u'):
                continue
            prop = properties.get(name, {})
            detail = credentialing.schema_detail(prop)
            value = values[name] if values is not None else None
            if detail and 'd' in detail.get('properties', {}):
                if values is None or isinstance(value, Mapping):
                    nested.append((name, detail, value))
                # A digest is not an available disclosure choice.
            else:
                direct.append(name)
        if direct:
            add(prefix + direct[0], direct, properties, values)
            if label:
                result[-1]['name'] = label if direct == ['value'] else label + ' · ' + result[-1]['name']
        for name, detail, value in nested:
            mapping(detail, value, prefix + name + '/', _disclosure_name([name], properties))

    if (sad and 'A' in sad) or (sad is None and 'a' not in schema.get('properties', {})):
        if sad is None:
            for definition in definitions:
                properties = definition.get('properties', {})
                names = [name for name in properties if name not in ('d', 'u')]
                if names:
                    add('A/' + names[0], names, properties, None)
        elif isinstance(sad.get('A'), list):
            for index, block in enumerate(sad['A'][1:], 1):
                if not isinstance(block, Mapping):
                    continue
                names = [name for name in block if name not in ('d', 'u')]
                matches = [d for d in definitions if set(names) <= d.get('properties', {}).keys()]
                properties = matches[0].get('properties', {}) if len(matches) == 1 else {}
                add(f'A/{index}/', names, properties, block)
    elif sad is None or isinstance(sad.get('a'), Mapping):
        mapping(definitions[0], sad['a'] if sad is not None else None, 'a/')
    return result


def disclosure_paths(schema, sad, selected):
    """Resolve wallet choices and include visible identity, edges, and terms."""
    choices = disclosure_fields(schema, sad)
    selected = set(selected)
    if selected - {field['path'] for field in choices}:
        raise ValueError('A selected field is no longer available')
    paths = [field['path'] for field in choices if field['required'] or field['path'] in selected]
    paths.extend(label + '/' for label in ('e', 'r') if label in sad)
    # An empty field list means unrestricted disclosure, never share nothing.
    if not paths:
        raise ValueError('Choose information to share')
    return paths
