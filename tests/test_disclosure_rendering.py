"""Schema-driven display contracts, independent of demo credential vocabulary."""
from copy import deepcopy

import pytest
from PySide6.QtWidgets import QLabel

from locksmith.ui.vault.credentials import disclosure
from locksmith.ui.vault.credentials.presentation import attribute_view, date_label, display_claims
from test_disclosure_ui import schema_vault


def selection(monkeypatch, properties, values, *, known=True):
    schema = {'$id': 'schema', 'title': 'Access record', 'properties': {'a': {
        'type': 'object', 'properties': {'i': {'type': 'string', 'description': 'Account'}, **properties}}}}
    node = {'i': 'issuer', 's': 'schema', 'a': {'i': 'account', **values}}
    monkeypatch.setattr(disclosure.ipexing, '_credential_evidence',
                        lambda *args: (None, None, [[['schema', '/', []]]], {'credential': node}))
    return disclosure.DisclosureSelection(schema_vault({'record': schema} if known else {}), 'credential')


def test_permission_labels_and_prominence_do_not_depend_on_field_name(qapp, monkeypatch):
    summaries = []
    for key in ('rc', 'accessRights'):
        widget = selection(monkeypatch, {key: {'type': 'array', 'description': 'Allowed operations',
                                              'items': {'type': 'string'}}}, {key: ['read', 'download']})
        summaries.append(widget.required_summary.text())
        labels = [label.text() for label in widget.findChildren(QLabel)]
        assert 'Allowed operations' in labels
        assert 'Permissions' not in labels and 'Value' not in labels and '1' not in labels
        assert widget.field_widgets['/'].selected_fields() == []
    assert summaries[0] == summaries[1]
    assert 'read, download' in summaries[0]


@pytest.mark.parametrize(('definition', 'value', 'expected'), [
    ({'type': 'string'}, 'unusual value', 'unusual value'),
    ({'type': 'boolean'}, False, 'No'),
    ({'type': 'array', 'items': {'type': 'string'}}, ['one', 'two'], 'one, two'),
    ({'type': 'object', 'properties': {'level': {'description': 'Level'}}}, {'level': 3}, 'Level: 3'),
    ({}, {'unfamiliar': ['alpha', {'nested': True}]}, 'unfamiliar: alpha, nested: Yes'),
    ({}, [], '[]'),
    ({}, {}, '{}'),
    ({}, None, '—'),
])
def test_required_business_values_remain_in_summary(qapp, monkeypatch, definition, value, expected):
    definition = dict(definition, description='Entitlement')
    widget = selection(monkeypatch, {'claim': definition}, {'claim': value})
    assert 'Entitlement' in widget.required_summary.text()
    assert expected in widget.required_summary.text()
    assert not widget.field_widgets['/'].checkboxes


def test_required_scalar_and_unknown_fields_have_readable_fallback(qapp, monkeypatch):
    scalar = selection(monkeypatch, {}, {})
    assert 'Account: account' in scalar.required_summary.text()
    untyped_scalar = selection(monkeypatch, {'i': True}, {})
    assert 'Subject: account' in untyped_scalar.required_summary.text()
    unknown = selection(monkeypatch, {}, {'unfamiliarKey': 'raw value'})
    assert 'unfamiliarKey: raw value' in unknown.required_summary.text()
    unspecified = selection(monkeypatch, {'extension': True}, {'extension': {'raw': 'value'}})
    assert 'extension: raw: value' in unspecified.required_summary.text()
    with pytest.raises(ValueError, match='Load the credential schema'):
        selection(monkeypatch, {}, {}, known=False)


def test_display_uses_schema_formats_not_names_and_preserves_input(qapp):
    stamp = '2026-10-24T09:30:00Z'
    values = {'ward': 'East medical ward', 'candidate': stamp, 'expirationDate': stamp,
              'window': stamp, 'birthday': '2000-01-01', 'invalid': 'not a timestamp',
              'nested': {'when': stamp}, 'events': [stamp]}
    schema = {'type': 'object', 'properties': {
        'window': {'type': 'string', 'format': 'date-time'},
        'birthday': {'type': 'string', 'format': 'date'},
        'invalid': {'type': 'string', 'format': 'date-time'},
        'nested': {'type': 'object', 'properties': {'when': {'format': 'date-time'}}},
        'events': {'type': 'array', 'items': {'format': 'date-time'}}}}
    original = deepcopy(values)
    rendered = display_claims(values, schema)
    assert rendered == dict(values, window=date_label(stamp), nested={'when': date_label(stamp)},
                            events=[date_label(stamp)])
    assert values == original
    assert display_claims(values) == values
    assert display_claims('raw', False) == 'raw'
    view = attribute_view(None, rendered['ward'])
    assert [label.text() for label in view.findChildren(QLabel)] == ['East medical ward']


def test_schema_title_is_consistent_between_choices_details_and_summary(qapp, monkeypatch):
    widget = selection(monkeypatch, {'claim': {'title': 'Scope', 'description': 'Long schema documentation'}},
                       {'claim': 'read'})
    labels = [label.text() for label in widget.findChildren(QLabel)]
    assert 'Scope' in labels
    assert 'Scope: read' in widget.required_summary.text()
    assert all('Long schema documentation' not in label for label in labels)
