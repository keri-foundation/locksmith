"""Schema-driven display contracts, independent of demo credential vocabulary."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QLabel

from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection
from locksmith.ui.vault.credentials import disclosure
from locksmith.ui.vault.credentials.presentation import attribute_view, date_label, display_claims, offer_summary


def schema_vault(*schemas):
    records = {(schema['$id'],): SimpleNamespace(sed=schema) for schema in schemas}
    store = SimpleNamespace(get=records.get, getTopItemIter=records.items)
    return SimpleNamespace(hby=SimpleNamespace(db=SimpleNamespace(schema=store), habs={},
        habByPre=lambda pre: SimpleNamespace(name=pre)),
        org=SimpleNamespace(get=lambda pre: None, list=lambda: []))


def selection(monkeypatch, properties, values, *, known=True, requested=None, issuer_delivery=False):
    schema = {'$id': 'schema', 'title': 'Access record', 'properties': {'a': {
        'type': 'object', 'properties': {'i': {'type': 'string', 'description': 'Account'}, **properties}}}}
    node = {'i': 'issuer', 's': 'schema', 'a': {'i': 'account', **values}}
    monkeypatch.setattr(disclosure.ipexing, '_credential_evidence',
                        lambda *args: (None, None, [[['schema', '/', []]]], {'credential': node}))
    return disclosure.DisclosureSelection(schema_vault(schema) if known else schema_vault(), 'credential',
                                         requested=requested, issuer_delivery=issuer_delivery)


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
    widget = selection(monkeypatch, {'claim': {'title': 'Scope', 'description': 'Long schema documentation'},
                                     'location': {'type': 'string', 'description': 'City Block'}},
                       {'claim': 'read', 'location': 'North'})
    labels = [label.text() for label in widget.findChildren(QLabel)]
    assert 'Scope' in labels
    assert 'Scope: read' in widget.required_summary.text()
    assert 'City Block: North' in widget.required_summary.text()
    assert all('Long schema documentation' not in label for label in labels)


def test_issuance_selection_keeps_linked_and_unavailable_fields_unchanged(qapp, monkeypatch):
    block = {'oneOf': [{'type': 'string'}, {'type': 'object', 'properties': {
        'd': {'type': 'string'}, 'u': {'type': 'string'}, 'value': {'type': 'string'}}}]}
    schema = {'$id': 'schema', 'title': 'Identity credential', 'properties': {'a': {
        'type': 'object', 'properties': {'i': {'type': 'string'}, 'name': block,
                                       'birthDate': block, 'unavailable': block}}}}
    nodes = {
        'root': {'d': 'root', 'i': 'issuer', 's': 'schema',
                 'a': {'i': 'holder', 'name': {'value': 'Name'},
                       'birthDate': {'value': 'Date'}, 'unavailable': 'digest'},
                 'e': {'source': {'n': 'linked'}}},
        'linked': {'d': 'linked', 'i': 'source issuer', 's': 'schema',
                   'a': {'i': 'issuer', 'name': {'value': 'Source'},
                         'birthDate': {'value': 'Private'}}},
    }
    monkeypatch.setattr(disclosure.ipexing, '_credential_evidence', lambda *args: (
        None, None, [[['schema', '/', []], ['schema', '/e/source/_/', []]]], nodes))
    vault = schema_vault(schema)
    widget = disclosure.DisclosureSelection(vault, 'root',
        selections={'/e/source/_/': ['a/name/value']})
    before = deepcopy(nodes)
    select_all = widget.field_widgets['/'].select_all
    select_all.click()
    assert widget.selected_fields() == {
        '/': ['a/name/value', 'a/birthDate/value'], '/e/source/_/': ['a/name/value']}
    assert nodes == before
    widget.field_widgets['/'].checkboxes['a/name/value'].setChecked(False)
    assert widget.selected_fields()['/'] == ['a/birthDate/value']
    assert 'issuing' in select_all.toolTip() and 'linked credentials' in select_all.toolTip()
    reopened = disclosure.DisclosureSelection(vault, 'root')
    assert reopened.selected_fields() == {'/': [], '/e/source/_/': []}
    assert reopened.field_widgets['/'].select_all.isEnabled()


def test_request_bulk_selection_matches_paths_even_when_field_labels_match(qapp, monkeypatch):
    block = {'title': 'Name', 'type': 'object', 'properties': {'d': {}, 'value': {'type': 'string'}}}
    definitions = {'given': block, 'family': block}
    values = {'given': {'value': 'Alice'}, 'family': {'value': 'Example'}}
    request = [[['schema', '/', ['a/given/value']]]]
    widget = selection(monkeypatch, definitions, values, requested=request)
    widget.show()
    fields = widget.field_widgets['/']
    extra = fields.checkboxes['a/family/value']
    assert fields.select_all.text() == 'Select all requested' and fields.select_all.isVisible()
    assert not extra.isVisible()
    fields.select_all.click()
    assert widget.selected_fields() == {'/': ['a/given/value']}
    additional, = [section for section in fields.findChildren(CollapsibleSection)
                   if section.toggle_button.text().strip() == 'Additional fields (not requested)']
    additional.toggle_button.click()
    assert extra.isVisible()
    extra.click()
    assert fields.selected_fields() == ['a/given/value', 'a/family/value']

    for schema, paths in [('schema', []), ('schema', ['a/i']), ('other schema', ['a/given/value'])]:
        empty = selection(monkeypatch, definitions, values, requested=[[[schema, '/', paths]]])
        assert empty.field_widgets['/'].select_all is None
        assert empty.selected_fields() == {'/': []}
    delivery = selection(monkeypatch, definitions, values, requested=[[['schema', '/', []]]], issuer_delivery=True)
    assert delivery.field_widgets['/'].select_all.text() == 'Select all'


def test_reference_offer_names_selected_fields_and_companion_fields(qapp):
    from locksmith.core.credentialing import builtin_schemas
    schemas = {s.sed['title']: s.said for s in builtin_schemas().values()}
    plan = [[[schemas['SEDI Core Schema'], '/', ['a/rd', 'a/givenName/value', 'a/familyName/value']],
             [schemas['SEDI Issuing Agent Schema'], '/e/utahAgent/_/', ['a/issuedDate', 'r/']]]]
    view, supporting = offer_summary(schema_vault(), plan)
    view.show()
    labels = view.findChildren(QLabel)
    assert 'Given Name\nFamily Name' in {label.text() for label in labels if label.isVisible()}
    assert all('Birth Date' not in label.text() for label in labels)
    assert any('Issued Date' in label.text() and label.isVisible() for label in labels)
    assert all('Issuing Agent Role' not in label.text() for label in labels)
    assert 'SEDI Core: Issuee AID, Primary' in supporting
    core, agent = supporting.split('\n')
    assert 'Issuing Agent Role' in agent
    assert core.count('Presentation Registry SAID') == 1 and '(if present)' not in core
    assert 'Presentation Registry SAID (if present)' in agent
    view.close()

    plan = [[[schemas['SEDI Core Schema'], '/', ['a/i', 'e/', 'r/']]]]
    view, _ = offer_summary(schema_vault(), plan)
    view.show()
    visible = {label.text() for label in view.findChildren(QLabel) if label.isVisible()}
    assert {'SEDI Core', 'Shares the subject’s identifier and supporting details.'} <= visible
    view.close()


def test_offer_wait_continues_to_the_next_check_and_stops_on_a_repeat(qapp):
    from PySide6.QtWidgets import QDialog, QPushButton, QWidget
    from locksmith.core.credentialing import RegistryCheckPending
    from locksmith.core.signals import DoerSignalBridge

    dialog = QDialog()
    dialog.send_button = QPushButton('Send offer', dialog)
    dialog.vault = SimpleNamespace(signals=DoerSignalBridge())
    form, failures = QWidget(dialog), []
    checks = [RegistryCheckPending('registry', operation, operation + ' pending')
              for operation in ('fetch', 'publish', 'fetch', 'fetch')]
    wait = disclosure.RegistryCheckWait(dialog, form, lambda: wait.wait(checks.pop(0)), failures.append)

    def complete():
        registry, operation = wait.pending
        wait.checked('RegistryEvidence', 'status_checked',
                     {'registry': registry, 'operation': operation, 'success': True, 'error': None})

    wait.send()
    for operation in ('fetch', 'publish', 'fetch'):
        assert wait.pending == ('registry', operation) and not form.isEnabled() and not failures
        complete()
    assert wait.pending is None and failures == ['fetch pending'] and not checks
    assert form.isEnabled() and dialog.send_button.isEnabled() and dialog.send_button.text() == 'Send offer'
    dialog.close()
