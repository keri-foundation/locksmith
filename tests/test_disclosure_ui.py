"""Disclosure choices use real credential schemas and preserve user intent."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QPoint, QRect, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QCheckBox, QLabel, QWidget
from hio.base import doing
from keri.core import scheming, SerderACDC

from locksmith.core.credentialing import IssueCredentialDoer
from locksmith.ui.vault.credentials.disclosure import DisclosureFields, DisclosureSelection
from locksmith.ui.vault.credentials.schema.list import SchemaListPage
from locksmith.ui.vault.credentials.start import RequestDisclosure, StartExchangeDialog
from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection
from locksmith.ui.toolkit.widgets.dialogs import LocksmithDialog
from test_credential_ui import wallet as wallet
from test_credential_ui import schema as credential_schema


@pytest.fixture
def disclosure_schemas():
    directory = Path(__file__).parents[1] / 'assets' / 'schemas' / 'sedi'
    return {name: json.loads((directory / f'{name}.json').read_text())
            for name in ('bespoke-presentation', 'core-identity', 'age')}


def schema_vault(schemas):
    records = {schema['$id']: SimpleNamespace(sed=schema) for schema in schemas.values()}
    store = SimpleNamespace(get=lambda keys: records.get(keys[0]),
                            getTopItemIter=lambda: (((said,), schema) for said, schema in records.items()))
    return SimpleNamespace(hby=SimpleNamespace(db=SimpleNamespace(schema=store), habs={},
        habByPre=lambda pre: SimpleNamespace(name=pre)),
        org=SimpleNamespace(get=lambda pre: None, list=lambda: []))


def choose(combo, value):
    index = combo.combo_box.findData(value)
    assert index >= 0
    combo.setCurrentIndex(index)


def test_request_fields_have_distinct_names_and_no_private_values(qapp, disclosure_schemas):
    fields = DisclosureFields(schema_vault(disclosure_schemas), disclosure_schemas['core-identity'])
    labels = {label.text() for label in fields.findChildren(QLabel)} | {
        checkbox.text() for checkbox in fields.findChildren(QCheckBox)}
    assert {'Given Name Block', 'Family Name Block', 'Birth Date Block'} <= labels
    assert not {'Yes', 'No', '—', 'Value'} & labels
    assert not fields.has_selection()
    assert not fields.request_notice.isHidden()
    fields.checkboxes['a/givenName/value'].setChecked(True)
    assert fields.request_notice.isHidden()
    fields.checkboxes['a/givenName/value'].setChecked(False)
    assert not fields.request_notice.isHidden()
    assert all(label.textFormat() == Qt.TextFormat.PlainText for label in fields.findChildren(QLabel))


def test_holder_sees_every_claim_coupled_to_required_information(qapp, disclosure_schemas):
    sad = {'a': {'d': 'attribute-commitment', 'u': 'attribute-blinder', 'i': 'holder-AID',
                 'rd': 'presentation-registry', 'primary': False,
                 'givenName': {'d': 'name-commitment', 'u': 'name-blinder', 'value': '<b>Alice</b>'}}}
    fields = DisclosureFields(schema_vault(disclosure_schemas), disclosure_schemas['core-identity'], sad)
    labels = {label.text() for label in fields.findChildren(QLabel)}
    assert {'holder-AID', 'presentation-registry', 'No', '<b>Alice</b>'} <= labels
    assert 'Value' not in labels
    assert not {'attribute-commitment', 'attribute-blinder', 'name-commitment', 'name-blinder'} & labels
    required = [box for box in fields.findChildren(QCheckBox) if not box.isEnabled()]
    assert not required  # Mandatory disclosures are information, not pretend choices.
    assert fields.selected_fields() == []
    fields.checkboxes['a/givenName/value'].setChecked(True)
    assert fields.selected_fields() == ['a/givenName/value']
    assert all(label.textFormat() == Qt.TextFormat.PlainText for label in fields.findChildren(QLabel))


def test_bespoke_request_keeps_choices_and_orders_source_links(qapp, disclosure_schemas):
    root, core, age = (disclosure_schemas[name] for name in ('bespoke-presentation', 'core-identity', 'age'))
    schemas = {schema['$id']: SimpleNamespace(sed=schema) for schema in disclosure_schemas.values()}
    request = RequestDisclosure(schema_vault(disclosure_schemas), root, schemas)
    for slot, schema, path in (('age', age, 'A/over13'), ('core', core, 'a/givenName/value')):
        choose(request.add_information, slot)
        choose(request.links[slot]['selector'], schema['$id'])
        request.links[slot]['fields'][schema['$id']].checkboxes[path].setChecked(True)
    choose(request.links['core']['selector'], age['$id'])
    choose(request.links['core']['selector'], core['$id'])
    assert request.disclosure_plan(root['$id']) == [[
        [root['$id'], '/', []],
        [core['$id'], '/e/core/_/', ['a/givenName/value', 'a/i']],
        [age['$id'], '/e/age/_/', ['A/over13', 'A/i']],
    ]]
    request._remove_link('core')
    assert request.add_information.combo_box.findData('core') >= 0
    assert request.disclosure_plan(root['$id']) == [[
        [root['$id'], '/', []],
        [age['$id'], '/e/age/_/', ['A/over13', 'A/i']],
    ]]


def test_incomplete_link_blocks_send_and_root_switch_keeps_selection(qapp, wallet, disclosure_schemas):
    app = wallet('disclosure-request')
    sender = app.hby.makeHab(name='requester')
    recipient = app.hby.makeHab(name='holder')
    parent = QWidget()
    parent.app = app
    schema_page = SchemaListPage(parent)
    schema_page.set_vault_name('disclosure-request')
    assert not schema_page.table._static_data
    dialog = StartExchangeDialog(app, parent, 'Apply', intent='presentation')
    assert not list(app.hby.db.schema.getTopItemIter())
    assert dialog.selection.currentData() is None
    root, core, age = (disclosure_schemas[name] for name in ('bespoke-presentation', 'core-identity', 'age'))
    choose(dialog.selection, root['$id'])
    choose(dialog.sender, sender.pre)
    choose(dialog.recipient, recipient.pre)
    assert dialog.send_button.isEnabled(), dialog.error.text()
    request = dialog._requests[root['$id']]
    choose(request.add_information, 'core')
    assert not dialog.send_button.isEnabled()
    assert dialog.error.text()
    assert request.links['core']['selector'].isEnabled()
    choose(request.links['core']['selector'], core['$id'])
    # Browsing built-in credential types leaves the vault unchanged until Send.
    assert not list(app.hby.db.schema.getTopItemIter())
    request.links['core']['fields'][core['$id']].checkboxes['a/givenName/value'].setChecked(True)
    assert dialog.send_button.isEnabled(), dialog.error.text()
    choose(dialog.selection, age['$id'])
    choose(dialog.selection, root['$id'])
    request = dialog._requests[root['$id']]
    assert request.links['core']['fields'][core['$id']].selected_fields() == ['a/givenName/value']
    assert dialog.send_button.isEnabled(), dialog.error.text()
    dialog.open()
    QTest.qWait(250)
    last_choice = request.links['core']['fields'][core['$id']].checkboxes['a/expirationDate/value']
    dialog.scroll_area.ensureWidgetVisible(last_choice)
    qapp.processEvents()
    viewport = dialog.scroll_area.viewport()
    assert viewport.rect().contains(QRect(last_choice.mapTo(viewport, QPoint()), last_choice.size()))
    QTest.mouseClick(last_choice, Qt.MouseButton.LeftButton, pos=QPoint(12, last_choice.height() // 2))
    assert last_choice.isChecked()
    QTest.keyClick(last_choice, Qt.Key.Key_Space)
    assert not last_choice.isChecked()
    assert dialog.send_button.isVisible()
    assert dialog.rect().contains(QRect(dialog.send_button.mapTo(dialog, QPoint()), dialog.send_button.size()))
    assert dialog.height() <= dialog.screen().availableGeometry().height()
    assert not list(app.vault.db.issuers.getTopItemIter())
    assert not app.vault.rgy.names
    dialog.send_button.click()
    assert dialog.result() == LocksmithDialog.DialogCode.Accepted, dialog.error.text()
    assert {said for (said,), _ in app.hby.db.schema.getTopItemIter()} == {root['$id'], core['$id']}
    app.vault.signals.emit_doer_event('MenuDoer', 'load', {'subpage': 'schema'})
    assert {row['SAID'] for row in schema_page.table._static_data} == {root['$id'], core['$id']}
    custom = credential_schema()
    app.hby.db.schema.pin((custom.said,), custom)
    reopened = StartExchangeDialog(app, parent, 'Apply', intent='presentation')
    choices = [reopened.selection.combo_box.itemData(i) for i in range(reopened.selection.count())]
    assert choices.count(root['$id']) == choices.count(core['$id']) == choices.count(custom.said) == 1
    choose(reopened.selection, custom.said)
    assert reopened._requests[custom.said].schema == custom.sed


def test_unsolicited_offer_sends_only_explicit_choices_and_keeps_original(wallet):
    app = wallet('disclosure-offer')
    holder = app.hby.makeHab(name='holder')
    recipient = app.hby.makeHab(name='requester')
    schema = credential_schema(composed=True).sed
    schema['$id'] = ''
    schema['required'].remove('rd')
    schema['properties'].pop('rd')
    block = {'oneOf': [{'type': 'string'}, {'type': 'object', 'properties': {
        'd': {'type': 'string'}, 'u': {'type': 'string'}, 'value': {'type': 'string'}},
        'required': ['d', 'u', 'value'], 'additionalProperties': False}]}
    attrs = schema['properties']['a']['oneOf'][1]
    attrs['properties'] = {'d': {'type': 'string'}, 'u': {'type': 'string'},
                           'i': {'type': 'string'}, 'name': block, 'birthDate': block}
    attrs['required'] = list(attrs['properties'])
    schemer = scheming.Schemer(sed=schema)
    app.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
    app.vault.db.issuers.pin(keys=(schemer.said,), val=holder.pre)
    credentials = []
    for name in ('Alice', 'Other name'):
        before = {said for (said,), _ in app.vault.db.issued.getTopItemIter()}
        doer = IssueCredentialDoer(app, schemer.said, holder.pre,
                                  {'name': {'value': name}, 'birthDate': {'value': '2010-01-01'}},
                                  authentication='anchor')
        doing.Doist(doers=[doer], limit=1.0, tock=0.03125).do()
        credential, = [SerderACDC(raw=record.raw.encode()) for (said,), record in app.vault.db.issued.getTopItemIter()
                       if said not in before]
        credentials.append(credential)
    first, other = credentials
    # An existing credential gets the issuance shortcut without a creation callback.
    all_fields = DisclosureSelection(app.vault, first.said)
    assert all_fields.selected_fields() == {'/': []}
    assert all_fields.select_all_issuance.text() == 'Select all for credential issuance'
    all_fields.select_all_issuance.click()
    full_plan, _, full_nodes = all_fields.prepare()
    assert set(full_plan[0][0][2]) == {'a/i', 'a/name/value', 'a/birthDate/value'}
    assert full_nodes[first.said]['a']['name']['value'] == 'Alice'
    assert full_nodes[first.said]['a']['birthDate']['value'] == '2010-01-01'
    all_fields.close()
    parent = QWidget()
    dialog = StartExchangeDialog(app, parent, 'Offer')
    choose(dialog.selection, first.said)
    choose(dialog.recipient, recipient.pre)
    selection = dialog._offers[first.said]
    assert selection.selected_fields() == {'/': []}
    dialog.open()
    QTest.qWait(250)
    additional = next(section for section in selection.field_widgets['/'].findChildren(CollapsibleSection)
                      if section.toggle_button.text().strip() == 'Additional fields')
    additional.toggle_button.setChecked(True)
    name_choice = selection.field_widgets['/'].checkboxes['a/name/value']
    dialog.scroll_area.ensureWidgetVisible(name_choice)
    assert name_choice.isVisible() and name_choice.minimumHeight() >= 32
    additional.toggle_button.setFocus()
    for _ in range(24):
        if name_choice.hasFocus():
            break
        QTest.keyClick(dialog.focusWidget() or dialog, Qt.Key.Key_Tab)
    assert name_choice.hasFocus()
    QTest.keyClick(name_choice, Qt.Key.Key_Space)
    assert name_choice.isChecked()
    assert 'Alice' in name_choice.accessibleDescription()
    choose(dialog.selection, other.said)
    assert dialog._offers[other.said].selected_fields() == {'/': []}
    choose(dialog.selection, first.said)
    assert selection.selected_fields() == {'/': ['a/name/value']}
    plan, message, nodes = selection.prepare()
    assert plan[0][0][2] == ['a/i', 'a/name/value']
    assert nodes[first.said]['a']['name']['value'] == 'Alice'
    assert isinstance(nodes[first.said]['a']['birthDate'], str)
    assert 'Name' in message and 'Alice' not in message and '2010-01-01' not in message
    assert dialog.send_button.isEnabled(), dialog.error.text()
    dialog.send_button.click()
    offer, = [exn for _, exn in app.hby.db.exns.getTopItemIter() if exn.route == '/ipex/offer']
    assert offer.sad['q']['dp'] == plan
    assert offer.sad['a']['m'] == message
    retained = SerderACDC(raw=app.vault.db.issued.get((first.said,)).raw.encode())
    assert retained.sad['a']['birthDate']['value'] == '2010-01-01'


def test_close_icon_is_named_focusable_and_keyboard_operable(qapp):
    from PySide6.QtWidgets import QPushButton
    dialog = LocksmithDialog(title='Synthetic review', content=QLabel('Review information'))
    dialog.open()
    QTest.qWait(250)
    close = next(button for button in dialog.findChildren(QPushButton)
                 if button.accessibleName() == 'Close dialog')
    assert close.width() >= 32 and close.height() >= 32
    close.setFocus()
    assert close.hasFocus()
    QTest.keyClick(close, Qt.Key.Key_Space)
    assert not dialog.isVisible()


@pytest.mark.parametrize('status', ['error', 'success'])
def test_long_banner_keeps_dialog_actions_reachable(qapp, monkeypatch, status):
    from PySide6.QtWidgets import QHBoxLayout, QPushButton

    action = QPushButton('Continue')
    buttons = QHBoxLayout()
    buttons.addWidget(action)
    dialog = LocksmithDialog(title='Synthetic review', content=QLabel('Review information'),
                             buttons=buttons)
    monkeypatch.setattr(dialog, 'screen', lambda: SimpleNamespace(
        availableGeometry=lambda: QRect(0, 0, 480, 640)))
    dialog.fit_content(448)
    dialog.open()
    QTest.qWait(350)
    getattr(dialog, f'show_{status}')('Synthetic status message with details. ' * 80)
    QTest.qWait(350)
    assert getattr(dialog, f'{status}_label').isVisible()
    assert dialog.width() <= 480 and dialog.height() <= 640
    assert action.visibleRegion().contains(action.rect())
