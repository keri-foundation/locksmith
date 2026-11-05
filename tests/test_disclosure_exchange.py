"""Selected source claims survive a complete exchange across wallet stores."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from PySide6.QtWidgets import QLabel, QWidget
from PySide6.QtTest import QTest

from keri.acdc.messaging import acmSchemaDefault
from keri.core import Parser, scheming
from keri.peer import exchanging
from keri import Vrsn_2_0
from keri.kering import ValidationError

from locksmith.core import credentialing, ipexing
from locksmith.ui.vault.credentials.activity import CredentialActivityPage
from locksmith.ui.vault.credentials.disclosure import DisclosureSelection
from locksmith.ui.vault.credentials.issued.view import ViewIssuedCredentialDialog
from locksmith.ui.vault.credentials.start import StartExchangeDialog
from test_credentialing import _issue
from test_ipex_policy import _introduce
from test_keri_v2_compat import _deliver_ipex
from test_keri_v2_compat import ipex_vaults as ipex_vaults


def test_selected_aggregate_exchange_preserves_source_and_reopens(ipex_vaults):
    state, citizen_app, store = apps = [ipex_vaults(name) for name in (
        'selected-state', 'selected-citizen', 'selected-store')]
    issuer, citizen, verifier = [app.hby.makeHab(name=role) for app, role in
                                zip(apps, ('State', 'Citizen', 'Store'))]

    # This generic credential uses a real issuer KEL anchor. The SEDI registry
    # profile has a separate native sparse-aggregate acceptance limitation.
    _, source_definition = acmSchemaDefault()
    source_definition['$id'] = ''
    source_definition['title'] = 'Age claims with issuer anchor'
    source_definition['properties'].pop('a')
    age = json.loads((Path(__file__).parents[1] / 'assets/schemas/sedi/age.json').read_text())
    source_definition['properties']['A'] = age['properties']['A']
    source_schema = scheming.Schemer(sed=source_definition)

    _, core_definition = acmSchemaDefault()
    core_definition['$id'] = ''
    core_definition['title'] = 'Identity claims with issuer anchor'
    core_properties = {'d': {'type': 'string'}, 'u': {'type': 'string'}, 'i': {'type': 'string'}}
    for key, label in (('givenName', 'Given name'), ('birthDate', 'Birth date')):
        core_properties[key] = {'title': label, 'oneOf': [
            {'type': 'string'}, {'type': 'object', 'properties': {
                'd': {'type': 'string'}, 'u': {'type': 'string'}, 'value': {'type': 'string'}}}]}
    core_definition['properties']['a'] = {'type': 'object', 'properties': core_properties}
    core_schema = scheming.Schemer(sed=core_definition)

    _, root_definition = acmSchemaDefault()
    root_definition['$id'] = ''
    root_definition['title'] = 'Presentation'
    root_definition['properties']['a'] = {'type': 'object', 'properties': {
        'd': {'type': 'string'}, 'u': {'type': 'string'},
        'i': {'type': 'string'}, 'purpose': {'type': 'string'}}}
    root_definition['properties']['e'] = json.loads((Path(__file__).parents[1] /
        'assets/schemas/sedi/bespoke-presentation.json').read_text())['properties']['e']
    root_schema = scheming.Schemer(sed=root_definition)
    for app in apps:
        for schema in (core_schema, source_schema, root_schema):
            app.hby.db.schema.pin((schema.said,), schema)
    state.vault.db.issuers.pin((source_schema.said,), issuer.pre)
    state.vault.db.issuers.pin((core_schema.said,), issuer.pre)
    citizen_app.vault.db.issuers.pin((root_schema.said,), citizen.pre)
    core = _issue(state, core_schema, citizen, authentication='anchor', attributes={
        'givenName': {'value': 'Alice'}, 'birthDate': {'value': '2010-01-01'}})
    source = _issue(state, source_schema, citizen, authentication='anchor', attributes=[
        {'i': citizen.pre}, {'over18': False}, {'over13': True}],
        edges={'core': {'n': core, 's': core_schema.said, 'o': ['E1E', 'NI2I']}})
    for app in apps:
        for other in apps:
            if app is not other:
                _introduce(app, other)

    for credential in (core, source):
        issued, atc = ipexing.grant(state.vault, issuer, credential, citizen.pre)
        _deliver_ipex(citizen_app.vault, ipexing.prepare(state.vault, issuer, issued, atc))
        assert citizen_app.vault.exc.complete(issued.said)
        ipexing.admit(citizen_app.vault, citizen, issued.said)
    retained = deepcopy(credentialing.credential(citizen_app.vault, source))
    retained_core = deepcopy(credentialing.credential(citizen_app.vault, core))
    origin = _issue(citizen_app, root_schema, citizen, authentication='signature',
                    attributes={'purpose': 'Check age'},
                    edges={'core': {'n': core, 's': core_schema.said, 'o': 'I2I'},
                           'age': {'n': source, 's': source_schema.said, 'o': 'I2I'}})

    def deliver(sender, recipient, said):
        stream = exchanging.serializeMessage(sender.hby, said)
        _deliver_ipex(recipient.vault, stream)
        assert recipient.vault.exc.complete(said), {
            'message': said,
            'pending_authentication': recipient.hby.db.epse.get((said,)) is not None,
            'missing_schemas': [keys[1] for keys, _ in recipient.hby.db.emse.getTopItemIter((said,))],
            'persisted': recipient.hby.db.exns.get((said,)) is not None,
        }
        return bytes(stream)

    parents = []

    def review(app, prior, action):
        parent = QWidget()
        parent.app = app
        parents.append(parent)
        page = CredentialActivityPage(parent)
        page.set_vault_name(app.name)
        row = next(row for row in page._rows if row['messages'][-1].said == prior
                   and action in row['_actions'])
        page._on_row_action(row, action)
        return page._response_dialog

    # The applicant requests more than the holder will consent to disclose.
    store.vault.org.update(citizen.pre, {'alias': 'Citizen'})
    request_parent = QWidget()
    parents.append(request_parent)
    request_dialog = StartExchangeDialog(store, request_parent, 'Apply', schema=root_schema.said,
                                         intent='presentation')
    request_dialog.sender.setCurrentIndex(request_dialog.sender.combo_box.findData(verifier.pre))
    request_dialog.recipient.setCurrentIndex(request_dialog.recipient.combo_box.findData(citizen.pre))
    request_fields = request_dialog._requests[root_schema.said]
    for slot, schema, paths in (
            ('core', core_schema, ('a/givenName/value', 'a/birthDate/value')),
            ('age', source_schema, ('A/over13', 'A/over18'))):
        request_fields.add_information.setCurrentIndex(request_fields.add_information.combo_box.findData(slot))
        selector = request_fields.links[slot]['selector']
        selector.setCurrentIndex(selector.combo_box.findData(schema.said))
        for path in paths:
            request_fields.links[slot]['fields'][schema.said].checkboxes[path].click()
    requested_plan = request_fields.disclosure_plan(root_schema.said)
    assert request_dialog.send_button.isEnabled(), request_dialog.error.text()
    requests = []
    request_dialog.submitted.connect(requests.append)
    request_dialog.send_button.click()
    request, = requests
    request_wire = deliver(store, citizen_app, request)
    assert b'a/birthDate/value' in request_wire and b'A/over18' in request_wire
    assert citizen_app.hby.db.exns.get((request,)).sad['q']['dp'] == requested_plan
    offer_dialog = review(citizen_app, request, 'Offer')
    assert offer_dialog.credential.currentData() == origin
    fields = offer_dialog._disclosure_selection.field_widgets
    QTest.qWait(150)
    first_choice = fields['/e/core/_/'].checkboxes['a/givenName/value']
    assert first_choice.visibleRegion().contains(first_choice.rect())
    assert all(not box.isChecked() for widget in fields.values()
               for box in widget.checkboxes.values())
    requested_labels = '\n'.join(label.text() for label in offer_dialog.offer_review.findChildren(QLabel))
    assert 'Birth date' in requested_labels and 'Over18 True if age>=18 else False' in requested_labels
    fields['/e/core/_/'].checkboxes['a/givenName/value'].click()
    fields['/e/age/_/'].checkboxes['A/3/'].click()
    assert not fields['/e/core/_/'].checkboxes['a/birthDate/value'].isChecked()
    assert not fields['/e/age/_/'].checkboxes['A/2/'].isChecked()
    plan, _, _ = offer_dialog._disclosure_selection.prepare()
    selected_plan = deepcopy(plan)
    assert offer_dialog.send_button.isEnabled(), offer_dialog.error_label.text()
    offer_dialog.send_button.click()
    assert not offer_dialog.error_label.text(), offer_dialog.error_label.text()
    offer = citizen_app.hby.db.erpy.get((request,)).qb64
    assert citizen_app.hby.db.exns.get((offer,)).sad['q']['dp'] == selected_plan
    # Later local draft changes cannot rewrite the already signed Offer.
    offer_dialog._selections[origin]['/e/core/_/'].append('a/birthDate/value')
    assert citizen_app.hby.db.exns.get((offer,)).sad['q']['dp'] == selected_plan
    offer_wire = deliver(citizen_app, store, offer)
    assert not exchanging.loadParsedNestedSubstreams(store.hby, offer)
    assert b'over18' not in offer_wire
    assert b'Alice' not in offer_wire and b'2010-01-01' not in offer_wire
    agree_dialog = review(store, offer, 'Agree')
    assert agree_dialog.send_button.isEnabled(), agree_dialog.error_label.text()
    agree_dialog.send_button.click()
    agree = store.hby.db.erpy.get((offer,)).qb64
    deliver(store, citizen_app, agree)
    # Consent must survive losing all in-memory selection widgets and reopening.
    for parent in parents:
        parent.close()
    citizen_app.close_vault()
    citizen_app = ipex_vaults('selected-citizen')
    citizen = citizen_app.hby.habByName('Citizen')
    assert citizen_app.hby.db.exns.get((offer,)).sad['q']['dp'] == selected_plan
    grant_dialog = review(citizen_app, agree, 'Grant')
    assert grant_dialog.credential.currentData() == origin and not grant_dialog.credential.isEnabled()
    assert grant_dialog.disclosure_choices.isHidden()
    grant_labels = {label.text() for label in grant_dialog.preview.findChildren(QLabel)}
    assert 'Alice' in grant_labels and '2010-01-01' not in grant_labels
    assert grant_dialog.send_button.isEnabled(), grant_dialog.error_label.text()
    grant_dialog.send_button.click()
    assert not grant_dialog.error_label.text(), grant_dialog.error_label.text()
    grant = citizen_app.hby.db.erpy.get((agree,)).qb64
    assert citizen_app.hby.db.exns.get((agree,)).sad['p'] == offer
    assert citizen_app.hby.db.exns.get((grant,)).sad['p'] == agree
    deliver(citizen_app, store, grant)
    # Native framing encodes nested bodies. Inspect the decoded wire evidence.
    grant_contents = b''.join(node.serder.raw for node in exchanging.loadParsedNestedSubstreams(store.hby, grant))
    assert b'over18' not in grant_contents
    assert b'Alice' in grant_contents and b'2010-01-01' not in grant_contents
    assert store.vault.db.accepted.get((origin,)) is None
    admit = ipexing.respond(store.vault, grant, 'Admit')
    deliver(store, citizen_app, admit)
    assert store.vault.db.receipts.get((verifier.pre, grant)).status == 'accepted'
    assert store.vault.db.accepted.get((origin,)).grant == grant

    def check_received(app, selected_grant=None, *, first=True):
        view = credentialing.credential(app.vault, origin, grant_said=selected_grant)
        ims = bytearray(view['artifacts'][source])
        parsed = Parser().parse(ims=ims, processive=False, version=Vrsn_2_0)
        assert len(parsed) == 1 and not ims
        assert parsed[0].serder.said == source
        if first:
            assert isinstance(parsed[0].serder.sad['A'][2], str)
            assert parsed[0].serder.sad['A'][3]['over13'] is True
        else:
            assert parsed[0].serder.sad['A'][2]['over18'] is False
            assert isinstance(parsed[0].serder.sad['A'][3], str)
        assert credentialing.authentication(app.vault, parsed[0])['et'] == 'authenticated'
        core_node, = Parser().parse(ims=bytearray(view['artifacts'][core]),
                                   processive=False, version=Vrsn_2_0)
        assert isinstance(core_node.serder.sad['a']['birthDate'], str)
        if first:
            assert core_node.serder.sad['a']['givenName']['value'] == 'Alice'
        else:
            assert isinstance(core_node.serder.sad['a']['givenName'], str)
        assert len(view['artifacts']) == 2
        assert view['sender'] == citizen.pre and view['recipient'] == verifier.pre
        assert view['accepted_at']

    check_received(store)
    assert credentialing.credential(citizen_app.vault, source)['proof'] == retained['proof']
    assert credentialing.credential(citizen_app.vault, source)['sad'] == retained['sad']

    # A second presentation has the same credential commitments but different
    # disclosed claims. Its history must not read the first inventory entry.
    second_request = ipexing.start(store.vault, verifier, citizen.pre, 'Apply', schema=root_schema.said,
                                  disclosure_plan=[[
                                      [root_schema.said, '/', []],
                                      [core_schema.said, '/e/core/_/', []],
                                      [source_schema.said, '/e/age/_/', ['A/over18']],
                                  ]])
    deliver(store, citizen_app, second_request)
    second_selection = DisclosureSelection(citizen_app.vault, origin, selections={'/e/age/_/': ['A/2/']})
    second_plan, _, _ = second_selection.prepare()
    second_offer = ipexing.respond(citizen_app.vault, second_request, 'Offer', 'Subject and over18',
                                  credential_said=origin, disclosure_plan=second_plan)
    deliver(citizen_app, store, second_offer)
    second_agree = ipexing.respond(store.vault, second_offer, 'Agree')
    deliver(store, citizen_app, second_agree)
    # Even a caller-supplied wider plan at Grant cannot replace the accepted Offer.
    second_grant = ipexing.respond(citizen_app.vault, second_agree, 'Grant', credential_said=origin,
                                  disclosure_plan=requested_plan)
    deliver(citizen_app, store, second_grant)
    second_contents = b''.join(node.serder.raw for node in exchanging.loadParsedNestedSubstreams(store.hby, second_grant))
    assert b'over18' in second_contents
    assert b'Alice' not in second_contents and b'over13' not in second_contents and b'2010-01-01' not in second_contents
    second_admit = ipexing.respond(store.vault, second_grant, 'Admit')
    deliver(store, citizen_app, second_admit)
    assert store.vault.db.receipts.get((verifier.pre, second_grant)).status == 'accepted'
    assert store.vault.db.accepted.get((origin,)).grant == grant
    check_received(store, grant)
    check_received(store, second_grant, first=False)
    check_received(store)  # Inventory keeps its original accepted evidence.
    sent_view = credentialing.credential(citizen_app.vault, origin, grant_said=second_grant)
    received_view = credentialing.credential(store.vault, origin, grant_said=second_grant)
    assert sent_view['artifacts'] == received_view['artifacts']
    assert received_view['accepted_at'] == store.hby.db.exns.get((second_admit,)).stamp
    assert credentialing.credential(citizen_app.vault, core)['proof'] == retained_core['proof']
    assert credentialing.credential(citizen_app.vault, source)['proof'] == retained['proof']
    with pytest.raises(ValidationError, match='requested origin'):
        credentialing.credential(store.vault, source, grant_said=grant)
    with pytest.raises(ValidationError, match='requested origin'):
        credentialing.credential(store.vault, origin, grant_said=offer)
    store.close_vault()
    store = ipex_vaults('selected-store')
    check_received(store)
    check_received(store, grant)
    check_received(store, second_grant, first=False)
    assert store.vault.db.accepted.get((origin,)).grant == grant

    parent = QWidget()
    history = []
    parent.show_credential_activity = lambda *args, **kwargs: history.append((args, kwargs))
    first_dialog = ViewIssuedCredentialDialog('', store, origin, parent, received=True, grant_said=grant)
    second_dialog = ViewIssuedCredentialDialog('', store, origin, parent, received=True, grant_said=second_grant)
    first_labels = {label.text() for label in first_dialog.findChildren(QLabel)}
    second_labels = {label.text() for label in second_dialog.findChildren(QLabel)}
    assert 'Shared in this exchange' in first_labels & second_labels
    assert 'Alice' in first_labels and 'Alice' not in second_labels
    assert '2010-01-01' not in first_labels | second_labels
    assert first_dialog.credential['artifacts'] != second_dialog.credential['artifacts']
    first_dialog.history_button.click()
    assert history == [((origin,), {'received': True})]
    second_dialog.close()
    parent.close()
    for parent in parents:
        parent.close()
    store.vault.db.accepted.rem((origin,))
    check_received(store, grant)
    check_received(store, second_grant, first=False)
