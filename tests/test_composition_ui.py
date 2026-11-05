from pathlib import Path

from PySide6.QtWidgets import QLabel, QWidget
from keri.core import scheming, SerderACDC

from test_keri_v2_compat import ipex_vaults as ipex_vaults
from test_credentialing import _load_schema, _issue
from locksmith.core import credentialing, ipexing
from locksmith.ui.vault.credentials.disclosure import DisclosureSelection
from locksmith.ui.vault.credentials.compose import ComposePresentationDialog, can_compose
from locksmith.ui.vault.credentials.activity import CredentialActivityPage


def _composition_request(app):
    issuer, holder, verifier = [app.hby.makeHab(name=name) for name in ('Issuer', 'Holder', 'Verifier')]
    source_schema = _load_schema(app, issuer)
    source = _issue(app, source_schema, holder, authentication='signature')
    other = _issue(app, source_schema, verifier, authentication='signature')
    schema = scheming.Schemer(raw=(Path(__file__).parents[1] /
                                  'assets/schemas/sedi/bespoke-presentation.json').read_bytes())
    app.hby.db.schema.pin((schema.said,), schema)
    app.vault.db.issuers.pin((schema.said,), holder.pre)
    request = ipexing.start(app.vault, verifier, holder.pre, 'Apply', schema=schema.said)
    page = QWidget()
    page.app, page.vault = app, app.vault
    return page, request, holder, schema, source, other


def test_composition_issues_self_root_with_retained_holder_evidence(ipex_vaults, qapp):
    app = ipex_vaults('compose-native')
    page, request, holder, schema, source, other = _composition_request(app)
    source_schema = app.hby.db.schema.get((credentialing.credential(app.vault, source)['schema']['$id'],))
    second = _issue(app, source_schema, holder, authentication='signature')
    assert can_compose(schema.sed)
    assert not can_compose(credentialing.credential(app.vault, source)['schema'])
    dialog = ComposePresentationDialog(page, request)
    field = dialog._sources['core']
    assert field.combo_box.findData(other) == -1
    assert field.combo_box.findData(source) >= 0
    dialog.create_button.click()
    assert dialog.error_label.text()
    field.setCurrentIndex(field.combo_box.findData(source))
    second_field = dialog._sources['age']
    second_field.setCurrentIndex(second_field.combo_box.findData(second))
    dialog.terms.setPlainText('')
    created = []
    dialog.credential_created.connect(created.append)
    dialog.create_button.click()
    for _ in range(30):
        app.qtask.run()
        qapp.processEvents()
        if created:
            break
    assert created, dialog.error_label.text()
    view = credentialing.credential(app.vault, created[0])
    assert view['sad']['i'] == holder.pre == view['subject']
    assert view['sad']['e']['core']['n'] == source
    assert view['sad']['e']['core']['o'] == 'I2I'
    assert view['sad']['e']['age']['n'] == second
    assert view['sad']['e']['age']['o'] == 'I2I'
    assert view['sad']['r']['l'] == ''
    assert view['status']['et'] == 'authenticated'
    assert set(ipexing._credential_evidence(app.vault, created[0])[3]) == {created[0], source, second}
    # A newly signed root must already use the edge form checked by native IPEX.
    # Selecting its required identity and links must not invalidate its signature.
    selection = DisclosureSelection(app.vault, created[0])
    plan, _, _ = selection.prepare()
    offer = ipexing.respond(app.vault, request, 'Offer', credential_said=created[0], disclosure_plan=plan)
    agree = ipexing.respond(app.vault, offer, 'Agree')
    grant = ipexing.respond(app.vault, agree, 'Grant', credential_said=created[0])
    assert app.vault.exc.complete(grant)
    dialog.close()


def test_composition_failure_restores_source_and_terms(ipex_vaults, qapp, monkeypatch):
    app = ipex_vaults('compose-retry')
    page, request, holder, _, source, _ = _composition_request(app)
    dialog = ComposePresentationDialog(page, request)
    field = dialog._sources['core']
    field.setCurrentIndex(field.combo_box.findData(source))
    dialog.terms.setPlainText('Retain these chosen terms.')
    before = {said for (said,), _ in app.vault.db.issued.getTopItemIter()}

    def unavailable_signer(*args, **kwargs):
        raise OSError('Signing temporarily unavailable')

    with monkeypatch.context() as signing:
        signing.setattr(holder, 'endorse', unavailable_signer)
        dialog.create_button.click()
        assert not field.isEnabled() and not dialog.terms.isEnabled()
        for _ in range(30):
            app.qtask.run()
            qapp.processEvents()
            if dialog.create_button.isEnabled():
                break
    assert field.isEnabled() and dialog.terms.isEnabled()
    assert dialog.create_button.isEnabled() and dialog.cancel_button.isEnabled()
    assert field.currentData() == source
    assert dialog.terms.toPlainText() == 'Retain these chosen terms.'
    assert dialog.error_label.text()
    assert {said for (said,), _ in app.vault.db.issued.getTopItemIter()} == before
    created = []
    dialog.credential_created.connect(created.append)
    dialog.create_button.click()
    assert not field.isEnabled() and not dialog.terms.isEnabled()
    dialog._create()  # A repeated start must not issue another credential.
    for _ in range(30):
        app.qtask.run()
        qapp.processEvents()
        if created:
            break
    assert created, dialog.error_label.text()
    assert {said for (said,), _ in app.vault.db.issued.getTopItemIter()} == before | {created[0]}
    assert credentialing.credential(app.vault, created[0])['sad']['r']['l'] == 'Retain these chosen terms.'
    dialog.close()


def test_composition_back_and_stale_vault_do_not_issue(ipex_vaults, qapp):
    app = ipex_vaults('compose-cancel')
    page, request, _, _, source, _ = _composition_request(app)
    initial = list(app.vault.db.issued.getTopItemIter())
    parent = QWidget()
    parent.app = app
    activity = CredentialActivityPage(parent)
    activity.set_vault_name(app.name)
    row = next(row for row in activity._rows if row['root'] == request and row['_actions'])
    activity._on_row_action(row, 'Offer')
    review = activity._response_dialog
    assert review.send_button.isEnabled()
    assert not review.offer_review.isHidden()
    review.send_button.click()
    dialog = review._issue_dialog
    field = dialog._sources['core']
    field.setCurrentIndex(field.combo_box.findData(source))
    dialog.terms.setPlainText('Synthetic test only.')
    assert not dialog.source_review.isHidden()
    labels = {label.text() for label in dialog.source_review.findChildren(QLabel)}
    assert 'Issued by Issuer' in labels
    dialog.cancel_button.click()
    qapp.processEvents()
    assert list(app.vault.db.issued.getTopItemIter()) == initial
    assert review.isVisible()
    review.send_button.click()
    dialog = review._issue_dialog
    assert dialog._sources['core'].currentData() == source
    assert dialog.terms.toPlainText() == 'Synthetic test only.'
    vault = app.vault
    app.vault = None
    try:
        dialog.create_button.click()
        assert dialog.error_label.text()
        assert list(vault.db.issued.getTopItemIter()) == initial
    finally:
        app.vault = vault
        dialog.close()
        review.close()
        parent.close()
