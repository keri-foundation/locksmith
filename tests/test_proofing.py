"""Native challenge and IAR binding; these checks do not establish State authority."""
import json
from pathlib import Path

import pytest
from hio.base import doing
from hio.core import http
from keri import kering
from keri.core import Noncer, SealNonce, SerderACDC, SerderKERI, eventing, scheming
from locksmith.core.receipting import agenting

from locksmith.core import credentialing, ipexing, proofing
from locksmith.core.remoting import identifier_introduction
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from locksmith.ui.vault.credentials.proofing import ProofingDialog
from test_credential_ui import schema, wallet as wallet
from test_keri_v2_compat import _deliver_ipex, _retry_ipex, ipex_vaults as ipex_vaults


def _anchor(app, record):
    doer = proofing.AnchorChallengeDoer(app, record.nonce)
    app.vault.extend([doer])
    for _ in range(16):
        app.qtask.run()
        if doer.done:
            break
    assert doer.done
    saved = proofing.session(app.vault, record.nonce)
    assert saved.status == 'binding_verified'
    return saved


def test_session_anchor_survives_reopen_and_does_not_claim_authority(ipex_vaults, qapp):
    app = ipex_vaults('proofing-durable')
    citizen = app.hby.makeHab(name='citizen')
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    assert not dialog.copy_anchor.isEnabled()
    dialog.close()
    saved = _anchor(app, record)
    anchor = proofing.binding(app.vault, record.nonce, saved.anchor_sn)
    assert SealNonce(nd=record.nonce)._asdict() in anchor.sad['a']
    assert app.hby.db.fullyWitnessed(anchor)
    with pytest.raises(ValueError, match='already'):
        proofing.start(app.vault, citizen.pre, proofer.pre, record.nonce)
    app.close_vault()
    app = ipex_vaults('proofing-durable')
    resumed = proofing.verify(app.vault, record.nonce, saved.anchor_sn)
    assert resumed == saved
    assert resumed.status == 'binding_verified'
    assert not resumed.receipt
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog.copy_anchor.click()
    assert json.loads(qapp.clipboard().text()) == dict(
        i=anchor.pre, s=anchor.snh, d=anchor.said)
    assert citizen.pre in dialog.anchor_reference.text()
    dialog.sessions.setCurrentIndex(0)
    assert not dialog.copy_anchor.isEnabled()
    assert not dialog.anchor_reference.text()
    app.hby.db.evts.rem((anchor.pre, anchor.said))
    dialog.sessions.setCurrentIndex(1)
    assert not dialog.copy_anchor.isEnabled()
    assert not dialog.anchor_reference.text()
    dialog.close()


@pytest.mark.parametrize('failure', ['nonce', 'unwitnessed', 'missing', 'superseded'])
def test_binding_requires_current_accepted_witnessed_citizen_event(ipex_vaults, failure):
    app = ipex_vaults('proofing-canonical')
    citizen = app.hby.makeHab(name='citizen')
    proofer = app.hby.makeHab(name='proofer')
    if failure == 'unwitnessed':
        witness = app.hby.makeHab(name='witness', transferable=False)
        citizen = app.hby.makeHab(name='witnessed-citizen', wits=[witness.pre], toad=1)
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    nonce = Noncer().qb64 if failure == 'nonce' else record.nonce
    anchor = SerderKERI(raw=citizen.interact(data=[SealNonce(nd=nonce)._asdict()]))
    if failure == 'missing':
        # Retained index with absent event bytes must fail closed.
        app.hby.db.evts.rem((citizen.pre, anchor.said))
    elif failure == 'superseded':
        # A same-seed independent controller makes a real recovery rotation
        # at sn=1. Native parsing determines which event is canonical.
        recovery = ipex_vaults('proofing-recovery')
        recovered = recovery.hby.makeHab(name='citizen')
        assert recovered.pre == citizen.pre
        observer = ipex_vaults('proofing-canonical-observer')
        proofing.start(observer.vault, citizen.pre, proofer.pre, record.nonce)
        _deliver_ipex(observer.vault, citizen.replay())
        _deliver_ipex(observer.vault, recovered.rotate())
        app = observer
        assert app.hby.db.kels.getLast(keys=citizen.pre, on=anchor.sn) != anchor.said
        assert app.hby.db.evts.get((citizen.pre, anchor.said)) is not None
    with pytest.raises((kering.ValidationError, kering.MissingEntryError, kering.MissingChainError)):
        proofing.verify(app.vault, record.nonce, anchor.sn)
    assert proofing.session(app.vault, record.nonce).status == 'challenge'


@pytest.mark.parametrize('mismatch', [None, 'nonce', 'subject', 'proofer', 'unaccepted'])
def test_received_iar_binding_uses_authenticated_inventory(ipex_vaults, mismatch):
    source = ipex_vaults('proofing-issuer')
    target = ipex_vaults('proofing-citizen')
    proofer = source.hby.makeHab(name='proofer')
    citizen = target.hby.makeHab(name='citizen')
    record = proofing.start(source.vault, citizen.pre, proofer.pre)
    imported = proofing.start(target.vault, citizen.pre, proofer.pre, record.nonce)
    saved = _anchor(target, imported)
    # Use the bundled published IAR schema, not a substitute
    # verifier or a mocked signature/credential boundary.
    path = Path(__file__).parents[1] / 'assets' / 'schemas' / 'sedi' / 'iar.json'
    schemer = scheming.Schemer(sed=json.loads(path.read_text()))
    assert schemer.said == proofing.IAR_SCHEMA
    issuer = source.hby.makeHab(name='other-proofer') if mismatch == 'proofer' else proofer
    source.hby.db.schema.pin((schemer.said,), schemer)
    target.hby.db.schema.pin((schemer.said,), schemer)
    source.vault.db.issuers.pin((schemer.said,), issuer.pre)
    _deliver_ipex(source.vault, identifier_introduction(citizen))
    _deliver_ipex(target.vault, identifier_introduction(issuer))
    subject = target.hby.makeHab(name='other-citizen') if mismatch == 'subject' else citizen
    if subject is not citizen:
        _deliver_ipex(source.vault, identifier_introduction(subject))
    attributes = {key: 'Example' for key in (
        'givenName', 'middleName', 'familyName', 'nameSuffix', 'birthDate',
        'facialImageProof', 'legalPresenceStatus', 'proofingDatetime', 'sediURL')}
    attributes['i'] = subject.pre
    attributes['residence'] = {key: 'Example' for key in (
        'street', 'city', 'county', 'state', 'postcode', 'country')}
    doer = credentialing.IssueCredentialDoer(
        source, schemer.said, subject.pre, attributes, authentication='signature',
        nonce=Noncer().qb64 if mismatch == 'nonce' else record.nonce)
    doing.Doist(doers=[doer], tock=0.03125, limit=1).do()
    ((said,), _), = source.vault.db.issued.getTopItemIter()
    grant, attachment = ipexing.grant(source.vault, issuer, said, citizen.pre)
    _deliver_ipex(target.vault, ipexing.prepare(source.vault, issuer, grant, attachment))
    _retry_ipex(target.vault)
    assert target.vault.exc.complete(grant.said)
    if mismatch != 'unaccepted':
        ipexing.admit(target.vault, citizen, grant.said)
        assert credentialing.credential(target.vault, said, received=True)['status']['et'] == 'authenticated'
    if mismatch:
        with pytest.raises(kering.ValidationError):
            proofing.verify(target.vault, record.nonce, saved.anchor_sn, said)
        assert proofing.session(target.vault, record.nonce).status == 'binding_verified'
    else:
        checked = proofing.verify(target.vault, record.nonce, saved.anchor_sn, said)
        assert checked.status == 'awaiting_authority'
        assert checked.receipt == said
        # A third wallet can record the OOB session and check ordinary received
        # IAR evidence without controlling either citizen or proofer.
        checker = ipex_vaults('proofing-independent-state-verifier')
        checking = checker.hby.makeHab(name='independent-checker')
        with pytest.raises(ValueError, match='local proofer'):
            proofing.start(checker.vault, citizen.pre, proofer.pre)
        independent = proofing.start(checker.vault, citizen.pre, proofer.pre, record.nonce)
        assert independent.status == 'challenge'
        checker.hby.db.schema.pin((schemer.said,), schemer)
        _deliver_ipex(checker.vault, identifier_introduction(issuer))
        _deliver_ipex(checker.vault, identifier_introduction(citizen))
        _deliver_ipex(source.vault, identifier_introduction(checking))
        checked_grant, checked_attachment = ipexing.grant(source.vault, issuer, said, checking.pre)
        _deliver_ipex(checker.vault, ipexing.prepare(source.vault, issuer, checked_grant, checked_attachment))
        _retry_ipex(checker.vault)
        assert checker.vault.exc.complete(checked_grant.said)
        ipexing.admit(checker.vault, checking, checked_grant.said)
        independently_checked = proofing.verify(checker.vault, record.nonce, saved.anchor_sn, said)
        assert independently_checked.status == 'awaiting_authority'
        assert independently_checked.citizen == citizen.pre
        assert independently_checked.proofer == proofer.pre
        # No local-citizen privilege is inferred from an imported session.
        denied = proofing.AnchorChallengeDoer(checker, record.nonce)
        doing.Doist(doers=[denied], tock=0.03125, limit=1).do()
        assert proofing.session(checker.vault, record.nonce) == independently_checked
        target.close_vault()
        target = ipex_vaults('proofing-citizen')
        assert proofing.session(target.vault, record.nonce) == checked


def test_stale_dialog_and_queued_anchor_do_not_use_replacement_vault(ipex_vaults, qapp):
    app = ipex_vaults('proofing-old')
    citizen = app.hby.makeHab(name='citizen')
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    old = app.vault
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    doer = proofing.AnchorChallengeDoer(app, record.nonce)
    replacement = ipex_vaults('proofing-replacement')
    app.vault = replacement.vault
    try:
        dialog._run(dialog._anchor)
        assert dialog._doer is None
        doing.Doist(doers=[doer], tock=0.03125, limit=1).do()
        assert citizen.kever.sn == 0
        assert old.db.proofing.get((record.nonce,)).anchor_sn == -1
        assert not list(replacement.vault.db.proofing.getTopItemIter())
    finally:
        dialog.close()
        app.vault = old


def test_issue_dialog_forwards_explicit_nonce_to_native_credential(wallet):
    app = wallet('proofing-nonce-ui')
    issuer = app.hby.makeHab(name='issuer')
    citizen = app.hby.makeHab(name='citizen')
    detail = schema().sed
    detail['$id'] = ''
    detail['properties'].pop('rd')
    detail['required'].remove('rd')
    detail['properties']['u'] = {'type': 'string'}
    schemer = scheming.Schemer(sed=detail)
    app.hby.db.schema.pin((schemer.said,), schemer)
    app.vault.db.issuers.pin((schemer.said,), issuer.pre)
    nonce = Noncer().qb64
    dialog = IssueCredentialDialog(app, nonce=nonce)
    dialog.schema_dropdown.setCurrentIndex(1)
    modes = dialog.authentication_dropdown.combo_box
    modes.setCurrentIndex(modes.findData('signature'))
    dialog.local_radio.setChecked(True)
    dialog.recipient_dropdown.setCurrentIndex(dialog.recipient_dropdown.combo_box.findData(citizen.pre))
    dialog._dynamic_field_widgets['nickname']['widget'].setText('Citizen')
    dialog._on_issue()
    assert len(app.queued) == 1
    doing.Doist(doers=app.queued, tock=0.03125, limit=1).do()
    ((_,), issued), = app.vault.db.issued.getTopItemIter()
    acdc = SerderACDC(raw=issued.raw.encode())
    assert acdc.sad['u'] == nonce
    assert acdc.sad['a']['i'] == citizen.pre
    assert acdc.sad['i'] == issuer.pre
    dialog.close()


def test_witness_auth_panel_cancels_or_forwards_valid_codes(ipex_vaults, qapp):
    app = ipex_vaults('proofing-witness-auth-ui')
    witness = app.hby.makeHab(name='witness', transferable=False)
    citizen = app.hby.makeHab(name='citizen', wits=[witness.pre], toad=1)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog.open()
    qapp.processEvents()
    dialog.anchor_button.click()
    qapp.processEvents()
    assert dialog.isVisible()
    assert dialog._auth_dialog is not None and dialog._auth_dialog.isVisible()
    assert dialog._doer is None
    assert citizen.kever.sn == 0
    assert not dialog.sessions.isEnabled()
    dialog._auth_dialog.reject()
    qapp.processEvents()
    assert dialog._auth_dialog is None
    assert dialog.isVisible()
    assert dialog.sessions.isEnabled()
    assert citizen.kever.sn == 0
    dialog.anchor_button.click()
    qapp.processEvents()
    assert dialog.isVisible() and dialog._auth_dialog.isVisible()
    field = dialog._auth_panel.passcode_fields[witness.pre]
    field.setText('12')
    dialog._run(lambda: dialog._submit_anchor_auth(record.nonce))
    assert dialog._doer is None
    field.setText('123456')
    dialog._run(lambda: dialog._submit_anchor_auth(record.nonce))
    assert dialog._doer.codes == [f'{witness.pre}:123456']
    assert dialog._doer.vault is app.vault
    assert dialog._auth_dialog is None
    assert not field.text()
    assert citizen.kever.sn == 0  # Queuing does not execute the interaction.
    dialog.reject()
    assert dialog._doer is None
    assert proofing.session(app.vault, record.nonce).anchor_sn == -1


def test_witness_auth_submission_refuses_replacement_vault(ipex_vaults, qapp):
    app = ipex_vaults('proofing-auth-old')
    witness = app.hby.makeHab(name='witness', transferable=False)
    citizen = app.hby.makeHab(name='citizen', wits=[witness.pre], toad=1)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog._run(dialog._anchor)
    dialog._auth_panel.passcode_fields[witness.pre].setText('123456')
    old = app.vault
    app.vault = ipex_vaults('proofing-auth-new').vault
    try:
        dialog._run(lambda: dialog._submit_anchor_auth(record.nonce))
        assert dialog._doer is None
        assert citizen.kever.sn == 0
        dialog.reject()
        assert dialog._auth_dialog is None
    finally:
        app.vault = old


def test_unwitnessed_anchor_needs_no_authentication_dialog(ipex_vaults, qapp):
    app = ipex_vaults('proofing-unwitnessed-ui')
    citizen = app.hby.makeHab(name='citizen')
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog._run(dialog._anchor)
    assert dialog._auth_dialog is None
    assert dialog._doer.codes == []
    for _ in range(16):
        app.qtask.run()
        if dialog._doer is None:
            break
    assert dialog._doer is None
    assert proofing.session(app.vault, record.nonce).status == 'binding_verified'
    dialog.reject()


@pytest.mark.parametrize('witness_receipt', [False, True])
def test_anchor_codes_reach_owned_receiptor_without_bypassing_witness_verification(
        ipex_vaults, monkeypatch, witness_receipt):
    app = ipex_vaults('proofing-auth-transport')
    witness = app.hby.makeHab(name='witness', transferable=False)
    citizen = app.hby.makeHab(name='citizen', wits=[witness.pre], toad=1)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    calls = []

    def capture_receipt(self, pre, sn, auths):
        calls.append((pre, sn, auths))
        # Replace transport only; receipt creation, signature verification,
        # accepted events, and final witness checks all remain native.
        if witness_receipt:
            digest = app.hby.db.kels.getLast(keys=pre, on=sn)
            anchor = app.hby.db.evts.get((pre, digest))
            _historical_witness_receipt(app, witness, anchor, 0)
        yield from ()

    monkeypatch.setattr(proofing.LocksmithReceiptor, 'receipt', capture_receipt)
    doer = proofing.AnchorChallengeDoer(app, record.nonce, codes=[f'{witness.pre}:123456'])
    app.vault.extend([doer])
    for _ in range(16):
        app.qtask.run()
        if doer.done:
            break
    assert doer.done
    (pre, sn, auths), = calls
    assert pre == citizen.pre
    assert sn == 1
    assert auths[witness.pre].startswith('123456#')
    expected = 'binding_verified' if witness_receipt else 'awaiting_witnesses'
    assert proofing.session(app.vault, record.nonce).status == expected


def _historical_witness_receipt(app, witness, anchor, index):
    """Sign and natively verify a receipt at an event's historical witness index."""
    receipt = eventing.receipt(pre=anchor.pre, sn=anchor.sn, said=anchor.said,
                              version=anchor.pvrsn)
    sigers = witness.mgr.sign(ser=anchor.raw, pubs=[witness.pre], indices=[index])
    stream = eventing.messagize(serder=receipt, wigers=sigers,
                               gvrsn=anchor.pvrsn, framed=True)
    _deliver_ipex(app.vault, stream)


@pytest.mark.parametrize('change', ['removed', 'replaced', 'increased', 'decreased'])
def test_pending_anchor_resume_uses_historical_witnesses_and_threshold(
        ipex_vaults, monkeypatch, qapp, change):
    app = ipex_vaults(f'proofing-historical-{change}')
    first = app.hby.makeHab(name='first-witness', transferable=False)
    second = app.hby.makeHab(name='second-witness', transferable=False)
    replacement = app.hby.makeHab(name='replacement-witness', transferable=False)
    old_wits = [first.pre, second.pre] if change in ('increased', 'decreased') else [first.pre]
    old_threshold = 2 if change == 'decreased' else 1
    citizen = app.hby.makeHab(name='citizen', wits=old_wits, toad=old_threshold)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)

    def no_receipt(self, pre, sn, auths):
        yield from ()

    monkeypatch.setattr(proofing.LocksmithReceiptor, 'receipt', no_receipt)
    pending = proofing.AnchorChallengeDoer(app, record.nonce)
    app.vault.extend([pending])
    for _ in range(16):
        app.qtask.run()
        if pending.done:
            break
    saved = proofing.session(app.vault, record.nonce)
    assert saved.status == 'awaiting_witnesses'
    assert saved.anchor_sn == 1
    anchor = app.hby.db.evts.get((citizen.pre, app.hby.db.kels.getLast(keys=citizen.pre, on=1)))
    if change == 'removed':
        citizen.rotate(cuts=old_wits, toad=0)
    elif change == 'replaced':
        citizen.rotate(cuts=old_wits, adds=[replacement.pre], toad=1)
    else:
        citizen.rotate(toad=1 if change == 'decreased' else 2)
    assert app.vault.kvy.fetchEstEvent(citizen.pre, anchor.sn).bner.num == old_threshold
    assert [wit.qb64 for wit in citizen.kvy.fetchWitnessState(citizen.pre, anchor.sn)] == old_wits
    with pytest.raises(kering.MissingChainError):
        proofing.binding(app.vault, record.nonce, anchor.sn)
    _historical_witness_receipt(app, first, anchor, 0)
    if old_threshold == 2:
        with pytest.raises(kering.MissingChainError):
            proofing.binding(app.vault, record.nonce, anchor.sn)
        _historical_witness_receipt(app, second, anchor, 1)
    assert proofing.binding(app.vault, record.nonce, anchor.sn).said == anchor.said

    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog._run(dialog._anchor)
    assert set(dialog._auth_panel.witness_ids) == set(old_wits)
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('123456')
    dialog._run(lambda: dialog._submit_anchor_auth(record.nonce))
    for _ in range(16):
        app.qtask.run()
        if dialog._doer is None:
            break
    verified = proofing.session(app.vault, record.nonce)
    assert verified.status == 'binding_verified'
    assert verified.anchor_sn == 1
    assert citizen.kever.sn == 2  # Resume did not make a second interaction.
    dialog.reject()


def test_pending_unwitnessed_anchor_ignores_later_added_witnesses(ipex_vaults, qapp):
    app = ipex_vaults('proofing-historical-unwitnessed')
    citizen = app.hby.makeHab(name='citizen')
    witness = app.hby.makeHab(name='later-witness', transferable=False)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    anchor = SerderKERI(raw=citizen.interact(data=[SealNonce(nd=record.nonce)._asdict()]))
    # Persist the native event before the workflow's final binding checkpoint.
    record.anchor_sn, record.status = anchor.sn, 'awaiting_witnesses'
    app.vault.db.proofing.pin((record.nonce,), record)
    citizen.rotate(adds=[witness.pre], toad=1)
    assert citizen.kever.wits == [witness.pre]
    assert proofing.binding(app.vault, record.nonce, anchor.sn).said == anchor.said
    dialog = ProofingDialog(app)
    dialog.sessions.setCurrentIndex(1)
    dialog._run(dialog._anchor)
    assert dialog._auth_dialog is None
    for _ in range(16):
        app.qtask.run()
        if dialog._doer is None:
            break
    assert proofing.session(app.vault, record.nonce).status == 'binding_verified'
    assert citizen.kever.sn == 2
    dialog.reject()


@pytest.mark.parametrize('stop', ['cancel', 'timeout'])
def test_owned_receiptor_closes_pending_http_client_without_touching_unrelated_work(
        ipex_vaults, monkeypatch, stop):
    app = ipex_vaults(f'proofing-owned-network-{stop}')
    witness = app.hby.makeHab(name='witness', transferable=False)
    citizen = app.hby.makeHab(name='citizen', wits=[witness.pre], toad=1)
    proofer = app.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre)
    clients = []

    def waiting_client():
        client = http.clienting.Client(hostname='127.0.0.1', port=1)
        # Keep real HTTP ClientDoer resource lifecycle while withholding all
        # transport service and responses. No server or live network is needed.
        monkeypatch.setattr(client, 'service', lambda: None)
        return client, http.clienting.ClientDoer(client=client)

    unrelated_client, unrelated_doer = waiting_client()
    app.vault.receiptor.extend([unrelated_doer])

    def http_client(hab, wit):
        client, client_doer = waiting_client()
        clients.append((client, client_doer))
        return client, client_doer

    monkeypatch.setattr(agenting, 'httpClient', http_client)
    doer = proofing.AnchorChallengeDoer(app, record.nonce)
    app.vault.extend([doer])
    for _ in range(16):
        app.qtask.run()
        if clients:
            break
    (client, client_doer), = clients
    owned, = [child for child in doer.doers if isinstance(child, proofing.LocksmithReceiptor)]
    assert client.connector.opened
    assert unrelated_client.connector.opened
    if stop == 'cancel':
        app.vault.remove([doer])
    else:
        for _ in range(1100):
            app.qtask.run()
            if doer.done:
                break
        assert doer.done
    assert not client.connector.opened
    assert not owned.deeds
    assert owned not in doer.doers
    assert unrelated_client.connector.opened
    assert unrelated_doer in app.vault.receiptor.doers
    assert proofing.session(app.vault, record.nonce).status == 'awaiting_witnesses'


def test_proofing_page_resumes_citizen_session_without_proofer_actions(ipex_vaults, qapp):
    from PySide6.QtWidgets import QWidget
    from locksmith.ui.vault.credentials.proofing import ProofingSessionsPage

    app = ipex_vaults('proofing-page-citizen')
    citizen = app.hby.makeHab(name='citizen')
    remote = ipex_vaults('proofing-page-proofer')
    proofer = remote.hby.makeHab(name='proofer')
    record = proofing.start(app.vault, citizen.pre, proofer.pre, Noncer().qb64)
    parent = QWidget()
    parent.app = app
    page = ProofingSessionsPage(parent)
    parent.show()
    page.show()
    qapp.processEvents()
    row, = page.table._static_data
    assert row['nonce'] == record.nonce
    page.table.row_clicked.emit(row)
    dialog = page._dialog
    assert dialog.nonce.text() == record.nonce
    assert dialog.anchor_button.isVisible() and not dialog.issue_button.isVisible()
    assert not dialog.start_button.isVisible()
    assert dialog.verify_button.isEnabled()
    assert dialog.sn.isVisible() and dialog.receipt.isVisible()
    dialog.close()
    assert proofing.session(app.vault, record.nonce) == record
    # A session can check an existing citizen anchor without making another one.
    citizen.interact(data=[SealNonce(nd=record.nonce)._asdict()])
    sequence = citizen.kever.sn
    page.table.row_clicked.emit(row)
    page._dialog.sn.setText(str(sequence))
    page._dialog.verify_button.click()
    assert proofing.session(app.vault, record.nonce).status == 'binding_verified'
    assert citizen.kever.sn == sequence
    page._dialog.close()
    page.table.add_clicked.emit()
    assert page._dialog.sessions.currentData() is None
    assert page._dialog.start_button.isVisible()
    assert not page._dialog.anchor_button.isVisible()
    page._dialog.close()
    parent.close()
