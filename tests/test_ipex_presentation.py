"""Holder registry preparation using native proof verification."""
from copy import deepcopy

import pytest
from keri.acdc import Registrar
from keri.core import scheming
from keri.peer import exchanging

from locksmith.core import credentialing, ipexing, registries
from test_credentialing import _issue, _load_schema
from test_ipex_policy import _introduce
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


@pytest.mark.parametrize('anchored', [False, True])
@pytest.mark.parametrize('linked', [False, True, 'other-issuee'])
def test_holder_prepares_one_grant_before_queueing_delivery(ipex_vaults, anchored, linked):
    issuer_app, holder_app, verifier_app = [ipex_vaults(name) for name in
                                          ('present-issuer', 'present-holder', 'present-verifier')]
    issuer = issuer_app.hby.makeHab(name='issuer')
    holder = holder_app.hby.makeHab(name='holder')
    verifier = verifier_app.hby.makeHab(name='verifier')
    schema = _load_schema(issuer_app, issuer)
    definition = deepcopy(schema.sed)
    credentialing.attribute_schemas(definition)[0].setdefault('properties', {})['rd'] = {'type': 'string'}
    schema = scheming.Schemer(sed=definition)
    for app in (issuer_app, holder_app, verifier_app):
        app.hby.db.schema.pin((schema.said,), schema)
    issuer_app.vault.db.issuers.pin((schema.said,), issuer.pre)
    registry = Registrar(rgy=holder_app.rgy).makeRegistry(name='presentations', prefix=holder.pre)
    rip = holder_app.rgy.store.event(registry.regk)
    holder.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    said = _issue(issuer_app, schema, holder, attributes={'LEI': 'credential-value', 'rd': registry.regk})
    if linked:
        if linked == 'other-issuee':
            # A linked authority's issuee does not co-grant this presentation.
            # Its declared registry must not require a proof from another wallet.
            authority = issuer_app.hby.makeHab(name='authority')
            authority_registry = Registrar(rgy=issuer_app.rgy).makeRegistry(
                name='authority-presentations', prefix=authority.pre)
            rip = issuer_app.rgy.store.event(authority_registry.regk)
            authority.interact(data=[dict(i=authority_registry.regk, s=rip.sad['n'], d=rip.said)])
            assert authority_registry.anchorMsg(rip.said)
            said = _issue(issuer_app, schema, authority,
                          attributes={'LEI': 'authority-value', 'rd': authority_registry.regk})
        said = _issue(issuer_app, schema, holder,
                      attributes={'LEI': 'linked-value', 'rd': registry.regk},
                      edges={'source': {'n': said, 's': schema.said, 'o': 'NI2I'}})
    origin = credentialing.credential(issuer_app.vault, said)
    issuer_registry = origin['sad']['rd']
    _introduce(issuer_app, holder_app)
    _introduce(holder_app, issuer_app)
    for regk in issuer_app.rgy.regs:
        registries.ingest(holder_app.vault, regk, issuer_app.rgy.store.cloneTel(regk))
    issuance, atc = ipexing.grant(issuer_app.vault, issuer, said, holder.pre)
    _deliver_ipex(holder_app.vault, ipexing.prepare(issuer_app.vault, issuer, issuance, atc))
    ipexing.admit(holder_app.vault, holder, issuance.said)
    _introduce(verifier_app, holder_app)
    cross_vault, cross_atc = ipexing.grant(issuer_app.vault, issuer, said, verifier.pre)
    with pytest.raises(ValueError, match='controlled by another vault'):
        ipexing.submit(issuer_app.vault, issuer, cross_vault, cross_atc)
    assert issuer_app.vault.db.outbox.get((cross_vault.said,)) is None
    from keri import kering
    from keri.acdc import ipexing as native
    proof_view, artifacts, plan, _ = ipexing._credential_evidence(holder_app.vault, said)
    draft, atc = native.grant(holder, verifier.pre, '', proof_view['proof'], artifacts=artifacts,
                               modifiers={'dp': plan}, ax=[anchored], anchorers=[], kind=kering.Kinds.json)
    holder_app.vault.remove([holder_app.vault.ipex_outbox])
    assert ipexing.submit(holder_app.vault, holder, draft, atc) == draft.said
    assert holder_app.vault.db.outbox.get((draft.said,)) is None
    preparation, = [doer for doer in holder_app.vault.doers if isinstance(doer, ipexing.PresentIpexDoer)]
    assert ipexing.submit(holder_app.vault, holder, draft, atc) == draft.said
    concurrent, concurrent_atc = ipexing.grant(holder_app.vault, holder, said, verifier.pre)
    with pytest.raises(ValueError, match='Another presentation'):
        ipexing.submit(holder_app.vault, holder, concurrent, concurrent_atc)
    # Run only preparation; the outbox must not contact the fixture's closed route.
    for _ in range(128):
        holder_app.qtask.run()
        if preparation.done:
            break
    assert preparation.done and not preparation.error
    assert holder_app.vault.exc.complete(draft.said)
    assert holder_app.hby.db.exns.get((draft.said,)).raw == draft.raw
    assert holder_app.vault.db.outbox.get((draft.said,)).status == 'pending'
    proof = holder_app.vault.db.presentations.get((draft.said, registry.regk))
    assert proof.blinder and proof.update == holder_app.rgy.store.head(registry.regk).qb64
    assert holder_app.rgy.store.headEvent(registry.regk).sad['n'] == '1'
    ipexing.submit(holder_app.vault, holder, draft, atc)
    assert holder_app.rgy.store.head(registry.regk).qb64 == proof.update
    _introduce(issuer_app, verifier_app)
    _introduce(holder_app, verifier_app)
    for source, regk in ((issuer_app, issuer_registry), (holder_app, registry.regk)):
        registries.ingest(verifier_app.vault, regk, source.rgy.store.cloneTel(regk))
    for regk in issuer_app.rgy.regs:
        registries.ingest(verifier_app.vault, regk, issuer_app.rgy.store.cloneTel(regk))
    _deliver_ipex(verifier_app.vault, exchanging.serializeMessage(holder_app.hby, draft.said))
    assert verifier_app.vault.exc.complete(draft.said)
    ipexing.admit(verifier_app.vault, verifier, draft.said)
    assert verifier_app.vault.db.accepted.get((said,)).grant == draft.said
    holder_app.close_vault()
    holder_app = ipex_vaults('present-holder')
    assert holder_app.vault.db.presentations.get((draft.said, registry.regk)) == proof


@pytest.mark.parametrize('est_only', [False, True])
@pytest.mark.parametrize('witnessed', [False, True])
def test_registry_dialog_creates_a_retained_public_registry(ipex_vaults, monkeypatch, est_only, witnessed):
    from keri.core import SerderKERI
    from locksmith.ui.vault.credentials.registry import RegistryDialog

    app = ipex_vaults('registry-ui')
    witness = app.hby.makeHab(name='witness', transferable=False) if witnessed else None
    hab = app.hby.makeHab(name='controller', estOnly=est_only,
                         wits=[witness.pre] if witnessed else [], toad=1 if witnessed else 0)
    if witnessed:
        _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
        def receipt(self, pre, sn=None, auths=None):
            yield self.tock
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
        monkeypatch.setattr(registries.LocksmithReceiptor, 'receipt', receipt)
    dialog = RegistryDialog(app)
    dialog.controller.setCurrentIndex(dialog.controller.combo_box.findData(hab.pre))
    dialog.name.setText('disclosures')
    if witnessed:
        for field in dialog._auth_panel.passcode_fields.values():
            field.setText('123456')
    dialog._create()
    for _ in range(128):
        app.qtask.run()
        if dialog._doer.done:
            break
    assert dialog._doer.done and not dialog._doer.error
    regk = dialog.identifier.text()
    assert app.rgy.registryByName('disclosures').regk == regk
    assert app.rgy.store.headEvent(regk).israid == hab.pre
    dialog.close()
    app.close_vault()
    app = ipex_vaults('registry-ui')
    other = app.hby.makeHab(name='other-controller')
    unrelated = Registrar(rgy=app.rgy).makeRegistry(name='other-registry', prefix=other.pre)
    inception = app.rgy.store.event(unrelated.regk)
    other.interact(data=[dict(i=unrelated.regk, s=inception.sad['n'], d=inception.said)])
    assert unrelated.anchorMsg(inception.said)
    reopened = RegistryDialog(app, controller=hab.pre)
    assert reopened.controller.count() == 1 and reopened.controller.currentData() == hab.pre
    assert not reopened.controller.isEnabled()
    assert reopened.existing.combo_box.findData(unrelated.regk) < 0
    assert reopened.existing.combo_box.findData(regk) >= 0
    reopened.name.setText('stale-input')
    app.hby.habByName('controller').rotate()
    reopened._create()
    assert 'key state changed' in reopened.error_label.text()
    assert app.rgy.registryByName('stale-input') is None
    reopened.close()


@pytest.mark.parametrize('reopen', [False, True])
def test_registry_wrong_code_retry_keeps_one_pending_inception(ipex_vaults, monkeypatch, reopen):
    from keri.core import SerderKERI
    from locksmith.ui.vault.credentials.registry import RegistryDialog

    app = ipex_vaults('registry-auth-retry')
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
    assert hab.db.fullyWitnessed(hab.kever.serder)
    original = hab.kever.sn

    def receipt(self, pre, sn=None, auths=None):
        yield self.tock
        if (auths or {}).get(witness.pre, '').split('#')[0] == '123456':
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))

    monkeypatch.setattr(registries.LocksmithReceiptor, 'receipt', receipt)
    dialog = RegistryDialog(app)
    dialog.controller.setCurrentIndex(dialog.controller.combo_box.findData(hab.pre))
    dialog.name.setText('disclosures')
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('123')
    dialog.create.click()
    assert dialog._doer is None and hab.kever.sn == original
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('654321')
    dialog.create.click()
    dialog.create.click()
    for _ in range(128):
        app.qtask.run()
        if dialog._doer.done:
            break
    assert dialog._doer.done and dialog._doer.error
    assert app.rgy.registryByName('disclosures') is None
    assert not list(app.rgy.store.records.getTopItemIter())
    assert dialog.identifier.text() == '' and dialog.create.isEnabled()
    pending = app.vault.db.registry_creations.get(('disclosures',))
    assert pending and app.rgy.store.head(pending.said) is None
    assert hab.kever.sn == original + 1
    other = registries.CreateRegistryDoer(app.vault, hab, 'another')
    app.vault.extend([other])
    for _ in range(16):
        app.qtask.run()
    assert other.done and 'Finish witness authentication' in other.error
    assert app.vault.db.registry_creations.get(('another',)) is None
    assert hab.kever.sn == original + 1
    if reopen:
        dialog.close()
        app.close_vault()
        app = ipex_vaults('registry-auth-retry')
        hab, witness = app.hby.habByName('controller'), app.hby.habByName('witness')
        dialog = RegistryDialog(app)
        dialog.existing.setCurrentIndex(dialog.existing.combo_box.findData(pending.said))
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('123456')
    dialog.create.click()
    for _ in range(128):
        app.qtask.run()
        if dialog._doer.done:
            break
    assert dialog._doer.done and not dialog._doer.error
    assert app.rgy.registryByName('disclosures').regk == pending.said
    assert dialog.identifier.text() == pending.said
    assert hab.kever.sn == original + 1
    assert app.vault.db.registry_creations.get(('disclosures',)) is None
    assert len(list(app.rgy.store.records.getTopItemIter())) == 1
    dialog.close()


@pytest.mark.parametrize('reopen', [False, True])
def test_registry_close_stops_creation_and_late_receipt_does_not_register(ipex_vaults, monkeypatch, reopen):
    from keri.core import SerderKERI
    from locksmith.ui.vault.credentials.registry import RegistryDialog

    app = ipex_vaults('registry-cancel')
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
    closed = []

    def receipt(self, *args, **kwa):
        try:
            while True:
                yield self.tock
        finally:
            closed.append(True)

    monkeypatch.setattr(registries.LocksmithReceiptor, 'receipt', receipt)
    dialog = RegistryDialog(app)
    dialog.controller.setCurrentIndex(dialog.controller.combo_box.findData(hab.pre))
    dialog.name.setText('disclosures')
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('123456')
    dialog.create.click()
    for _ in range(12):
        app.qtask.run()
    pending = app.vault.db.registry_creations.get(('disclosures',))
    assert pending and not dialog._doer.done
    sn = hab.kever.sn
    dialog.close()
    assert closed and dialog._doer not in app.vault.doers
    _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
    for _ in range(12):
        app.qtask.run()
    assert app.rgy.registryByName('disclosures') is None
    assert app.rgy.store.head(pending.said) is None
    if reopen:
        app.close_vault()
        app = ipex_vaults('registry-cancel')
        hab = app.hby.habByName('controller')
    retry = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
    app.vault.extend([retry])
    for _ in range(128):
        app.qtask.run()
        if retry.done:
            break
    assert retry.done and not retry.error
    assert app.rgy.registryByName('disclosures').regk == pending.said
    assert hab.kever.sn == sn


@pytest.mark.parametrize('phase', ['intent', 'anchor', 'publication'])
def test_registry_creation_resumes_retained_native_state(ipex_vaults, monkeypatch, phase):
    from keri.core import SerderKERI
    from locksmith.ui.vault.credentials.registry import RegistryDialog

    app = ipex_vaults('registry-interruption')
    witness = app.hby.makeHab(name='witness', transferable=False) if phase == 'publication' else None
    hab = app.hby.makeHab(name='controller', wits=[witness.pre] if witness else [], toad=1 if witness else 0)
    if witness:
        _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
        def receipt(self, pre, sn=None, auths=None):
            yield self.tock
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
        monkeypatch.setattr(registries.LocksmithReceiptor, 'receipt', receipt)
    interact = hab.interact

    def interrupted_interact(*args, **kwa):
        if phase == 'anchor':
            interact(*args, **kwa)
        raise OSError('creation interrupted')

    def interrupted_publish(self, *args):
        raise OSError('publication unavailable')
        yield

    with monkeypatch.context() as patch:
        if phase == 'publication':
            patch.setattr(registries.CreateRegistryDoer, 'publish', interrupted_publish)
        else:
            patch.setattr(hab, 'interact', interrupted_interact)
        worker = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
        app.vault.extend([worker])
        for _ in range(32):
            app.qtask.run()
            if worker.done:
                break
        assert worker.done and worker.error
    pending = app.vault.db.registry_creations.get(('disclosures',))
    assert pending
    app.close_vault()
    app = ipex_vaults('registry-interruption')
    hab = app.hby.habByName('controller')
    if phase == 'publication':
        dialog = RegistryDialog(app)
        index = dialog.existing.combo_box.findData(pending.said)
        dialog.existing.setCurrentIndex(index)
        assert not dialog.name.isEnabled() and not dialog.controller.isEnabled()
        assert dialog._auth_panel.isHidden() and dialog.identifier.text() == ''
        dialog.existing.setCurrentIndex(0)
        assert dialog.name.isEnabled() and not dialog._auth_panel.isHidden()
        dialog.existing.setCurrentIndex(index)
        dialog.create.click()
        worker = dialog._doer
    else:
        worker = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
        app.vault.extend([worker])
    for _ in range(128):
        app.qtask.run()
        if worker.done:
            break
    assert worker.done and not worker.error
    assert app.rgy.registryByName('disclosures').regk == pending.said
    assert hab.kever.sn == 1
    assert len(list(app.rgy.store.records.getTopItemIter())) == 1
    assert app.vault.db.registry_creations.get(('disclosures',)) is None
    if phase == 'publication':
        dialog.close()


def test_registry_intent_without_anchor_cannot_extend_an_unwitnessed_tail(ipex_vaults, monkeypatch):
    from locksmith.ui.vault.credentials.registry import RegistryDialog

    app = ipex_vaults('registry-gap')
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
    with monkeypatch.context() as patch:
        def interrupted(*args, **kwa):
            raise OSError('interrupted before anchor')
        patch.setattr(hab, 'interact', interrupted)
        worker = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
        app.vault.extend([worker])
        for _ in range(16):
            app.qtask.run()
    pending = app.vault.db.registry_creations.get(('disclosures',))
    assert pending
    hab.interact()
    sn = hab.kever.sn
    retry = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
    app.vault.extend([retry])
    for _ in range(16):
        app.qtask.run()
    assert retry.done and 'Finish witness authentication' in retry.error
    assert hab.kever.sn == sn and app.rgy.registryByName('disclosures') is None
    dialog = RegistryDialog(app)
    dialog.controller.setCurrentIndex(dialog.controller.combo_box.findData(hab.pre))
    dialog.name.setText('another')
    for field in dialog._auth_panel.passcode_fields.values():
        field.setText('123456')
    dialog.create.click()
    for _ in range(16):
        app.qtask.run()
    assert dialog._doer.done and dialog._doer.error
    assert dialog.name.isEnabled() and dialog.controller.isEnabled()
    assert app.vault.db.registry_creations.get(('another',)) is None
    assert hab.kever.sn == sn
    dialog.close()


@pytest.mark.parametrize('escrow_advances', [False, True])
def test_witness_resubmit_finishes_pending_events_in_order(ipex_vaults, monkeypatch, escrow_advances):
    from keri.core import SerderKERI
    from locksmith.core.rotating import AuthenticateWitnessesDoer

    app = ipex_vaults('receipt-gap')
    app.plugin_manager.update_witness_state_after_auth = lambda *args: None
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
    events = [SerderKERI(raw=hab.interact()) for _ in range(3)]
    accepted = [0]
    submitted = []

    def get(self, pre, sn=None):
        yield self.tock
        if sn <= accepted[0]:
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))

    def receipt(self, pre, sn=None, auths=None):
        yield self.tock
        submitted.append(sn)
        if (auths or {}).get(witness.pre, '').split('#')[0] == '123456' and sn == accepted[0] + 1:
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
            accepted[0] = 3 if escrow_advances else sn

    monkeypatch.setattr(registries.LocksmithReceiptor, 'get', get)
    monkeypatch.setattr(registries.LocksmithReceiptor, 'receipt', receipt)
    for code in ('654321', '123456'):
        worker = AuthenticateWitnessesDoer(app, hab, [f'{witness.pre}:{code}'])
        app.vault.extend([worker])
        for _ in range(128):
            app.qtask.run()
            if worker.done:
                break
        assert worker.done
        if code == '654321':
            assert accepted[0] == 0 and app.vault.db.idm.get((hab.pre,)).auth_pending
    assert all(hab.db.fullyWitnessed(event) for event in events)
    assert not app.vault.db.idm.get((hab.pre,)).auth_pending
    assert hab.kever.sn == 3 and hab.kever.serder.said == events[-1].said
    assert submitted == ([1, 1] if escrow_advances else [1, 1, 2, 3])


@pytest.mark.parametrize('operation', ['presentation', 'create'])
def test_receipt_child_failure_keeps_unrelated_vault_work_running(ipex_vaults, monkeypatch, operation):
    from hio.base import doing
    from keri import kering
    from keri.acdc import ipexing as native
    from keri.core import parsing

    app = ipex_vaults('receipt-child')
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(hab.kever.serder))
    recipient = app.hby.makeHab(name='recipient')

    class BrokenReceiptor(doing.Doer):
        def recur(self, tyme):
            raise OSError('synthetic receipt socket failure')

    def pending_receipt(self, *args):
        while True:
            yield self.tock

    monkeypatch.setattr(ipexing, 'LocksmithReceiptor', lambda **kwa: BrokenReceiptor())
    monkeypatch.setattr(registries, 'LocksmithReceiptor', lambda **kwa: BrokenReceiptor())
    monkeypatch.setattr(credentialing.CredentialUpdateDoer, 'receipt', pending_receipt)
    if operation == 'presentation':
        registry = Registrar(rgy=app.rgy).makeRegistry(name='disclosures', prefix=hab.pre)
        grant, atc = native.grant(hab, recipient.pre, '', kind=kering.Kinds.json)
        parsed, = parsing.Parser().parse(ims=bytearray(grant.raw + atc), processive=False,
                                          version=kering.Vrsn_2_0)
        worker = ipexing.PresentIpexDoer(app.vault, hab, parsed, {registry.regk: registry})
    else:
        worker = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
    ticks = []
    def tick(tymth, tock=0.0, **kwa):
        while True:
            ticks.append(tymth())
            yield tock
    app.vault.extend([worker, doing.doify(tick)])
    for _ in range(16):
        app.qtask.run()
    assert worker.done and worker.error == 'synthetic receipt socket failure'
    before = len(ticks)
    for _ in range(4):
        app.qtask.run()
    assert len(ticks) > before


def test_queued_registry_creation_rejects_changed_controller_state(ipex_vaults):
    app = ipex_vaults('queued-registry')
    hab = app.hby.makeHab(name='controller')
    worker = registries.CreateRegistryDoer(app.vault, hab, 'disclosures')
    hab.rotate()
    app.vault.extend([worker])
    for _ in range(16):
        app.qtask.run()
    assert worker.done and 'key state changed' in worker.error
    assert app.rgy.registryByName('disclosures') is None


def test_grant_authentication_refreshes_when_principal_adds_witnesses(ipex_vaults):
    from locksmith.ui.vault.credentials.issued.grant import GrantCredentialDialog

    app = ipex_vaults('grant-auth')
    issuer = app.hby.makeHab(name='issuer')
    schema = _load_schema(app, issuer)
    definition = deepcopy(schema.sed)
    credentialing.attribute_schemas(definition)[0].setdefault('properties', {})['rd'] = {'type': 'string'}
    schema = scheming.Schemer(sed=definition)
    app.hby.db.schema.pin((schema.said,), schema)
    app.vault.db.issuers.pin((schema.said,), issuer.pre)
    first_wit = app.hby.makeHab(name='first-witness', transferable=False)
    second_wit = app.hby.makeHab(name='second-witness', transferable=False)
    first = app.hby.makeHab(name='first-controller', wits=[first_wit.pre], toad=1)
    second = app.hby.makeHab(name='second-controller')
    recipient = app.hby.makeHab(name='recipient')
    registrar = Registrar(rgy=app.rgy)
    first_reg = registrar.makeRegistry(name='first', prefix=first.pre)
    second_reg = registrar.makeRegistry(name='second', prefix=second.pre)
    linked = _issue(app, schema, second, attributes={'rd': second_reg.regk})
    said = _issue(app, schema, first, attributes={'rd': first_reg.regk},
                  edges={'related': {'n': linked, 's': schema.said, 'o': 'NI2I'}})
    grant, atc = ipexing.grant(app.vault, issuer, said, recipient.pre)
    dialog = GrantCredentialDialog(app, None, said, schema.sed['title'], issuer.pre)
    dialog._send_grant(issuer, grant, atc)
    assert len(dialog._auth_panels) == 1
    for field in dialog._auth_panels[0].passcode_fields.values():
        field.setText('123456')
    first.rotate(adds=[second_wit.pre], toad=2)
    dialog._send_grant(issuer, grant, atc)
    assert {panel.hab.pre for panel in dialog._auth_panels} == {first.pre}
    assert set(dialog._auth_panels[0].passcode_fields) == {first_wit.pre, second_wit.pre}
    assert dialog._pending_said is None
    assert app.vault.db.outbox.get((grant.said,)) is None
    dialog.close()


@pytest.mark.parametrize('failure', ['anchor', 'publication', 'submission', 'queued'])
def test_request_registry_and_apply_survive_retry_and_reopen(ipex_vaults, monkeypatch, failure):
    from keri.core import SerderKERI

    source, target = ipex_vaults('request-holder'), ipex_vaults('request-issuer')
    holder = source.hby.makeHab(name='holder')
    issuer = target.hby.makeHab(name='issuer')
    schema = _load_schema(target, issuer)
    definition = deepcopy(schema.sed)
    credentialing.attribute_schemas(definition)[0].setdefault('properties', {}).update(
        i={'type': 'string'}, rd={'type': 'string'})
    schema = scheming.Schemer(sed=definition)
    for app in (source, target):
        app.hby.db.schema.pin((schema.said,), schema)
        app.vault.remove([app.vault.ipex_outbox])
    target.vault.db.issuers.pin((schema.said,), issuer.pre)
    _introduce(source, target)
    _introduce(target, source)

    def fail_publish(self, registries):
        raise TimeoutError('publication interrupted')
        yield

    submit = ipexing.submit

    def fail_submit(*args, **kwargs):
        if failure == 'queued':
            submit(*args, **kwargs)
        raise ValueError('submission interrupted')

    def fail_anchor(*args, **kwargs):
        raise ValueError('anchor interrupted')

    with monkeypatch.context() as patch:
        if failure == 'anchor':
            patch.setattr(holder, 'interact', fail_anchor)
        elif failure == 'publication':
            patch.setattr(registries.CreateRegistryDoer, 'publish', fail_publish)
        else:
            patch.setattr(ipexing, 'submit', fail_submit)
        worker = ipexing.RequestCredentialDoer(source.vault, holder, issuer.pre, schema.said)
        source.vault.extend([worker])
        with pytest.raises(ValueError, match='already being prepared'):
            ipexing.RequestCredentialDoer(source.vault, holder, issuer.pre, schema.said)
        for _ in range(128):
            source.qtask.run()
            if worker.done:
                break
        assert worker.done and 'interrupted' in worker.error
    operation = worker.request_id
    saved = source.vault.db.requests.get((operation,))
    original_stream = saved.stream
    pending = source.vault.db.registry_creations.get(('request-' + operation,))
    registry = pending.said if pending else source.rgy.registryByName('request-' + operation).regk
    sequence = holder.kever.sn
    source.close_vault()
    source = ipex_vaults('request-holder')
    source.vault.remove([source.vault.ipex_outbox])
    holder = source.hby.habByName('holder')
    worker = ipexing.RequestCredentialDoer(source.vault, holder, issuer.pre, schema.said)
    assert worker.request_id == operation
    source.vault.extend([worker])
    for _ in range(128):
        source.qtask.run()
        if worker.done:
            break
    assert worker.done and not worker.error, worker.error
    saved = source.vault.db.requests.get((operation,))
    assert saved.submitted
    assert len(source.rgy.regs) == 1 and holder.kever.sn == sequence + (failure == 'anchor')
    if original_stream:
        assert saved.stream == original_stream
    apply = SerderKERI(raw=saved.stream.encode())
    assert apply.said == worker.said and apply.sad['a']['preg'] == registry
    assert source.vault.db.outbox.get((apply.said,)) is not None
    # A delivery retry uses the retained Apply rather than creating a new registry.
    ipexing.retry(source.vault, apply.said)
    assert len(source.rgy.regs) == 1
    assert source.hby.db.exns.get((apply.said,)).raw == apply.raw

    _introduce(source, target)
    _deliver_ipex(target.vault, exchanging.serializeMessage(source.hby, apply.said))
    assert target.vault.exc.complete(apply.said)
    with pytest.raises(ValueError, match='evidence is missing'):
        ipexing.request_registry(target.vault, apply, issuer)
    registries.ingest(target.vault, registry, source.rgy.store.cloneTel(registry))
    assert ipexing.request_registry(target.vault, apply, issuer) == registry
    events = []
    target.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    rejected = credentialing.IssueCredentialDoer(target, schema.said, holder.pre,
                                                {'LEI': 'conflict', 'rd': issuer.pre}, request_said=apply.said)
    target.vault.extend([rejected])
    for _ in range(128):
        target.qtask.run()
        if rejected.done:
            break
    assert events[-1][0] == 'credential_issuance_failed'
    assert 'conflict' in events[-1][1]['error']
    assert not list(target.vault.db.issued.getTopItemIter())
    assert not target.rgy.regs
    issuance = credentialing.IssueCredentialDoer(target, schema.said, holder.pre,
                                                {'LEI': 'Requested credential'}, request_said=apply.said)
    target.vault.extend([issuance])
    for _ in range(128):
        target.qtask.run()
        if issuance.done:
            break
    issued = next(data['credential_said'] for event, data in events if event == 'credential_issued')
    credential = credentialing.credential(target.vault, issued)
    assert credential['sad']['a']['rd'] == registry
    assert credential['sad']['a']['i'] == holder.pre
    offered = ipexing.respond(target.vault, apply.said, 'Offer', credential_said=issued)
    offer = target.hby.db.exns.get((offered,))
    assert offer.sad['a']['preg'] == registry
    assert b'Requested credential' not in exchanging.serializeMessage(target.hby, offered)
    _deliver_ipex(source.vault, exchanging.serializeMessage(target.hby, offered))
    agreed = ipexing.respond(source.vault, offered, 'Agree')
    assert source.vault.exc.complete(agreed)
    _deliver_ipex(target.vault, exchanging.serializeMessage(source.hby, agreed))
    _introduce(target, source)
    issuer_registry = credential['sad']['rd']
    registries.ingest(source.vault, issuer_registry, target.rgy.store.cloneTel(issuer_registry))
    granted = ipexing.respond(target.vault, agreed, 'Grant', credential_said=issued)
    _deliver_ipex(source.vault, exchanging.serializeMessage(target.hby, granted))
    assert source.vault.exc.complete(granted)
    ipexing.admit(source.vault, holder, granted)
    assert source.vault.db.accepted.get((issued,)) is not None


def test_requested_registry_rejects_wrong_controller_and_substituted_credential(ipex_vaults):
    from keri import kering
    from keri.acdc import ipexing as native

    app = ipex_vaults('request-policy')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    definition = deepcopy(schema.sed)
    credentialing.attribute_schemas(definition)[0].setdefault('properties', {}).update(
        i={'type': 'string'}, rd={'type': 'string'})
    schema = scheming.Schemer(sed=definition)
    app.hby.db.schema.pin((schema.said,), schema)
    app.vault.db.issuers.pin((schema.said,), issuer.pre)
    app.vault.remove([app.vault.ipex_outbox])
    worker = ipexing.RequestCredentialDoer(app.vault, holder, issuer.pre, schema.said)
    app.vault.extend([worker])
    for _ in range(128):
        app.qtask.run()
        if worker.done:
            break
    assert worker.done and not worker.error, worker.error
    request = app.hby.db.exns.get((worker.said,))
    # The signed Apply alone must not let its author claim someone else's registry.
    foreign = Registrar(rgy=app.rgy).makeRegistry(name='foreign', prefix=issuer.pre)
    rip = app.rgy.store.event(foreign.regk)
    issuer.interact(data=[dict(i=foreign.regk, s=rip.sad['n'], d=rip.said)])
    assert foreign.anchorMsg(rip.said)
    forged, atc = native.apply(holder, issuer.pre, '', attrs={'preg': foreign.regk},
                               modifiers={'dp': [[[schema.said, '/', []]]]}, kind=kering.Kinds.json)
    ipexing.submit(app.vault, holder, forged, atc)
    with pytest.raises(ValueError, match='does not belong to the requester'):
        ipexing.request_registry(app.vault, forged, issuer)

    # Issuer UI selection and receiver acceptance both enforce the saved request.
    wrong = _issue(app, schema, holder, attributes={'LEI': 'Missing requested registry'})
    with pytest.raises(ValueError, match='does not use the requested'):
        ipexing.respond(app.vault, request.said, 'Offer', credential_said=wrong)
    view = credentialing.credential(app.vault, wrong)
    grant, atc = native.grant(issuer, holder.pre, '', view['proof'], artifacts=[],
                               apply=request, modifiers={'dp': [[]]}, kind=kering.Kinds.json)
    ipexing.prepare(app.vault, issuer, grant, atc)
    with pytest.raises(ValueError, match='does not use the requested'):
        ipexing.admit(app.vault, holder, grant.said)
    assert app.vault.db.accepted.get((wrong,)) is None
    assert app.vault.db.receipts.get((holder.pre, grant.said)) is None

    # A deliberate new request after submission gets a fresh registry.
    next_request = ipexing.RequestCredentialDoer(app.vault, holder, issuer.pre, schema.said)
    assert next_request.request_id != worker.request_id
    app.vault.extend([next_request])
    for _ in range(128):
        app.qtask.run()
        if next_request.done:
            break
    assert next_request.done and not next_request.error, next_request.error
    assert app.hby.db.exns.get((next_request.said,)).sad['a']['preg'] != request.sad['a']['preg']
