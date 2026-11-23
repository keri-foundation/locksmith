"""Show what a witness will receipt, including each independent effect."""
from keri.acdc import Registrar

from locksmith.core import ipexing
from locksmith.core.receipt_review import describe_receipt_event
from locksmith.db.basing import PresentationProof
from test_credentialing import _issue, _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults
from test_revocation import _revoke


def test_review_registry_events_and_missing_openings(ipex_vaults):
    app = ipex_vaults('review-registry')
    issuer = app.hby.makeHab(name='issuer')
    schema = _load_schema(app, issuer)
    said = _issue(app, schema, issuer)
    inception = issuer.getOwnEvent(1)[0]
    issuance = issuer.getOwnEvent(2)[0]
    regk = inception.seals[0]['i']

    assert describe_receipt_event(app.vault, inception) == f'Create registry {regk}'
    assert describe_receipt_event(app.vault, issuance) == f'Issue credential {said} in registry {regk}'
    _revoke(app)
    revocation = issuer.kever.serder
    assert describe_receipt_event(app.vault, revocation) == f'Revoke credential {said} in registry {regk}'

    # A local record naming the old update cannot open it with the revocation proof.
    record = app.vault.db.issued.get((said,))
    record.update = issuance.seals[0]['d']
    app.vault.db.issued.pin((said,), record)
    assert describe_receipt_event(app.vault, issuance) == (
        f'Blinded update {record.update} to registry {regk}. Its effect is unknown.')


def test_review_all_rotation_seals_and_witness_change(ipex_vaults):
    app = ipex_vaults('review-rotation')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    witness = app.hby.makeHab(name='witness', transferable=False)
    assert describe_receipt_event(app.vault, issuer.kever.serder).startswith('Create identifier')
    schema = _load_schema(app, issuer)
    credential = _issue(app, schema, holder, authentication='anchor')
    apply = ipexing.start(app.vault, issuer, holder.pre, 'Apply', schema=schema.said)
    unknown = {'i': holder.pre, 's': '0', 'd': holder.pre}
    issuer.rotate(adds=[witness.pre], toad=1, data=[{'d': credential}, {'d': apply}, unknown])

    review = describe_receipt_event(app.vault, issuer.kever.serder).splitlines()
    assert review[:5] == [
        'Rotate signing keys', f'Add witness {witness.pre}', 'Witness threshold 1',
        f'Anchor credential {credential} for {holder.pre}', f'Anchor IPEX Apply {apply} to {holder.pre}']
    assert len(review) == 6 and 'Unrecognized seal' in review[5] and holder.pre in review[5]


def test_review_presentation_opening(ipex_vaults):
    app = ipex_vaults('review-presentation')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    credential = _issue(app, schema, holder)
    grant, _ = ipexing.grant(app.vault, issuer, credential, holder.pre)
    registrar = Registrar(rgy=app.rgy)
    registry = registrar.makeRegistry(name='presentations', prefix=holder.pre)
    regk = registry.regk
    holder.interact(data=[dict(i=regk, s='0', d=regk)])
    assert registry.anchorMsg(regk)
    opening, update = registrar.present(registry, grant)
    holder.interact(data=[dict(i=regk, s=update.sad['n'], d=update.said)])
    app.vault.db.presentations.pin((grant.said, regk), PresentationProof(opening.qb64, update.said))
    assert describe_receipt_event(app.vault, holder.kever.serder) == (
        f'Record presentation of Grant {grant.said} in registry {regk}')
