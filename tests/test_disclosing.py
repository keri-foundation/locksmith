"""Selected disclosures preserve commitments and the holder's original evidence."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from keri import Kinds, Vrsn_2_0
from keri.acdc import acdcagg, acdcmap, ipexing as native
from keri.app import openHby
from keri.core import Aggor, Diger, Noncer, Parser, SealSource, SerderACDC, messagize, scheming
from keri.peer import Exchanger

from locksmith.core import ipexing
from locksmith.ui.vault.credentials.presentation import disclosure_fields, disclosure_paths
from test_keri_v2_compat import ipex_vaults as ipex_vaults
from test_credentialing import _issue


@pytest.fixture
def identity():
    def block(properties):
        return {'oneOf': [{'type': 'string'}, {'type': 'object', 'properties': {
            'd': {'type': 'string'}, 'u': {'type': 'string'}, **properties}}]}

    schema = {'properties': {'a': block({
        'i': {'type': 'string'},
        'name': block({'givenName': {'type': 'string'}, 'familyName': {'type': 'string'}}),
        'birth': block({'birthDate': {'type': 'string'}}),
    })}}
    credential = acdcmap(
        israid=Diger(ser=b'issuer').qb64,
        uuid=Noncer().qb64,
        attribute=dict(d='', u=Noncer().qb64, i=Diger(ser=b'holder').qb64,
                       name=dict(d='', u=Noncer().qb64, givenName='Alice', familyName='Example'),
                       birth=dict(d='', u=Noncer().qb64, birthDate='2010-01-01')),
    )
    return credential, schema


def test_hierarchical_disclosure_keeps_atomic_siblings_and_hides_other_blocks(identity):
    credential, schema = identity
    original = deepcopy(credential.sad)
    choices = disclosure_fields(schema, credential.sad)
    name = next(choice for choice in choices if isinstance(choice['value'], dict)
                and choice['value'].get('givenName') == 'Alice')
    assert name['value'] == {'givenName': 'Alice', 'familyName': 'Example'}

    paths = disclosure_paths(schema, credential.sad, [name['path']])
    _, sad = ipexing._disclose(SimpleNamespace(serder=credential), paths)
    partial = SerderACDC(sad=sad)
    assert partial.said == credential.said
    assert partial.sad['a']['i'] == credential.sad['a']['i']
    assert partial.sad['a']['name']['givenName'] == 'Alice'
    assert partial.sad['a']['name']['familyName'] == 'Example'
    assert isinstance(partial.sad['a']['birth'], str)
    assert b'2010-01-01' not in partial.raw
    assert credential.sad == original

    remaining = disclosure_fields(schema, partial.sad)
    assert all(choice['value'] != '2010-01-01' for choice in remaining)
    hidden = next(choice for choice in choices if choice['value'] == '2010-01-01')
    with pytest.raises(ValueError, match='no longer available'):
        disclosure_paths(schema, partial.sad, [hidden['path']])


def test_aggregate_disclosure_uses_actual_positions_and_preserves_agid():
    path = Path(__file__).parents[1] / 'assets/schemas/sedi/age.json'
    schema = json.loads(path.read_text())
    aggregate = Aggor(ael=[
        '',
        dict(d='', u=Noncer().qb64, i=Diger(ser=b'holder').qb64),
        dict(d='', u=Noncer().qb64, over18=False),
        dict(d='', u=Noncer().qb64, over13=True),
    ], makify=True, kind=Kinds.json)
    credential = acdcagg(israid=Diger(ser=b'issuer').qb64, uuid=Noncer().qb64,
                         regid=Diger(ser=b'registry').qb64, schema=schema['$id'],
                         aggregate=aggregate.ael)
    original = deepcopy(credential.sad)
    requested = disclosure_fields(schema)
    assert any(choice['path'].rstrip('/') == 'A/over13' for choice in requested)
    choices = disclosure_fields(schema, credential.sad)
    over13 = next(choice for choice in choices if choice['value'] is True)
    assert over13['path'] == 'A/3/'

    _, sad = ipexing._disclose(SimpleNamespace(serder=credential), disclosure_paths(
        schema, credential.sad, [over13['path']]))
    partial = SerderACDC(sad=sad)
    assert partial.said == credential.said
    assert partial.sad['A'][0] == credential.sad['A'][0]
    assert Aggor.verifyDisclosure(partial.sad['A'], kind=credential.kind)
    assert partial.sad['A'][1]['i'] == credential.sad['A'][1]['i']
    assert isinstance(partial.sad['A'][2], str)
    assert partial.sad['A'][3]['over13'] is True
    assert b'over18' not in partial.raw
    assert credential.sad == original


def test_partial_proof_retains_source_seal(identity):
    credential, schema = identity
    choices = disclosure_fields(schema, credential.sad)
    name = next(choice for choice in choices if isinstance(choice['value'], dict))
    paths = disclosure_paths(schema, credential.sad, [name['path']])
    anchor = Diger(ser=b'issuer anchor').qb64
    original = messagize(serder=credential, bonds=[SealSource(s='1', d=anchor)], framed=False)
    original_bytes = bytes(original)
    nest, = Parser().parse(ims=bytearray(original), processive=False, version=Vrsn_2_0)
    stream, _ = ipexing._disclose(nest, paths)
    ims = bytearray(stream)
    parsed = Parser().parse(ims=ims, processive=False, version=Vrsn_2_0)
    assert len(parsed) == 1 and not ims
    assert parsed[0].serder.said == credential.said
    assert b'2010-01-01' not in parsed[0].serder.raw
    assert [(number.sn, diger.qb64) for number, diger in parsed[0].sscs] == [(1, anchor)]
    assert bytes(original) == original_bytes


@pytest.mark.parametrize('aggregate', [False, True])
def test_terms_only_disclosure_hides_all_attributes_without_an_issuee(aggregate):
    block = dict(d='', u=Noncer().qb64, privateValue='private-value-not-for-requester')
    attributes = ({'aggregate': Aggor(ael=['', block], makify=True, kind=Kinds.json).ael}
                  if aggregate else {'attribute': block})
    credential = acdcmap(israid=Diger(ser=b'issuer').qb64, uuid=Noncer().qb64,
                         rule={'d': '', 'l': 'Public terms'}, **attributes)
    _, sad = ipexing._disclose(SimpleNamespace(serder=credential), ['r/'])
    partial = SerderACDC(sad=sad)
    assert partial.said == credential.said
    assert b'private-value-not-for-requester' not in partial.raw
    assert partial.sad['r'] == credential.sad['r']
    if aggregate:
        assert all(isinstance(item, str) for item in partial.sad['A'])
        assert Aggor.verifyDisclosure(partial.sad['A'], kind=credential.kind)
    else:
        assert isinstance(partial.sad['a'], str) and partial.sad['a']


def test_native_rejection_keeps_changed_body_signature_out_of_outbox(ipex_vaults, identity):
    from keri.acdc.messaging import acmSchemaDefault
    from keri.kering import ValidationError
    from locksmith.core import credentialing

    app = ipex_vaults('signed-disclosure')
    issuer, holder = [app.hby.makeHab(name=name) for name in ('Issuer', 'Holder')]
    _, definition = acmSchemaDefault()
    definition['$id'] = ''
    definition['properties']['a'] = identity[1]['properties']['a']
    schema = scheming.Schemer(sed=definition)
    app.hby.db.schema.pin((schema.said,), schema)
    app.vault.db.issuers.pin((schema.said,), issuer.pre)
    said = _issue(app, schema, holder, authentication='signature', attributes={
        'name': {'givenName': 'Alice', 'familyName': 'Example'},
        'birth': {'birthDate': '2010-01-01'}})
    original = credentialing.credential(app.vault, said)['proof']
    plan = [[[schema.said, '/', ['a/i']]]]
    proof, artifacts, _, _ = ipexing.disclosure(app.vault, said, plan=plan, hab=issuer)
    exn, atc = native.grant(issuer, holder.pre, '', proof, artifacts=artifacts,
                            modifiers={'dp': plan}, kind=Kinds.json)
    before = list(app.vault.db.outbox.getTopItemIter())
    with pytest.raises(ValidationError):
        ipexing.submit(app.vault, issuer, exn, atc)
    assert list(app.vault.db.outbox.getTopItemIter()) == before
    assert not app.vault.exc.complete(exn.said)
    assert credentialing.credential(app.vault, said)['proof'] == original


def test_apply_semantic_aggregate_request_can_negotiate_actual_offer_positions():
    with openHby(name='disclosure-negotiation', base='test', temp=True, version=Vrsn_2_0) as hby:
        requester = hby.makeHab(name='requester')
        holder = hby.makeHab(name='holder')
        exc = Exchanger(hby=hby, handlers=[])
        native.loadHandlers(hby=hby, exc=exc, notifier=SimpleNamespace(add=lambda attrs: None))
        schema = Diger(ser=b'age schema').qb64
        apply, atc = native.apply(requester, holder.pre, 'Please share over13',
                                 modifiers={'dp': [[[schema, '/', ['A/over13']]]]}, kind=Kinds.json)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(apply.raw + atc), framed=False, exc=exc)
        assert hby.db.exns.get((apply.said,)) is not None

        offer, atc = native.offer(holder, 'I offer subject and over13', origin=None, apply=apply,
                                 modifiers={'dp': [[[schema, '/', ['A/1/', 'A/4/']]]]}, kind=Kinds.json)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(offer.raw + atc), framed=False, exc=exc)
        assert hby.db.exns.get((offer.said,)) is not None

        agree, atc = native.agree(requester, 'Accept', offer, kind=Kinds.json)
        Parser(version=Vrsn_2_0).parse(ims=bytearray(agree.raw + atc), framed=False, exc=exc)
        assert hby.db.exns.get((agree.said,)) is not None
        assert agree.sad['q']['dp'] == [[]]
