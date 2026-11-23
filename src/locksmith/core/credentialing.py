# -*- encoding: utf-8 -*-
"""Schema selection, native credential issuance, and the wallet's inventory."""
from collections.abc import Mapping
from copy import deepcopy
from functools import cache
import json
from time import monotonic
from types import MappingProxyType
import uuid

from PySide6.QtCore import QDir, QFile, QIODevice, QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from hio.base import doing
from keri import help, kering
from keri.acdc import Registrar, acdcmap, messaging, regeventing
from keri.app.habbing import GroupHab
from keri.core import (Aggor, Compactor, Blinder, BlindState, BoundState, Diger, Noncer, Salter, Number, SerderACDC,
                       SerderKERI, SealSource, messagize, parsing, scheming)
from keri.help import helping
from keri.peer import exchanging

from locksmith import resources_rc  # noqa: F401 - register bundled schemas
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.core.receipt_review import ReceiptReview, describe_receipt_event
from locksmith.db.basing import IssuedCredential, PendingIssuance

logger = help.ogler.getLogger(__name__)


@cache
def builtin_schemas():
    """Parse the bundled schemas once; the result is shared and read-only."""
    schemas = {}
    directory = QDir(':/assets/schemas/sedi')
    for filename in directory.entryList(['*.json'], QDir.Filter.Files):
        source = QFile(directory.filePath(filename))
        if not source.open(QIODevice.OpenModeFlag.ReadOnly):
            raise OSError(source.errorString())
        try:
            schemer = scheming.Schemer(raw=bytes(source.readAll()))
        finally:
            source.close()
        schemas[schemer.said] = schemer
    return MappingProxyType(schemas)


def request_schemas(vault):
    """Include imported schemas and keep one entry for each schema SAID."""
    return builtin_schemas() | {said: schemer for (said,), schemer in vault.hby.db.schema.getTopItemIter()}


def schema_detail(definition, kind='object'):
    """Find the expanded form of a compact-or-expanded section schema."""
    return schema_detail_path(definition, kind)[0]


def schema_detail_path(definition, kind, path=''):
    """Return the expanded schema and its JSON Pointer within the definition."""
    if not isinstance(definition, Mapping):
        return None, ''
    if definition.get('type') == kind:
        return definition, path
    key = 'oneOf' if 'oneOf' in definition else 'anyOf'
    for index, choice in enumerate(definition.get(key, [])):
        detail, pointer = schema_detail_path(choice, kind, f'{path}/{key}/{index}')
        if detail is not None:
            return detail, pointer
    return None, ''


def attribute_schemas(schema, aggregate=False):
    """Return attribute block definitions in the schema's declared order."""
    properties = schema.get('properties', {})
    if 'a' in properties and not aggregate:
        detail = schema_detail(properties['a'])
        if detail is None:
            raise ValueError('The schema has no expanded attribute definition')
        return [detail]
    aggregate = schema_detail(properties.get('A'), 'array')
    if aggregate is None:
        raise ValueError('The schema has no expanded attributes or aggregate')
    items = aggregate.get('items', {})
    blocks = [detail for choice in items.get('anyOf', [items])
              if (detail := schema_detail(choice)) is not None]
    if not blocks:
        raise ValueError('The aggregate schema has no attribute block definitions')
    return blocks


def complete_block(definition, values, issuee=None):
    """Fill schema constants and native block identifiers without inventing data."""
    result = deepcopy(values)
    definition = schema_detail(definition) or {}
    properties = definition.get('properties', {})
    for name, prop in properties.items():
        if 'const' in prop:
            if name in result and result[name] != prop['const']:
                raise ValueError(f'{name} does not match the schema constant')
            result[name] = deepcopy(prop['const'])
        elif name == 'd':
            result.setdefault(name, '')
        elif name == 'u':
            if not result.get(name):
                result[name] = Noncer().qb64
        elif name == 'i' and issuee is not None:
            if name in result and result[name] != issuee:
                raise ValueError('The attribute issuee does not match the selected recipient')
            result[name] = issuee
        elif name in result and isinstance(result[name], Mapping):
            result[name] = complete_block(prop, result[name])
    if issuee is not None and 'i' in result and result['i'] != issuee:
        raise ValueError('The attribute issuee does not match the selected recipient')
    return result


def validate_schema(vault, acdc):
    schema = acdc.schema
    schemer = (scheming.Schemer(sed=schema) if isinstance(schema, Mapping)
               else vault.hby.db.schema.get(keys=(schema,)))
    if schemer is None:
        raise kering.ValidationError(f'Load credential schema {schema} before accepting it')
    # Validate fields without changing the credential's signed wire format.
    schemer.verify(raw=json.dumps(acdc.sad).encode())
    return schemer


class RegistryCheckPending(kering.MissingChainError):
    """An in-progress service check that can resume a wallet decision."""

    def __init__(self, registry, operation, message):
        super().__init__(message)
        self.registry = registry
        self.operation = operation


def require_registry_evidence(vault, acdc, hab):
    """Require a recent independent status check before a wallet decision."""
    from locksmith.core.registries import required

    worker = getattr(vault, 'registry_evidence', None)
    if worker is None:
        return
    for regk in required(acdc.sad):
        if not worker.ensure(regk, hab):
            if not worker.observer_url:
                raise kering.MissingChainError('Configure an observer in Settings to check credential status')
            raise RegistryCheckPending(regk, 'fetch', worker.errors.get(regk) or 'Waiting for a current observer status check')
        rip = vault.rgy.store.seqEvent(regk, 0)
        if rip is not None and rip.israid in vault.hby.prefixes and not worker.published(regk):
            if not worker.registrar_url:
                raise kering.MissingChainError('Configure a registrar in Settings to publish the issuer registry')
            raise RegistryCheckPending(regk, 'publish', worker.errors.get(regk) or
                                       'Waiting for the registrar to accept the issuer registry update')


def credential_state(vault, acdc, blinder=None, *, blinders=None):
    """Verify a disclosed credential against the locally known registry head."""
    regk = acdc.sad.get('rd')
    store = vault.rgy.store
    rip, head = store.seqEvent(regk, 0), store.headEvent(regk)
    if rip is None or head is None:
        raise kering.MissingChainError(f'Missing registry evidence for {regk}')
    updates = []
    for sn in range(1, Number(numh=head.sad['n']).num + 1):
        update = store.seqEvent(regk, sn)
        if update is None:
            raise kering.MissingChainError(f'Missing registry update {sn} for {regk}')
        updates.append(update)
    try:
        return regeventing.vetBinds(rip=rip, updates=updates, db=vault.hby.db,
                                   acdc=acdc, target=acdc.said,
                                   blinders=blinders if blinders is not None else [blinder])
    except kering.MissingAnchorError as ex:
        raise kering.MissingChainError(f'Missing issuer KEL evidence for {regk}') from ex


def authentication(vault, nest):
    """Use the pinned native issuer policy; do not infer it from the Grant signer."""
    acdc = nest.serder
    if acdc.sad.get('rd'):
        proofs = [Blinder(clan=clan, qb64=b''.join(part.qb64b for part in proof))
                  for clan, groups in ((BlindState, nest.bsqs), (BoundState, nest.bsss))
                  for proof in groups]
        state = credential_state(vault, acdc, blinders=proofs)
        return {'et': state.state, 'dt': state.stamp, 'auth': 'registry'}
    # Keripy has no public standalone issuer-authentication entry point yet.
    # Keep its anchor selection and current-key rules at this one adapter boundary.
    try:
        # Statedict.get is cache-only; load persisted state for native signature checks.
        vault.hby.db.kevers[acdc.israid]
    except KeyError:
        pass
    handler = vault.exc.routes['/ipex/grant']
    authenticated, _ = handler._authenticateIssuer(acdc, nest)
    if not authenticated:
        raise kering.ValidationError('Credential issuer authentication failed')
    anchored = bool(nest.sscs or any(pre.qb64 == acdc.israid for pre, _, _ in nest.ssts))
    attributes = acdc.sad.get('a')
    stamp = attributes.get('dt', '') if isinstance(attributes, Mapping) else ''
    return {'et': 'authenticated', 'dt': stamp, 'auth': 'anchor' if anchored else 'signature'}


def credential(vault, said, received=False, *, grant_said=None):
    """Read inventory evidence or the exact disclosure in a retained Grant."""
    artifacts = {}
    pending = False
    created_at, accepted_at, sender = '', '', ''
    exact_grant = grant_said is not None
    if grant_said is None and not received and (record := vault.db.issued.get(keys=(said,))):
        created_at = record.created_at
        acdc = SerderACDC(raw=record.raw.encode())
        recipient = acdc.iseaid
        if record.stream:
            proof = record.stream.encode()
        else:  # Persisted registry issuances from before native stream retention.
            blinder = Blinder(clan=BlindState, qb64=record.blinder)
            proof = messagize(serder=acdc, bonds=[blinder.data], framed=False)
        ims = bytearray(proof)
        parsed = parsing.Parser().parse(ims=ims, processive=False, version=kering.Vrsn_2_0)
        if len(parsed) != 1 or ims or not isinstance(parsed[0].serder, SerderACDC):
            raise kering.ValidationError('Invalid retained credential evidence')
        nest = parsed[0]
        if nest.serder.said != said or nest.serder.raw != acdc.raw:
            raise kering.ValidationError('Invalid retained credential evidence')
        if record.update:
            update = vault.rgy.store.event(record.update)
            pending = update is None or vault.rgy.store.seqEvent(
                acdc.sad['rd'], Number(numh=update.sad['n']).num) is None
        # Locally created anchors remain pending until their witness quorum arrives.
        for _, diger in nest.sscs:
            pending |= len(vault.hby.db.wigs.get(keys=(acdc.israid, diger.qb64))) < record.witness_threshold
    else:
        record = vault.db.accepted.get(keys=(said,))
        if grant_said is None:
            if record is None:
                raise kering.ValidationError(f'Credential {said} is not in this wallet')
            grant_said = record.grant
        grant = vault.hby.db.exns.get(keys=(grant_said,))
        if (grant is None or grant.route != '/ipex/grant' or grant.pvrsn.major != 2
                or grant.sad['a'].get('o') != [said]):
            raise kering.ValidationError('Grant does not disclose the requested origin credential')
        exchanging.verify(vault.hby, grant)
        sender, recipient = grant.pre, grant.sad['ri']
        if exact_grant:
            created_at = grant.stamp
        if record is not None and record.grant == grant_said:
            accepted_at = record.accepted_at
        else:
            receipt = vault.db.receipts.get((recipient, grant_said))
            admit = vault.hby.db.exns.get((receipt.admit,)) if receipt and receipt.status == 'accepted' else None
            if (admit is not None and admit.route == '/ipex/admit'
                    and admit.pre == recipient and admit.sad['p'] == grant_said):
                accepted_at = admit.stamp
        nests = exchanging.loadParsedNestedSubstreams(vault.hby, grant_said)
        nest = next((nest for nest in nests if nest.serder.said == said), None)
        if nest is None:
            raise kering.ValidationError('Grant origin evidence is missing')
        acdc = nest.serder
        proof = exchanging.serializeParsedSubstream(nest)
        artifacts = {other.serder.said: exchanging.serializeParsedSubstream(other)
                     for other in nests if other.serder.said != said}
    try:
        if pending:
            raise kering.MissingChainError('Credential registry update is still pending')
        status = authentication(vault, nest)
    except kering.MissingChainError:
        status = {'et': 'pending', 'dt': ''}
    except kering.ValidationError:
        status = {'et': 'unknown', 'dt': ''}
    schema = acdc.schema
    schemer = (scheming.Schemer(sed=schema) if isinstance(schema, Mapping)
               else vault.hby.db.schema.get(keys=(schema,)))
    return {'sad': acdc.sad, 'schema': schemer.sed if schemer else {}, 'recipient': recipient,
            'subject': acdc.iseaid, 'held': acdc.iseaid in vault.hby.prefixes,
            'created_at': created_at, 'accepted_at': accepted_at, 'sender': sender,
            'status': status, 'proof': proof, 'artifacts': artifacts}


def credential_saids(vault, received=None):
    """Read inventory keys in display order without loading credential proofs."""
    stores = ([vault.db.accepted] if received is True else
              [vault.db.issued] if received is False else [vault.db.issued, vault.db.accepted])
    saids = {}
    with vault.db.env.begin() as txn:
        for store in stores:
            with txn.cursor(store.sdb) as cursor:
                for key in cursor.iternext(values=False):
                    saids[key.decode()] = None
    return list(saids)


def credentials(vault, received=None):
    return [credential(vault, said, received=received is True) for said in credential_saids(vault, received)]


def delete_credential(vault, said, received=False):
    """Remove one wallet entry while retaining signed protocol history."""
    store = vault.db.accepted if received else vault.db.issued
    return store.rem(keys=(said,))


class LoadSchemaDoer(doing.DoDoer):
    """Load a schema and optionally select its local issuer."""

    Timeout = 15.0

    def __init__(self, app, oobi=None, file_content=None,
                 enable_issuance=False, issuer_aid=None, signal_bridge=None, request_said=None):
        self.vault = app.vault
        self.request_said = request_said
        self.oobi, self.file_content = oobi, file_content
        self.enable_issuance, self.issuer_aid = enable_issuance, issuer_aid
        self.signals = signal_bridge if signal_bridge is not None else self.vault.signals
        if bool(oobi) == bool(file_content):
            raise ValueError('Provide a schema URL or file content')
        super().__init__(doers=[doing.doify(self.load_schema_do)])

    def load_schema_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        manager = reply = None
        try:
            raw = self.file_content
            if self.oobi:
                url = QUrl(self.oobi)
                if url.scheme() not in ('http', 'https'):
                    raise ValueError('Schema URL must use HTTP or HTTPS')
                manager = QNetworkAccessManager()
                reply = manager.get(QNetworkRequest(url))
                deadline = monotonic() + self.Timeout
                while not reply.isFinished():
                    if monotonic() >= deadline:
                        raise TimeoutError('Schema download timed out')
                    yield self.tock
                if reply.error() != QNetworkReply.NetworkError.NoError:
                    raise ValueError(reply.errorString())
                raw = bytes(reply.readAll())
            schemer = scheming.Schemer(raw=raw)
            if self.request_said:
                from locksmith.core import ipexing
                request = self.vault.hby.db.exns.get((self.request_said,))
                if (request is None or request.route != '/ipex/apply'
                        or not {'Offer', 'Grant'}.intersection(ipexing.responses(self.vault, request))):
                    raise ValueError('This request is no longer available for issuance')
                if schemer.said != ipexing.request_schema(request):
                    raise ValueError('This schema does not match the credential request')
                if not self.enable_issuance or self.issuer_aid != request.sad['ri']:
                    raise ValueError('Use the identifier that received this request for issuance')
            if self.enable_issuance:
                hab = self.vault.hby.habByPre(self.issuer_aid)
                if hab is None or isinstance(hab, GroupHab):
                    raise ValueError('Select an individual local identifier for issuance')
            self.vault.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
            if self.enable_issuance:
                self.vault.db.issuers.pin(keys=(schemer.said,), val=hab.pre)
            self.signals.emit_doer_event('LoadSchemaDoer', 'schema_loaded', {
                'title': schemer.sed.get('title', 'Untitled'), 'said': schemer.said,
                'enable_issuance': self.enable_issuance, 'success': True, 'request': self.request_said})
        except Exception as ex:
            logger.exception('Schema loading failed')
            self.signals.emit_doer_event('LoadSchemaDoer', 'schema_load_failed',
                                        {'error': str(ex), 'success': False, 'request': self.request_said})
        finally:
            if reply is not None and not reply.isFinished():
                reply.abort()
            if manager is not None:
                manager.deleteLater()


class CredentialUpdateDoer(doing.DoDoer):
    """Anchor a native registry event and collect its witness receipts."""

    def anchor(self, registry, event, receiptor, auths, *, remember=None):
        hab = registry.hab
        try:
            sn, _ = regeventing.vetAnchor(event, db=self.vault.hby.db, issuer=hab.pre)
            anchor = SerderKERI(raw=hab.msgOwnEvent(sn=sn))
        except kering.MissingAnchorError:
            seal = dict(i=registry.regk, s=event.sad['n'], d=event.said)
            raw = hab.rotate(data=[seal]) if hab.kever.estOnly else hab.interact(data=[seal])
            anchor = SerderKERI(raw=raw)
            if remember:
                remember(anchor)
        yield from self.receipt(hab, anchor, receiptor, auths)
        if not registry.anchorMsg(event.said):
            raise kering.ValidationError('Registry anchor is still pending')

    def receipt(self, hab, anchor, receiptor, auths):
        threshold = hab.kvy.fetchEstEvent(hab.pre, anchor.sn).bner.num
        if len(hab.db.wigs.get((hab.pre, anchor.said))) >= threshold:
            return
        receipt = receiptor.receipt(hab.pre, sn=anchor.sn, auths=auths)
        deadline = self.tyme + 30.0
        try:
            for _ in receipt:
                if self.tyme >= deadline:
                    raise TimeoutError('Timed out waiting for witness receipts.')
                yield self.tock
        finally:
            receipt.close()
        received = len(self.vault.hby.db.wigs.get(keys=(hab.pre, anchor.said)))
        if received < threshold:
            raise kering.MissingChainError(f'Missing witness receipts ({received} of {threshold} required) '
                                           f'for event {anchor.sn}. Retry with a current witness code.')

    def _check_receipt_history(self, hab, tip):
        if (self.app.vault is not self.vault or getattr(self.vault, 'closed', False)
                or not self.vault.db.opened or self.vault.hby.habByPre(hab.pre) is not hab
                or hab.kever.serder.said != tip):
            raise kering.ValidationError('The vault or identifier changed. Review authentication again.')

    def missing_receipts(self, hab, tip):
        """Read the whole pending set before a witness receives any request."""
        missing = []
        threshold = 0
        for sn in range(hab.kever.sn + 1):
            if sn and sn % 32 == 0:
                yield self.tock
            self._check_receipt_history(hab, tip)
            event = hab.getOwnEvent(sn)[0]
            if event.estive:
                threshold = event.bner.num
            if len(hab.db.wigs.get((hab.pre, event.said))) < threshold:
                missing.append((event, threshold))
        return missing

    def recover_receipts(self, hab, receiptor, auths, *, tip, missing, progress=None):
        """Finish the reviewed events in order with their original witness thresholds."""
        for event, threshold in missing:
            self._check_receipt_history(hab, tip)
            sn = event.sn
            if progress:
                progress(sn)
            fetch = receiptor.get(hab.pre, sn=sn)
            deadline = self.tyme + 15.0
            try:
                for _ in fetch:
                    if self.tyme >= deadline:
                        raise TimeoutError(f'Receipt lookup timed out for event {sn}')
                    yield self.tock
                    self._check_receipt_history(hab, tip)
            finally:
                fetch.close()
            if len(hab.db.wigs.get((hab.pre, event.said))) >= threshold:
                continue
            witnesses = [wit.qb64 for wit in hab.kvy.fetchWitnessState(hab.pre, sn)]
            if witnesses != hab.kever.wits or threshold != hab.kever.toader.num:
                raise kering.ValidationError(f'Event {sn} needs its original witness configuration')
            yield from self.receipt(hab, event, receiptor, auths)
            self._check_receipt_history(hab, tip)

    def publish(self, registries):
        """Wait for accepted publication and a fresh independent status check."""
        worker = self.vault.registry_evidence
        if worker is None:
            return
        deadline = self.tyme + 60.0
        while True:
            if getattr(self.vault, 'closed', False):
                raise ValueError('The vault is closed')
            checked = [worker.ensure(registry.regk, registry.hab) and worker.published(registry.regk)
                       for registry in registries]
            if all(checked):
                return
            if self.tyme >= deadline:
                errors = [worker.errors[registry.regk] for registry in registries
                          if registry.regk in worker.errors]
                detail = ': ' + '; '.join(dict.fromkeys(errors)) if errors else ''
                raise TimeoutError('Registry publication or status check is still pending' + detail)
            yield self.tock


class IssueCredentialDoer(CredentialUpdateDoer):
    """Issue a native credential with the selected issuer authentication factor."""

    def __init__(self, app, schema_said, recipient_pre, attributes, edges=None, rules=None,
                 codes=None, signal_bridge=None, authentication='registry', nonce=None, request_said=None, resume=None,
                 review_only=False, approval: ReceiptReview | None = None):
        self.resume = resume
        self.review_only = review_only
        self.approval = approval
        self.app = app
        self.vault = app.vault
        self.schema_said, self.recipient_pre = schema_said, recipient_pre
        self.issuance_id = uuid.uuid4().hex
        self.attributes, self.edges, self.rules = attributes, edges or {}, rules
        stamp = helping.nowIso8601()
        self.auths = {}
        for entry in codes or ():
            witness, code = entry.split(':', 1)
            self.auths[witness] = f'{code}#{stamp}'
        self.active_issuer = None
        if authentication not in ('registry', 'anchor', 'signature'):
            raise ValueError('Select registry, anchor, or signature authentication')
        self.authentication, self.nonce = authentication, nonce
        self.request_said = request_said
        self.signals = signal_bridge if signal_bridge is not None else self.vault.signals
        super().__init__(doers=[doing.doify(self.issue_credential_do)])

    def _credential(self, hab, schemer, requested_registry, rip):
        properties = schemer.sed.get('properties', {})
        definitions = attribute_schemas(schemer.sed, aggregate=isinstance(self.attributes, list))
        if isinstance(self.attributes, list) or 'a' not in properties:
            if not isinstance(self.attributes, list):
                raise ValueError('Provide the aggregate attribute blocks as a list')
            blocks = []
            for values in self.attributes:
                matches = [definition for definition in definitions
                           if set(values) - {'d', 'u'} <= definition.get('properties', {}).keys()]
                if len(matches) != 1:
                    raise ValueError('Each aggregate block must match one schema definition')
                blocks.append(complete_block(matches[0], values, self.recipient_pre))
            attributes = {'aggregate': Aggor(ael=['', *blocks], makify=True,
                                             kind=kering.Kinds.json).ael}
        else:
            values = {'d': '', **self.attributes}
            if requested_registry:
                if values.get('rd') not in (None, '', requested_registry):
                    raise ValueError('The attributes conflict with the requested presentation registry')
                values['rd'] = requested_registry
            if 'dt' in definitions[0].get('properties', {}):
                values.setdefault('dt', definitions[0]['properties']['dt'].get('const', helping.nowIso8601()))
            if (self.recipient_pre is not None and
                    ('i' in definitions[0].get('properties', {}) or
                     definitions[0].get('additionalProperties', True))):
                values.setdefault('i', self.recipient_pre)
            attributes = {'attribute': complete_block(definitions[0], values, self.recipient_pre)}
        nonce = self.nonce
        if nonce is None and 'u' in properties:
            nonce = properties['u'].get('const', Noncer().qb64)
        if self.authentication != 'registry' and 'rd' in schemer.sed.get('required', []):
            raise kering.ValidationError('This schema requires registry authentication')
        if self.authentication == 'registry' and 'rd' not in properties and not schemer.sed.get('additionalProperties', True):
            raise kering.ValidationError('This schema does not permit a registry')
        if self.authentication == 'anchor' and not hab.kever.prefixer.transferable:
            raise kering.ValidationError('KEL anchors require a transferable issuer identifier')
        edges = complete_block(properties.get('e', {}), {'d': '', **self.edges}) if self.edges else None
        if edges is not None:
            # Sign the canonical expanded edge form used by native IPEX.
            compactor = Compactor(mad=edges, makify=True, kind=kering.Kinds.json)
            compactor.compact(paths=['e/'], root='e')
            edges = compactor.partials[('e/',)].mad
        rules = complete_block(properties.get('r', {}), self.rules) if self.rules is not None else None
        return acdcmap(israid=hab.pre, uuid=nonce, regid=rip.said if rip else None, schema=self.schema_said,
                       **attributes, edge=edges, rule=rules)

    def receipt(self, hab, anchor, receiptor, auths):
        tip = hab.kever.serder.said
        yield from super().receipt(hab, anchor, receiptor, auths)
        self._check_receipt_history(hab, tip)

    def _issue_registry(self, hab, acdc, rip, pending, key, receiptor, created_at, remember):
        registrar = Registrar(rgy=self.vault.rgy)
        registry = self.vault.rgy.regs.get(rip.said)
        if registry is None:
            registry = registrar.makeRegistry(name=rip.said, prefix=hab.pre, uuid=rip.sad['u'], stamp=rip.stamp)
        yield from self.anchor(registry, rip, receiptor, self.auths, remember=remember)
        # Recover the opening even if the process stopped after native TEL staging.
        blinder = Blinder.blind(sn=1, acdc=acdc.said, state='issued', salt=pending.salt)
        update = messaging.blindate(regid=rip.said, prior=rip.said, blid=blinder.said, stamp=rip.stamp)
        previous = self.vault.db.issued.get((acdc.said,))
        if previous and previous.update != update.said:
            self.vault.db.pending_issuances.rem(key)
            raise kering.ValidationError('This credential already has a later status update. Check Issued Credentials.')
        if self.vault.rgy.store.event(update.said) is None:
            blinder, staged = registrar.issue(registry, acdc=acdc, state='issued', salt=pending.salt, stamp=rip.stamp)
            if staged.said != update.said:
                raise kering.ValidationError('The issuance registry already contains a different update')
        else:
            registry.processEvent(update)
        stream = messagize(serder=acdc, bonds=[blinder.data], framed=False)
        record = IssuedCredential(acdc.raw.decode(), blinder.qb64, update.said, stream.decode(), created_at=created_at)
        self.vault.db.issued.pin((acdc.said,), record)
        yield from self.anchor(registry, update, receiptor, self.auths, remember=remember)

    def recur(self, tyme, deeds=None):
        try:
            return super().recur(tyme, deeds)
        except Exception as ex:
            logger.exception('Credential issuance failed')
            self._failed(ex)
            return True

    def _failed(self, error):
        self.signals.emit_doer_event('IssueCredentialDoer', 'credential_issuance_failed',
                                    {'issuance_id': self.issuance_id, 'error': str(error),
                                     'schema_said': self.schema_said, 'success': False})

    def issue_credential_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        receiptor = None
        try:
            issuer = self.vault.db.issuers.get(keys=(self.schema_said,))
            hab = self.vault.hby.habByPre(issuer)
            if hab is None or isinstance(hab, GroupHab):
                raise ValueError('Select an individual local identifier for this schema')
            if any(isinstance(other, IssueCredentialDoer) and other.active_issuer == issuer
                   for other in self.vault.doers if other is not self and not other.done):
                raise ValueError('An issuance is already in progress for this identifier.')
            self.active_issuer = issuer
            schemer = self.vault.hby.db.schema.get(keys=(self.schema_said,))
            if schemer is None:
                raise kering.ValidationError(f'Load credential schema {self.schema_said} before issuing it')
            request = None
            requested_registry = None
            operation = self.resume
            if operation is None:
                inputs = [issuer, self.schema_said, self.recipient_pre, self.authentication,
                          self.attributes, self.edges, self.rules, self.nonce]
                operation = Diger(ser=json.dumps(inputs, sort_keys=True).encode()).qb64
            key = (self.request_said or 'direct', operation)
            pending = self.vault.db.pending_issuances.get(key)
            resuming = pending is not None
            if resuming:
                rip = SerderACDC(raw=pending.inception.encode()) if pending.inception else None
                acdc = SerderACDC(raw=pending.raw.encode())
                # Finish the saved credential even if its original Apply has closed.
                if (acdc.israid != issuer or acdc.schema != self.schema_said or pending.recipient != self.recipient_pre
                        or self.authentication != ('registry' if rip else 'anchor')):
                    raise ValueError('The saved issuance does not match this issuer, subject, schema or authentication.')
            elif self.resume:
                raise ValueError('This issuance is no longer pending. Check Issued Credentials.')
            elif self.request_said:
                from locksmith.core import ipexing
                request = self.vault.hby.db.exns.get((self.request_said,))
                if ('Offer' not in ipexing.responses(self.vault, request) or request.sad['ri'] != issuer
                        or request.pre != self.recipient_pre or ipexing.request_schema(request) != self.schema_said):
                    raise ValueError('This request has changed. Review it before issuing.')
                if next(self.vault.db.pending_issuances.getTopItemIter((self.request_said,)), None):
                    raise ValueError('Reopen this request to resume its saved credential.')
            tip = hab.kever.serder.said
            if self.authentication != 'signature':
                missing = yield from self.missing_receipts(hab, tip)
                own = pending.anchors if resuming else ()
                review = [event for event, _ in missing if event.said not in own]
                needs_approval = bool(review) if self.approval is None else not self.approval.covers(hab, review)
                if self.review_only or needs_approval:
                    rows = tuple((e.said, e.sn, describe_receipt_event(self.vault, e)) for e in review)
                    self.signals.emit_doer_event('IssueCredentialDoer', 'receipt_review', {
                        'issuance_id': self.issuance_id, 'review': ReceiptReview(issuer, tip, rows)})
                    return
                receiptor = LocksmithReceiptor(hby=self.vault.hby)
                self.extend([receiptor])

                def progress(sn):
                    self.signals.emit_doer_event('IssueCredentialDoer', 'progress', {
                        'issuance_id': self.issuance_id, 'message': f'Recovering witness receipts for event {sn}…'})

                yield from self.recover_receipts(hab, receiptor, self.auths, tip=tip, missing=missing, progress=progress)
            elif self.review_only:
                return
            if request:
                deadline = self.tyme + 60.0
                waiting = False
                while True:
                    if getattr(self.vault, 'closed', False):
                        raise ValueError('The vault is closed')
                    if 'Offer' not in ipexing.responses(self.vault, request):
                        raise ValueError('This request has changed. Review it before issuing.')
                    try:
                        requested_registry = ipexing.request_registry(self.vault, request, hab)
                        break
                    except kering.MissingChainError:
                        if not waiting:
                            self.signals.emit_doer_event('IssueCredentialDoer', 'progress', {
                                'issuance_id': self.issuance_id, 'message': 'Checking presentation registry…'})
                            waiting = True
                        if self.tyme >= deadline:
                            detail = self.vault.registry_evidence.errors.get(request.sad['a'].get('preg'))
                            raise TimeoutError('Presentation registry verification is still pending'
                                               + (': ' + detail if detail else ''))
                        yield self.tock
                if waiting:
                    self.signals.emit_doer_event('IssueCredentialDoer', 'progress', {
                        'issuance_id': self.issuance_id, 'message': 'Issuing…'})
                if requested_registry and self.authentication != 'registry':
                    raise ValueError('The requested presentation registry requires registry issuance')
                if requested_registry and (isinstance(self.attributes, list)
                                           or not ipexing.requests_presentation_registry(schemer.sed)):
                    raise ValueError('This schema does not declare an issuee presentation registry')
                if hab.kever.serder.said != tip or self.vault.db.issuers.get((self.schema_said,)) != issuer:
                    raise ValueError('The issuer changed. Review this request before issuing.')
            if not resuming:
                rip = messaging.regcept(israid=hab.pre) if self.authentication == 'registry' else None
                acdc = self._credential(hab, schemer, requested_registry, rip)
            if requested_registry:
                ipexing.check_requested_registry(request, acdc)
            validate_schema(self.vault, acdc)
            if not resuming and self.authentication != 'signature':
                pending = PendingIssuance(acdc.raw.decode(), self.recipient_pre, rip.raw.decode() if rip else '',
                                          Salter().qb64 if rip else '')
                self.vault.db.pending_issuances.put(key, pending)
            previous = self.vault.db.issued.get((acdc.said,))
            created_at = previous.created_at if previous else helping.nowIso8601()

            def remember(anchor):
                # Bind automatic retries to the exact KEL events this operation signed.
                pending.anchors.append(anchor.said)
                self.vault.db.pending_issuances.pin(key, pending)

            if rip is not None:
                yield from self._issue_registry(hab, acdc, rip, pending, key, receiptor, created_at, remember)
            elif self.authentication == 'anchor':
                seal = dict(d=acdc.said)
                anchor = None
                if resuming:
                    for sn in range(hab.kever.sn, -1, -1):
                        event = hab.getOwnEvent(sn)[0]
                        if seal in (event.seals or []):
                            anchor = event
                            break
                if anchor is None:
                    raw = hab.rotate(data=[seal]) if hab.kever.estOnly else hab.interact(data=[seal])
                    anchor = SerderKERI(raw=raw)
                    remember(anchor)
                stream = messagize(serder=acdc, bonds=[SealSource(s=anchor.snh, d=anchor.said)])
                threshold = hab.kvy.fetchEstEvent(hab.pre, anchor.sn).bner.num
                self.vault.db.issued.pin(keys=(acdc.said,),
                                         val=IssuedCredential(acdc.raw.decode(), stream=stream.decode(),
                                                              witness_threshold=threshold,
                                                              created_at=created_at))
                yield from self.receipt(hab, anchor, receiptor, self.auths)
            else:
                stream = hab.endorse(acdc)
                self.vault.db.issued.pin(keys=(acdc.said,),
                                         val=IssuedCredential(acdc.raw.decode(), stream=stream.decode(),
                                                              created_at=created_at))
            if pending is not None:
                self.vault.db.pending_issuances.rem(key)
            self.signals.emit_doer_event('IssueCredentialDoer', 'credential_issued', {
                'issuance_id': self.issuance_id,
                'schema_title': schemer.sed.get('title', 'Untitled'),
                'schema_said': self.schema_said, 'credential_said': acdc.said,
                'recipient_pre': self.recipient_pre, 'success': True})
        except Exception as ex:
            logger.exception('Credential issuance failed')
            self._failed(ex)
        finally:
            self.auths.clear()
            self.active_issuer = None
            if receiptor is not None:
                self.remove([receiptor])


class RevokeCredentialDoer(CredentialUpdateDoer):
    """Retain and anchor one revocation, including retries after a vault close."""

    def __init__(self, app, credential_said, codes=None):
        self.vault = app.vault
        self.credential_said = credential_said
        self.revocation_id = uuid.uuid4().hex
        self.codes = codes or []
        super().__init__(doers=[doing.doify(self.revoke_do)])

    def revoke_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        receiptor = None
        try:
            record = self.vault.db.issued.get((self.credential_said,))
            if record is None:
                raise ValueError('This credential was not issued by this wallet')
            acdc = SerderACDC(raw=record.raw.encode())
            hab = self.vault.hby.habByPre(acdc.israid)
            if hab is None or isinstance(hab, GroupHab):
                raise ValueError('Revocation requires the individual local issuer')
            registry = self.vault.rgy.regs.get(acdc.regid)
            if registry is None or not record.blinder:
                raise ValueError('This credential has no local revocable registry')
            blinder = Blinder(clan=BlindState, qb64=record.blinder)
            if blinder.state == 'revoked':
                update = self.vault.rgy.store.event(record.update)
                if update is None:
                    raise kering.MissingChainError('The retained revocation update is missing')
            else:
                if credential(self.vault, acdc.said)['status']['et'] != 'issued':
                    raise kering.ValidationError('Wait for verified issuance before revoking')
                blinder, update = Registrar(rgy=self.vault.rgy).issue(registry, acdc, state='revoked')
                record.blinder = blinder.qb64
                record.update = update.said
                record.stream = messagize(serder=acdc, bonds=[blinder.data], framed=False).decode()
                # Keep the new private proof before any asynchronous receipt work.
                self.vault.db.issued.pin(keys=(acdc.said,), val=record)
            auths = {}
            for entry in self.codes:
                wit, code = entry.split(':', 1)
                auths[wit] = f'{code}#{helping.nowIso8601()}'
            receiptor = LocksmithReceiptor(hby=self.vault.hby)
            self.extend([receiptor])
            yield from self.anchor(registry, update, receiptor, auths)
            if credential_state(self.vault, acdc, blinder).state != 'revoked':
                raise kering.ValidationError('The registry does not verify this revocation')
            self.vault.signals.emit_doer_event('RevokeCredentialDoer', 'credential_revoked', {
                'revocation_id': self.revocation_id, 'credential_said': acdc.said, 'success': True})
        except Exception as ex:
            logger.exception('Credential revocation failed')
            self.vault.signals.emit_doer_event('RevokeCredentialDoer', 'credential_revocation_failed', {
                'revocation_id': self.revocation_id, 'credential_said': self.credential_said,
                'error': str(ex), 'success': False})
        finally:
            if receiptor is not None:
                self.remove([receiptor])
