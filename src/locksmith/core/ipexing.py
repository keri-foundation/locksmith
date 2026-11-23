# -*- encoding: utf-8 -*-
"""Native exchanges with V2 JSON bodies and V2 CESR attachments."""
from collections import deque
from collections.abc import Mapping
from contextlib import closing
from itertools import islice
from time import monotonic
import random
import uuid

from hio.base import doing
from hio.core.http import httping
from keri import help, kering
from keri.acdc import Registrar, evaluating, ipexing, regeventing
from keri.app import agenting, forwarding
from keri.app.habbing import GroupHab
from keri.core import Aggor, Compactor, Saider, SealEvent, SerderACDC, SerderKERI, parsing
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import credentialing
from locksmith.core.messaging import delivery_route, receiving_ready
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.db.basing import AcceptedCredential, CredentialRequest, GrantReceipt, IpexSubmission, PresentationProof

logger = help.ogler.getLogger(__name__)


class IpexHandler(ipexing.IpexHandler):
    """Apply the wallet's endpoint and incoming-notification policy."""

    def __init__(self, *args, signals=None, **kwa):
        super().__init__(*args, **kwa)
        self.signals = signals

    def verify(self, serder, attachments=None, nests=None, sscs=None, evidence=None):
        if serder.pvrsn.major != 2 or not ({serder.pre, serder.ked.get('ri')} & self.hby.prefixes):
            return False
        for nest in nests or []:
            credential = nest.get('serder') if isinstance(nest, dict) else nest.serder
            issuer = getattr(credential, 'israid', None)
            if issuer:
                try:
                    # Native current-key checks use get(), which does not load disk state.
                    self.hby.db.kevers[issuer]
                except KeyError:
                    pass
            schema = credential.sad.get('s')
            if (serder.route in ('/ipex/offer', '/ipex/grant')
                    and serder.sad.get('ri') in self.hby.prefixes and isinstance(schema, str)
                    and self.hby.db.schema.get((schema,)) is None
                    and (schemer := credentialing.builtin_schemas().get(schema)) is not None):
                self.hby.db.schema.put((schema,), schemer)
        try:
            return super().verify(serder, attachments=attachments, nests=nests,
                                  sscs=sscs, evidence=evidence)
        except kering.MissingSchemaError as ex:
            if serder.route in ('/ipex/offer', '/ipex/grant') and serder.sad.get('ri') in self.hby.prefixes:
                said = ex.args[0]
                if (schemer := credentialing.builtin_schemas().get(said)) is not None:
                    self.hby.db.schema.put((said,), schemer)
            # Keripy retains the exchange and retries all checks through its normal escrow.
            raise

    def handle(self, serder, attachments=None, nests=None, sscs=None):
        if serder.pre not in self.hby.prefixes:
            super().handle(serder, attachments=attachments, nests=nests, sscs=sscs)
        if self.signals is not None:
            self.signals.emit_doer_event('Ipex', 'saved', {'said': serder.said})


class MissingRouteError(kering.ConfigurationError):
    """The recipient needs an introduction with a usable delivery endpoint."""


def _edge_nodes(sad):
    """Yield far node SAIDs and paths, including nested edge groups."""
    edges = sad.get('e')
    blocks = [(edges, 'e/')] if isinstance(edges, Mapping) else (
        [(edge, f'e/{index}/') for index, edge in enumerate(edges)] if isinstance(edges, list) else [])
    for edge, path in blocks:
        groups = deque([(edge, path, False)])
        while groups:
            group, path, nested = groups.popleft()
            if not isinstance(group, Mapping):
                raise kering.ValidationError('Invalid retained credential edges')
            if 'n' in group:
                yield group['n'], path + '_/'
                continue
            labels = evaluating.EdgeGroupLabels if nested else evaluating.EdgeSectionLabels
            groups.extend((node, path + label + '/', True)
                          for label, node in group.items() if label not in labels)


def _require_route(vault, hab, recipient, reply=True):
    """Return the delivery route and check that the sender can receive a required reply."""
    route = delivery_route(hab, recipient)
    if route is None:
        raise MissingRouteError('No explicit delivery route is available. Import an introduction with an HTTP or HTTPS mailbox, agent, or controller address.')
    if reply and not receiving_ready(vault, hab):
        raise kering.ConfigurationError('This identifier cannot receive replies. Open Connection details to check its HTTP or HTTPS address.')
    return route


def _require_vault(vault, hab=None):
    if getattr(vault, 'closed', False) or not vault.db.opened or not vault.hby.db.opened:
        raise ValueError('The vault is closed')
    if hab is not None and hab is not vault.hby.habByPre(hab.pre):
        raise ValueError('The identifier does not belong to this vault')


def _validate_outgoing_grant(vault, hab, grant):
    """Recheck retained proofs before a new or retried disclosure leaves the wallet."""
    for (_, regk), proof in vault.db.presentations.getTopItemIter(keys=(grant.said,)):
        # This wallet attached the opening for its binding update only.
        head = vault.rgy.store.head(regk)
        if head is None or head.qb64 != proof.update:
            raise kering.ValidationError('The presentation registry binding changed. Start a new presentation.')
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant.said):
        credentialing.require_registry_evidence(vault, nest.serder, hab)
        state = credentialing.authentication(vault, nest)
        if state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError(f"Credential state is {state['et']}, not issued")


def prepare(vault, hab, serder, attachment):
    """Retain a new local message, or reuse its previously verified copy.

    This is submission preparation, not intake of additional attachments.
    """
    _require_vault(vault, hab)
    if hab is not vault.hby.habByPre(serder.pre) or serder.pvrsn.major != 2:
        raise ValueError('IPEX must be signed by this vault')
    if not serder.route.startswith('/ipex/'):
        raise ValueError('Expected an IPEX message')
    if not vault.exc.complete(serder.said):
        if error := exchange_error(vault, serder, sending=True):
            raise kering.ValidationError(error)
        vault.mbx.parser.parse(ims=bytearray(serder.raw + attachment), local=True,
                               version=kering.Vrsn_2_0)
    if not vault.exc.complete(serder.said):
        raise kering.ValidationError('Outgoing IPEX has not passed protocol verification')
    if serder.route == '/ipex/grant' and serder.sad['a'].get('o'):
        _validate_outgoing_grant(vault, hab, serder)
    return exchanging.serializeMessage(vault.hby, serder.said)


def _presentation_requirements(sender, recipient, origin, nodes):
    """Resolve declarations for the sender and origin principal of a wallet Grant."""
    nodes = list(nodes)
    root = next((node for node in nodes if node.said == origin), None)
    if root is None:
        raise ValueError('Grant origin evidence is missing')
    grantors = {sender, root.iseaid or root.israid}
    issuance = (sender, recipient) == (root.israid, root.iseaid)
    for acdc in nodes:
        declarations = ipexing.IpexHandler._presentationRegistries(acdc)
        if declarations is None:
            raise ValueError('The presentation registry declaration is hidden or malformed')
        for controller, regk in declarations:
            if controller in grantors and not (issuance and controller == recipient):
                yield controller, regk


def presentation_registries(vault, sender, recipient, origin, nodes):
    """Resolve required holder registries without changing native declarations."""
    registries = {}
    for controller, regk in _presentation_requirements(sender, recipient, origin, nodes):
        registry = vault.rgy.regs.get(regk)
        if registry is None or registry.hab.pre != controller:
            raise ValueError('This disclosure requires a presentation registry controlled by another vault')
        if isinstance(registry.hab, GroupHab):
            raise ValueError('Presentation preparation requires an individual local controller')
        registries[regk] = registry
    return registries


def _check_presentation_reuse(vault, said, registries):
    """Keep a Grant verifiable until its recipient replies or its exchange expires."""
    if next(vault.db.presentations.getTopItemIter(keys=(said,)), None):
        raise ValueError('This presentation was already prepared; inspect its registry state before trying again')
    heads = {head.qb64 for regk in registries if (head := vault.rgy.store.head(regk))}
    handler = vault.exc.routes['/ipex/grant']
    for (previous, _), proof in vault.db.presentations.getTopItemIter():
        if proof.update not in heads:
            continue
        # A failed preparation can leave a TEL proof without a sendable Grant.
        grant = vault.hby.db.exns.get((previous,))
        if grant is None:
            continue
        if expiry_error(vault, grant):
            # A Grant signed near exchange expiry can still arrive within KRAM's delivery lag.
            policy = vault.hby.db.kramCTYP.get('~')
            age = (helping.nowUTC() - helping.fromIso8601(grant.stamp)).total_seconds() * 1000
            if age > policy.ll + policy.d:
                continue
        reply = handler.response(grant)
        if reply is None or reply.route not in ('/ipex/admit', '/ipex/spurn'):
            raise ValueError(f'Presentation registry is waiting for a reply to Grant {previous}. '
                             'Check its delivery in Credentials → Activity.')


def submit(vault, hab, serder, attachment, *, codes=None):
    """Retain a signed message and authorize its delivery by the vault worker."""
    _require_vault(vault, hab)
    if serder.pre != hab.pre or serder.pvrsn.major != 2:
        raise ValueError('IPEX must be signed by this vault')
    if error := _legacy_opener_error(vault, serder, sending=True):
        raise kering.ValidationError(error)
    if serder.route == '/ipex/grant' and serder.sad['a'].get('o') and not vault.exc.complete(serder.said):
        if error := expiry_error(vault, serder):
            raise kering.ValidationError(error)
        parsed, = parsing.Parser().parse(ims=bytearray(serder.raw + attachment),
                                          processive=False, version=kering.Vrsn_2_0)
        registries = presentation_registries(vault, serder.pre, serder.sad['ri'],
                                             serder.sad['a']['o'][0],
                                             [nest.serder for nest in parsed.nests])
        if registries:
            for doer in vault.doers:
                if not isinstance(doer, PresentIpexDoer) or doer.done:
                    continue
                if doer.serder.said == serder.said:
                    return serder.said
                if registries.keys() & doer.registries.keys():
                    raise ValueError('Another presentation is being prepared with this registry')
            _check_presentation_reuse(vault, serder.said, registries)
            vault.extend([PresentIpexDoer(vault, hab, parsed, registries, codes=codes)])
            return serder.said
    prepare(vault, hab, serder, attachment)
    if vault.db.outbox.put((serder.said,), IpexSubmission()):
        vault.signals.emit_doer_event('Ipex', 'queued', {'said': serder.said})
    return serder.said


def retry(vault, said):
    """Retry an existing submission without building or signing another message."""
    _require_vault(vault)
    record = vault.db.outbox.get((said,))
    if record is None:
        raise ValueError('No saved submission to retry')
    if error := exchange_error(vault, vault.hby.db.exns.get((said,)), sending=True):
        raise kering.ValidationError(error)
    if record.status != 'sending':
        record.status, record.error, record.retry_at = 'pending', '', 0.0
        record.attempts = 0
        record.missing_route = False
        vault.db.outbox.pin((said,), record)
        vault.signals.emit_doer_event('Ipex', 'queued', {'said': said})


def grant_evidence(vault, grant_said):
    """Load the origin and disclosed nodes from the same verified Grant."""
    exn = vault.hby.db.exns.get(keys=(grant_said,))
    if exn is None or exn.route != '/ipex/grant' or exn.pvrsn.major != 2:
        raise kering.ValidationError('Verified native grant not found')
    exchanging.verify(vault.hby, exn)
    origin = exn.sad['a']['o'][0]
    nests = exchanging.loadParsedNestedSubstreams(vault.hby, grant_said)
    for nest in nests:
        if nest.serder.said == origin:
            return nest.serder, nests
    raise kering.ValidationError('Grant origin evidence is missing')


def grant_credential(vault, grant_said):
    return grant_evidence(vault, grant_said)[0]


def _disclosure_plan(origin, nodes):
    """Name the retained nodes in native BFS order without expanding their fields."""
    plan, seen = [], set()
    pending = deque([(origin, '/')])
    while pending:
        said, prefix = pending.popleft()
        if said in seen:
            continue
        if said not in nodes:
            raise kering.ValidationError('Linked credential evidence is missing')
        seen.add(said)
        sad = nodes[said]
        schema = sad['s']
        plan.append([schema if isinstance(schema, str) else schema['$id'], prefix, []])
        pending.extend((far, prefix + path) for far, path in _edge_nodes(sad))
    if seen != nodes.keys():
        raise kering.ValidationError('Retained evidence contains unrelated credentials')
    return [plan]


def issuer_delivery(sender, recipient, credential):
    """Return whether an exchange delivers a credential from its issuer to its issuee."""
    return (sender, recipient) == (credential.israid, credential.iseaid)


def _credential_evidence(vault, credential_said, hab=None):
    """Load the retained origin and its linked credentials."""
    view = credentialing.credential(vault, credential_said)
    if view['status']['et'] not in ('issued', 'authenticated'):
        raise kering.ValidationError('Credential does not have a verified issued state or issuer authentication')
    if hab is not None:
        credentialing.require_registry_evidence(vault, SerderACDC(sad=view['sad']), hab)
    artifacts = dict(view['artifacts'])
    # Received credentials already retain the native Grant's complete evidence.
    pending = [view] if vault.db.issued.get((credential_said,)) else []
    while pending:
        current = pending.pop()
        for said, _ in _edge_nodes(current['sad']):
            if said == credential_said or said in artifacts:
                continue
            source = credentialing.credential(vault, said)
            if hab is not None:
                credentialing.require_registry_evidence(vault, SerderACDC(sad=source['sad']), hab)
            if source['status']['et'] not in ('issued', 'authenticated'):
                raise kering.ValidationError(f'Source credential {said} is not issued')
            artifacts[said] = source['proof']
            artifacts.update(source['artifacts'])
            if vault.db.issued.get((said,)):
                pending.append(source)
    nodes = {credential_said: view['sad']}
    for stream in artifacts.values():
        ims = bytearray(stream)
        parsed = parsing.Parser().parse(ims=ims, processive=False, version=kering.Vrsn_2_0)
        if len(parsed) != 1 or ims or not isinstance(parsed[0].serder, SerderACDC):
            raise kering.ValidationError('Invalid retained credential evidence')
        if hab is not None:
            credentialing.require_registry_evidence(vault, parsed[0].serder, hab)
        state = credentialing.authentication(vault, parsed[0])
        if state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError('Source credential does not have a verified issued state')
        nodes[parsed[0].serder.said] = parsed[0].serder.sad
    return view, list(artifacts.values()), _disclosure_plan(credential_said, nodes), nodes


def _offer_disclosure(sender, recipient, credential_said, plan, nodes):
    """Expand an issuance Offer without carrying the Grant's proof attachments."""
    origin = SerderACDC(sad=nodes[credential_said])
    if not issuer_delivery(sender, recipient, origin):
        return origin, None, plan
    bodies = [SerderACDC(sad=disclosure_node(nodes, credential_said, prefix))
              for _, prefix, _ in plan[0]]
    return bodies[0], bodies[1:], [[
        [schema, prefix, ['']] for schema, prefix, _ in plan[0]
    ]]


def grant(vault, hab, credential_said, recipient, message=''):
    """Build a grant from the wallet's retained issuance or received evidence."""
    _require_vault(vault, hab)
    view, artifacts, plan, nodes = _credential_evidence(vault, credential_said, hab)
    registries = list(_presentation_requirements(
        hab.pre, recipient, credential_said, [SerderACDC(sad=sad) for sad in nodes.values()]))
    return ipexing.grant(hab, recipient, message, origin=view['proof'], artifacts=artifacts,
                         modifiers={'dp': plan}, kind=kering.Kinds.json,
                         anchorers=[] if registries else None)


def _disclose(nest, paths):
    """Use native constructors and retain the credential's proof attachments."""
    original = nest.serder
    sad = original.sad
    disclosed = dict(sad)
    if paths not in ([], ['']):
        for root in ('a', 'e', 'r'):
            if not isinstance(sad.get(root), Mapping):
                continue
            selected = [path for path in paths if path.startswith(root + '/')]
            if selected:
                compactor = Compactor(mad=sad[root], makify=True, kind=original.kind)
                compactor.compact(paths=selected, root=root)
                disclosed[root] = compactor.partials[tuple(selected)].mad
                if sad[root].get('d') == '':
                    disclosed[root]['d'] = ''
            elif root == 'a':
                compactor = Compactor(mad=sad[root], makify=True, kind=original.kind)
                compactor.compact()
                disclosed[root] = compactor.said
        if isinstance(sad.get('A'), list) and 'A/' not in paths:
            indices = [int(path.strip('/').split('/')[1]) for path in paths if path.startswith('A/')]
            disclosed['A'], _ = Aggor(ael=sad['A'], kind=original.kind).disclose(indices=indices)
        disclosed = SerderACDC(sad=disclosed, makify=True)
        if disclosed.said != original.said:
            raise kering.ValidationError('Disclosure changed the credential commitment')
    else:
        disclosed = original
    return exchanging.serializeParsedSubstream(dict(nest.__dict__, serder=disclosed)), disclosed.sad


def disclosure_node(nodes, origin, prefix):
    """Resolve a plan's virtual edge path against retained credential nodes."""
    node = nodes[origin]
    for part in prefix.strip('/').split('/') if prefix != '/' else []:
        node = nodes[node['n']] if part == '_' else node[int(part)] if isinstance(node, list) else node[part]
    return node


def disclosure(vault, credential_said, *, plan, hab=None):
    """Build selected evidence from a native plan without changing the originals.

    Native IPEX validates the plan and authentication before submission.
    """
    view, artifacts, _, nodes = _credential_evidence(vault, credential_said, hab)
    return _disclose_evidence(view, artifacts, nodes, plan)


def _disclose_evidence(view, artifacts, nodes, plan):
    credential_said = view['sad']['d']
    selected_nodes, streams, parsed = {}, {}, {}
    for stream in [view['proof'], *artifacts]:
        nest, = parsing.Parser().parse(ims=bytearray(stream), processive=False, version=kering.Vrsn_2_0)
        parsed[nest.serder.said] = nest
    for _, prefix, paths in plan[0]:
        node = disclosure_node(nodes, credential_said, prefix)
        streams[node['d']], selected_nodes[node['d']] = _disclose(parsed[node['d']], paths)
    return streams[credential_said], [stream for said, stream in streams.items() if said != credential_said], plan, selected_nodes


def request_schema(exn):
    """Read the origin schema for the composer's retained-node disclosure plans."""
    plan = exn.sad['q'].get('dp', [])
    if len(plan) == 1 and plan[0]:
        schema, path, fields = plan[0][0]
        if path == '/':
            return schema
    return None


def requests_presentation_registry(schema):
    """Only declared issuee registry fields opt an issuance request into setup."""
    properties = schema.get('properties', {})
    attribute = credentialing.schema_detail(properties.get('a'))
    return bool('rd' in properties and attribute
                and {'i', 'rd'} <= attribute.get('properties', {}).keys())


def request_registry(vault, request, hab):
    """Verify the registry named by an authenticated issuance Apply."""
    if (request is None or request.route != '/ipex/apply'
            or not vault.exc.complete(request.said) or request.sad['ri'] != hab.pre):
        raise ValueError('Expected an authenticated credential request addressed to this issuer')
    regk = request.sad['a'].get('preg')
    if regk is None:
        return None
    if not isinstance(regk, str) or not regk:
        raise ValueError('Invalid requested presentation registry')
    Saider(qb64=regk)
    worker = vault.registry_evidence
    if worker is not None and not worker.ensure(regk, hab):
        raise kering.MissingChainError('Presentation registry evidence is pending')
    rip = vault.rgy.store.seqEvent(regk, 0)
    if rip is None:
        raise ValueError('Presentation registry evidence is missing')
    if rip.said != regk or rip.israid != request.pre:
        raise ValueError('The presentation registry does not belong to the requester')
    regeventing.vet(rip=rip, db=vault.hby.db)
    return regk


def check_requested_registry(request, credential):
    """Require the original issuance request's registry on the origin credential."""
    regk = request.sad['a'].get('preg') if request and request.route == '/ipex/apply' else None
    if regk is None:
        return
    declarations = ipexing.IpexHandler._presentationRegistries(credential)
    if credential.israid != request.sad['ri'] or declarations != [(request.pre, regk)]:
        raise ValueError('The credential does not use the requested presentation registry')


def _issuance_request(vault, exn):
    """Follow accepted exchange predecessors to the initiating Apply."""
    while exn is not None and exn.route != '/ipex/apply':
        exn = vault.hby.db.exns.get((exn.sad.get('p', ''),)) if exn.sad.get('p', '') else None
    return exn


class RequestCredentialDoer(doing.DoDoer):
    """Create one registry and retain one signed Apply across preparation retries."""

    def __init__(self, vault, hab, recipient, schema, *, disclosure_plan=None, ax=None, codes=None):
        _require_vault(vault, hab)
        _require_route(vault, hab, recipient)
        schemer = vault.hby.db.schema.get((schema,))
        if schemer is None or not requests_presentation_registry(schemer.sed):
            raise ValueError('This credential type does not declare a presentation registry')
        if isinstance(hab, GroupHab):
            raise ValueError('Choose an individual local identifier')
        record = CredentialRequest(hab.pre, recipient, schema,
                                   disclosure_plan if disclosure_plan is not None else [[[schema, '/', []]]], ax)
        request_id = uuid.uuid4().hex
        for (key,), saved in vault.db.requests.getTopItemIter():
            if not saved.submitted and (saved.sender, saved.recipient, saved.schema, saved.plan, saved.ax) == (
                    record.sender, record.recipient, record.schema, record.plan, record.ax):
                request_id, record = key, saved
                break
        if any(isinstance(doer, RequestCredentialDoer) and not doer.done and doer.request_id == request_id
               for doer in vault.doers):
            raise ValueError('This request is already being prepared')
        vault.db.requests.put((request_id,), record)
        self.vault, self.hab, self.record = vault, hab, record
        self.request_id, self.codes = request_id, codes
        self.error, self.said = '', ''
        self.stage = ''
        super().__init__(doers=[doing.doify(self.requestDo)])

    def _progress(self, stage):
        if stage != self.stage:
            self.stage = stage
            self.vault.signals.emit_doer_event('RequestCredential', 'progress',
                                               {'request': self.request_id, 'stage': stage})

    def requestDo(self, tymth=None, tock=0.0, **kwa):
        from locksmith.core.registries import CreateRegistryDoer

        self.wind(tymth)
        yield self.tock
        worker = None
        try:
            _require_vault(self.vault, self.hab)
            record = self.record
            if not record.stream:
                name = 'request-' + self.request_id
                registry = self.vault.rgy.registryByName(name)
                if registry is None or self.vault.db.registry_creations.get((name,)) is not None:
                    worker = CreateRegistryDoer(self.vault, self.hab, name, codes=self.codes)
                    self.codes = None
                    self.extend([worker])
                    while not worker.done:
                        self._progress(worker.stage)
                        yield self.tock
                    self._progress(worker.stage)
                    if worker.error:
                        raise ValueError(worker.error)
                    registry = worker.registry
                exn, atc = ipexing.apply(self.hab, record.recipient, '',
                                         modifiers={'dp': record.plan}, attrs={'preg': registry.regk},
                                         ax=record.ax, kind=kering.Kinds.json)
                record.stream = (exn.raw + atc).decode()
                self.vault.db.requests.pin((self.request_id,), record)
            exn = SerderKERI(raw=record.stream.encode())
            atc = record.stream.encode()[exn.size:]
            self._progress('sending')
            self.said = submit(self.vault, self.hab, exn, atc)
            record.submitted = True
            self.vault.db.requests.pin((self.request_id,), record)
            self.vault.signals.emit_doer_event('RequestCredential', 'submitted',
                                               {'request': self.request_id, 'said': self.said})
        except Exception as ex:
            self.error = str(ex)
            self.vault.signals.emit_doer_event('RequestCredential', 'failed',
                                               {'request': self.request_id, 'error': self.error})
        finally:
            if worker is not None:
                self.remove([worker])


def start(vault, hab, recipient, action, message='', *, schema=None, credential_said=None, ax=None,
          disclosure_plan=None):
    """Start a schema request or a credential offer after explicit consent."""
    _require_vault(vault, hab)
    if not recipient or recipient == hab.pre:
        raise ValueError('Choose another identifier for this exchange')
    _require_route(vault, hab, recipient)
    if action == 'Apply':
        if not schema or vault.hby.db.schema.get((schema,)) is None:
            raise ValueError('Choose a loaded schema')
        exn, atc = ipexing.apply(hab, recipient, message,
                                 modifiers={'dp': disclosure_plan if disclosure_plan is not None else [[[schema, '/', []]]]}, ax=ax,
                                 kind=kering.Kinds.json)
    elif action == 'Offer':
        _, _, plan, nodes = _credential_evidence(vault, credential_said, hab)
        origin, artifacts, plan = _offer_disclosure(
            hab.pre, recipient, credential_said, plan, nodes)
        if artifacts is None and disclosure_plan is not None:
            plan = disclosure_plan
        exn, atc = ipexing.offer(hab, message, origin, artifacts=artifacts, recp=recipient,
                                 modifiers={'dp': plan}, ax=ax,
                                 kind=kering.Kinds.json)
    else:
        raise ValueError('Start with Apply or Offer')
    return submit(vault, hab, exn, atc)


def _legacy_opener_error(vault, exn, *, sending=False):
    # Keripy checks the immediate parent of an incoming reply. Later stages can
    # continue if both peers already accepted the first reply before upgrading.
    if sending and exn is not None and (prior := exn.sad.get('p')):
        exn = vault.hby.db.exns.get((prior,))
    if exn is not None and exn.ilk == kering.Ilks.exn and not exn.sad.get('p'):
        return 'This exchange uses an older message format. Start a new exchange to continue.'
    return None


def exchange_error(vault, exn, *, sending=False):
    """Explain why Keripy cannot continue or deliver this saved exchange."""
    return _legacy_opener_error(vault, exn, sending=sending) or expiry_error(vault, exn)


def expiry_error(vault, exn):
    """Explain an expired exchange using the wallet's native KRAM policy."""
    kramer = vault.kvy.kramer
    if exn is None or kramer is None or not kramer.enabled:
        return None
    seen = set()
    while exn.sad.get('p', ''):
        if exn.said in seen:
            return None  # Leave incomplete or damaged chains to protocol validation.
        seen.add(exn.said)
        exn = vault.hby.db.exns.get((exn.sad.get('p', ''),))
        if exn is None:
            return None
    # Vault uses one policy for all IPEX routes. The saved opener remains
    # available after KRAM has pruned its transaction cache.
    policy = vault.hby.db.kramCTYP.get('~')
    age = (helping.nowUTC() - helping.fromIso8601(exn.stamp)).total_seconds() * 1000
    if age <= policy.xl:
        return None
    if exn.route == '/ipex/apply':
        if exn.pre in vault.hby.prefixes:
            return 'This request has expired. Send a new request to continue.'
        return ('This request has expired. Ask the requester to send a new request. '
                'You can reuse the existing credential.')
    if exn.pre in vault.hby.prefixes:
        return 'This exchange has expired. Start a new offer using the existing credential.'
    return 'This exchange has expired. Ask the sender to start a new offer.'


def responses(vault, exn):
    """Return decisions available to the local recipient of a saved message."""
    if (exn is None or exn.sad['ri'] not in vault.hby.prefixes
            or vault.hby.db.erpy.get((exn.said,)) is not None
            or exchange_error(vault, exn)):
        return []
    match exn.route:
        case '/ipex/apply':
            return ['Offer', 'Grant', 'Spurn']
        case '/ipex/offer':
            return ['Agree', 'Spurn']
        case '/ipex/agree':
            return ['Grant', 'Spurn']
        case '/ipex/grant':
            return ['Admit', 'Spurn'] if not exn.sad.get('p', '') else ['Admit']
    return []


def anchor_error(hab):
    """Return why this wallet cannot prepare an IPEX KEL anchor, if any."""
    if not hab.kever.prefixer.transferable:
        return 'This step requires an identifier that supports KEL anchoring.'
    return None


def respond(vault, said, action, message='', credential_said=None, disclosure_plan=None, codes=None):
    """Validate the current decision before building and saving one response."""
    _require_vault(vault)
    prior = vault.hby.db.exns.get((said,))
    if error := exchange_error(vault, prior):
        raise kering.ValidationError(error)
    if action not in responses(vault, prior):
        raise ValueError('This exchange has changed. Review its current status.')
    hab = vault.hby.habByPre(prior.sad['ri'])
    if action in ('Agree', 'Grant') and prior.sad['a'].get('ax', [False])[0]:
        if error := anchor_error(hab):
            raise kering.ValidationError(error)
    if action == 'Admit':
        exn, _ = admit(vault, hab, said, message, send=True)
        if vault.db.receipts.get((hab.pre, said)).status == 'accepted':
            vault.signals.emit_doer_event('Ipex', 'accepted', {'said': exn.said})
        return exn.said
    _require_route(vault, hab, prior.pre, reply=action != 'Spurn')
    if action in ('Offer', 'Grant'):
        view, artifacts, plan, nodes = _credential_evidence(vault, credential_said, hab)
        issuance_request = _issuance_request(vault, prior)
        check_requested_registry(issuance_request, SerderACDC(sad=view['sad']))
        request = (vault.hby.db.exns.get((prior.sad.get('p', ''),))
                   if prior.route == '/ipex/agree' else prior)
        schema = request_schema(request)
        if request.sad['q'].get('dp') not in (None, [[]]) and schema is None:
            raise ValueError('This disclosure plan does not identify one origin credential')
        offered = request.sad['a'].get('o', []) if request.route == '/ipex/offer' else []
        if offered:
            previews = exchanging.loadParsedNestedSubstreams(vault.hby, request.said)
            metadata = previews and previews[0].serder.sad.get('u') == ''
            if not metadata and credential_said != offered[0]:
                raise ValueError('Grant must disclose the credential identified by the Offer')
        actual = view['sad']['s']
        actual = actual if isinstance(actual, str) else actual['$id']
        if schema and schema != actual:
            raise ValueError('The credential does not match the requested schema')
        requested = request.sad['q'].get('dp', [[]])
        if schema:
            plan[0][0][2] = requested[0][0][2]
        if action == 'Offer':
            origin, offer_artifacts, plan = _offer_disclosure(
                hab.pre, prior.pre, credential_said, plan, nodes)
            if offer_artifacts is None and disclosure_plan is not None:
                plan = disclosure_plan
            exn, atc = ipexing.offer(hab, message, origin, artifacts=offer_artifacts, apply=prior,
                                    modifiers={'dp': plan}, ax=prior.sad['a'].get('ax'),
                                    attrs={'preg': issuance_request.sad['a']['preg']}
                                    if issuance_request and 'preg' in issuance_request.sad['a'] else None,
                                    kind=kering.Kinds.json)
        else:
            proof, artifacts, _, nodes = _disclose_evidence(view, artifacts, nodes, requested)
            registries = presentation_registries(vault, hab.pre, prior.pre, credential_said,
                                                 [SerderACDC(sad=sad) for sad in nodes.values()])
            link = {'apply': prior} if prior.route == '/ipex/apply' else {'agree': prior}
            exn, atc = ipexing.grant(hab, prior.pre, message, proof, artifacts=artifacts,
                                    modifiers={'dp': [[]]}, ax=prior.sad['a'].get('ax'),
                                    kind=kering.Kinds.json, anchorers=[] if registries else None, **link)
    elif action == 'Agree':
        request = _issuance_request(vault, prior)
        if request and 'preg' in request.sad['a'] and prior.sad['a'].get('preg') != request.sad['a']['preg']:
            raise ValueError('The offer does not confirm the requested presentation registry')
        exn, atc = ipexing.agree(hab, message, prior, kind=kering.Kinds.json)
    else:
        exn, atc = ipexing.spurn(hab, message, prior, kind=kering.Kinds.json)
    return submit(vault, hab, exn, atc, codes=codes)


def _history_keys(store):
    """Read pages of keys without holding an LMDB transaction between yields."""
    last = None
    while True:
        with store.db.env.begin() as txn, txn.cursor(store.sdb) as cursor:
            if last is not None and not cursor.set_range(last + b'\0'):
                return
            keys = list(islice(cursor.iternext(values=False), 128))
        if not keys:
            return
        for key in keys:
            yield tuple(key.decode().split(store.sep))
        last = keys[-1]


def iter_exchanges(vault, *, root_said=None):
    """Yield a saved exchange or None for each history record checked.

    The root fixes credential direction. Reply links fix stage; signed dates
    are display metadata and never select a winner.
    """
    _require_vault(vault)
    db = vault.hby.db

    def lookup(said):
        exn = db.exns.get((said,))
        if (exn is not None and exn.pvrsn.major == 2 and exn.route.startswith('/ipex/')
                and {exn.pre, exn.sad['ri']} & vault.hby.prefixes):
            return exn
        return None

    visited = set()
    roots = ((root_said,),) if root_said is not None else _history_keys(db.exns)
    for (said,) in roots:
        if said in visited or (root := lookup(said)) is None:
            yield None
            continue
        prior = root.sad.get('p', '')
        if prior and lookup(prior) is not None:
            if root_said is not None:
                return
            yield None
            continue
        chain, tip = [], root
        problem = 'Earlier message is missing.' if prior else ''
        while tip.said not in visited:
            visited.add(tip.said)
            chain.append(tip)
            reply = db.erpy.get((tip.said,))
            if reply is None:
                break
            child = lookup(reply.qb64)
            if child is None or child.said in visited:
                problem = 'Saved reply history is incomplete.'
                break
            tip = child
        sender, recipient = root.pre, root.sad['ri']
        if root.route == '/ipex/apply':
            sender, recipient = recipient, sender
        submissions = {msg.said: record for msg in chain
                       if (record := vault.db.outbox.get((msg.said,))) is not None}
        receipts = []
        for msg in chain:
            if msg.route == '/ipex/grant':
                keys = (msg.sad['ri'], msg.said)
                if (record := vault.db.receipts.get(keys)) is not None:
                    receipts.append((keys, record))
        expired = (expiry_error(vault, tip)
                   if not problem and tip.route not in ('/ipex/admit', '/ipex/spurn') else None)
        problem = problem or expired or _legacy_opener_error(vault, tip) or ''
        yield dict(root=root.said, messages=chain, sender=sender, recipient=recipient,
                   actions=responses(vault, tip) if not problem else [], problem=problem,
                   expired=bool(expired), submissions=submissions, receipts=receipts)
        if root_said is not None:
            return
    # Keep damaged saved work reachable without inventing a protocol stage.
    outbox_keys = ((root_said,),) if root_said is not None else _history_keys(vault.db.outbox)
    for (said,) in outbox_keys:
        if said not in visited and lookup(said) is None and (record := vault.db.outbox.get((said,))) is not None:
            yield dict(root=said, messages=[], sender='', recipient='', actions=[],
                       problem='Saved message is missing.', submissions={said: record}, receipts=[])
        else:
            yield None
    for keys in _history_keys(vault.db.receipts):
        said = keys[1]
        if ((root_said is None or root_said == said) and said not in visited and lookup(said) is None
                and (record := vault.db.receipts.get(keys)) is not None and record.status != 'accepted'):
            yield dict(root=said, messages=[], sender='', recipient=keys[0], actions=[],
                       problem='Original grant is missing.', submissions={}, receipts=[(keys, record)])
        else:
            yield None


def exchanges(vault):
    """Read saved IPEX chains with their transport and acceptance records."""
    return [row for row in iter_exchanges(vault) if row is not None]


def _validate_credential(vault, credential, grant_said):
    grant = vault.hby.db.exns.get((grant_said,))
    check_requested_registry(_issuance_request(vault, grant), credential)
    prior = vault.hby.db.exns.get((grant.sad.get('p', ''),)) if grant.sad.get('p', '') else None
    if prior and prior.route == '/ipex/agree':
        prior = vault.hby.db.exns.get((prior.sad.get('p', ''),))
    expected = request_schema(prior) if prior else None
    actual = credential.schema if isinstance(credential.schema, str) else credential.schema['$id']
    if expected and actual != expected:
        raise kering.ValidationError('The disclosed credential does not match the agreed schema')
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant_said):
        credentialing.validate_schema(vault, nest.serder)
        credentialing.require_registry_evidence(vault, nest.serder, vault.hby.habByPre(grant.sad['ri']))
        state = credentialing.authentication(vault, nest)
        if state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError(f"Credential state is {state['et']}, not issued")


def _pending_anchors(vault, exn):
    """Load unreceipted local anchors from the retained native source seals."""
    pending = []
    for (_, pre), (_, diger) in vault.hby.db.ests.getTopItemIter(keys=(exn.said, '')):
        if pre not in vault.hby.prefixes:
            continue
        anchor = vault.hby.db.evts.get((pre, diger.qb64))
        if anchor is None:
            raise kering.ValidationError('Retained IPEX anchor event is missing')
        hab = vault.hby.habByPre(pre)
        threshold = hab.kvy.fetchEstEvent(pre, anchor.sn).bner.num
        if len(vault.hby.db.wigs.get((pre, anchor.said))) < threshold:
            pending.append((hab, anchor))
    return pending


def _finish_receipt(vault, pre, grant_said, receipt, restore=False):
    """Reconcile native evidence, the send permission and wallet membership."""
    grant = vault.hby.db.exns.get((grant_said,))
    reply = vault.hby.db.erpy.get((grant_said,))
    exn = vault.hby.db.exns.get((reply.qb64,)) if reply else None
    if (grant is None or grant.route != '/ipex/grant' or grant.sad['ri'] != pre
            or exn is None or exn.route != '/ipex/admit' or exn.pre != pre
            or exn.sad['ri'] != grant.pre or exn.sad.get('p', '') != grant_said
            or (receipt.admit and receipt.admit != exn.said)):
        raise kering.ValidationError('Acceptance preparation is incomplete; a new exchange may be required')
    credential = grant_credential(vault, grant_said)
    if credential.said != receipt.credential:
        raise kering.ValidationError('Acceptance does not match the grant credential')
    stream = exchanging.serializeMessage(vault.hby, exn.said)
    if receipt.status != 'accepted':
        accepted = vault.db.accepted.get((credential.said,))
        # Inventory can commit before the final receipt write is interrupted.
        if (accepted is None or accepted.grant != grant_said
                or accepted.admit != exn.said):
            _validate_credential(vault, credential, grant_said)
    receipt.admit = exn.said
    if receipt.send:
        vault.db.outbox.put((exn.said,), IpexSubmission())
    if receipt.status != 'accepted' and _pending_anchors(vault, exn):
        receipt.status, receipt.error = 'preparing', ''
        vault.db.receipts.pin((pre, grant_said), receipt)
        return exn, stream[exn.size:]
    if receipt.status != 'accepted' or restore:
        # Keep the original inventory provenance when another grant contains C.
        vault.db.accepted.put((credential.said,), AcceptedCredential(grant_said, exn.said,
                                                                    helping.nowIso8601()))
    receipt.status, receipt.error = 'accepted', ''
    vault.db.receipts.pin((pre, grant_said), receipt)
    return exn, stream[exn.size:]


def admit(vault, hab, grant_said, message='', *, send=False):
    """Record consent, retain one admit and optionally authorize its delivery."""
    _require_vault(vault, hab)
    grant = vault.hby.db.exns.get((grant_said,))
    if grant is None or grant.route != '/ipex/grant' or grant.sad['ri'] != hab.pre:
        raise kering.ValidationError('Grant is not addressed to the selected identifier')
    if send:
        _require_route(vault, hab, grant.pre, reply=False)
    reply = vault.hby.db.erpy.get((grant_said,))
    if not reply and (error := exchange_error(vault, grant)):
        raise kering.ValidationError(error)
    if reply:
        saved = vault.hby.db.exns.get((reply.qb64,))
        if saved is None or saved.route != '/ipex/admit':
            raise kering.ValidationError('This Grant already has a terminal reply and cannot be accepted')
    receipt = vault.db.receipts.get((hab.pre, grant_said))
    if receipt is None:
        credential = grant_credential(vault, grant_said)
        accepted = vault.db.accepted.get((credential.said,))
        if accepted is not None and accepted.grant == grant_said:
            # Earlier V2 vaults saved acceptance without a separate receipt.
            receipt = GrantReceipt(credential=credential.said, admit=accepted.admit,
                                   send=send, status='accepted')
            return _finish_receipt(vault, hab.pre, grant_said, receipt, restore=True)
        if grant.sad['a'].get('ax', [False])[0] and vault.hby.db.erpy.get((grant_said,)) is None:
            if error := anchor_error(hab):
                raise kering.ValidationError(error)
        _validate_credential(vault, credential, grant_said)
        receipt = GrantReceipt(credential=credential.said, send=send)
        # Save consent before the native builder can create an AX anchor.
        vault.db.receipts.put((hab.pre, grant_said), receipt)
        if vault.hby.db.erpy.get((grant_said,)) is None:
            exn, atc = ipexing.admit(hab, message, grant, kind=kering.Kinds.json)
            prepare(vault, hab, exn, atc)
    elif send and not receipt.send:
        receipt.send = True
        vault.db.receipts.pin((hab.pre, grant_said), receipt)
    # Never repeat the builder after interrupted preparation.
    return _finish_receipt(vault, hab.pre, grant_said, receipt, restore=True)


class IpexOutboxDoer(doing.DoDoer):
    """Resume saved decisions and submit one pending message at a time."""

    ScanBatch = 256
    ScanDelay = 1.0
    RecoverySeconds = 0.004

    def __init__(self, vault, **kwa):
        self.vault = vault
        self._recovery = self._recover()
        # Finish small recoveries before the vault opens. Continue larger ones on its scheduler.
        for _ in islice(self._recovery, 4):
            pass
        super().__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def _recover(self):
        vault = self.vault
        for keys in _history_keys(vault.db.outbox):
            record = vault.db.outbox.get(keys)
            if record is not None and record.status in ('sending', 'pending'):
                status = 'pending' if record.attempts <= len(SendIpexDoer.RetryDelays) else 'failed'
                if status != record.status:
                    record.status = status
                    vault.db.outbox.pin(keys, record)
                    vault.signals.emit_doer_event('Ipex', 'saved', {'said': keys[0]})
            yield
        for keys in _history_keys(vault.db.receipts):
            receipt = vault.db.receipts.get(keys)
            # Acceptance commits last. A later decision to send can survive a
            # crash before its outbox entry is written.
            if receipt is not None and (receipt.status != 'accepted' or receipt.error or not receipt.admit
                    or (receipt.send and vault.db.outbox.get((receipt.admit,)) is None)):
                previous = receipt.status
                try:
                    _finish_receipt(vault, *keys, receipt)
                except Exception as ex:
                    receipt.error = str(ex)
                    if receipt.status != 'accepted':
                        receipt.status = 'interrupted'
                    vault.db.receipts.pin(keys, receipt)
                event = 'accepted' if receipt.status == 'accepted' and previous != 'accepted' else 'saved'
                vault.signals.emit_doer_event('Ipex', event, {'said': receipt.admit or keys[1]})
            yield

    def sendDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        deadline = monotonic() + self.RecoverySeconds
        for _ in self._recovery:
            if monotonic() >= deadline:
                yield self.tock
                deadline = monotonic() + self.RecoverySeconds
        while not getattr(self.vault, 'closed', False):
            pending = []
            # Yield while scanning history, and close the read transaction
            # before delivery can change records or wait on the network.
            with closing(self.vault.db.outbox.getTopItemIter()) as records:
                while batch := list(islice(records, self.ScanBatch)):
                    now = helping.nowUTC().timestamp()
                    pending.extend(said for (said,), record in batch if _due(record, now))
                    yield self.tock
            with closing(self.vault.db.receipts.getTopItemIter()) as receipts:
                while batch := list(islice(receipts, self.ScanBatch)):
                    pending.extend(receipt.admit for _, receipt in batch
                                   if receipt.status == 'preparing' and receipt.admit)
                    yield self.tock
            for said in dict.fromkeys(pending):
                if getattr(self.vault, 'closed', False):
                    return
                delivery = SendIpexDoer(self.vault, said)
                self.extend([delivery])
                try:
                    while not delivery.done:
                        yield self.tock
                finally:
                    self.remove([delivery])
            yield self.ScanDelay


def _due(record, now):
    """Return whether the outbox should send record now.

    A failed message retries automatically after each delay in RetryDelays,
    then waits for a manual Retry, which sets it back to pending.
    """
    if record.status == 'pending':
        return record.attempts <= len(SendIpexDoer.RetryDelays)
    return (record.status == 'failed' and record.attempts <= len(SendIpexDoer.RetryDelays)
            and record.retry_at <= now)


class PresentIpexDoer(credentialing.CredentialUpdateDoer):
    """Bind one immutable Grant in its locally controlled presentation registries.

    Returned proof material is saved before waiting for witness receipts. An
    interrupted native staging operation is not automatically reconstructed.
    """

    def __init__(self, vault, hab, parsed, registries, codes=None, **kwa):
        self.vault, self.hab, self.parsed = vault, hab, parsed
        self.serder, self.registries = parsed.serder, registries
        self.estates = {controller.pre: controller.kever.lastEst.d
                        for controller in [hab, *(registry.hab for registry in registries.values())]}
        self.codes = {pre: list(values) for pre, values in (codes or {}).items()}
        self.error = ''
        super().__init__(doers=[doing.doify(self.presentDo)], **kwa)

    def recur(self, tyme, deeds=None):
        try:
            return super().recur(tyme, deeds)
        except Exception as ex:
            self.error = str(ex)
            self.vault.signals.emit_doer_event('Ipex', 'preparation_failed',
                                               {'said': self.serder.said, 'error': self.error})
            return True

    def presentDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        receiptor = None
        try:
            _require_vault(self.vault, self.hab)
            if any((controller := self.vault.hby.habByPre(pre)) is None or controller.kever.lastEst.d != said
                   for pre, said in self.estates.items()):
                raise ValueError('Identifier key state changed. Review the presentation and witness authentication again.')
            _require_route(self.vault, self.hab, self.serder.sad['ri'])
            registrar = Registrar(rgy=self.vault.rgy)
            receiptor = LocksmithReceiptor(hby=self.vault.hby)
            self.extend([receiptor])
            auths = {}
            for pre, values in self.codes.items():
                auths[pre] = {}
                for entry in values:
                    wit, code = entry.split(':', 1)
                    auths[pre][wit] = f'{code}#{helping.nowIso8601()}'
            self.codes.clear()
            proofs = {}
            self.vault.signals.emit_doer_event('Ipex', 'preparing', {'said': self.serder.said})
            for regk, registry in self.registries.items():
                inception = self.vault.rgy.store.event(regk)
                yield from self.anchor(registry, inception, receiptor, auths.get(registry.hab.pre, {}))
                blinder, update = registrar.present(registry, grant=self.serder)
                self.vault.db.presentations.pin((self.serder.said, regk),
                                                PresentationProof(blinder.qb64, update.said))
                yield from self.anchor(registry, update, receiptor, auths.get(registry.hab.pre, {}))
                sn, _ = credentialing.regeventing.vetAnchor(update, db=self.vault.hby.db,
                                                          issuer=registry.hab.pre)
                anchor = SerderKERI(raw=registry.hab.msgOwnEvent(sn=sn))
                proofs[regk] = blinder.data, SealEvent(i=registry.hab.pre, s=anchor.snh, d=anchor.said)
            yield from self.publish(list(self.registries.values()))
            for nest in self.parsed.nests:
                for _, regk in ipexing.IpexHandler._presentationRegistries(nest.serder) or []:
                    if regk in proofs:
                        proof, source = proofs[regk]
                        nest.bsqs.append(proof)
                        nest.ssts.append(source)
            prior = self.vault.hby.db.exns.get((self.serder.sad.get('p', ''),)) if self.serder.sad.get('p', '') else None
            if error := exchange_error(self.vault, prior):
                raise kering.ValidationError(error)
            stream = exchanging.serializeParsedSubstream(self.parsed)
            self.vault.mbx.parser.parse(ims=bytearray(stream), local=True, version=kering.Vrsn_2_0)
            if not self.vault.exc.complete(self.serder.said):
                raise kering.ValidationError('Outgoing IPEX has not passed protocol verification')
            submit(self.vault, self.hab, self.serder, b'')
        except (OSError, kering.KeriError, ValueError) as ex:
            self.error = str(ex)
            if self.vault.db.opened:
                self.vault.signals.emit_doer_event('Ipex', 'preparation_failed',
                                                   {'said': self.serder.said, 'error': self.error})
            logger.exception('Presentation preparation failed')
        finally:
            if receiptor is not None:
                self.remove([receiptor])


class SendIpexDoer(credentialing.CredentialUpdateDoer):
    """Receipt a retained native exchange and submit authorized delivery."""

    Timeout = 30.0

    RetryDelays = (30.0, 60.0, 120.0)

    def __init__(self, vault, said, **kwa):
        self.vault, self.said = vault, said
        super().__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        delivery = None
        receiptor = None
        record = None
        consent = None
        claimed = False
        try:
            _require_vault(self.vault)
            record = self.vault.db.outbox.get((self.said,))
            if record is not None and not _due(record, helping.nowUTC().timestamp()):
                record = None  # Local acceptance can still need witness receipts.
            self.serder = self.vault.hby.db.exns.get((self.said,))
            if self.serder is None:
                raise kering.ValidationError('Saved submission has no retained message')
            self.hab = self.vault.hby.habByPre(self.serder.pre)
            if self.hab is None:
                raise kering.ValidationError('Saved submission has no local sender')
            if self.serder.route == '/ipex/admit':
                consent = self.vault.db.receipts.get((self.hab.pre, self.serder.sad.get('p', '')))
            preparing = consent is not None and consent.status == 'preparing'
            if record is None and not preparing:
                return
            # Finish an already signed acceptance even when its Admit cannot travel.
            wire_error = exchange_error(self.vault, self.serder, sending=True) if record else None
            if wire_error and not preparing:
                raise kering.ValidationError(wire_error)
            if record is not None and not wire_error:
                if self.serder.route == '/ipex/grant' and self.serder.sad['a'].get('o'):
                    _validate_outgoing_grant(self.vault, self.hab, self.serder)
                if consent is not None and not consent.send:
                    raise kering.ValidationError('Network delivery was not authorized')
                _require_route(self.vault, self.hab, self.serder.sad['ri'],
                               reply=self.serder.route not in ('/ipex/admit', '/ipex/spurn'))
                record.status, record.error = 'sending', ''
                record.missing_route = False
                record.attempts += 1
                claimed = True
                self.vault.db.outbox.pin((self.said,), record)
            # The EXN and its exact source seals are durable before this wait.
            anchors = _pending_anchors(self.vault, self.serder)
            if anchors:
                receiptor = LocksmithReceiptor(hby=self.vault.hby)
                self.extend([receiptor])
                self.vault.signals.emit_doer_event('Ipex', 'awaiting_witnesses', {'said': self.said})
                for hab, anchor in anchors:
                    yield from self.receipt(hab, anchor, receiptor, {})
            if consent is not None:
                accepted = consent.status == 'accepted'
                _finish_receipt(self.vault, self.hab.pre, self.serder.sad.get('p', ''), consent)
                if consent.status != 'accepted':
                    raise kering.MissingChainError('Witness receipts are still pending for the IPEX anchor')
                if not accepted:
                    self.vault.signals.emit_doer_event('Ipex', 'accepted', {'said': self.said})
            if record is None:
                return
            if error := exchange_error(self.vault, self.serder, sending=True):
                raise kering.ValidationError(error)
            # Receipts may take several scheduler turns. Endpoint authority can
            # change during that wait; StreamPoster must never fall back to witnesses.
            role, endpoints = _require_route(self.vault, self.hab, self.serder.sad['ri'],
                                             reply=self.serder.route not in ('/ipex/admit', '/ipex/spurn'))
            self.vault.signals.emit_doer_event('Ipex', 'sending', {'said': self.said})
            poster = forwarding.StreamPoster(hby=self.vault.hby, hab=self.hab,
                                             recp=self.serder.sad['ri'], topic='credential')
            prefixes = []
            if self.serder.route == '/ipex/grant':
                for nest in exchanging.loadParsedNestedSubstreams(self.vault.hby, self.serder.said):
                    prefixes.append(nest.serder.israid)
                    issuee = nest.serder.iseaid
                    # Issuer authentication does not require the subject's KEL.
                    if (issuee is not None and issuee != self.serder.sad['ri']
                            and issuee in self.vault.hby.kevers):
                        prefixes.append(issuee)
            from locksmith.core.remoting import identifier_introduction
            stream = bytearray().join(self.vault.hby.db.cloneDelegation(self.hab.kever, gvrsn=kering.Vrsn_2_0))
            stream.extend(identifier_introduction(self.hab, vault=self.vault))
            for pre in dict.fromkeys(prefixes):
                if pre == self.hab.pre:
                    continue  # Its complete introduction was already sent above.
                stream.extend(self.hab.replay(pre=pre, gvrsn=kering.Vrsn_2_0))
            stream.extend(exchanging.serializeMessage(self.vault.hby, self.said))
            if role == kering.Roles.mailbox:
                # The mailbox requires a signed /fwd envelope for each message.
                frames = bytearray(stream)
                parser = parsing.Parser(version=kering.Vrsn_2_0)
                # The operator needs the signer's key history to verify the envelopes.
                forwarded = self.hab.replay(gvrsn=kering.Vrsn_2_0)
                offset = 0
                while frames:
                    serder = parser.parseOneBare(ims=frames, processive=False).serder
                    end = len(stream) - len(frames)
                    envelope, atc = poster.createForward(self.hab, endpoints, serder,
                                                         stream[offset + serder.size:end], poster.topic)
                    forwarded.extend(envelope.raw)
                    forwarded.extend(atc)
                    offset = end
                mailbox = random.choice(list(endpoints))
                endpoints = {mailbox: endpoints[mailbox]}
                stream = forwarded
            doers = poster.sendDirect(self.hab, endpoints, msg=stream)
            if not doers:
                raise kering.ConfigurationError('No transport could submit this IPEX message')
            # Own recurrence here so child transport failures reach this retry
            # boundary rather than escaping through the vault scheduler.
            delivery = doing.DoDoer(doers=doers, tymth=self.tymth)
            delivery.enter()
            deadline = self.tyme + self.Timeout
            while not delivery.recur(tyme=self.tyme):
                if self.tyme >= deadline:
                    raise TimeoutError('IPEX transport did not finish before its deadline')
                yield self.tock
            for messenger in poster.messagers:
                if isinstance(messenger, agenting.HTTPStreamMessenger):
                    if messenger.rep is None or not 200 <= messenger.rep.status < 300:
                        status = messenger.rep.status if messenger.rep is not None else 'no response'
                        if status == 'no response' or status in (408, 429) or status >= 500:
                            raise OSError(f'IPEX transport request failed ({status})')
                        raise kering.ValidationError(f'IPEX transport request failed ({status})')
            record.status = 'submitted'
            self.vault.db.outbox.pin((self.said,), record)
            self.vault.signals.emit_doer_event('Ipex', 'transport_submitted', {'said': self.said})
        except (OSError, httping.HTTPException, kering.KeriError, ValueError) as ex:
            if record is not None and self.vault.db.opened:
                failure = ('blocked' if isinstance(ex, (kering.ValidationError, kering.ConfigurationError))
                           else 'failed')
                record.status, record.error = failure, str(ex)
                record.missing_route = isinstance(ex, MissingRouteError)
                delays = self.RetryDelays
                record.retry_at = (helping.nowUTC().timestamp()
                                   + delays[min(max(record.attempts, 1), len(delays)) - 1])
                self.vault.db.outbox.pin((self.said,), record)
                self.vault.signals.emit_doer_event('Ipex', 'send_failed',
                                                   {'said': self.said, 'error': record.error})
            elif consent is not None and self.vault.db.opened:
                consent.status, consent.error = 'interrupted', str(ex)
                self.vault.db.receipts.pin((self.hab.pre, self.serder.sad.get('p', '')), consent)
                self.vault.signals.emit_doer_event('Ipex', 'preparation_failed',
                                                   {'said': self.said, 'error': str(ex)})
            logger.exception('IPEX submission failed')
        finally:
            if receiptor is not None:
                self.remove([receiptor])
            if delivery is not None:
                delivery.exit()
            if claimed and record.status == 'sending' and self.vault.db.opened:
                record.status = 'pending' if record.attempts <= len(self.RetryDelays) else 'failed'
                self.vault.db.outbox.pin((self.said,), record)
