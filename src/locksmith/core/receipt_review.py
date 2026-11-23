"""Describe the effects of witnessing an existing KEL event."""
from dataclasses import dataclass
import json

from keri import kering
from keri.acdc import regeventing
from keri.core import SerderACDC


@dataclass(frozen=True)
class ReceiptReview:
    issuer: str
    tip: str
    events: tuple[tuple[str, int, str], ...]  # KEL digest, sequence number, displayed effect

    def covers(self, hab, events):
        reviewed = {said for said, _, _ in self.events}
        return (self.issuer == hab.pre and self.tip == hab.kever.serder.said and
                all(event.said in reviewed for event in events))


def _opened_state(proof, update, target):
    if proof.update != update.said:
        return None
    try:
        said, state = regeventing.vetBlind(proof.blinder, blid=update.sad['b'])
    except kering.UnverifiedBlindError:
        return None
    return state if said == target else None


def _registry_update(vault, update):
    for (said,), proof in vault.db.issued.getTopItemIter():
        state = _opened_state(proof, update, said)
        if state in ('issued', 'revoked'):
            action = 'Issue' if state == 'issued' else 'Revoke'
            return f'{action} credential {said} in registry {update.regid}'
    for (grant, regk), proof in vault.db.presentations.getTopItemIter():
        if regk == update.regid and _opened_state(proof, update, grant) == 'presented':
            return f'Record presentation of Grant {grant} in registry {regk}'
    return f'Blinded update {update.said} to registry {update.regid}. Its effect is unknown.'


def _seal_effect(vault, event, seal):
    if isinstance(seal, dict) and set(seal) == {'i', 's', 'd'}:
        regk, sequence, said = seal['i'], seal['s'], seal['d']
        if all(isinstance(value, str) for value in (regk, sequence, said)):
            rip = vault.rgy.store.event(regk)
            if rip is None and regk == said and sequence == '0':
                rip = next((r for _, r in vault.db.registry_creations.getTopItemIter() if r.said == regk), None)
            if rip and rip.ilk == 'rip' and rip.sad['n'] == '0' and rip.said == regk and rip.israid == event.pre:
                if sequence == '0' and said == rip.said:
                    return f'Create registry {regk}'
                update = vault.rgy.store.event(said)
                if (update and update.ilk == 'bup' and update.said == said and
                        update.regid == regk and update.sad['n'] == sequence):
                    return _registry_update(vault, update)
    if isinstance(seal, dict) and set(seal) == {'d'} and isinstance(seal['d'], str):
        said = seal['d']
        record = vault.db.issued.get((said,))
        if record:
            acdc = SerderACDC(raw=record.raw.encode())
            if acdc.said == said:
                return f'Anchor credential {said}' + (f' for {acdc.iseaid}' if acdc.iseaid else '')
        exn = vault.hby.db.exns.get((said,))
        if exn and exn.said == said and exn.route and exn.route.startswith('/ipex/') and exn.sad.get('ri'):
            return f'Anchor IPEX {exn.route.removeprefix("/ipex/").capitalize()} {said} to {exn.sad["ri"]}'
    return 'Unrecognized seal ' + json.dumps(seal, ensure_ascii=True)


def describe_receipt_event(vault, event) -> str:
    """Describe every seal and any key or witness changes without changing wallet state."""
    effects = []
    if event.estive:
        inception = event.ilk in ('icp', 'dip')
        effects.append('Create identifier' if inception else 'Rotate signing keys')
        if event.delpre:
            effects.append(f'Delegator {event.delpre}')
        for witness in (event.backs if inception else event.adds) or ():
            effects.append(f'Add witness {witness}')
        for witness in event.cuts or ():
            effects.append(f'Remove witness {witness}')
        effects.append(f'Witness threshold {event.bn}')
    effects.extend(_seal_effect(vault, event, seal) for seal in event.seals or ())
    return '\n'.join(effects) or f'Interaction event {event.said} with no seals'
