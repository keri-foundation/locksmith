"""Ordinary citizen challenge binding, without a State authorization decision."""
from time import time

from hio.base import doing
from keri import kering
from keri.app.habbing import GroupHab
from keri.core import Noncer, Prefixer, SealNonce, SerderKERI
from keri.help import helping

from locksmith.core import credentialing
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.db.basing import ProofingSession


IAR_SCHEMA = 'EFAB6k77bXHs6bg9PORW7UYF79GD_OuEcEjmBpwhcfRN'


def session(vault, nonce):
    if getattr(vault, 'closed', False):
        raise ValueError('This vault is closed')
    record = vault.db.proofing.get((nonce,))
    if record is None:
        raise ValueError('Proofing session not found')
    return record


def start(vault, citizen, proofer, nonce=None):
    """Create or import an OOB challenge; identifiers do not establish authority."""
    if getattr(vault, 'closed', False):
        raise ValueError('This vault is closed')
    if Prefixer(qb64=citizen).qb64 != citizen or Prefixer(qb64=proofer).qb64 != proofer:
        raise ValueError('Enter complete citizen and proofer identifiers')
    if citizen == proofer:
        raise ValueError('Citizen and proofer must be different identifiers')
    if nonce is None:
        if vault.hby.habByPre(proofer) is None:
            raise ValueError('Generate challenges with a local proofer identifier')
        nonce = Noncer().qb64
    else:
        parsed = Noncer(qb64=nonce)
        if parsed.qb64 != nonce or len(parsed.raw) < 16:
            raise ValueError('Enter a complete challenge with at least 128 bits of entropy')
    record = ProofingSession(citizen=citizen, proofer=proofer, nonce=nonce,
                            expires_at=time() + 900)
    if not vault.db.proofing.put((nonce,), record):
        raise ValueError('This challenge already has a session; resume it instead')
    return record


def binding(vault, nonce, sn):
    """Require the nonce seal in the currently accepted canonical citizen KEL."""
    record = session(vault, nonce)
    if sn < 0:
        raise ValueError('Enter the citizen anchor sequence number')
    db = vault.hby.db
    # Stored event material alone does not establish canonical KEL acceptance.
    digest = db.kels.getLast(keys=record.citizen, on=sn)
    anchor = db.evts.get(keys=(record.citizen, digest)) if digest else None
    if anchor is None:
        raise kering.MissingEntryError('Citizen anchor is not in the accepted KEL')
    if (anchor.pre != record.citizen or anchor.sn != sn or anchor.said != digest
            or anchor.ilk != 'ixn'
            or SealNonce(nd=nonce)._asdict() not in anchor.sad.get('a', [])):
        raise kering.ValidationError('Citizen event does not bind this challenge')
    threshold = vault.kvy.fetchEstEvent(anchor.pre, anchor.sn).bner.num
    if len(db.wigs.get(keys=(anchor.pre, anchor.said))) < threshold:
        raise kering.MissingChainError('Citizen anchor witness receipts are pending')
    return anchor


def verify(vault, nonce, sn, receipt=None):
    """Bind an authenticated received IAR; deliberately stop before authority."""
    record = session(vault, nonce)
    if not record.anchor_said and time() >= record.expires_at:
        raise ValueError('Challenge expired before its anchor was verified')
    anchor = binding(vault, nonce, sn)
    if record.anchor_said and (record.anchor_sn != sn or record.anchor_said != anchor.said):
        raise ValueError('This session already binds a different citizen event')
    receipt = receipt or record.receipt
    if receipt:
        view = credentialing.credential(vault, receipt, received=True)
        sad = view['sad']
        schema = sad.get('s')
        schema = schema.get('$id') if isinstance(schema, dict) else schema
        if (not view['accepted_at'] or view['status'].get('et') not in ('issued', 'authenticated')
                or schema != IAR_SCHEMA or sad.get('i') != record.proofer
                or sad.get('u') != nonce or not isinstance(sad.get('a'), dict)
                or sad['a'].get('i') != record.citizen):
            raise kering.ValidationError('Received IAR does not authenticate this session binding')
        record.receipt = receipt
    record.anchor_sn, record.anchor_said = sn, anchor.said
    record.status = 'awaiting_authority' if record.receipt else 'binding_verified'
    vault.db.proofing.pin((nonce,), record)
    return record


class AnchorChallengeDoer(doing.DoDoer):
    """One vault-owned interaction and receiptor child on the vault scheduler."""

    def __init__(self, app, nonce, codes=None):
        self.app, self.vault, self.nonce = app, app.vault, nonce
        self.codes = codes or []
        super().__init__(doers=[doing.doify(self.anchor_do)])

    def anchor_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        receipt = None
        receiptor = None
        try:
            if self.app.vault is not self.vault:
                raise ValueError('This vault is closed')
            record = session(self.vault, self.nonce)
            if time() >= record.expires_at:
                raise ValueError('Challenge expired')
            hab = self.vault.hby.habByPre(record.citizen)
            if hab is None or isinstance(hab, GroupHab) or hab.kever.estOnly:
                raise ValueError('Choose a local individual identifier that allows interactions')
            if record.anchor_sn < 0:
                anchor = SerderKERI(raw=hab.interact(data=[SealNonce(nd=self.nonce)._asdict()]))
                record.anchor_sn = anchor.sn
                record.status = 'awaiting_witnesses'
                self.vault.db.proofing.pin((self.nonce,), record)
            if hab.kvy.fetchWitnessState(hab.pre, record.anchor_sn):
                auths = {}
                for entry in self.codes:
                    wit, code = entry.split(':', 1)
                    auths[wit] = f'{code}#{helping.nowIso8601()}'
                receiptor = LocksmithReceiptor(hby=self.vault.hby)
                self.extend([receiptor])
                receipt = receiptor.receipt(hab.pre, sn=record.anchor_sn, auths=auths)
                deadline = self.tyme + 30
                for _ in receipt:
                    if (self.app.vault is not self.vault or getattr(self.vault, 'closed', False)):
                        raise ValueError('This vault is closed')
                    if self.tyme >= deadline:
                        raise TimeoutError('Citizen witness receipts are pending; resume this session')
                    yield self.tock
            verify(self.vault, self.nonce, record.anchor_sn)
            self.vault.signals.emit_doer_event('Proofing', 'anchor_verified', {'nonce': self.nonce})
        except Exception as error:
            if not getattr(self.vault, 'closed', False):
                self.vault.signals.emit_doer_event('Proofing', 'failed',
                                                 {'nonce': self.nonce, 'error': str(error)})
        finally:
            try:
                if receipt is not None:
                    receipt.close()
            finally:
                if receiptor is not None:
                    self.remove([receiptor])
