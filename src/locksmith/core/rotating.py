# -*- encoding: utf-8 -*-
"""
locksmith.core.identifying module

Functions for working with KERI Identifiers
"""
from hio.base import doing
from keri import help
from keri import kering
from keri.core import coring, serdering
from keri.help import helping

from locksmith.db.basing import IdentifierMetaInfo
from locksmith.core.credentialing import CredentialUpdateDoer
from locksmith.core.receipting import LocksmithReceiptor

logger = help.ogler.getLogger(__name__)


def recommend_toad(num_witnesses):
    """Recommend an appropriate TOAD value based on witness count."""
    match num_witnesses:
        case 0:
            return 0
        case 1:
            return 1
        case 2 | 3:
            return 2
        case 4:
            return 3
        case 5 | 6:
            return 4
        case 7:
            return 5
        case 8 | 9:
            return 7
        case 10:
            return 8
        case n if n > 10:
            return int(n * 0.8)
    return 0


def validate_toad(toad, num_witnesses):
    """
    Validate TOAD value against witness count.
    
    Args:
        toad: The TOAD value to validate
        num_witnesses: Number of witnesses after rotation (current + adds - cuts)
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if num_witnesses > 0:
        if toad < 1 or toad > num_witnesses:
            return False, f"TOAD must be between 1 and {num_witnesses} for {num_witnesses} witness(es)"
    else:
        if toad != 0:
            return False, "TOAD must be 0 when there are no witnesses"
    return True, None


def rotate_identifier(app, hab, isith=None, nsith=None, count=None, toad=None, cuts=None, adds=None,
                      proxy=None, authenticate=False, codes=None):

    rotate_doer = RotateDoer(app, hab, isith=isith, nsith=nsith, count=count,
                             toad=toad, cuts=cuts, adds=adds, proxy=proxy,
                             authenticate=authenticate, codes=codes, signal_bridge=app.vault.signals)

    app.vault.extend([rotate_doer])


def authenticate_witnesses(app, hab, codes, proxy=None):
    """
    Trigger witness authentication and delegation for an identifier after rotation.

    Args:
        app: Application instance with vault
        hab: Habitat (identifier) to authenticate
        codes: List of "witness_id:passcode" strings
        proxy: Optional proxy Hab for delegation
    """
    auth_doer = AuthenticateWitnessesDoer(
        app=app,
        hab=hab,
        codes=codes,
        proxy=proxy,
        signal_bridge=app.vault.signals
    )

    app.vault.extend([auth_doer])


class RotateDoer(doing.DoDoer):
    """
    Doer for asynchronous identifier rotation with delegation and witness support.

    Handles the complete rotation workflow including:
    - Rotating the identifier keys
    - Waiting for witness receipts
    - Waiting for delegation approval (if delegated)
    - Sending events to delegator
    - Updating witness states
    - Signaling completion to UI
    """

    def __init__(self, app, hab, isith=None, nsith=None, count=None,
                 toad=None, cuts=None, adds=None, proxy=None, authenticate=False,
                 codes=None, signal_bridge=None):
        """
        Initialize the RotateDoer.

        Args:
            app: Application instance with vault
            hab: Hab instance to rotate
            isith: Current signing threshold as int or str hex or list of str weights
            nsith: Next signing threshold as int or str hex or list of str weights
            count: Next number of signing keys
            toad: Witness threshold after cuts and adds (int or str hex)
            cuts: List of qb64 pre of witnesses to be removed
            adds: List of qb64 pre of witnesses to be added
            proxy: Optional proxy Hab for delegation
            authenticate: Whether to authenticate with witnesses
            codes: List of witness:code authentication pairs
            signal_bridge: DoerSignalBridge for UI communication
        """
        self.app = app
        self.hab = hab
        self.hby = self.app.vault.hby
        self.signal_bridge = signal_bridge

        # Rotation parameters
        self.isith = isith
        self.nsith = nsith
        self.count = count
        self.toad = toad
        self.authenticate = authenticate
        self.codes = codes if codes is not None else []
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []

        # Setup doers from vault
        self.proxy = proxy
        self.swain = self.app.vault.swain
        self.postman = self.app.vault.postman

        doers = [doing.doify(self.rotate_do)]

        super(RotateDoer, self).__init__(doers=doers)

    def rotate_do(self, tymth, tock=0.0, **opts):
        """
        Generator method for identifier rotation.

        Performs ONLY the key rotation operation. Authentication and delegation
        are handled separately by AuthenticateWitnessesDoer.

        Args:
            tymth: Tymist function for time management
            tock: Initial tock value

        Yields:
            tock: Current tock value for doer scheduling
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Perform the rotation
            self.hab.rotate(
                isith=self.isith,
                nsith=self.nsith,
                ncount=self.count,
                toad=self.toad,
                cuts=list(self.cuts),
                adds=list(self.adds)
            )

            # Log rotation details
            logger.info(f"Rotation complete for {self.hab.name} ({self.hab.pre})")
            logger.info(f"New Sequence No.: {self.hab.kever.sn}")
            for idx, verfer in enumerate(self.hab.kever.verfers):
                logger.info(f"\tPublic key {idx + 1}: {verfer.qb64}")

            # Update witness states for witnesses that were rotated OUT (cuts) via plugin hooks
            if hasattr(self.app, 'plugin_manager') and self.app.plugin_manager:
                for wit in self.cuts:
                    self.app.plugin_manager.update_witness_state_after_rotation(self.app.vault, wit)
                    logger.info(f"Notified plugins about rotated-out witness {wit}")

            # Set auth_pending if there are witnesses (authentication still needed)
            if self.hab.kever.wits:
                identifier_meta_info = IdentifierMetaInfo(prefix=self.hab.pre, auth_pending=True)
                self.app.vault.db.idm.pin(keys=(self.hab.pre,), val=identifier_meta_info)
                logger.info(f"Set auth_pending=True for {self.hab.pre} (witnesses need authentication)")

            # Signal rotation complete to UI
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="RotateDoer",
                    event_type="rotation_complete",
                    data={
                        'alias': self.hab.name,
                        'pre': self.hab.pre,
                        'sn': self.hab.kever.sn,
                        'has_witnesses': bool(self.hab.kever.wits),
                        'is_delegated': bool(self.hab.kever.delpre),
                        'success': True
                    }
                )

            logger.info(f"Identifier {self.hab.name} ({self.hab.pre}) rotation complete")
            return

        except Exception as e:
            logger.exception(f"RotateDoer failed with exception: {e}")

            # Signal failure to UI
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="RotateDoer",
                    event_type="rotation_failed",
                    data={
                        'alias': self.hab.name if self.hab else None,
                        'pre': self.hab.pre if self.hab else None,
                        'error': str(e),
                        'success': False
                    }
                )
            if self.hab.kever.wits:
                identifier_meta_info = IdentifierMetaInfo(prefix=self.hab.pre, auth_pending=True)
                self.app.vault.db.idm.pin(keys=(self.hab.pre,), val=identifier_meta_info)
            return

class AuthenticateWitnessesDoer(CredentialUpdateDoer):
    """Finish saved witness receipts in order, then complete authentication."""

    def __init__(self, app, hab, codes, proxy=None, signal_bridge=None):
        self.app, self.vault, self.hab = app, app.vault, hab
        self.hby = self.vault.hby
        self.codes, self.proxy = list(codes or []), proxy
        self.signal_bridge = signal_bridge
        self.swain, self.postman = self.vault.swain, self.vault.postman
        self.tip, self.error = hab.kever.serder.said, ''
        super().__init__(doers=[doing.doify(self.authenticate_do)])

    def _check_current(self):
        if (self.app.vault is not self.vault or getattr(self.vault, 'closed', False)
                or not self.vault.db.opened or self.hby.habByPre(self.hab.pre) is not self.hab
                or self.hab.kever.serder.said != self.tip):
            raise kering.ValidationError('The vault or identifier changed. Review authentication again.')

    def _failed(self, error):
        self.error = str(error)
        if self.vault.db.opened:
            self.vault.db.idm.pin((self.hab.pre,), IdentifierMetaInfo(self.hab.pre, auth_pending=True))
        if self.signal_bridge and self.app.vault is self.vault:
            self.signal_bridge.emit_doer_event('AuthenticateWitnessesDoer', 'witness_authentication_failed',
                {'alias': self.hab.name, 'pre': self.hab.pre, 'error': self.error, 'success': False})

    def recur(self, tyme, deeds=None):
        try:
            return super().recur(tyme, deeds)
        except Exception as ex:
            self._failed(ex)
            return True

    def authenticate_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        receiptor = None
        try:
            self._check_current()
            code_time = helping.nowIso8601()
            auths = {}
            for entry in self.codes:
                witness, code = entry.split(':', 1)
                auths[witness] = f'{code}#{code_time}'
            self.codes.clear()
            if self.hab.kever.delpre:
                self.swain.delegation(pre=self.hab.pre, sn=self.hab.kever.sn,
                                      auths=auths, proxy=self.proxy)
                while not self.swain.complete(self.hab.kever.prefixer, coring.Seqner(sn=self.hab.kever.sn)):
                    self._check_current()
                    yield self.tock
                sender = self.proxy if self.proxy is not None else self.hab
                yield from self.postman.sendEventToDelegator(hab=self.hab, sender=sender, fn=self.hab.kever.sn)
            else:
                for sn in range(self.hab.kever.sn + 1):
                    self._check_current()
                    yield self.tock
                    self._check_current()
                    event = serdering.SerderKERI(raw=self.hab.msgOwnEvent(sn=sn))
                    threshold = self.hab.kvy.fetchEstEvent(self.hab.pre, sn).bner.num
                    if len(self.hab.db.wigs.get((self.hab.pre, event.said))) >= threshold:
                        continue
                    if receiptor is None:
                        receiptor = LocksmithReceiptor(hby=self.hby)
                        self.extend([receiptor])
                    # A witness may already have advanced beyond this saved event.
                    fetch = receiptor.get(self.hab.pre, sn=sn)
                    deadline = self.tyme + 15.0
                    try:
                        for _ in fetch:
                            self._check_current()
                            if self.tyme >= deadline:
                                raise TimeoutError(f'Receipt lookup timed out for event {sn}')
                            yield self.tock
                    finally:
                        fetch.close()
                    if len(self.hab.db.wigs.get((self.hab.pre, event.said))) >= threshold:
                        continue
                    witnesses = [wit.qb64 for wit in self.hab.kvy.fetchWitnessState(self.hab.pre, sn)]
                    if witnesses != self.hab.kever.wits or threshold != self.hab.kever.toader.num:
                        raise kering.ValidationError(f'Event {sn} needs its original witness configuration')
                    yield from self.receipt(self.hab, event, receiptor, auths)
            self._check_current()
            if self.app.plugin_manager:
                for witness in self.hab.kever.wits:
                    self.app.plugin_manager.update_witness_state_after_auth(self.vault, witness)
            self.vault.db.idm.pin((self.hab.pre,), IdentifierMetaInfo(self.hab.pre, auth_pending=False))
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event('AuthenticateWitnessesDoer', 'witness_authentication_success',
                    {'alias': self.hab.name, 'pre': self.hab.pre, 'sn': self.hab.kever.sn, 'success': True})
        except Exception as ex:
            logger.exception('Witness authentication failed')
            self._failed(ex)
        finally:
            self.codes.clear()
            if receiptor is not None:
                self.remove([receiptor])
