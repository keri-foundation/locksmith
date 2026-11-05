# -*- encoding: utf-8 -*-

"""
KERI
locksmith.core.basing package

"""

from dataclasses import dataclass

from keri.core import SerderACDC
from keri.db import dbing, koming, subing


@dataclass
class OTPSecret:
    vault: str
    secret: str

class OTPSecrets(dbing.LMDBer):

    TailDirPath = "keri/locksmith"
    AltTailDirPath = ".keri/locksmith"
    TempPrefix = "locksmith"

    def __init__(self, name="locksmithOtpSecrets", headDirPath=None, reopen=True, **kwa):
        self.otpSecrets = None

        super(OTPSecrets, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):  # type: ignore[override]
        """
        Reopen database and initialize sub-dbs
        """
        super(OTPSecrets, self).reopen(**kwa)

        self.otpSecrets = koming.Komer(db=self, subkey='otpSecrets.', klas=OTPSecret)

        return self.env

@dataclass
class IdentifierMetaInfo:
    """
    Class to track identifier metadata
    """
    prefix: str
    auth_pending: bool

@dataclass
class BrowserPluginSettings:
    """
    Track browser plugin connection settings.

    Stores the Locksmith Identifier (HAD prefix) and Plugin Identifier
    for browser plugin integration.
    """
    locksmith_identifier: str
    locksmith_alias: str
    plugin_identifier: str | None = None


@dataclass
class IssuedCredential:
    raw: str
    blinder: str = ''
    update: str = ''
    stream: str = ''
    witness_threshold: int = 0
    created_at: str = ''


@dataclass
class PresentationProof:
    blinder: str
    update: str


@dataclass
class CredentialRequest:
    sender: str
    recipient: str
    schema: str
    plan: list
    ax: list | None = None
    stream: str = ''
    submitted: bool = False


@dataclass
class AcceptedCredential:
    grant: str
    admit: str
    accepted_at: str = ''


@dataclass
class GrantReceipt:
    credential: str
    admit: str = ''
    send: bool = False
    status: str = 'preparing'
    error: str = ''


@dataclass
class ProofingSession:
    citizen: str
    proofer: str
    nonce: str
    expires_at: float
    anchor_sn: int = -1
    anchor_said: str = ''
    receipt: str = ''
    status: str = 'challenge'


@dataclass
class IpexSubmission:
    status: str = 'pending'
    attempts: int = 0
    retry_at: float = 0.0
    error: str = ''
    missing_route: bool = False


@dataclass
class MailboxFrame:
    raw: str


@dataclass
class MailboxMigration:
    until: float
    witnesses: list[str]


@dataclass
class ConnectionRecord:
    """Consecutive connection failures, retained across wallet reopen."""

    attempts: int = 0
    retry_at: float = 0.0
    error: str = ''
    paused: bool = False


class LocksmithBaser(dbing.LMDBer):
    TailDirPath = "keri/rt"
    AltTailDirPath = ".keri/rt"
    TempPrefix = "rt"

    def __init__(self, name="locksmith", headDirPath=None, reopen=True, **kwa):
        """
        Initialize the LocksmithBaser database.

        Args:
            name: Database name (typically the vault name)
            headDirPath: Base directory path for the database
            reopen: Whether to reopen the database on init
            **kwa: Additional keyword arguments passed to LMDBer
        """

        # identifier metadata
        self.idm = None

        # Browser plugin settings
        self.pluginSettings = None

        super(LocksmithBaser, self).__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):  # type: ignore[override]
        """
        Reopen database and initialize sub-dbs
        """
        super(LocksmithBaser, self).reopen(**kwa)

        # Identifier metadata storage
        self.idm = koming.Komer(db=self, subkey='.idm', klas=IdentifierMetaInfo)

        # Browser plugin settings storage
        self.pluginSettings = koming.Komer(
            db=self,
            subkey='pluginSettings.',
            klas=BrowserPluginSettings
        )

        # Schema-to-issuer choices and private wallet inventory. Received
        # credentials refer to the evidence retained by Keripy's exchange store.
        self.issuers = subing.Suber(db=self, subkey='issuers.')
        self.issued = koming.Komer(db=self, subkey='issued.', klas=IssuedCredential)
        self.accepted = koming.Komer(db=self, subkey='accepted.', klas=AcceptedCredential)
        self.receipts = koming.Komer(db=self, subkey='receipts.', klas=GrantReceipt)
        self.proofing = koming.Komer(db=self, subkey='proofing.', klas=ProofingSession)
        # Private creation intent: registry alias -> native inception, not an accepted registry.
        self.registry_creations = subing.SerderSuber(db=self, subkey='rcrt.', klas=SerderACDC)
        # Private request intent: operation ID -> inputs and exact signed Apply.
        # Retain across restart so creation and delivery retries reuse one registry.
        self.requests = koming.Komer(db=self, subkey='crqs.', klas=CredentialRequest)
        # Private presentation proofs: one returned blinder/update per (Grant, registry).
        self.presentations = koming.Komer(db=self, subkey='prpf.', klas=PresentationProof)
        self.outbox = koming.Komer(db=self, subkey='outbox.', klas=IpexSubmission)
        self.inbox = koming.Komer(db=self, subkey='inbox.', klas=MailboxFrame)
        self.mailboxMigrations = koming.Komer(db=self, subkey='mailboxMigrations.', klas=MailboxMigration)
        self.connections = koming.Komer(db=self, subkey='connections.', klas=ConnectionRecord)

        return self.env
