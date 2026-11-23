# -*- encoding: utf-8 -*-
"""
locksmith.core.indirecting module

Mailbox director and supporting classes

"""
import datetime
import ssl
import time
import functools

from hio.base import doing
from hio.core.http.httping import HTTPException, PrematureClosure
from hio.help import decking
from keri import help, kering
from keri.app import httping, agenting
from keri.app.habbing import GroupHab
from keri.core import Diger, Texter, parsing, routing
from keri.db import basing
from keri.help import helping
from ordered_set import OrderedSet as oset
from locksmith.db.basing import ConnectionRecord, MailboxFrame, MailboxMigration
from locksmith.core.messaging import NETWORK_TIMEOUT, RETRY_DELAYS

logger = help.ogler.getLogger()


def receiving_endpoints(hab):
    """Return the witnesses and mailboxes authorized by this identifier."""
    if isinstance(hab, GroupHab) or not hab.accepted:
        return set()
    endpoints = set(hab.kever.wits)
    endpoints.update(eid for (_, _, eid), end in hab.db.ends.getTopItemIter(
        keys=(hab.pre, kering.Roles.mailbox)) if end.allowed)
    return endpoints


class MailboxDirector(doing.DoDoer):
    """Poll authorized endpoints and retain mailbox frames before advancing their cursors."""

    def __init__(self, hby, topics, rgy, kvy, exc, db, ims=None,
                 rep=None, cues=None, rvy=None, **kwa):
        self.hby = hby
        self.db = db
        self.rgy = rgy
        self.exchanger = exc
        self.rep = rep
        self.topics = topics
        self.pollers = list()
        self.cues = cues if cues is not None else decking.Deck()

        self.ims = ims if ims is not None else bytearray()
        self.messages = decking.Deck()

        doers = []
        doers.extend([doing.doify(self.pollDo),
                      doing.doify(self.msgDo),
                      doing.doify(self.escrowDo)])

        self.rtr = routing.Router()
        self.rvy = rvy

        self.kvy = kvy
        self.kvy.registerReplyRoutes(self.rtr)

        self.parser = parsing.Parser(ims=self.ims,
                                     framed=True,
                                     kvy=self.kvy,
                                     exc=self.exchanger,
                                     rvy=self.rvy,
                                     version=kering.Vrsn_2_0)

        super(MailboxDirector, self).__init__(doers=doers, **kwa)

    @property
    def mailboxes(self):
        return oset([(poller.hab.name, poller.hab.pre, poller.mailbox) for poller in self.pollers])

    def pollDo(self, tymth=None, tock=0.0, **kwa):
        """Drain queued frames and reconcile pollers with authorized routes."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            # Retain queued frames before a stopped or changed poller is removed.
            for item in self.processPollIter():
                self.messages.append(item)
                _ = (yield self.tock)
            wanted = {(hab.pre, eid): (hab, topics) for hab in self.hby.habs.values()
                      for eid, topics in self.receiving_topics(hab).items()}
            for poller in list(self.pollers):
                target = wanted.get((poller.pre, poller.mailbox))
                if (target is None or poller.topics != target[1]
                        or (poller.done and not poller.state.paused and time.time() >= poller.retry_at)):
                    self.remove_poller(poller.hab, poller.mailbox)
            for (pre, eid), (hab, topics) in wanted.items():
                self.add_poller(hab, eid, topics=topics)
            _ = (yield 1.0)

    def add_pollers(self, hab):
        """
        Poll every witness and authorized mailbox of an accepted single identifier.

        Group identifiers are not listened for yet.

        Parameters:
            hab: The habitat whose messages are polled.
        """
        for eid, topics in self.receiving_topics(hab).items():
            self.add_poller(hab, eid, topics=topics)

    def receiving_topics(self, hab):
        """Poll authorized mailboxes for credentials and forwarded witness messages."""
        endpoints = receiving_endpoints(hab)
        mailboxes = {eid for (_, _, eid), end in hab.db.ends.getTopItemIter(
            keys=(hab.pre, kering.Roles.mailbox)) if end.allowed}
        migration = self.db.mailboxMigrations.get(keys=(hab.pre,))
        if mailboxes and migration is None:
            # An unread first message has no local cursor yet. Start at zero
            # for every witness already configured when the route changes.
            migration = MailboxMigration(until=time.time() + 86400, witnesses=list(hab.kever.wits))
            self.db.mailboxMigrations.pin(keys=(hab.pre,), val=migration)
        result = {}
        for eid in endpoints:
            topics = []
            if eid in hab.kever.wits:
                topics = [topic for topic in self.topics if topic != '/credential']
                if migration is None or (eid in migration.witnesses and time.time() < migration.until):
                    if '/credential' in self.topics:
                        topics.append('/credential')
            if eid in mailboxes:
                topics.extend(topic for topic in self.topics
                              if topic in ('/credential', '/receipt', '/replay', '/reply') and topic not in topics)
            if topics:
                result[eid] = topics
        return result

    def add_poller(self, hab, mailbox, *, topics=None):
        """
        Start polling mailbox for hab unless a poller for that pair already runs.

        Parameters:
            hab: The habitat whose messages are polled.
            mailbox: The witness or mailbox prefix to poll.
        """
        if any(poller.pre == hab.pre and poller.mailbox == mailbox for poller in self.pollers):
            return

        poller = Poller(hab=hab, topics=self.topics if topics is None else topics, mailbox=mailbox, db=self.db)
        self.pollers.append(poller)
        self.extend([poller])

    def retry_receiving(self, pre):
        """Resume paused reads without discarding retained frames or cursors."""
        for keys, _ in self.db.connections.getTopItemIter(keys=(pre,)):
            self.db.connections.pin(keys, ConnectionRecord())
        for poller in self.pollers:
            if poller.pre == pre:
                poller.state = ConnectionRecord()
                poller.error, poller.retry_at = '', 0.0

    def processPollIter(self):
        """
        Drain the messages queued by each mailbox poller.

        Yields:
            tuple: (message, commit) where commit records the message's topic
                position after the raw frame is retained.

        """
        mail = []
        for poller in self.pollers:  # get responses from all behaviors
            while poller.msgs:
                msg, topic, idx = poller.msgs.popleft()
                mail.append((msg, functools.partial(poller.commit, topic, idx)))

        while mail:  # iteratively process each response in responses
            msg = mail.pop(0)
            yield msg

    def msgDo(self, tymth=None, tock=0.0, **kwa):
        """
        Parse queued mailbox messages.

        Select the attachment version for each frame before validation.

        Scheduler:
            Wrap this generator with doing.doify to schedule it as a doer.
            Yield the delay before the next scheduler step.

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns the associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            Add doing.doify(self.msgDo) to the doers list.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            while self.messages:
                msg, commit = self.messages.popleft()
                # Arrival order keeps a sender's KEL ahead of the messages it signs.
                key = (f'{time.time_ns():020d}', Diger(ser=bytes(msg)).qb64)
                self.db.inbox.put(key, MailboxFrame(Texter(raw=bytes(msg)).qb64))
                if commit is not None:
                    commit()
                yield self.tock
            for keys, frame in list(self.db.inbox.getTopItemIter()):
                msg = bytearray(Texter(qb64=frame.raw).raw)
                version = kering.Vrsn_2_0
                try:
                    v1_body = (kering.sniff(msg) == kering.Colds.msg
                               and kering.smell(msg).pvrsn == kering.Vrsn_1_0)
                except kering.KeriError:
                    v1_body = False  # Let the parser discard the malformed frame.
                if v1_body:
                    # V1 bodies do not identify their attachment genus. Extract
                    # the whole frame without validation before choosing V1.
                    try:
                        yield from self.parser.groupParsator(
                            ims=bytearray(msg), framed=True, local=False,
                            version=kering.Vrsn_2_0, processive=False)
                    except Exception:
                        version = kering.Vrsn_1_0
                try:
                    self.parser.parse(ims=msg, version=version, local=False)
                except Exception:
                    logger.exception('Mailbox frame could not be processed')
                # Native processing owns the message once the parser has run.
                self.db.inbox.rem(keys)
                yield self.tock
            yield 1.0

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """
        Retry pending key, reply, exchange, and registry evidence.

        Scheduler:
            Wrap this generator with doing.doify to schedule it as a doer.
            Yield the delay before the next scheduler step.

        Parameters:
            tymth is injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns the associated Tymist .tyme.
            tock is injected initial tock value

        Usage:
            Add doing.doify(self.escrowDo) to the doers list.
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.kvy.processEscrows()
            if self.rvy:
                self.rvy.processEscrowReply()
            self.exchanger.processEscrow()
            self.rgy.processEscrows()
            self.kvy.kramer.cues.clear()
            # The vault registry worker consumes proof cues and retries escrow.

            yield

    @property
    def times(self):
        times = dict()
        for poller in self.pollers:  # get responses from all pollers
            times |= poller.times

        return times

    def remove_poller(self, hab, mailbox):
        """
        Remove a Poller instance from the director.

        Finds the poller matching the hab and mailbox, removes it from the pollers list,
        and properly closes it via the DoDoer remove mechanism.

        Parameters:
            hab: The habitat associated with the poller to remove.
            mailbox: The mailbox EID associated with the poller to remove.
        """
        # Find the poller to remove
        poller_to_remove = None
        for poller in self.pollers:
            if poller.hab.pre == hab.pre and poller.mailbox == mailbox:
                poller_to_remove = poller
                break

        if poller_to_remove is not None:
            self.pollers.remove(poller_to_remove)
            self.remove([poller_to_remove])  # This closes the poller via DoDoer.remove()
            logger.info(f"Removed poller for hab={hab.pre}, mailbox={mailbox}")
        else:
            logger.warning(f"No poller found for hab={hab.pre}, mailbox={mailbox}")


class Poller(doing.DoDoer):
    """
    Polls remote SSE endpoint for event that are KERI messages to be processed

    Queued messages are (message, topic, index) tuples. The stored topic position
    advances only through commit, after the director has retained the raw message.
    """

    def __init__(self, hab, mailbox, topics, msgs=None, retry=1000, db=None, **kwa):
        self.hab = hab
        self.pre = hab.pre
        self.mailbox = mailbox
        self.topics = topics
        self.retry = retry
        self.db = db
        self.state = (db.connections.get((hab.pre, mailbox)) if db else None) or ConnectionRecord()
        if self.state.paused and self.state.retry_at:
            # Older wallets set a retry time even when they stopped polling.
            # Recheck this authorized route once. New permanent stops have no retry time.
            self.state = ConnectionRecord()
            self._save_connection()
        self.error = self.state.error
        self.connected = False
        self.msgs = msgs if msgs is not None else decking.Deck()
        self.times = dict()
        self.introduced = None
        self.retry_at = self.state.retry_at

        doers = [doing.doify(self.eventDo)]

        super(Poller, self).__init__(doers=doers, **kwa)

    def recur(self, tyme, deeds=None):
        """Contain HTTP child failures so one offline mailbox cannot stop the vault."""
        try:
            return super().recur(tyme=tyme, deeds=deeds)
        except (OSError, HTTPException) as exc:
            permanent = (isinstance(exc, ssl.SSLCertVerificationError)
                         or isinstance(exc, HTTPException) and not isinstance(exc, PrematureClosure))
            self._failed(str(exc), permanent=permanent)
            logger.warning('Mailbox %s disconnected: %s', self.mailbox, exc)
            return True  # HIO closes this poller and its remaining child sockets.

    def _save_connection(self):
        if self.db is not None:
            self.db.connections.pin((self.pre, self.mailbox), self.state)

    def _failed(self, error, *, permanent=False):
        self.error, self.connected = error, False
        self.state.error = error
        self.state.attempts += 1
        self.state.paused = permanent
        delay = RETRY_DELAYS[min(self.state.attempts, len(RETRY_DELAYS)) - 1]
        self.retry_at = 0.0 if permanent else time.time() + delay
        self.state.retry_at = self.retry_at
        self._save_connection()

    def eventDo(self, tymth=None, tock=0.0, **kwa):
        """Query mailbox topics from their saved cursors and retain retry state."""
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        witrec = self.hab.db.tops.get((self.pre, self.mailbox))
        if witrec is None:
            witrec = basing.TopicsRecord(topics=dict())

        while self.retry > 0:
            if self.state.paused:
                return
            while time.time() < self.state.retry_at:
                yield min(1.0, self.state.retry_at - time.time())
            try:
                client, clientDoer = agenting.httpClient(self.hab, self.mailbox)
            except (kering.MissingEntryError, ValueError) as e:
                self._failed(str(e), permanent=True)
                return

            self.extend([clientDoer])
            self.error = ''

            # A mailbox need not witness this identifier. Introduce its KEL
            # before the first signed query and after rotation.
            end = self.hab.db.ends.get(keys=(self.pre, kering.Roles.mailbox, self.mailbox))
            establishment = self.hab.kever.lastEst
            if end is not None and end.allowed and self.introduced != establishment:
                stream = bytearray()
                for message in self.hab.db.cloneDelegation(self.hab.kever, gvrsn=kering.Vrsn_2_0):
                    stream.extend(message)
                stream.extend(self.hab.replay(gvrsn=kering.Vrsn_2_0))
                client.request(method='PUT', path='/', body=bytes(stream), headers={
                    'Content-Type': 'application/cesr', 'Content-Length': str(len(stream)),
                    httping.CESR_DESTINATION_HEADER: self.mailbox,
                })
                deadline = self.tyme + NETWORK_TIMEOUT
                while not client.responses and self.tyme < deadline:
                    yield self.tock
                response = client.respond() if client.responses else None
                self.remove([clientDoer])
                status = response.status if response else None
                if status is None or not 200 <= status < 300 or response.errored:
                    error = f'Mailbox introduction failed ({status})' if status else 'Mailbox introduction timed out'
                    self._failed(response.error if response and response.error else error,
                                 permanent=status is not None and 400 <= status < 500 and status not in (408, 429))
                    return
                self.introduced = establishment
                continue  # The mailbox may close the introduction connection.

            topics = dict()
            q = dict(pre=self.pre, topics=topics)
            for topic in self.topics:
                if topic in witrec.topics:
                    topics[topic] = witrec.topics[topic] + 1
                else:
                    topics[topic] = 0

            # Create query message
            if isinstance(self.hab, GroupHab):
                msg = self.hab.mhab.query(
                    pre=self.pre,
                    src=self.mailbox,
                    route="mbx",
                    query=q,
                    version=kering.Vrsn_2_0,
                    gvrsn=kering.Vrsn_2_0,
                    kind=kering.Kinds.json,
                )  # type: ignore
            else:
                msg = self.hab.query(
                    pre=self.pre,
                    src=self.mailbox,
                    route="mbx",
                    query=q,
                    version=kering.Vrsn_2_0,
                    gvrsn=kering.Vrsn_2_0,
                    kind=kering.Kinds.json,
                )

            httping.createCESRRequest(msg, client, dest=self.mailbox)

            deadline = self.tyme + NETWORK_TIMEOUT
            while client.requests:
                if self.tyme >= deadline:
                    self._failed('Mailbox request timed out')
                    self.remove([clientDoer])
                    return
                yield self.tock

            created = helping.nowUTC()
            received_headers = False
            while True:

                now = helping.nowUTC()
                if (now - created > datetime.timedelta(seconds=30)
                        or self.hab.kever.lastEst != establishment):
                    self.remove([clientDoer])
                    self.connected = False
                    if not received_headers and self.hab.kever.lastEst == establishment:
                        self._failed('Mailbox connection timed out')
                        return
                    break

                status = client.respondent.status
                if status is not None and status >= 400:
                    self._failed(f'Mailbox read failed ({status})',
                                 permanent=400 <= status < 500 and status not in (408, 429))
                    self.remove([clientDoer])
                    return
                if (client.respondent.headed and status is not None and 200 <= status < 300
                        and not client.respondent.evented):
                    self._failed('Mailbox did not return an event stream', permanent=True)
                    self.remove([clientDoer])
                    return
                if (client.respondent.evented and status is not None
                        and 200 <= status < 300 and not received_headers):
                    received_headers = True
                    self.connected, self.error = True, ''
                    self.state = ConnectionRecord()
                    self._save_connection()

                while client.events:
                    self.connected = True
                    evt = client.events.popleft()
                    if "retry" in evt:
                        self.retry = evt["retry"]
                    if "id" not in evt or "data" not in evt or "name" not in evt:
                        logger.error(f"bad mailbox event: {evt}")
                        continue
                    idx = evt["id"]
                    msg = evt["data"]
                    tpc = evt["name"]

                    if idx is None or not msg or tpc not in self.topics:
                        logger.error(f"bad mailbox event: {evt}")
                        continue
                    try:
                        idx = int(idx)
                        if idx < 0:
                            raise ValueError('Negative mailbox position')
                    except (TypeError, ValueError):
                        self.error = 'The mailbox returned an invalid message position.'
                        continue

                    # Only the next query uses this in-memory position. The
                    # stored one waits for commit.
                    witrec.topics[tpc] = idx
                    self.times[tpc] = helping.nowUTC()
                    self.msgs.append((msg.encode("utf-8"), tpc, idx))
                    yield self.tock

                if client.respondent.evented:
                    self.retry = max(1000, client.respondent.retry)
                if client.respondent.ended:
                    self.remove([clientDoer])
                    self.connected = False
                    if not received_headers:
                        status = client.respondent.status
                        self._failed(f'Mailbox read failed ({status})',
                                     permanent=status is not None and 400 <= status < 500
                                     and status not in (408, 429))
                        return
                    break
                yield 0.25
            yield self.retry / 1000

    def commit(self, topic, idx):
        """
        Store idx as the last processed index for topic, if it is newer.

        Parameters:
            topic (str): mailbox topic of the processed message.
            idx (int): mailbox index of the processed message.
        """
        keys = (self.pre, self.mailbox)
        record = self.hab.db.tops.get(keys)
        if record is None:
            record = basing.TopicsRecord(topics=dict())
        if record.topics.get(topic, -1) < idx:
            record.topics[topic] = idx
            self.hab.db.tops.pin(keys, record)
