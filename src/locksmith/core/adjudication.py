# -*- encoding: utf-8 -*-
"""
locksmith.core.adjudication module

"""
import random
from time import monotonic

from hio.base import doing
from hio.help import decking
from keri import help
from keri.app import watching
from keri.app.agenting import httpClient
from keri.app.httping import streamCESRRequests
from keri.core import eventing, routing, parsing

from locksmith.core.messaging import NETWORK_TIMEOUT
from locksmith.core.remoting import message_version

logger = help.ogler.getLogger(__name__)


class Watchmen(doing.DoDoer):
    """Poll enabled watchers with at most one new request per scheduler turn."""

    MaxRequests = 4

    def __init__(self, hby, tock=15.0, **kwa):
        self.hby = hby
        self.interval = tock
        self.cues = decking.Deck()
        super().__init__(doers=[doing.doify(self.poll_do)], **kwa)

    def poll_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        rounds, requests = {}, []
        while True:
            watched = {}
            for (cid, wid, oid), record in self.hby.db.obvs.getTopItemIter():
                if record.enabled:
                    watched.setdefault((cid, oid), []).append(wid)
            for key, query in list(rounds.items()):
                if query.done or query.wids != watched.get(key):
                    self.remove([query])
                    del rounds[key]

            for (cid, oid), wids in watched.items():
                if (hab := self.hby.habByPre(cid)) is None:
                    continue
                if (query := rounds.get((cid, oid))) is None:
                    query = rounds[cid, oid] = KeyStateQuerier(self.hby, hab, oid, wids, self.cues)
                    self.extend([query])
                for wid in wids:
                    while len(requests) >= self.MaxRequests:
                        requests = [(owner, wit, req) for owner, wit, req in requests
                                    if owner.requests.get(wit) is req and not req.done]
                        if len(requests) >= self.MaxRequests:
                            yield self.tock
                    # A cut can arrive while other identifiers use the available slots.
                    record = self.hby.db.obvs.get((cid, wid, oid))
                    if record and record.enabled and (req := query.request(wid)):
                        requests.append((query, wid, req))
                        yield self.tock
            yield self.interval


class KeyStateQuerier(doing.DoDoer):
    """Wait for a signed state notice from each watcher in this round."""

    def __init__(self, hby, hab, oid, wids, cues, **opts):
        self.hby = hby
        self.hab = hab
        self.oid = oid
        self.wids = wids
        self.cues = cues
        self.requests = {}
        self.previous = {}
        for wid in wids:
            keys = (oid, wid)
            if (saider := hby.db.knas.get(keys)) is not None:
                self.previous[keys] = saider
                hby.db.knas.rem(keys)
        super().__init__(doers=[], **opts)

    def request(self, wid):
        if self.done:
            return None
        if previous := self.requests.get(wid):
            if not previous.done:
                return None
            self.remove([previous])
            del self.requests[wid]
        if self.hby.db.knas.get((self.oid, wid)) is None:
            query = WatcherInquisitor(hab=self.hab, pre=self.oid, wit=wid, route="ksn",
                                      query={"s": "0", "fn": "0"})
            self.extend([query])
            self.requests[wid] = query
            return query
        return None

    def exit(self, deeds=None):
        super().exit(deeds)
        if deeds is None:
            self.requests.clear()
            if self.hby.db.opened:
                for keys, saider in self.previous.items():
                    if self.hby.db.knas.get(keys) is None:
                        self.hby.db.knas.put(keys, saider)

    def recur(self, tyme, deeds=None):
        try:
            super().recur(tyme, deeds)
            reports = []
            for wid in self.wids:
                report = self.hby.db.knas.get((self.oid, wid))
                if report is None:
                    return False
                reports.append(report)
            # The local KEL still shows a missed update after a cut or vault reopen.
            if self.oid in self.hby.kevers:
                local = self.hby.kevers[self.oid].serder.said
                if any(report.qb64 != local for report in reports):
                    watching.Adjudicator(self.hby, self.hab, cues=self.cues).adjudicate(self.oid)
            return True
        except Exception:
            logger.exception('Watcher query failed for %s', self.oid)
            return True


class KeyStateVarianceAuthority(doing.DoDoer):

    def __init__(self, hby, notifier, cues=None):
        self.hby = hby
        self.notifier = notifier
        self.cues = cues if cues is not None else decking.Deck()
        self.queries = {}
        self.pending = {}
        super().__init__(doers=[], always=True, tock=1.0)

    def recur(self, tyme, deeds=None):
        for key, query in list(self.queries.items()):
            if query.done:
                self.remove([query])
                del self.queries[key]
                if query.retry:
                    self.pending[key] = query.state

        while self.cues:
            cue = self.cues.pull()
            if cue['kin'] == 'keyStateUpdate':
                state = random.choice(cue['aheads'])
                cid = cue['cid']
                key = (cid, state.pre)
                if key not in self.queries and self.hby.kevers[state.pre].sn < state.sn:
                    self.pending[key] = state
        if self.pending and len(self.queries) < Watchmen.MaxRequests:
            key = next(iter(self.pending))
            state = self.pending.pop(key)
            hab = self.hby.habByPre(key[0])
            if hab is not None:
                query = SeqNoQuerier(self.hby, hab, state, self.notifier)
                self.queries[key] = query
                self.extend([query])
        return super().recur(tyme, deeds)


class SeqNoQuerier(doing.DoDoer):
    """Wait for the requested KEL event, including delivery through the mailbox."""

    def __init__(self, hby, hab, state, notifier):
        self.hby = hby
        self.hab = hab
        self.state = state
        self.notifier = notifier
        self.witq = None
        self.deadline = None
        self.retry = False
        super().__init__(doers=[])

    def recur(self, tyme, deeds=None):
        state = self.state
        observed = self.hby.db.obvs.get((self.hab.pre, state.wit, state.pre))
        if not observed or not observed.enabled:
            return True
        kever = self.hby.kevers[state.pre]
        if kever.sn >= state.sn:
            if self.hby.db.kels.getLast(keys=state.pre, on=state.sn) == state.dig:
                self.notifier.add(dict(r='/keystate/update', pre=state.pre, sn=state.sn, dig=state.dig))
            return True
        if self.deadline is None:
            self.deadline = tyme + NETWORK_TIMEOUT
            self.witq = WatcherInquisitor(hab=self.hab, pre=state.pre, wit=state.wit, route="logs",
                                          query={"s": f"{state.sn:x}", "fn": f"{kever.sn + 1:x}"})
            self.extend([self.witq])
        if tyme >= self.deadline:
            self.retry = True
            return True
        try:
            super().recur(tyme, deeds)
        except Exception:
            logger.exception('Watcher replay failed for %s', state.pre)
            self.remove([self.witq])
        return False


class WatcherInquisitor(doing.DoDoer):

    """Send a single signed query and release its HTTP client when it finishes."""

    def __init__(self, *, hab, pre, wit, route, query):
        super().__init__(doers=[doing.doify(self.execute, hab=hab, pre=pre, wit=wit, route=route, query=query)])

    def execute(self, tymth, *, hab, pre, wit, route, query, **opts):
        self.wind(tymth)
        yield self.tock
        try:
            client, client_doer = httpClient(hab, wit)
            self.extend([client_doer])
        except Exception:
            logger.exception("Unable to create HTTP client for watcher %s", wit)
            return

        try:
            msg = hab.query(pre, src=wit, route=route, query=query, version=eventing.Vrsn_2_0,
                            gvrsn=eventing.Vrsn_2_0, kind=eventing.Kinds.json)
            streamCESRRequests(client=client, dest=wit, ims=bytearray(msg), path="/", headers=dict())
            deadline = monotonic() + NETWORK_TIMEOUT
            while not client.responses:
                if monotonic() >= deadline:
                    logger.warning("Watcher %s timed out querying %s", wit, pre)
                    return
                yield self.tock

            reply = client.respond()
            if reply.status == 200:
                ims = bytearray(reply.body)
                router = routing.Router()
                rvy = routing.Revery(db=hab.db, rtr=router)
                kvy = eventing.Kevery(db=hab.db, lax=True, rvy=rvy)
                kvy.registerReplyRoutes(router=router)
                parsing.Parser(framed=True, kvy=kvy, rvy=rvy, local=True,
                               version=message_version(ims)).parse(ims)
            elif reply.status != 204:
                logger.info("Invalid response %s from watcher %s", reply.status, wit)
        finally:
            self.remove([client_doer])
