# -*- encoding: utf-8 -*-
"""
locksmith.core.receipting module

Locksmith-local witness receipting compatibility helpers.
"""
from functools import partial
from socket import gaierror

from keri.app import agenting, httping
from keri import kering
from locksmith.core.remoting import message_version


def reverse_kel(hab, said):
    """Yield cloned events from the selected branch tip back to inception."""
    expected_sn = None
    while True:
        event = hab.db.evts.get((hab.pre, said))
        fn = hab.db.fons.get((hab.pre, said))
        if event is None or fn is None or (expected_sn is not None and event.sn != expected_sn):
            raise kering.MissingEntryError(f'Incomplete key event history at {said}')
        yield hab.db.cloneEvtMsg(pre=hab.pre, fn=fn.num, dig=said, gvrsn=kering.Vrsn_2_0)
        if event.sn == 0:
            return
        said, expected_sn = event.prior, event.sn - 1


def replay_through(hab, said):
    """Clone the controller's KEL through the selected event on its own branch."""
    return b''.join(reversed(list(reverse_kel(hab, said))))


class LocksmithReceiptor(agenting.Receiptor):
    """Collect receipts and catch new witnesses up through the requested rotation."""

    def receipt(self, pre, sn=None, auths=None):
        hab = self.hby.habByPre(pre)
        if hab is None:
            raise kering.MissingEntryError(f'{pre} is not a local identifier')
        event = hab.kever.serder if sn is None else hab.getOwnEvent(sn=sn)[0]
        if event.ilk != kering.Ilks.rot or not event.adds:
            return (yield from super().receipt(pre, sn=event.sn, auths=auths))

        # Keripy's catchup callback receives no event. Bind this request's
        # history before starting I/O, so concurrent receipts cannot change it.
        replay = b''.join(hab.db.cloneDelegation(hab.kever)) + replay_through(hab, event.said)
        worker = agenting.Receiptor(hby=self.hby)
        worker.catchup = partial(self.catchup, replay=replay)
        self.extend([worker])
        try:
            return (yield from worker.receipt(pre, sn=event.sn, auths=auths))
        finally:
            self.remove([worker])

    def get(self, pre, sn=None):
        """Retrieve existing receipts with the hosted witness destination header."""
        hab = self.hby.habByPre(pre)
        if hab is None:
            raise kering.MissingEntryError(f'{pre} is not a local identifier')
        sn = hab.kever.sn if sn is None else sn
        event = hab.getOwnEvent(sn=sn)[0]
        threshold = hab.kvy.fetchEstEvent(pre, sn).bner.num
        for witness in hab.kvy.fetchWitnessState(pre, sn):
            if len(hab.db.wigs.get((pre, event.said))) >= threshold:
                return
            try:
                client, client_doer = agenting.httpClient(hab, witness.qb64)
            except (kering.MissingEntryError, gaierror):
                continue
            self.extend([client_doer])
            try:
                client.request(method='GET', path='/receipts', qargs={'pre': pre, 'sn': sn},
                               headers={httping.CESR_DESTINATION_HEADER: witness.qb64})
                while not client.responses:
                    yield self.tock
                reply = client.respond()
                if reply.status == 200:
                    hab.psr.parseOne(bytearray(reply.body), version=message_version(reply.body))
            finally:
                self.remove([client_doer])

    def catchup(self, pre, wit, *, replay=None):
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        client, client_doer = agenting.httpClient(hab, wit)
        self.extend([client_doer])

        try:
            sent = httping.streamCESRRequests(
                client=client,
                dest=wit,
                ims=hab.replay(pre=pre) if replay is None else bytearray(replay),
            )
            while len(client.responses) < sent:
                yield self.tock

            while client.responses:
                client.respond()
        finally:
            self.remove([client_doer])
