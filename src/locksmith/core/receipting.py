# -*- encoding: utf-8 -*-
"""
locksmith.core.receipting module

Locksmith-local witness receipting compatibility helpers.
"""
from socket import gaierror

from keri.app import agenting, httping
from keri import kering
from locksmith.core.remoting import message_version


class LocksmithReceiptor(agenting.Receiptor):
    """Receiptor with fixed witness catch-up behavior.

    keripy replays new-witness catch-up one event at a time and only waits
    for the first HTTP response before tearing down the client. When a controller
    already has witnessed history, newly added witnesses can miss later replayed
    events and then reject the next `/receipts` request with HTTP 202.

    Locksmith only overrides the broken replay strategy here: send the full
    KEL replay in one burst, wait for all HTTP responses, then drain them
    before removing the client doer.
    """

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

    def catchup(self, pre, wit):
        if pre not in self.hby.prefixes:
            raise kering.MissingEntryError(f"{pre} not a valid AID")

        hab = self.hby.habs[pre]
        client, client_doer = agenting.httpClient(hab, wit)
        self.extend([client_doer])

        try:
            sent = httping.streamCESRRequests(
                client=client,
                dest=wit,
                ims=hab.replay(pre=pre),
            )
            while len(client.responses) < sent:
                yield self.tock

            while client.responses:
                client.respond()
        finally:
            self.remove([client_doer])
