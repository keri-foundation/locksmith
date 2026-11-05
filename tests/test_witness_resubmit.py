"""Saved KEL receipt retry and isolated watcher failures."""
from types import SimpleNamespace

from hio.base import doing
from keri.core import eventing
from locksmith.core import adjudication, receipting
from locksmith.core.rotating import AuthenticateWitnessesDoer
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


def test_hosted_receipt_lookup_uses_event_destination_and_closes_client(ipex_vaults, monkeypatch):
    app = ipex_vaults('hosted-receipt')
    witness_app = ipex_vaults('hosted-witness')
    witness = witness_app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller', wits=[witness.pre], toad=1)
    event = hab.kever.serder
    receipt = eventing.receipt(pre=hab.pre, sn=0, said=event.said)
    reply = eventing.messagize(receipt, wigers=witness.sign(ser=event.raw, indices=[0]))
    requests, closed = [], []
    class ClientDoer(doing.Doer):
        def exit(self):
            closed.append(True)
    client = SimpleNamespace(responses=[True], request=lambda **kwa: requests.append(kwa),
                             respond=lambda: SimpleNamespace(status=200, body=reply))
    monkeypatch.setattr(receipting.agenting, 'httpClient', lambda *a: (client, ClientDoer()))
    worker = receipting.LocksmithReceiptor(hby=app.hby)
    app.vault.extend([worker])
    list(worker.get(hab.pre, sn=0))
    assert requests[0]['headers'][receipting.httping.CESR_DESTINATION_HEADER] == witness.pre
    assert requests[0]['qargs'] == {'pre': hab.pre, 'sn': 0}
    assert hab.db.fullyWitnessed(hab.kever.serder) and closed
    client.responses.clear()
    hab.interact()
    pending = worker.get(hab.pre, sn=1)
    next(pending)
    pending.close()
    assert len(closed) == 2


def test_resubmit_does_not_borrow_current_threshold_for_old_event(ipex_vaults, monkeypatch):
    app = ipex_vaults('historical-quorum')
    witnesses = [app.hby.makeHab(name=name, transferable=False) for name in ('first', 'second')]
    hab = app.hby.makeHab(name='controller', wits=[wit.pre for wit in witnesses], toad=2)
    _deliver_ipex(app.vault, witnesses[0].witness(hab.kever.serder))
    hab.rotate(toad=1)
    submitted = []
    def get(self, *a, **k):
        yield self.tock
    def receipt(self, *a, **k):
        submitted.append(True)
        yield self.tock
    monkeypatch.setattr(receipting.LocksmithReceiptor, 'get', get)
    monkeypatch.setattr(receipting.LocksmithReceiptor, 'receipt', receipt)
    worker = AuthenticateWitnessesDoer(app, hab, [])
    app.vault.extend([worker])
    for _ in range(32):
        app.qtask.run()
    assert worker.done and 'original witness configuration' in worker.error
    assert not submitted and app.vault.db.idm.get((hab.pre,)).auth_pending
    assert hab.kever.sn == 1


def test_failed_watcher_child_does_not_stop_other_vault_work(ipex_vaults, monkeypatch):
    app = ipex_vaults('watcher-socket')
    hab = app.hby.makeHab(name='controller')
    closed, ticks, cues = [], [], []
    class BrokenQuery(doing.Doer):
        def query(self, **kwa):
            pass
        def recur(self, tyme):
            raise OSError(22, 'Invalid argument')
        def exit(self):
            closed.append(True)
    monkeypatch.setattr(adjudication, 'WatcherInquisitor', lambda **kwa: BrokenQuery())
    worker = adjudication.KeyStateQuerier(hby=app.hby, hab=hab, oid=hab.pre,
                                         wids=[hab.pre], cues=cues)
    def tick(tymth, tock=0.0, **kwa):
        while True:
            ticks.append(tymth())
            yield tock
    app.vault.extend([worker, doing.doify(tick)])
    for _ in range(8):
        app.qtask.run()
    before = len(ticks)
    for _ in range(4):
        app.qtask.run()
    assert worker.done and closed and not cues
    assert len(ticks) > before


def test_receipt_lookup_can_reach_quorum_without_one_endpoint(ipex_vaults, monkeypatch):
    from keri import kering
    app = ipex_vaults('receipt-quorum')
    remote = ipex_vaults('remote-witnesses')
    witnesses = [remote.hby.makeHab(name=str(n), transferable=False) for n in range(3)]
    hab = app.hby.makeHab(name='controller', wits=[w.pre for w in witnesses], toad=2)
    contacted = []
    def http_client(hab, wit):
        index = [w.pre for w in witnesses].index(wit)
        if index == 0:
            raise kering.MissingEntryError('No endpoint')
        contacted.append(wit)
        receipt = eventing.receipt(pre=hab.pre, sn=0, said=hab.kever.serder.said)
        reply = eventing.messagize(receipt, wigers=witnesses[index].sign(ser=hab.kever.serder.raw, indices=[index]))
        client = SimpleNamespace(responses=[True], request=lambda **kwa: None,
                                 respond=lambda: SimpleNamespace(status=200, body=reply))
        return client, doing.Doer()
    monkeypatch.setattr(receipting.agenting, 'httpClient', http_client)
    worker = receipting.LocksmithReceiptor(hby=app.hby)
    app.vault.extend([worker])
    list(worker.get(hab.pre, sn=0))
    assert hab.db.fullyWitnessed(hab.kever.serder)
    assert contacted == [w.pre for w in witnesses[1:]]
