"""Saved KEL receipt retry and isolated watcher failures."""
from collections import deque
from types import SimpleNamespace

from hio.base import doing
from keri.core import Saider, SerderKERI, eventing
from keri.recording import ObservedRecord
from locksmith.core import adjudication, receipting
from locksmith.core.rotating import AuthenticateWitnessesDoer
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


def test_receipting_an_earlier_rotation_limits_new_witness_catchup(ipex_vaults, monkeypatch):
    app = ipex_vaults('rotation-receipt')
    remote = ipex_vaults('rotation-witness')
    witness = remote.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='controller')
    inception = hab.kever.serder
    hab.rotate(adds=[witness.pre], toad=1)
    rotation = hab.kever.serder
    hab.interact()
    later = hab.kever.serder
    signed = witness.sign(ser=rotation.raw, indices=[0])
    reply = eventing.messagize(eventing.receipt(pre=hab.pre, sn=rotation.sn, said=rotation.said),
                               wigers=signed)
    posts = []

    class Client:
        def __init__(self):
            self.requester = SimpleNamespace(path='/')
            self.responses = deque()

        def request(self, method, path, body, headers):
            posts.append((path, SerderKERI(raw=body).said, headers.get('Authorization')))
            self.responses.append(SimpleNamespace(status=200 if path == '/receipts' else 204, body=reply))

        def respond(self):
            return self.responses.popleft()

    monkeypatch.setattr(receipting.agenting, 'httpClient', lambda *a: (Client(), doing.Doer()))
    worker = receipting.LocksmithReceiptor(hby=app.hby)
    app.vault.extend([worker])
    list(worker.receipt(hab.pre, sn=rotation.sn, auths={witness.pre: 'rotation-code'}))
    assert posts == [('/', inception.said, None), ('/', rotation.said, None),
                     ('/receipts', rotation.said, 'rotation-code')]
    assert [sig.qb64 for sig in hab.db.wigs.get((hab.pre, rotation.said))] == [signed[0].qb64]
    assert not hab.db.wigs.get((hab.pre, later.said))


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
    worker.request(hab.pre)
    for _ in range(8):
        app.qtask.run()
    before = len(ticks)
    for _ in range(4):
        app.qtask.run()
    assert worker.done and closed and not cues
    assert len(ticks) > before


def test_unanswered_watcher_polls_release_transports_and_keep_partial_replies(ipex_vaults, monkeypatch):
    app = ipex_vaults('watcher-retry')
    hab = app.hby.makeHab(name='controller')
    wids = [app.hby.makeHab(name=name).pre for name in ('first', 'second')]
    reports = app.hby.db.knas
    previous = Saider(qb64=hab.kever.serder.said)
    for wid in wids:
        app.hby.db.obvs.pin((hab.pre, wid, hab.pre), ObservedRecord(enabled=True))
        reports.put((hab.pre, wid), previous)

    opened, closed = [], []
    class UnansweredQuery(doing.Doer):
        def __init__(self, *, wit, **kwa):
            super().__init__()
            self.wid = wit
            opened.append(wit)
        def recur(self, tyme):
            return tyme >= 3  # HTTP completed without a signed notice.
        def exit(self):
            closed.append(self.wid)
    monkeypatch.setattr(adjudication, 'WatcherInquisitor', UnansweredQuery)
    watchmen = adjudication.Watchmen(app.hby, tock=1)
    runner = doing.Doist(doers=[watchmen], tock=0.125)
    runner.enter()
    try:
        for _ in range(4):
            runner.recur()
        reports.pin((hab.pre, wids[0]), previous)
        for _ in range(16):
            runner.recur()
        assert sorted(opened) == sorted(wids) and not closed  # Both transports are still in flight.
        for _ in range(80):
            runner.recur()
        assert opened.count(wids[0]) == 1 and opened.count(wids[1]) > 5
        assert len(opened) - len(closed) <= 1
        assert len(watchmen.doers) == 2
        assert reports.get((hab.pre, wids[0])).qb64 == previous.qb64
        assert reports.get((hab.pre, wids[1])) is None

        # A cut preserves the database row. The remaining watcher has already
        # advanced, even though it returns the same notice in the replacement round.
        remote = ipex_vaults('watcher-ahead')
        target = remote.hby.makeHab(name='controller')
        assert target.pre == hab.pre
        target.interact()
        ahead = Saider(qb64=target.kever.serder.said)
        app.hby.db.ksns.pin((ahead.qb64,), target.kever.state())
        reports.pin((hab.pre, wids[0]), ahead)
        app.hby.db.obvs.pin((hab.pre, wids[1], hab.pre), ObservedRecord(enabled=False))
        disabled_count = opened.count(wids[1])
        for _ in range(12):
            runner.recur()
        reports.pin((hab.pre, wids[0]), ahead)
        runner.recur()
        assert watchmen.cues.pull()['kin'] == 'keyStateUpdate'
        assert opened.count(wids[1]) == disabled_count
    finally:
        runner.exit()
    assert len(opened) == len(closed)
    assert reports.get((hab.pre, wids[0])).qb64 == ahead.qb64
    assert reports.get((hab.pre, wids[1])).qb64 == previous.qb64

    app.close_vault()
    reopened = ipex_vaults('watcher-retry')
    watchmen = adjudication.Watchmen(reopened.hby, tock=1)
    runner = doing.Doist(doers=[watchmen], tock=0.125)
    runner.enter()
    try:
        runner.recur()
        reopened.hby.db.knas.pin((hab.pre, wids[0]), ahead)
        runner.recur()
        assert watchmen.cues.pull()['kin'] == 'keyStateUpdate'
    finally:
        runner.exit()


def test_watcher_paces_initial_polls_and_retries_across_identifiers(ipex_vaults, monkeypatch):
    app = ipex_vaults('watcher-dispatch')
    hab = app.hby.makeHab(name='controller')
    targets = [f'target-{n}' for n in range(12)]
    for target in targets:
        app.hby.db.obvs.pin((hab.pre, hab.pre, target), ObservedRecord(enabled=True))

    starts, active, peaks = [], set(), []
    def accepted_without_notice(self, tymth, *, pre, **kwa):
        self.wind(tymth)
        yield self.tock
        starts.append((pre, self.tyme))
        active.add(pre)
        peaks.append(len(active))
        try:
            for _ in range(12):
                yield self.tock
        finally:
            active.remove(pre)
    monkeypatch.setattr(adjudication.WatcherInquisitor, 'execute', accepted_without_notice)
    watchmen = adjudication.Watchmen(app.hby, tock=1)
    runner = doing.Doist(doers=[watchmen], tock=0.125)
    runner.enter()
    try:
        for _ in range(160):
            runner.recur()
        first_two_rounds = starts[:2 * len(targets)]
        assert sorted(target for target, _ in first_two_rounds) == sorted(targets * 2)
        assert len({tyme for _, tyme in starts}) == len(starts)
        assert max(peaks) <= watchmen.MaxRequests
    finally:
        runner.exit()
    assert not active


def test_watcher_replay_retries_and_notifies_only_after_local_acceptance(ipex_vaults, monkeypatch):
    app = ipex_vaults('watcher-replay')
    hab = app.hby.makeHab(name='controller')
    target = ipex_vaults('watcher-replay-target').hby.makeHab(name='observed')
    _deliver_ipex(app.vault, target.msgOwnEvent(sn=0))
    rotation = target.rotate()
    state = adjudication.watching.DiffState(target.pre, hab.pre, 'ahead', 1, target.kever.serder.said)
    app.hby.db.obvs.pin((hab.pre, hab.pre, target.pre), ObservedRecord(enabled=True))

    requests, notifications = [], []
    def replay(self, tymth, *, query, **kwa):
        self.wind(tymth)
        yield self.tock
        requests.append(query)
        yield self.tock
        if len(requests) == 2:
            _deliver_ipex(app.vault, rotation)
    monkeypatch.setattr(adjudication.WatcherInquisitor, 'execute', replay)
    authority = adjudication.KeyStateVarianceAuthority(app.hby, SimpleNamespace(add=notifications.append))
    update = dict(kin='keyStateUpdate', cid=hab.pre, aheads=[state])
    authority.cues.extend([update, update])
    runner = doing.Doist(doers=[authority], tock=1.0)
    runner.enter()
    try:
        for _ in range(16):
            runner.recur()
        assert requests == [{'s': '1', 'fn': '1'}] and not notifications
        for _ in range(32):
            runner.recur()
        assert requests == [{'s': '1', 'fn': '1'}] * 2
        assert notifications == [dict(r='/keystate/update', pre=target.pre, sn=1, dig=state.dig)]
        assert not authority.doers
    finally:
        runner.exit()


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
