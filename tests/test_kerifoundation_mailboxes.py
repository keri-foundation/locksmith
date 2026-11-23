import asyncio
import threading
from types import SimpleNamespace

import pytest
from keri import kering
from keri.app import habbing
from keri.core import SerderKERI, exchange
from keri.peer import exchanging

from locksmith.plugins.kerifoundation.db.basing import ACCOUNT_STATUS_ONBOARDED, KFBaser, KFAccountRecord, MailboxRecord
from locksmith.plugins.kerifoundation.mailboxes import KFMailboxService
from locksmith.plugins.kerifoundation.onboarding.service import KFBootClient, KFBootError, KFSurfaceConfig
from locksmith.plugins.kerifoundation.plugin import KeriFoundationPlugin
from locksmith.ui.toolkit.widgets import LocksmithButton
from locksmith.core.messaging import ensure_receiving, receiving_ready
from locksmith.core.signals import DoerSignalBridge
from test_keri_v2_compat import ipex_vaults as ipex_vaults


@pytest.mark.parametrize(('fields', 'enabled'), [
    ({}, False), ({'mailbox_enabled': True}, True), ({'mailbox_enabled': False}, False),
    ({'mailbox_enabled': 'true'}, False), ({'mailbox_enabled': 1}, False),
])
def test_bootstrap_mailbox_capability_requires_json_true(monkeypatch, fields, enabled):
    monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get',
                        lambda *args, **kwargs: SimpleNamespace(raise_for_status=lambda: None,
                            json=lambda: {'bootstrap': fields}))
    client = KFBootClient(None, surfaces=KFSurfaceConfig('http://example.test/onboarding',
                                                       'http://example.test/account'))
    assert client.fetch_bootstrap_config().mailbox_enabled is enabled


@pytest.fixture
def mailbox_plugin(qapp, tmp_path, monkeypatch):
    habs = {prefix: SimpleNamespace(pre=prefix, name=prefix, accepted=True, kever=SimpleNamespace(sn=0, wits=[]))
            for prefix in ('account', 'recipient', 'other')}

    def vault(name):
        hby = SimpleNamespace(name=name, base='', temp=False,
                              db=SimpleNamespace(headDirPath=str(tmp_path), names=SimpleNamespace(
                                  getTopItemIter=lambda keys=(): iter(((('', hab.name), hab.pre)
                                                                     for hab in habs.values())))),
                              habByPre=habs.get, habByName=habs.get)
        return SimpleNamespace(hby=hby, closed=False,
                               signals=DoerSignalBridge())

    app = SimpleNamespace(vault=vault('capability'),
                          config=SimpleNamespace(environment=SimpleNamespace(value='development')))
    plugin = KeriFoundationPlugin()
    plugin.initialize(app)
    plugin.on_vault_opened(app.vault)
    plugin._db.pin_account(KFAccountRecord(account_aid='account', boot_server_aid='boot',
                                          status=ACCOUNT_STATUS_ONBOARDED))
    monkeypatch.setattr('locksmith.plugins.kerifoundation.plugin.RETRY_DELAYS', (0.0, 0.0, 0.0))
    state = SimpleNamespace(app=app, plugin=plugin, db=plugin._db, vault=vault,
                            bootstrap={}, fetches=[], allocations=[], error=None)

    def fetch(url, **kwargs):
        state.fetches.append(url)
        if state.error is not None:
            raise state.error
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'bootstrap': state.bootstrap})

    async def provision(service, prefix):
        state.allocations.append(prefix)
        record = service.db.mailboxes.get((prefix,))
        record.status, record.eid, record.error = 'active', 'operator', ''
        service.db.mailboxes.pin((prefix,), record)
        service.db.attach_identifier(prefix)
        return record

    monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get', fetch)
    monkeypatch.setattr(KFMailboxService, 'provision', provision)
    try:
        yield state
    finally:
        plugin.on_vault_closed(app.vault, clear=True)


@pytest.mark.parametrize('enabled', [False, True])
def test_onboarding_uses_its_bootstrap_without_another_capability_fetch(mailbox_plugin, enabled):
    state = mailbox_plugin
    state.bootstrap = {'mailbox_enabled': enabled}
    bootstrap = state.plugin._boot_client.fetch_bootstrap_config()
    state.fetches.clear()
    outcome = SimpleNamespace(account_aid='account', bootstrap=bootstrap,
                              witness_registration=SimpleNamespace(results=[], batch_mode=True))

    async def complete():
        state.plugin._handle_onboarding_success('account', outcome)
        await state.plugin._mailbox_task

    asyncio.run(complete())
    assert state.fetches == []
    assert set(state.allocations) == ({'account', 'recipient', 'other'} if enabled else set())
    assert state.db.get_account().status == ACCOUNT_STATUS_ONBOARDED
    assert state.plugin._onboarding_page.phase == 'completed'
    assert state.db.mailboxes.get(('account',)).status == ('active' if enabled else 'pending')


def test_disabled_mailboxes_preserve_setup_and_allow_local_witness_attachment(mailbox_plugin, monkeypatch):
    state = mailbox_plugin
    pending = MailboxRecord(account_aid='account', status='pending', error='waiting')
    active = MailboxRecord(account_aid='account', status='active', eid='boot', url='http://old.test')
    state.db.mailboxes.pin(('recipient',), pending)
    state.db.mailboxes.pin(('account',), active)
    page = state.plugin._identifiers_page
    monkeypatch.setattr(page, '_choose_identifier_prefix', lambda: 'other')

    async def reopen_and_attach():
        state.plugin._start_mailboxes()
        await state.plugin._mailbox_task
        page._on_add_identifier_clicked()
        await state.plugin._mailbox_task

    asyncio.run(reopen_and_attach())
    assert state.allocations == []
    assert state.db.mailboxes.get(('recipient',)) == pending
    assert state.db.mailboxes.get(('account',)) == active
    assert state.db.is_identifier_attached('other')
    assert state.db.mailboxes.get(('other',)).status == 'pending'
    rows = {row['Prefix']: row for row in page._table._static_data}
    assert rows['account']['Mailbox'] == 'Ready'
    assert 'Setup paused' in rows['recipient']['Mailbox']
    assert rows['other']['Mailbox'] == 'Setup paused'
    assert page._row_actions(rows['recipient'])[0] == ['Add Witnesses']
    assert state.db.get_account().status == ACCOUNT_STATUS_ONBOARDED

    async def refresh_after_enable():
        state.bootstrap = {'mailbox_enabled': True}
        state.plugin._start_mailboxes()
        await state.plugin._mailbox_task

    asyncio.run(refresh_after_enable())
    assert set(state.allocations) == {'recipient', 'other'}
    assert all(record.status == 'active' for _, record in state.db.mailboxes.getTopItemIter())


def test_mailbox_capability_failure_can_be_retried_without_account_failure(mailbox_plugin):
    state = mailbox_plugin
    state.error = OSError('Boot unavailable')

    async def retry():
        state.plugin._queue_mailbox('recipient')
        await state.plugin._mailbox_task
        assert state.db.mailboxes.get(('recipient',)).status == 'failed'
        assert state.db.mailboxes.get(('recipient',)).attempts == 4
        assert len(state.fetches) == 4
        assert not state.db.is_identifier_attached('recipient')
        assert 'Could not check' in state.plugin._identifiers_page._mailbox_notice.text()
        state.error = None
        state.bootstrap = {'mailbox_enabled': True}
        state.plugin._queue_mailbox('recipient')
        await state.plugin._mailbox_task

    asyncio.run(retry())
    assert state.allocations == ['recipient']
    assert state.db.mailboxes.get(('recipient',)).status == 'active'
    assert state.db.get_account().status == ACCOUNT_STATUS_ONBOARDED
    assert state.plugin._mailbox_task is None


@pytest.mark.parametrize('close', [False, True], ids=['switch', 'close'])
def test_capability_lookup_keeps_its_vault_and_busy_controls(mailbox_plugin, monkeypatch, close):
    state = mailbox_plugin
    entered, release = threading.Event(), threading.Event()
    page = state.plugin._identifiers_page
    first_vault, first_db = state.app.vault, state.db

    def fetch(url, **kwargs):
        entered.set()
        assert release.wait(2)
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'bootstrap': {'mailbox_enabled': True}})

    monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get', fetch)
    monkeypatch.setattr(page, '_choose_identifier_prefix', lambda: pytest.fail('Busy Add remained usable'))

    async def finish_late():
        state.plugin._start_mailboxes()
        task = state.plugin._mailbox_task
        assert await asyncio.to_thread(entered.wait, 2)
        assert not page._table.header.add_button.isEnabled()
        empty_buttons = page._table.empty_state.findChildren(LocksmithButton)
        assert empty_buttons and all(not button.isEnabled() for button in empty_buttons)
        assert page._row_actions({'Prefix': 'recipient'})[0] == ['Add Witnesses']
        page._on_add_identifier_clicked()
        page._on_row_action({'Prefix': 'recipient'}, 'Retry Mailbox')
        assert state.plugin._mailbox_task is task
        assert all(record.status == 'pending' for _, record in first_db.mailboxes.getTopItemIter())
        if close:
            first_vault.closed = True
            state.plugin.on_vault_closed(first_vault)
        else:
            state.app.vault = state.vault('other-vault')
        release.set()
        if close:
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            await task
            assert all(record.status == 'pending' for _, record in first_db.mailboxes.getTopItemIter())
            state.app.vault = first_vault

    try:
        asyncio.run(finish_late())
        assert state.allocations == []
        assert state.plugin._mailbox_task is None
    finally:
        release.set()


@pytest.fixture
def mailbox_account(ipex_vaults, tmp_path, monkeypatch):
    app = ipex_vaults('account-mailbox')
    account = app.hby.makeHab(name='account')
    recipient = app.hby.makeHab(name='recipient')
    db = KFBaser(name='mailbox-plugin', headDirPath=str(tmp_path))
    with habbing.openHab(name='boot-mailbox', temp=True, version=kering.Vrsn_2_0) as (bhby, boot), \
            habbing.openHab(name='operator-mailbox', temp=True, transferable=False,
                            version=kering.Vrsn_2_0) as (mhby, operator):
        db.pin_account(KFAccountRecord(account_aid=account.pre, status=ACCOUNT_STATUS_ONBOARDED,
                                      boot_server_aid=boot.pre))
        url = 'http://127.0.0.1:9783'
        client = KFBootClient(app, surfaces=KFSurfaceConfig(url + '/onboarding', url + '/account'))
        state = SimpleNamespace(app=app, db=db, account=account, recipient=recipient, boot=boot,
                                bhby=bhby, operator=operator, client=client, requests=[], mode='', entered=threading.Event(),
                                release=threading.Event())

        def post(url, *, data, headers, timeout):
            message = bytes(data) + headers.get('CESR-ATTACHMENT', '').encode()
            request = SerderKERI(raw=data)
            if url == allocation['url']:
                mhby.psr.parse(ims=bytearray(message), version=kering.Vrsn_2_0)
                return SimpleNamespace(status_code=204, headers={}, content=b'')
            bhby.psr.parse(ims=bytearray(message))
            if request.ilk != 'exn':
                return SimpleNamespace(status_code=204, headers={}, content=b'')
            exchanging.verify(bhby, request)
            if request.route == '/operations/status':
                result = exchange(
                    route=request.route, sender=boot.pre, receiver=request.pre,
                    attributes={'request_said': request.said, 'operation': {
                        'operation_id': 'operation-1', 'kind': 'mailbox_create',
                        'requester': account.pre, 'subject': recipient.pre, 'state': 'succeeded',
                        'result': {'mailbox': allocation}}},
                    version=kering.Vrsn_2_0, kind=kering.Kinds.json,
                )
                signed = boot.endorse(result, last=False, framed=True)
                return SimpleNamespace(status_code=200, headers={}, content=bytes(boot.replay() + signed))
            assert request.route == '/account/mailboxes/create'
            binding = request.ked['a']['binding'].encode()
            bind = SerderKERI(raw=binding)
            bhby.psr.parse(ims=bytearray(binding))
            exchanging.verify(bhby, bind)
            assert bind.pre == request.ked['a']['recipient_aid']
            assert bind.ked['a']['account_aid'] == request.pre == account.pre
            assert bind.ked['ri'] == boot.pre
            state.requests.append(request)
            state.entered.set()
            if state.mode == 'wait':
                assert state.release.wait(5)
            payload = {'request_said': request.said if state.mode != 'correlation' else boot.pre,
                       'mailbox': allocation}
            if state.mode == 'operation':
                payload['operation'] = {'operation_id': 'operation-1', 'kind': 'mailbox_create',
                                        'requester': account.pre, 'subject': recipient.pre, 'state': 'pending'}
            result = exchange(
                route=request.route, sender=boot.pre, receiver=request.pre,
                attributes=payload,
                version=kering.Vrsn_2_0, kind=kering.Kinds.json,
            )
            signed = boot.endorse(result, last=False, framed=True)
            if state.mode == 'signature':
                signed = result.raw + boot.endorse(exchange(
                    route='/wrong', sender=boot.pre, attributes={}, version=kering.Vrsn_2_0,
                    kind=kering.Kinds.json), last=False, framed=True)[-len(signed[result.size:]):]
            return SimpleNamespace(status_code=200, headers={}, content=bytes(boot.replay() + signed))

        allocation = {'mailbox_id': 'allocation-1', 'recipient_aid': recipient.pre,
                      'eid': operator.pre, 'url': 'http://127.0.0.1:6732', 'status': 'active',
                      'oobis': [f'http://127.0.0.1:6732/oobi/{operator.pre}/controller']}

        async def resolve(app, *, pre, oobi, **kwa):
            # Unit transport boundary: parse the genuine operator's signed introduction.
            stream = operator.replay(gvrsn=kering.Vrsn_2_0)
            stream += operator.makeEndRole(eid=operator.pre, role=kering.Roles.controller,
                                          version=kering.Vrsn_2_0, kind=kering.Kinds.json)
            if state.mode != 'location':
                stream += operator.makeLocScheme(url=allocation['url'], scheme='http',
                                                  version=kering.Vrsn_2_0, kind=kering.Kinds.json)
            app.vault.hby.psr.parse(ims=bytearray(stream))
            mhby.psr.parse(ims=bytearray(stream))
            return pre in app.vault.hby.kevers

        monkeypatch.setattr('locksmith.plugins.kerifoundation.mailboxes.resolve_oobi', resolve)
        monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.post', post)
        def get(url, **kwargs):
            if '/oobi/' in url:
                if state.mode == 'unpublished':
                    return SimpleNamespace(status_code=404, content=b'')
                stream = operator.replay(pre=recipient.pre, gvrsn=kering.Vrsn_2_0)
                stream.extend(operator.replay(gvrsn=kering.Vrsn_2_0))
                stream.extend(operator.loadLocScheme(eid=operator.pre, gvrsn=kering.Vrsn_2_0))
                stream.extend(operator.loadEndRole(cid=recipient.pre, role=kering.Roles.mailbox,
                                                   eid=operator.pre, gvrsn=kering.Vrsn_2_0))
                return SimpleNamespace(status_code=200, content=bytes(stream))
            return SimpleNamespace(raise_for_status=lambda: None,
                                   json=lambda: {'bootstrap': {'mailbox_enabled': True}})
        monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get', get)
        try:
            yield state
        finally:
            state.release.set()
            db.close()


@pytest.mark.real_routes
def test_mailbox_setup_verifies_binding_and_retains_signed_route_on_reopen(mailbox_account, ipex_vaults):
    state = mailbox_account
    service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
    record = asyncio.run(service.provision(state.recipient.pre))
    assert record.status == 'active'
    assert record.eid == state.operator.pre != state.boot.pre
    assert state.db.is_identifier_attached(state.recipient.pre)
    role = state.app.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.operator.pre))
    assert role.allowed
    assert state.app.hby.db.locs.get((state.operator.pre, 'http')).url == record.url
    state.app.close_vault()
    state.db.close()
    state.db.reopen()
    assert state.db.mailboxes.get((state.recipient.pre,)).status == 'active'
    reopened = ipex_vaults('account-mailbox')
    assert reopened.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.operator.pre)).allowed
    recovered = asyncio.run(KFMailboxService(vault=reopened.vault, db=state.db,
                                             boot_client=state.client).provision(state.recipient.pre))
    assert recovered.mailbox_id == record.mailbox_id
    assert len(state.requests) == 2


@pytest.mark.real_routes
@pytest.mark.parametrize('offline', [False, True])
def test_unavailable_provider_preserves_signed_routes_on_reopen(mailbox_account, ipex_vaults,
                                                                monkeypatch, offline):
    state = mailbox_account
    record = asyncio.run(KFMailboxService(vault=state.app.vault, db=state.db,
                                          boot_client=state.client).provision(state.recipient.pre))
    account, recipient = state.account.pre, state.recipient.pre
    state.app.hby.psr.parse(ims=state.account.makeLocScheme(url='http://independent.test'))
    state.app.hby.psr.parse(ims=state.account.makeEndRole(eid=account, role=kering.Roles.mailbox))
    requests_before = len(state.requests)
    state.app.config = SimpleNamespace(environment=SimpleNamespace(value='development'))
    plugin = KeriFoundationPlugin()
    plugin.initialize(state.app)
    plugin.on_vault_opened(state.app.vault)
    plugin._db.pin_account(state.db.get_account())
    plugin._db.mailboxes.pin((recipient,), record)
    def fetch(*args, **kwargs):
        if offline:
            raise ConnectionError('Boot unavailable')
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'bootstrap': {'mailbox_enabled': False}})

    monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get', fetch)
    monkeypatch.setattr('locksmith.plugins.kerifoundation.plugin.RETRY_DELAYS', (0, 0, 0))
    async def check(app):
        plugin._start_mailboxes()
        await plugin._mailbox_task
        assert plugin._db.mailboxes.get((recipient,)) == record
        assert plugin._db.mailboxes.get((account,)).status == ('failed' if offline else 'pending')
        app.vault.plugin_manager = plugin
        for pre in (account, recipient):
            hab = app.hby.habByPre(pre)
            assert receiving_ready(app.vault, hab)
            await ensure_receiving(app.vault, hab)

    try:
        asyncio.run(check(state.app))
        plugin.on_vault_closed(state.app.vault)
        state.app.close_vault()
        reopened = ipex_vaults('account-mailbox')
        reopened.config = state.app.config
        plugin.initialize(reopened)
        plugin.on_vault_opened(reopened.vault)
        asyncio.run(check(reopened))
        assert len(state.requests) == requests_before
    finally:
        plugin.on_vault_closed(plugin._app.vault, clear=True)


@pytest.mark.real_routes
@pytest.mark.parametrize('mode', ['signature', 'correlation', 'location'])
def test_mailbox_setup_rejects_untrusted_allocation(mailbox_account, mode):
    state = mailbox_account
    state.mode = mode
    service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
    with pytest.raises(KFBootError):
        asyncio.run(service.provision(state.recipient.pre))
    assert state.db.mailboxes.get((state.recipient.pre,)).status == 'failed'
    assert not state.db.is_identifier_attached(state.recipient.pre)
    assert state.app.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.operator.pre)) is None


@pytest.mark.real_routes
def test_mailbox_setup_cancel_preserves_pending_for_reopen(mailbox_account, ipex_vaults):
    state = mailbox_account
    state.mode = 'wait'

    async def cancel_after_request():
        service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
        task = asyncio.create_task(service.provision(state.recipient.pre))
        assert await asyncio.to_thread(state.entered.wait, 5)
        task.cancel()
        # Cancellation must retain ownership until the blocking HTTP worker stops.
        await asyncio.sleep(0)
        assert not task.done()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert state.db.mailboxes.get((state.recipient.pre,)).status == 'pending'
        state.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        state.app.close_vault()

    asyncio.run(cancel_after_request())
    state.db.close()
    state.db.reopen()
    assert state.db.mailboxes.get((state.recipient.pre,)).status == 'pending'
    state.mode = ''
    reopened = ipex_vaults('account-mailbox')
    record = asyncio.run(KFMailboxService(vault=reopened.vault, db=state.db,
                                         boot_client=state.client).provision(state.recipient.pre))
    assert record.status == 'active'


@pytest.mark.real_routes
def test_attach_identifier_shows_setup_failure_and_retries(mailbox_account, monkeypatch):
    from locksmith.plugins.kerifoundation.plugin import KeriFoundationPlugin

    state = mailbox_account
    state.app.config = SimpleNamespace(environment=SimpleNamespace(value='development'))
    plugin = KeriFoundationPlugin()
    plugin.initialize(state.app)
    plugin.on_vault_opened(state.app.vault)
    plugin._db.pin_account(state.db.get_account())
    monkeypatch.setattr(plugin._identifiers_page, '_choose_identifier_prefix', lambda: state.recipient.pre)

    async def attach_and_retry():
        state.mode = 'correlation'
        plugin._identifiers_page._on_add_identifier_clicked()
        await plugin._mailbox_task
        row = next(row for row in plugin._identifiers_page._table._static_data
                   if row['Prefix'] == state.recipient.pre)
        assert 'Setup failed' in row['Mailbox'] and 'Retry Mailbox' in row['Mailbox']
        assert not plugin._db.is_identifier_attached(state.recipient.pre)
        state.mode = ''
        plugin._identifiers_page._on_row_action(row, 'Retry Mailbox')
        await plugin._mailbox_task
        row = next(row for row in plugin._identifiers_page._table._static_data
                   if row['Prefix'] == state.recipient.pre)
        assert row['Mailbox'] == 'Ready'
        assert plugin._db.is_identifier_attached(state.recipient.pre)

    try:
        asyncio.run(attach_and_retry())
    finally:
        plugin.on_vault_closed(state.app.vault)


@pytest.mark.real_routes
def test_mailbox_setup_waits_for_provider_operation(mailbox_account):
    state = mailbox_account
    state.mode = 'operation'
    service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
    record = asyncio.run(service.provision(state.recipient.pre))
    assert record.status == 'active'
    assert record.eid == state.operator.pre
    assert state.db.is_identifier_attached(state.recipient.pre)


@pytest.mark.real_routes
@pytest.mark.parametrize('offline', [False, True])
def test_vault_open_replaces_legacy_boot_mailbox_after_operator_verification(mailbox_account, monkeypatch, offline):
    state = mailbox_account
    app, recipient, boot = state.app, state.recipient, state.boot
    old = MailboxRecord(mailbox_id='old-allocation', account_aid=state.account.pre,
                        eid=boot.pre, url='http://127.0.0.1:9783', status='active', attempts=4)
    app.hby.psr.parse(ims=boot.replay() + boot.makeLocScheme(url=old.url) +
                      recipient.makeEndRole(eid=boot.pre, role=kering.Roles.mailbox))
    app.config = SimpleNamespace(environment=SimpleNamespace(value='development'))
    plugin = KeriFoundationPlugin()
    plugin.initialize(app)
    plugin._boot_client = state.client
    plugin.on_vault_opened(app.vault)
    plugin._db.pin_account(state.db.get_account())
    plugin._db.mailboxes.pin((recipient.pre,), old)
    other_account = MailboxRecord(account_aid='other-account', eid=boot.pre, status='active')
    plugin._db.mailboxes.pin((state.account.pre,), other_account)
    plugin.on_vault_closed(app.vault)
    app.vault.plugin_manager = plugin
    fetches = []
    if offline:
        def unavailable(*args, **kwargs):
            fetches.append(1)
            raise ConnectionError('Boot unavailable')
        monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get', unavailable)
        monkeypatch.setattr('locksmith.plugins.kerifoundation.plugin.RETRY_DELAYS', (0, 0, 0))

    async def reopen():
        plugin.on_vault_opened(app.vault)
        await plugin._mailbox_task

    try:
        asyncio.run(reopen())
        record = plugin._db.mailboxes.get((recipient.pre,))
        assert plugin._db.mailboxes.get((state.account.pre,)) == other_account
        assert app.hby.db.ends.get((recipient.pre, 'mailbox', boot.pre)).allowed == offline
        assert receiving_ready(app.vault, recipient)
        if offline:
            assert record.status == 'failed' and record.eid == boot.pre and record.attempts == len(fetches) == 4
            assert app.hby.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)) is None
        else:
            assert record.status == 'active' and record.eid == state.operator.pre
            assert app.hby.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)).allowed
            assert len(state.requests) == 1
        plugin.on_vault_closed(app.vault)
        asyncio.run(reopen())
        assert plugin._db.mailboxes.get((recipient.pre,)) == record
        assert len(fetches) == (4 if offline else 0)
        assert len(state.requests) == (0 if offline else 1)
    finally:
        plugin.on_vault_closed(app.vault, clear=True)


@pytest.mark.real_routes
def test_async_boot_client_keeps_signing_and_reply_parsing_on_loop(mailbox_account, monkeypatch):
    state = mailbox_account
    owner = threading.get_ident()
    original = state.account.endorse

    def sign(*args, **kwargs):
        assert threading.get_ident() == owner
        return original(*args, **kwargs)

    monkeypatch.setattr(state.account, 'endorse', sign)
    from locksmith.plugins.kerifoundation.onboarding import service as module
    parse = module.parse_cesr_http_reply

    def parse_on_owner(*args, **kwargs):
        assert threading.get_ident() == owner
        return parse(*args, **kwargs)

    monkeypatch.setattr(module, 'parse_cesr_http_reply', parse_on_owner)
    bind = exchange(route='/mailbox/bind', sender=state.recipient.pre, receiver=state.boot.pre,
                    attributes={'account_aid': state.account.pre, 'recipient_aid': state.recipient.pre},
                    version=kering.Vrsn_2_0, kind=kering.Kinds.json)
    async def send():
        # The account client syncs its own KEL; this separate recipient also needs introduction.
        await state.client._post_cesr_async(
            vault=state.app.vault, url=state.client.account_url,
            ims=state.recipient.msgOwnInception(gvrsn=kering.Vrsn_2_0),
            destination=state.boot.pre,
        )
        return await state.client.send_exn_async(
            surface='account', hab=state.account, route='/account/mailboxes/create',
            payload={'account_aid': state.account.pre, 'recipient_aid': state.recipient.pre,
                     'binding': state.recipient.endorse(bind, last=False, framed=True, gvrsn=kering.Vrsn_2_0).decode()},
            destination=state.boot.pre, vault=state.app.vault)
    reply = asyncio.run(send())
    assert reply.payload['mailbox']['recipient_aid'] == state.recipient.pre
    assert state.app.hby.db.exns.get((reply.said,)) is not None


@pytest.mark.real_routes
def test_async_boot_client_drops_late_reply_after_vault_switch(mailbox_account, monkeypatch):
    state = mailbox_account
    vault = state.app.vault
    state.mode = 'wait'
    from locksmith.plugins.kerifoundation.onboarding import service as module
    parsed = []
    parse = module.parse_cesr_http_reply

    def record_parse(*args, **kwargs):
        parsed.append(args[0])
        return parse(*args, **kwargs)

    monkeypatch.setattr(module, 'parse_cesr_http_reply', record_parse)
    bind = exchange(route='/mailbox/bind', sender=state.recipient.pre, receiver=state.boot.pre,
                    attributes={'account_aid': state.account.pre, 'recipient_aid': state.recipient.pre},
                    version=kering.Vrsn_2_0, kind=kering.Kinds.json)

    async def switch_during_request():
        await state.client._post_cesr_async(
            vault=vault, url=state.client.account_url,
            ims=state.recipient.msgOwnInception(gvrsn=kering.Vrsn_2_0),
            destination=state.boot.pre,
        )
        task = asyncio.create_task(state.client.send_exn_async(
            surface='account', hab=state.account, route='/account/mailboxes/create',
            payload={'account_aid': state.account.pre, 'recipient_aid': state.recipient.pre,
                     'binding': state.recipient.endorse(bind, last=False, framed=True, gvrsn=kering.Vrsn_2_0).decode()},
            destination=state.boot.pre, vault=vault))
        assert await asyncio.to_thread(state.entered.wait, 5)
        vault.closed = True
        state.app.vault = SimpleNamespace(closed=False)
        state.release.set()
        try:
            with pytest.raises(KFBootError):
                await task
            assert parsed == []
        finally:
            state.app.vault = vault
            vault.closed = False

    asyncio.run(switch_during_request())


def test_exhausted_setup_stays_paused_until_explicit_retry(mailbox_plugin):
    state = mailbox_plugin
    state.bootstrap = {'mailbox_enabled': True}
    state.db.mailboxes.pin(('recipient',), MailboxRecord(account_aid='account', attempts=4))
    async def resume():
        state.plugin._start_mailboxes(requested_prefix='recipient')
        await state.plugin._mailbox_task
        assert state.allocations == [] and state.fetches == []
        assert state.db.mailboxes.get(('recipient',)).status == 'failed'
        state.plugin._queue_mailbox('recipient')
        await state.plugin._mailbox_task
    asyncio.run(resume())
    assert state.allocations == ['recipient']
    assert state.db.mailboxes.get(('recipient',)).status == 'active'


@pytest.mark.real_routes
def test_publication_failure_preserves_old_route_and_prevents_ready(mailbox_account, monkeypatch):
    from keri.acdc import ipexing as native
    from locksmith.core import ipexing
    from locksmith.core.habbing import generate_oobi
    from locksmith.core.remoting import identifier_introduction

    state = mailbox_account
    old = state.boot
    app, recipient = state.app, state.recipient
    app.config = SimpleNamespace(environment=SimpleNamespace(value='development'))
    plugin = KeriFoundationPlugin()
    plugin.initialize(app)
    plugin.on_vault_opened(app.vault)
    plugin._db.pin_account(state.db.get_account())
    app.vault.plugin_manager = plugin
    app.hby.psr.parse(ims=bytearray(old.replay(gvrsn=kering.Vrsn_2_0)))
    app.hby.psr.parse(ims=bytearray(old.makeLocScheme(url='http://old.test')))
    app.hby.psr.parse(ims=bytearray(recipient.makeEndRole(
        eid=old.pre, role=kering.Roles.mailbox, version=kering.Vrsn_2_0)))
    plugin._db.mailboxes.pin((recipient.pre,), MailboxRecord(account_aid=state.account.pre,
                                                            eid=old.pre, status='active'))
    service = KFMailboxService(vault=app.vault, db=plugin._db, boot_client=state.client)
    state.mode = 'unpublished'
    with pytest.raises(TimeoutError, match='publish'):
        asyncio.run(service.provision(recipient.pre))
    assert app.hby.db.ends.get((recipient.pre, 'mailbox', old.pre)).allowed
    assert app.hby.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)) is None
    assert plugin._db.mailboxes.get((recipient.pre,)).status == 'failed'
    assert receiving_ready(app.vault, recipient)  # The old route still works.

    app.hby.psr.parse(ims=old.makeEndRole(eid=old.pre, role=kering.Roles.controller))
    apply, atc = native.apply(recipient, old.pre, 'Apply', modifiers={'dp': [[]]})
    ipexing.submit(app.vault, recipient, apply, atc)

    # Older wallets already installed the new authorization before the failed readback.
    app.hby.psr.parse(ims=state.operator.loadEndRole(
        cid=recipient.pre, eid=state.operator.pre, role=kering.Roles.mailbox, gvrsn=kering.Vrsn_2_0))
    plugin.on_vault_closed(app.vault)
    plugin.on_vault_opened(app.vault)
    service.db = plugin._db
    # A TCP-only controller cannot take this message. Mailbox delivery could select the unpublished EID.
    app.hby.psr.parse(ims=state.account.makeLocScheme(url='tcp://127.0.0.1:9999', scheme=kering.Schemes.tcp))
    app.hby.psr.parse(ims=recipient.makeEndRole(eid=state.account.pre, role=kering.Roles.controller))
    assert not receiving_ready(app.vault, recipient)
    with pytest.raises(kering.ConfigurationError, match='cannot receive replies'):
        ipexing.start(app.vault, recipient, old.pre, 'Apply')
    for _ in range(64):
        app.qtask.run()
    submission = app.vault.db.outbox.get((apply.said,))
    assert submission.status == 'blocked' and submission.attempts == 0
    assert 'cannot receive replies' in submission.error

    app.hby.psr.parse(ims=bytearray(recipient.makeEndRole(eid=old.pre, role=kering.Roles.agent)))
    assert receiving_ready(app.vault, recipient)  # Agent delivery takes precedence over mailboxes.
    with habbing.openHby(name='introduction-reader', temp=True, version=kering.Vrsn_2_0) as reader:
        reader.psr.parse(ims=bytearray(identifier_introduction(recipient, vault=app.vault)))
        assert reader.db.ends.get((recipient.pre, 'agent', old.pre)).allowed
        assert reader.db.ends.get((recipient.pre, 'mailbox', old.pre)).allowed
        assert reader.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)) is None
    assert app.hby.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)).allowed
    with monkeypatch.context() as patch:
        patch.setattr('random.choice', lambda urls: next((url for url in urls if url.endswith(state.operator.pre)), urls[0]))
        assert generate_oobi(app, recipient, role='mailbox')['oobi'] == f'http://old.test/oobi/{recipient.pre}/mailbox/{old.pre}'
    state.mode = ''
    record = asyncio.run(service.provision(state.recipient.pre))
    assert record.status == 'active'
    assert not state.app.hby.db.ends.get((state.recipient.pre, 'mailbox', old.pre)).allowed
    assert state.operator.db.ends.get((state.recipient.pre, 'mailbox', state.operator.pre)).allowed
    with habbing.openHby(name='published-reader', temp=True, version=kering.Vrsn_2_0) as reader:
        reader.psr.parse(ims=bytearray(identifier_introduction(recipient, vault=app.vault)))
        assert reader.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)).allowed

    # Explicit retry repairs an active record whose signed route is no longer usable.
    app.hby.psr.parse(ims=recipient.makeEndRole(eid=old.pre, role=kering.Roles.agent, allow=False))
    app.hby.psr.parse(ims=recipient.makeEndRole(eid=state.operator.pre, role=kering.Roles.mailbox, allow=False))
    assert not receiving_ready(app.vault, recipient)
    plugin._boot_client = state.client
    asyncio.run(ensure_receiving(app.vault, recipient, retry=True))
    assert receiving_ready(app.vault, recipient)
    assert app.hby.db.ends.get((recipient.pre, 'mailbox', state.operator.pre)).allowed
    attempts = len(state.requests)
    assert asyncio.run(plugin.ensure_messaging(app.vault, recipient.pre, retry=True))
    assert len(state.requests) == attempts
    plugin.on_vault_closed(app.vault, clear=True)


def test_ready_identifier_does_not_wait_for_other_setup(mailbox_plugin):
    state = mailbox_plugin
    state.bootstrap = {'mailbox_enabled': True}
    state.db.mailboxes.pin(('recipient',), MailboxRecord(account_aid='account', status='active'))
    state.db.mailboxes.pin(('other',), MailboxRecord(account_aid='account', retry_at=10**12))
    async def ready():
        state.plugin._start_mailboxes()
        worker = state.plugin._mailbox_task
        assert await asyncio.wait_for(state.plugin.ensure_messaging(state.app.vault, 'recipient'), 0.5)
        assert not worker.done()
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
    asyncio.run(ready())


def test_retry_existing_mailbox_does_not_require_provider(ipex_vaults):
    app = ipex_vaults('unmanaged-mailbox')
    hab = app.hby.makeHab(name='recipient')
    app.vault.plugin_manager = None
    asyncio.run(ensure_receiving(app.vault, hab, retry=True))
