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
        state.plugin._resume_mailboxes()
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
        state.plugin._resume_mailboxes()
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
        state.plugin._resume_mailboxes()
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
def test_disabled_capability_preserves_verified_operator_route(mailbox_account, monkeypatch):
    state = mailbox_account
    record = asyncio.run(KFMailboxService(vault=state.app.vault, db=state.db,
                                          boot_client=state.client).provision(state.recipient.pre))
    requests_before = len(state.requests)
    state.app.config = SimpleNamespace(environment=SimpleNamespace(value='development'))
    plugin = KeriFoundationPlugin()
    plugin.initialize(state.app)
    plugin.on_vault_opened(state.app.vault)
    plugin._db.pin_account(state.db.get_account())
    plugin._db.mailboxes.pin((state.recipient.pre,), record)
    monkeypatch.setattr('locksmith.plugins.kerifoundation.onboarding.service.requests.get',
                        lambda *args, **kwargs: SimpleNamespace(raise_for_status=lambda: None,
                            json=lambda: {'bootstrap': {'mailbox_enabled': False}}))

    async def reopen():
        plugin._resume_mailboxes()
        await plugin._mailbox_task

    try:
        asyncio.run(reopen())
        assert plugin._db.mailboxes.get((state.recipient.pre,)) == record
        assert plugin._db.mailboxes.get((state.account.pre,)).status == 'pending'
        assert state.app.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.operator.pre)).allowed
        assert len(state.requests) == requests_before
    finally:
        plugin.on_vault_closed(state.app.vault, clear=True)


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
def test_existing_boot_mailbox_route_is_replaced_after_operator_verification(mailbox_account):
    state = mailbox_account
    state.db.mailboxes.pin((state.recipient.pre,), MailboxRecord(
        mailbox_id='old-allocation', account_aid=state.account.pre,
        eid=state.boot.pre, url='http://127.0.0.1:9783', status='active'))
    authorization = state.recipient.makeEndRole(eid=state.boot.pre, role=kering.Roles.mailbox,
                                               version=kering.Vrsn_2_0, kind=kering.Kinds.json)
    state.app.hby.psr.parse(ims=bytearray(authorization))
    service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
    record = asyncio.run(service.provision(state.recipient.pre))
    assert record.eid == state.operator.pre
    assert not state.app.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.boot.pre)).allowed
    assert state.app.hby.db.ends.get((state.recipient.pre, kering.Roles.mailbox, state.operator.pre)).allowed


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
            destination=state.boot.pre, require_reply=False,
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
        parsed.append(args[0].vault)
        return parse(*args, **kwargs)

    monkeypatch.setattr(module, 'parse_cesr_http_reply', record_parse)
    bind = exchange(route='/mailbox/bind', sender=state.recipient.pre, receiver=state.boot.pre,
                    attributes={'account_aid': state.account.pre, 'recipient_aid': state.recipient.pre},
                    version=kering.Vrsn_2_0, kind=kering.Kinds.json)

    async def switch_during_request():
        await state.client._post_cesr_async(
            vault=vault, url=state.client.account_url,
            ims=state.recipient.msgOwnInception(gvrsn=kering.Vrsn_2_0),
            destination=state.boot.pre, require_reply=False,
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
def test_publication_failure_preserves_old_route_and_prevents_ready(mailbox_account):
    from locksmith.core.messaging import receiving_ready
    state = mailbox_account
    old = state.boot
    state.app.hby.psr.parse(ims=bytearray(old.replay(gvrsn=kering.Vrsn_2_0)))
    state.app.hby.psr.parse(ims=bytearray(state.recipient.makeEndRole(
        eid=old.pre, role=kering.Roles.mailbox, version=kering.Vrsn_2_0)))
    state.db.mailboxes.pin((state.recipient.pre,), MailboxRecord(account_aid=state.account.pre,
                                                               eid=old.pre, status='active'))
    service = KFMailboxService(vault=state.app.vault, db=state.db, boot_client=state.client)
    state.mode = 'unpublished'
    with pytest.raises(TimeoutError, match='publish'):
        asyncio.run(service.provision(state.recipient.pre))
    assert state.app.hby.db.ends.get((state.recipient.pre, 'mailbox', old.pre)).allowed
    record = state.db.mailboxes.get((state.recipient.pre,))
    assert record.status == 'failed'
    state.app.vault.plugin_manager = SimpleNamespace(messaging_status=lambda vault, pre: (record.status, record.error))
    assert not receiving_ready(state.app.vault, state.recipient)
    state.mode = ''
    record = asyncio.run(service.provision(state.recipient.pre))
    assert record.status == 'active'
    assert not state.app.hby.db.ends.get((state.recipient.pre, 'mailbox', old.pre)).allowed
    assert state.operator.db.ends.get((state.recipient.pre, 'mailbox', state.operator.pre)).allowed


def test_ready_identifier_does_not_wait_for_other_setup(mailbox_plugin):
    state = mailbox_plugin
    state.bootstrap = {'mailbox_enabled': True}
    state.db.mailboxes.pin(('recipient',), MailboxRecord(account_aid='account', status='active'))
    state.db.mailboxes.pin(('other',), MailboxRecord(account_aid='account', retry_at=10**12))
    async def ready():
        state.plugin._resume_mailboxes()
        worker = state.plugin._mailbox_task
        assert await asyncio.wait_for(state.plugin.ensure_messaging(state.app.vault, 'recipient'), 0.5)
        assert not worker.done()
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
    asyncio.run(ready())


def test_retry_existing_mailbox_does_not_require_provider(ipex_vaults):
    from locksmith.core.messaging import ensure_receiving
    app = ipex_vaults('unmanaged-mailbox')
    hab = app.hby.makeHab(name='recipient')
    app.vault.plugin_manager = None
    asyncio.run(ensure_receiving(app.vault, hab, retry=True))
