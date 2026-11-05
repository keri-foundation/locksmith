"""Provision recipient-owned mailboxes under the open vault's KF account."""

import asyncio

import requests
from types import SimpleNamespace
from urllib.parse import urlsplit

from keri import kering
from keri.app import habbing
from keri.app.habbing import GroupHab
from keri.core import exchange, parsing

from locksmith.core.remoting import resolve_oobi
from locksmith.plugins.kerifoundation.db.basing import ACCOUNT_STATUS_ONBOARDED, MailboxRecord
from locksmith.plugins.kerifoundation.onboarding.service import (
    KFBootError, KFOnboardingService, parse_cesr_http_reply,
)


class KFMailboxService:
    """Keep local setup recoverable when an account request loses its reply."""

    def __init__(self, *, vault, db, boot_client):
        self.vault = vault
        self.db = db
        self.client = boot_client

    def _require_open(self):
        if self.vault.closed or not self.db.opened or not self.vault.hby.db.opened:
            raise KFBootError("The vault is closed")

    async def provision(self, recipient_aid: str) -> MailboxRecord:
        """Create or recover one allocation and retain its signed delivery route."""
        self._require_open()
        account = self.db.get_account()
        if account is None or account.status != ACCOUNT_STATUS_ONBOARDED:
            raise KFBootError("Complete KF account onboarding before setting up a mailbox")
        destination = account.boot_server_aid
        if not destination:
            raise KFBootError("The KF account has no verified boot service")
        hby = self.vault.hby
        account_hab = hby.habByPre(account.account_aid)
        recipient = hby.habByPre(recipient_aid)
        if any(hab is None or isinstance(hab, GroupHab) or not hab.accepted
               for hab in (account_hab, recipient)):
            raise KFBootError("Mailbox setup requires local, accepted single identifiers")
        record = self.db.mailboxes.get(keys=(recipient_aid,)) or MailboxRecord()
        if record.account_aid and record.account_aid != account.account_aid:
            raise KFBootError("This identifier has a mailbox under a different account")
        record.account_aid, record.status, record.error = account.account_aid, "pending", ""
        self.db.mailboxes.pin(keys=(recipient_aid,), val=record)
        try:
            # Read and sign on the vault's event loop. Workers receive bytes only.
            introductions = []
            for hab in {hab.pre: hab for hab in (account_hab, recipient)}.values():
                introductions.extend(bytes(message) for message in hby.db.cloneDelegation(
                    hab.kever, gvrsn=kering.Vrsn_2_0))
                introductions.extend(self.client._iter_surface_keystate_messages(
                    hab=hab, start_sn=0, end_sn=hab.kever.sn))
            for message in introductions:
                await self._post(message, destination)
            # Create fresh binding timestamps after the KEL upload completes.
            bind = exchange(
                route="/mailbox/bind", sender=recipient_aid, receiver=destination,
                attributes={"account_aid": account.account_aid, "recipient_aid": recipient_aid},
                version=kering.Vrsn_2_0, pvrsn=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0,
                kind=kering.Kinds.json,
            )
            request = exchange(
                route="/account/mailboxes/create", sender=account.account_aid, receiver=destination,
                attributes={"account_aid": account.account_aid, "recipient_aid": recipient_aid,
                            "binding": recipient.endorse(bind, last=False, framed=True).decode("utf-8")},
                version=kering.Vrsn_2_0, pvrsn=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0,
                kind=kering.Kinds.json,
            )
            signed = account_hab.endorse(request, last=False, framed=True)
            response = await self._post(signed, destination)
            reply = parse_cesr_http_reply(
                SimpleNamespace(vault=self.vault), response, expected_kinds=("exn",),
                expected_route=request.ked["r"], expected_sender=destination,
                expected_request=request.said, expected_recipient=account.account_aid,
            )
            operation = reply.payload.get("operation")
            if operation:
                mailbox = await self._wait_for_allocation(
                    operation, account_hab=account_hab, recipient_aid=recipient_aid,
                    destination=destination,
                )
            else:
                mailbox = reply.payload.get("mailbox", {})
            if (not isinstance(mailbox, dict) or mailbox.get("recipient_aid") != recipient_aid
                    or not isinstance(mailbox.get("eid"), str) or not mailbox["eid"]
                    or mailbox.get("status") != "active"
                    or not isinstance(mailbox.get("mailbox_id"), str) or not mailbox["mailbox_id"]):
                raise KFBootError("Boot returned an invalid mailbox allocation")
            url = mailbox.get("url", "")
            location = urlsplit(url) if isinstance(url, str) else None
            if (location is None or location.scheme not in ("http", "https") or not location.netloc
                    or location.path not in ("", "/") or location.query or location.fragment
                    or location.username or location.password):
                raise KFBootError("Mailbox location must be an HTTP service root")
            mailbox_eid = mailbox["eid"]
            accepted_location = hby.db.locs.get(keys=(mailbox_eid, location.scheme))
            if accepted_location is None or accepted_location.url != url:
                oobis = mailbox.get("oobis")
                if not isinstance(oobis, list) or not oobis or not all(isinstance(oobi, str) for oobi in oobis):
                    raise KFBootError("Mailbox allocation has no operator OOBI")
                # Bind the resolver to this vault, even if the application's vault changes.
                app = SimpleNamespace(vault=self.vault, qtask=getattr(self.client._app, "qtask", None))
                resolved = await resolve_oobi(
                    app, pre=mailbox_eid, oobi=oobis[0], force=True,
                    alias="KF Mailbox", cid=recipient_aid, tag="mailbox",
                )
                self._require_open()
                if not resolved:
                    raise KFBootError("Mailbox operator OOBI could not be resolved")
                accepted_location = hby.db.locs.get(keys=(mailbox_eid, location.scheme))
            if accepted_location is None or accepted_location.url != url:
                raise KFBootError("Mailbox location has no matching signed service reply")

            authorization = recipient.makeEndRole(
                eid=mailbox_eid, role=kering.Roles.mailbox,
                version=kering.Vrsn_2_0, pvrsn=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0,
            )
            parsing.Parser(kvy=hby.kvy, rvy=hby.rvy, local=True,
                           version=kering.Vrsn_2_0).parse(ims=bytearray(authorization))
            end = hby.db.ends.get(keys=(recipient_aid, kering.Roles.mailbox, mailbox_eid))
            if end is None or not end.allowed:
                raise KFBootError("Mailbox authorization was not accepted")
            # Publish the recipient's signed role at the mailbox that serves its OOBI.
            for message in hby.db.cloneDelegation(recipient.kever, gvrsn=kering.Vrsn_2_0):
                await self._post(message, mailbox_eid, url=url)
            for message in hby.db.clonePreIter(pre=recipient_aid, gvrsn=kering.Vrsn_2_0):
                await self._post(message, mailbox_eid, url=url)
            await self._post(authorization, mailbox_eid, url=url)
            response = await KFOnboardingService._await_blocking_result(
                requests.get, f"{url.rstrip('/')}/oobi/{recipient_aid}/mailbox/{mailbox_eid}", timeout=30)
            self._require_open()
            if response.status_code == 404:
                raise TimeoutError("Waiting for the mailbox to publish this identifier's introduction")
            if response.status_code != 200:
                raise KFBootError("The mailbox has not published this identifier's introduction",
                                  status_code=response.status_code)
            # A fresh reader must accept the route without our locally cached authorization.
            with habbing.openHby(name="mailbox-introduction", temp=True, version=kering.Vrsn_2_0) as reader:
                reader.psr.parse(ims=bytearray(response.content), version=kering.Vrsn_2_0)
                published = reader.db.ends.get((recipient_aid, kering.Roles.mailbox, mailbox_eid))
                published_location = reader.db.locs.get((mailbox_eid, location.scheme))
                if (recipient_aid not in reader.kevers or published is None or not published.allowed
                        or published_location is None or published_location.url != url):
                    raise KFBootError("The mailbox introduction has no verified receiving address")
            if record.eid and record.eid != mailbox_eid:
                old_end = hby.db.ends.get(keys=(recipient_aid, kering.Roles.mailbox, record.eid))
                if old_end is not None and old_end.allowed:
                    replacement = recipient.makeEndRole(
                        eid=record.eid, role=kering.Roles.mailbox, allow=False,
                        version=kering.Vrsn_2_0, pvrsn=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0,
                    )
                    parsing.Parser(kvy=hby.kvy, rvy=hby.rvy, local=True,
                                   version=kering.Vrsn_2_0).parse(ims=bytearray(replacement))
                    revoked = hby.db.ends.get(keys=(recipient_aid, kering.Roles.mailbox, record.eid))
                    if revoked is None or revoked.allowed:
                        raise KFBootError("Previous mailbox authorization was not revoked")
            record.mailbox_id, record.eid, record.url = mailbox["mailbox_id"], mailbox_eid, url
            record.status = "active"
            self.db.mailboxes.pin(keys=(recipient_aid,), val=record)
            self.db.attach_identifier(recipient_aid)
            return record
        except asyncio.CancelledError:
            # The server may have committed. The durable pending record retries
            # the same account/recipient allocation when this vault reopens.
            raise
        except Exception as exc:
            if not self.vault.closed and self.db.opened:
                record.status, record.error = "failed", str(exc)
                self.db.mailboxes.pin(keys=(recipient_aid,), val=record)
            raise

    async def _wait_for_allocation(self, operation, *, account_hab, recipient_aid, destination):
        operation_id = operation.get("operation_id") if isinstance(operation, dict) else None
        if not isinstance(operation_id, str) or not operation_id:
            raise KFBootError("Boot returned an invalid mailbox operation")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 60
        while True:
            self._require_open()
            if (operation.get("operation_id") != operation_id
                    or operation.get("requester") != account_hab.pre
                    or operation.get("subject") != recipient_aid
                    or operation.get("kind") != "mailbox_create"):
                raise KFBootError("Boot returned a different mailbox operation")
            state = operation.get("state")
            if state == "succeeded":
                return operation.get("result", {}).get("mailbox", {})
            if state == "failed":
                raise KFBootError(operation.get("last_error") or "Mailbox allocation failed")
            if state not in {"pending", "running"} or loop.time() >= deadline:
                raise KFBootError("Mailbox allocation is still pending. Retry setup to resume it.")
            await asyncio.sleep(0.5)
            self._require_open()
            request = exchange(
                route="/operations/status", sender=account_hab.pre, receiver=destination,
                attributes={"operation_id": operation_id}, version=kering.Vrsn_2_0,
                pvrsn=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0, kind=kering.Kinds.json,
            )
            response = await self._post(account_hab.endorse(request, last=False, framed=True), destination)
            reply = parse_cesr_http_reply(
                SimpleNamespace(vault=self.vault), response, expected_kinds=("exn",),
                expected_route=request.route, expected_sender=destination,
                expected_request=request.said, expected_recipient=account_hab.pre,
            )
            operation = reply.payload.get("operation", {})

    async def _post(self, message, destination, *, url=None):
        self._require_open()
        response = await KFOnboardingService._await_blocking_result(
            self.client.request_cesr, url=url or self.client.account_url,
            ims=bytes(message), destination=destination,
        )
        self._require_open()
        return response
