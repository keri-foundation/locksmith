KERI Foundation Plugin
======================

This document covers the Locksmith side of the KERI Foundation plugin.

The canonical server contract lives in the `kf-boot README
<https://github.com/keri-foundation/kf-boot/blob/main/README.md>`_. This document
keeps the client-side obligations and the current transition state in one place.

Client Contract
---------------

The plugin is account-gated.

- no local KF account record means show onboarding
- a local record that is not onboarded means return to onboarding, where a
  saved session can resume or an abandoned attempt can restart
- an onboarded record means show the normal KF pages

The plugin owns:

- the hidden ephemeral onboarding AID
- permanent account AID creation or selection
- local key management
- witness registration and witness authentication flows
- witness and watcher OOBI resolution
- local witness auth state and local account state persistence
- automatic mailbox setup for local individual identifiers
- coordinating remote onboarding cancellation and account deletion during cleanup

The provider service remains authoritative for:

- hosted witness or watcher allocation
- account approval state on the server
- hosted resource lifecycle on the server

Authenticated client-server traffic uses:

- CESR-over-HTTP over HTTPS/TLS in production
- KRAM for onboarding and approved-account requests

Local development uses the configured localhost HTTP surfaces.

Auth principals:

- onboarding uses the hidden ephemeral onboarding AID
- approved-account management uses the permanent account AID

First-contact rule:

- before the first KRAM-authenticated onboarding request, the plugin must send
  or precede it with the ephemeral AID inception or keystate material so
  ``kf-boot`` can resolve sender state

Onboarding Responsibilities
---------------------------

1. Fetch bootstrap config from ``kf-boot`` and resolve the selected witness profile.
2. Create or select the permanent account AID locally and persist the pending account state.
3. Create or reload the hidden ephemeral onboarding AID.
4. Resume a saved onboarding session, or introduce the ephemeral AID and start a new one.
5. Receive and validate the allocated witnesses and required watcher.
6. Register the permanent account AID with the witnesses and persist the local auth state.
7. Rotate the account AID onto the allocated witness set and collect the required receipts.
8. Resolve the watcher OOBI, then introduce the account AID and its witness OOBIs to the watcher.
9. Create the provider-side account and complete the remote onboarding session.
10. Mark the local account as onboarded and remove the ephemeral onboarding AID.
11. Use the permanent account AID for later approved-account requests.

After onboarding, the plugin sets up receiving for local individual identifiers
when ``bootstrap.mailbox_enabled`` is JSON ``true``. New identifiers use the same
account automatically. Namespaced internal identifiers and groups are excluded.
A missing or false capability pauses setup without changing account or witness
state. The provider page remains available for witness management.

Setup verifies the signed allocation, publishes the recipient's signed mailbox
authorization to the allocated operator, and reads its introduction back. A fresh
reader must verify the receiving address before setup reports success. The
operator must serve ``/oobi/{recipient}/mailbox/{operator}``. Use a mailbox service
that supports recipient introductions; an operator-only OOBI is insufficient.

Temporary failures receive at most three retries after the first attempt. The
attempt count and next attempt time survive closing the vault. Exhausted or
rejected setup waits for **Connection details → Retry connection**. A failed
replacement leaves the previous authorization in place.

**Copy contact link** shares the mailbox-hosted introduction. **Share introduction**
exports the signed public history, service location, and mailbox authorization.
Neither operation exports private keys or grants another user mailbox read access.

Credential messages use this explicit mailbox route. Witnesses continue to
receive control traffic. When an existing identifier first gets a mailbox,
Locksmith reads its saved witness credential queues for 24 hours. The deadline
survives a restart. This does not delete messages from the old queues. Exchange
new introductions with contacts so they use the new route.

For the strongest practical setup offered here, use four witnesses with a TOAD
of three; this requires three witness receipts while allowing one witness to be
unavailable.

Onboarding progress is checkpointed in the per-vault plugin database. A retry
can resume a compatible server session and reuse persisted witness registration
state. Failures before local witness state changes can be abandoned and cleaned
up; after the account AID has rotated, the session is preserved for recovery.

Vault deletion also crosses the client-server boundary. The plugin cancels a
saved onboarding session or deletes an onboarded provider account before the
local vault is removed. If that remote cleanup fails, vault deletion stops.

Current Transition
------------------

The repo still contains transitional raw witness-server configuration and UI
paths from the earlier server-oriented model.

Those paths are legacy. Do not expand them.

The target model is:

- onboarding and account management through ``kf-boot``
- hosted witness and watcher allocation returned by the onboarding service
- witness registration and auth state stored in the per-vault plugin database
- witness rows built from local plugin state
- watcher rows fetched from the approved-account service

The manual watcher registration page is still a placeholder. The current
working path is the watcher allocated during account onboarding.

Legacy witness provisioning code still reads environment variables such as
`KF_DEV_WITNESS_URL_*` and `KF_DEV_BOOT_URL_*`. That is transitional support,
not the long-term plugin contract.

Boot Surface Configuration
--------------------------

The onboarding flow reads the public boot surfaces from plugin-local defaults in
``locksmith.plugins.kerifoundation.core.configing``.

Development defaults to the local ``kf-boot`` stack at
``http://127.0.0.1:9723/onboarding`` and ``http://127.0.0.1:9723/account``.
Staging and production routes intentionally default to blank until the real
hosted URLs are available.

Set ``KF_DEV_ONBOARDING_URL`` and ``KF_DEV_ACCOUNT_URL`` to use another local
stack. Use the ``KF_STAGING`` or ``KF_PROD`` prefix for those environments.
Replace the example origin with the configured service origin:

.. code-block:: bash

   export KF_DEV_ONBOARDING_URL=https://boot.example/onboarding
   export KF_DEV_ACCOUNT_URL=https://boot.example/account

The optional ``ONBOARDING_DESTINATION`` and ``ACCOUNT_DESTINATION`` variables
under the same prefix pin the service AID. Mailbox setup uses the verified boot
AID saved with the account for management. Message transport uses the verified
operator returned by allocation. Configure Boot's private provider connection
with ``KF_BOOT_MBX_BOOT_URL`` and the provider's public origin with
``KF_MAILBOX_PUBLIC_URL``. The provider connection defaults to empty, so mailbox
allocation is opt-in. Boot advertises ``bootstrap.mailbox_enabled`` from that
configuration; Locksmith does not persist a separate capability setting. Use
HTTPS for hosted services.

Old allocations whose endpoint equals the Boot AID are queued for replacement
on vault open. The old role is revoked only after the new operator is verified.
This does not transfer old queued messages. Preserve and drain used queues before
changing deployments, then exchange fresh introductions. Live standalone
interoperation remains an acceptance gate.

``/bootstrap/config`` remains plain JSON over the configured HTTP(S) surface.
Authenticated onboarding and approved-account requests are posted as
CESR-over-HTTP with KRAM-authenticated messages signed by the appropriate local
AID.
