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

Development is hardcoded to the local ``kf-boot`` stack at
``http://127.0.0.1:9723/onboarding`` and ``http://127.0.0.1:9723/account``.
Staging and production routes intentionally default to blank until the real
hosted URLs are available.

Temporary local-stack variants should be added as explicit configing values,
not ``.env``-driven runtime overrides.

``/bootstrap/config`` remains plain JSON over the configured HTTP(S) surface.
Authenticated onboarding and approved-account requests are posted as
CESR-over-HTTP with KRAM-authenticated messages signed by the appropriate local
AID.
