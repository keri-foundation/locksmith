Credential Exchange
===================

Locksmith uses IPEX to issue credentials and present credentials that a wallet
already holds. Issuer authentication, current credential state, and the
recipient's decision to use a credential are separate checks.

Before an exchange
------------------

Install and configure the wallet using :doc:`developer-guide` and, when using
KERI Foundation services, :doc:`kerifoundation-plugin`. Choose local identifiers
for the sending and receiving roles. The identifiers can be in separate wallets.
Use a distinct storage base when running separate instances; changing
``LOCKSMITH_BASE`` does not move existing vault data.

Add a contact through its OOBI or signed introduction file. Locksmith verifies
and saves the delivery address. Local aliases are labels, not trust anchors.
Use **Identifiers → View → Copy contact link** or **Share introduction** to
share your own identifier. Sharing and credential actions finish receiving
setup through your configured account provider when needed.

Messaging starts automatically for local individual identifiers when the KERI
Foundation account offers mailboxes. No separate mailbox registration is needed.
An account can still finish onboarding when its provider does not offer mailboxes.

Temporary connection failures get three retries after the first attempt, with
waits of 30, 60, and 120 seconds. Exhausted attempts remain paused after reopening.
Open **Connection details → Retry connection** to resume receiving. Use
**Retry sending** for a saved outgoing message. Neither action changes the
credential or its approved disclosure. Invalid authorization and expired
exchanges require correction instead of automatic retries.

Connection details also contains technical addresses and an export of the
available introduction. For an old contact without a delivery address, refresh
the contact or import its updated introduction. Witness routes alone do not
provide credential delivery.

Issue and send
--------------

1. Load the intended schema in the issuer and recipient wallets. In the issuer,
   enable credential issuance for that schema and select the local issuer AID.
2. Open Issued Credentials and choose Issue Credential. Select the schema,
   recipient, attributes, linked credentials and terms. Use the authentication
   supported by that schema and the relying application: registry, issuer KEL
   anchor, or issuer signature. Registry-backed credentials require configured
   registry services and accepted evidence.
3. Review the entered information and choose Issue Credential. Complete any
   witness authentication requested by the identifier. Wait for Credential
   created before continuing.
4. Choose Grant, or use the credential's Grant action later. Verify the recipient
   and expand Review data and terms to share. Send only the intended disclosure.
5. In the recipient wallet, open Activity, review the received exchange and choose
   Add credential when appropriate. The wallet retains the accepted credential
   and sends an acknowledgment.

Check Accepted in both activity histories and compare the full credential SAID.
Submitted confirms submission, not recipient acceptance. Closing and reopening
the vault should retain the credential and accepted exchange history.

An authenticated credential establishes the evidence recorded by the wallet.
The relying application still needs to check its trust anchor, authority scope,
credential status and the claim required for its purpose. Receiving an IAR does
not by itself approve a proofer or complete registration; see :doc:`proofing`.

Negotiate a disclosure
----------------------

Grant followed by Admit can deliver a credential directly. The longer flow
negotiates what to share:

- Apply requests a schema and selected information.
- Offer proposes the credential and disclosure plan.
- Agree requests the proposed disclosure.
- Grant delivers the agreed evidence.
- Admit acknowledges acceptance of that Grant.

In Received Credentials, choose **Request credential…** to ask an issuer for a new
credential, or **Request presentation…** to ask a holder to disclose an existing
credential. For a new credential, choose the issuer and credential type. To request
a presentation, choose the holder and the information you need, including any
linked credential fields. Both use IPEX Apply. The presentation path does not
create an issuance registry. These actions remain available when the inventory is empty.
Choose a built-in schema directly in the request form. Sending the request saves
the chosen schema, and any linked credential types, in the current vault;
cancelling leaves the vault unchanged. The Schema tab
is available for inspection and custom imports; built-in requests do not require
a separate loading step.
On the issuer's request review, choose **Create credential**. This loads a known
schema and enables issuance with the identifier that received the request, then
opens the credential form. If the schema is not available, the same flow asks
for its file or URL. The imported schema must match the request. Setup does not
create or send a credential; review the credential fields before issuing it.
Start an Offer from an issued or
received credential. Open the exchange in Activity for the next available
response. Requested fields are not selected automatically: the holder reviews
and chooses what to offer. Fields in one indivisible block are shared together.
Required identity, credential links and terms remain visible.

For schemas that declare both an issuance registry and an issuee presentation
registry (``rd`` and ``a.i``/``a.rd``), **Request credential…** names the controlling
identifier and explains the setup before you send. Sending the request creates,
anchors, and publishes a new presentation registry before contacting the issuer.
The issuer includes that registry in the new credential. Complete witness
authentication if prompted. The code authorizes the witness receipt for registry
setup. The form shows progress through witness approval, registry publication
and verification, and request submission. The wallet saves the request before
creation starts.
Retry request reuses the saved registry and signed Apply. Once registry setup
has its witness receipts, retry does not ask for another code. A setup failure
leaves the credential request unsent. After reopening a
wallet, request the same credential type from the same issuer with the same
identifier to resume an unfinished request. Delivery retries remain available in
Activity.

Locksmith carries the registry SAID in the signed Apply body as ``a.preg``.
This is a Locksmith application field, not a standard IPEX field. The issuer
verifies the registry's anchor and requester control before it uses that SAID
in the credential's issuee ``rd`` field. Both wallets need registry-service
configuration and the required identifier evidence. Offer confirms ``a.preg``
without disclosing credential values. Acceptance rejects a credential that
does not use the requested registry. Schemas without this supported attribute
declaration keep the existing request flow. The locked protocol does not enforce
presentation-registry declarations in aggregate blocks.

Offer does not disclose the credential's values or terms. Its reference can
identify the same credential across exchanges. Grant carries the selected
values and authentication evidence. Later disclosures do not fill hidden fields
in earlier exchanges. Review the retained Grant to inspect exactly what that
exchange shared, including supporting credentials.

Compose held credentials
------------------------

For a supported presentation schema, enable issuance with the presenting
identifier. Open a request, choose Create credential, select source credentials
and terms, and continue to disclosure review. The wallet creates a self-issued
root linking those sources; it does not send them during creation. Back preserves
choices until the request review closes.

The current composer supports identity-only roots with simple issuer-to-issuee
source edges. Each chosen source must belong to the presenting identifier. This
does not grant control of another party's identifiers or provide their consent.

Limits
------

Selective sharing needs issuer authentication that remains valid for the
selected variant, such as an issuer KEL anchor or registry proof. A signature
over a full credential cannot authenticate a different partial body.

Before an issuer declares your presentation registry in a credential, open
Local Identifiers → the controller's row actions → **Presentation registries…**.
The dialog shows only that controller's registries and pending requests. Choose an
unused name, provide any witness authentication, and wait for
anchoring and publication. Give the resulting public registry identifier to the
issuer through your agreed channel. Existing named registries remain listed
when the vault reopens.

A creation request stays pending until its sealing event has the required
witness receipts. An incorrect or expired code does not register or export the
new registry. Enter a current code and choose **Retry creation**; this keeps the
same request and sealing event. After closing or reopening the vault, select
the pending request to continue. Closing the dialog stops that attempt without
deleting signed event history. Finish an identifier's pending witness
authentication before starting another registry. If authentication succeeded
but publication failed, **Retry publication** completes the existing registry.

Open the controller under **Local Identifiers** and choose **Resubmit** to
finish missing witness receipts. The wallet retrieves existing receipts first
and submits the saved events in order without creating new events. If an older
event needs a different witness configuration, authentication stays pending;
the current witness codes cannot substitute for that original configuration.

For network submissions, credentials declaring a presentation registry require
an individual controller in the same vault. The wallet binds the registry to
one immutable Grant, obtains witness receipts, and waits for configured registry
publication and status checks before queueing delivery. Closing the response
view does not cancel an authorized submission.

Native issuance exempts only the origin credential's presentation requirement
when its issuer grants it to its issuee. A linked credential's presentation
requirement still applies to that new Grant. Collecting a registry binding from
another vault is not implemented; the wallet stops before sending that disclosure.

Preparation is not automatically resumed after interruption or failure. Returned
proofs are retained, but a crash during native staging can occur before the
wallet saves them. Inspect the registry state before creating another
presentation. File export does not run this asynchronous preparation path.
Composition or a local stream alone does not establish recipient acceptance or
complete recovery support. Unsupported graph operators
must not be replaced by removing their authority checks.
