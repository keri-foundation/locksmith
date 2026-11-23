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

Add a contact through its OOBI or signed introduction file. Verify the contact's
AID through your agreed channel. An introduction may contain only key history.
Use **Identifiers → View → Copy contact link** or **Share introduction** to
share your own identifier. You can share the introduction file before account or mailbox
setup. The contact link and credential actions require a receiving address.

Messaging starts automatically for local individual identifiers when the KERI
Foundation account offers mailboxes. No separate mailbox registration is needed.
An account can still finish onboarding when its provider does not offer mailboxes.

Locksmith reads credentials and forwarded witness receipts from authorized
mailboxes. If a mailbox goes offline, the open vault retries after 30 seconds,
then 60 seconds, then every 120 seconds. It resumes at the saved position.
If the mailbox denies access, correct the receiving setup and choose
**Connection details → Retry connection**. Use **Retry sending** for a saved
outgoing message after its three automatic retries. Retrying preserves the
credential and its approved disclosure. Invalid authorization and expired
exchanges require correction.

If a contact lacks a delivery address, refresh the contact or import its updated
introduction. For credential delivery, use a controller, agent, or mailbox
route with an HTTP or HTTPS address. A TCP-only address cannot deliver the
credential stream with this version of Keripy.

Issue and send
--------------

1. Load the schema in the issuer wallet, enable issuance, and select the local
   issuer AID. The recipient wallet loads matching built-in schemas when it
   verifies an Offer or Grant. Import any other required schemas in the recipient wallet.
2. Open Issued Credentials and choose Issue Credential. Select the credential type,
   recipient, attributes, linked credentials and terms. Use the authentication
   supported by that schema and the relying application: registry, issuer KEL
   anchor, or issuer signature. Registry-backed credentials require configured
   registry services and accepted evidence.
3. Review the entered information and choose Issue Credential. Complete any
   witness authentication requested by the identifier. Wait for Credential
   created before continuing. If the witness code expires, enter a current code
   and retry. Locksmith can collect missing receipts for this issuance on retry.
   If earlier events belong to other operations, review what each event seals.
   Choose **Approve recovery** to collect their receipts with the witness code,
   or choose **Back** to leave them pending. To continue after a
   vault restart, open **Issued Credentials → Resume issuance** on the pending
   credential. You can also reopen its original request. Review the saved values
   and authenticate again. If the original request expired, this finishes issuance
   in your wallet. Start a new exchange to send the credential.
4. For the negotiated issuance flow, choose Offer. Locksmith includes the complete
   bare credential and its supporting authority chain so the recipient can review
   every value and term before agreeing. Issuer-authentication proofs remain in the
   later Grant. Direct Grant is still available when no Offer review is required.
5. In the recipient wallet, open Activity and review the Offer. Choose Agree to
   request its authenticated evidence. After the Grant arrives, review it and choose
   Add credential when appropriate. The wallet retains the accepted credential and
   sends an acknowledgment.

Check Accepted in both activity histories and compare the full credential SAID.
Submitted confirms submission, not recipient acceptance. Closing and reopening
the vault should retain the credential and accepted exchange history.

An authenticated credential establishes the evidence recorded by the wallet.
The relying application still needs to check its trust anchor, authority scope,
credential status and the claim required for its purpose. Receiving an IAR does
not by itself approve a proofer or complete registration; see :doc:`proofing`.

For a SEDI Grant, review **Verified delegation links** before you choose
**Add credential**. Each row names a delegation and shows its issuer and
delegate. The wallet checks these links against its local evidence. Compare
the Organizational Unit credential's issuer with the published State AID
to establish trust in the root.

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
In a SEDI Bespoke request, choose **Age** under **Choose information** to
open the Age fields. You can change the source type if needed.
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
response. On a presentation request, **Select all requested** selects the
requested fields on that credential. To add another field, open **Additional
fields (not requested)** and select it individually. Fields in one indivisible
block are shared together.
For a new credential request without selected fields, the issuer can use
**Select all** under **Available fields**. Choose linked fields separately.
Required identity, credential links and terms remain visible.

Update both wallets before starting a new exchange. This version opens an
IPEX exchange with an ``xip`` message. Wallets that still use the earlier
``exn`` opener cannot exchange new requests with this version.
If Activity reports an older message format, start a new request or offer.
You can reuse the existing credential and view its signed history in Activity.

Activity moves expired exchanges to **History** on refresh. An interrupted
acceptance stays in **In progress** so you can resume it. To clear another
exchange, open its row menu and choose **Move to history**.
Use **Return to in progress** to restore it. This choice applies to your wallet.
Delivery continues, and a new reply that needs action appears in **In progress**.

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
in the credential's ``a.rd`` field. Both wallets need registry-service
configuration and the required identifier evidence. An issuance Offer confirms
``a.preg`` and discloses the complete bare credential for review. Acceptance
rejects a credential that does not use the requested registry. Schemas without
this supported attribute declaration keep the existing request flow. The pinned
Keripy version reads presentation-registry declarations from the expanded ``a``
block only.

Issuance and presentation Offers intentionally differ. An Offer sent by the
credential issuer to its issuee contains the complete bare origin credential and
supporting authority-chain credentials. It does not contain their registry, KEL,
or signature proofs; Grant carries that authenticated evidence after the issuee
agrees. A holder-to-verifier presentation Offer remains value-free: it identifies
the credential and the selected field paths, and the Grant carries only the agreed
values and proofs. Later disclosures do not fill hidden fields in earlier
presentation exchanges. Review the retained Grant to inspect exactly what that
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

Keripy checks presentation registry declarations on the origin credential and
its disclosed links. A declaration applies when its issuee is a grantor in this
exchange. When the origin issuer grants directly to the origin issuee, Keripy
skips declarations for that recipient throughout the graph. Other grantors'
declarations still apply.

Before using the same registry for a different Grant, check the earlier Grant
in **Activity**. Use **Retry sending** to deliver the original Grant again.
The wallet releases the registry when it verifies the recipient's Admit or
Spurn. Without a reply, it waits until both the exchange and the Grant's
delivery window expire under its KRAM policy.

Preparation is not automatically resumed after interruption or failure. Returned
proofs are retained, but a crash during native staging can occur before the
wallet saves them. Inspect the registry state before creating another
presentation. File export does not run this asynchronous preparation path.
Composition or a local stream alone does not establish recipient acceptance or
complete recovery support. Unsupported graph operators
must not be replaced by removing their authority checks.
