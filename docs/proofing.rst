Citizen Challenge and IAR Binding
=================================

This workflow checks citizen control of an AID and binds an authenticated Identity
Assurance Receipt (IAR) to that challenge. It does not complete registration or
approve the proofer's authority, identity attributes, entitlements, or age claim.

Open **Credentials → Proofing**. Choose **New session**, or open a saved session
to resume it. Sessions are stored in that vault. Citizen anchoring and proofer
issuance actions are shown only when that identifier is local; independent
verifiers can still check a received receipt binding. The
challenge and AIDs are exchanged out of band; this dialog does not transport
them or synchronize remote KELs automatically.

1. In the proofer wallet, enter the citizen AID received out of band and the
   local proofer AID. Leave Challenge blank and choose **Save challenge** to
   generate a fresh nonce. Send that exact nonce to the citizen out of band.
2. In the citizen wallet, enter the same citizen AID, proofer AID, and nonce.
   Choose **Save challenge**, then **Anchor as citizen**. Witnessed citizens
   use the existing witness authentication panel: enter their witness passcodes
   and choose **Authenticate and anchor**. Cancellation before submission
   creates no event. Citizens without witnesses proceed directly.
3. The citizen interaction contains a native ``SealNonce``. The vault scheduler
   runs an owned receiptor child to collect witness receipts. A successful check
   records ``binding_verified`` and displays the anchor sequence number. If collection
   is interrupted after the event was created, resume the saved session to
   retry receipts for that event using its historical witnesses and threshold,
   even if the citizen has since rotated. Closing the dialog cancels its
   scheduled anchor task and its owned network work. Unverified challenges
   expire after 15 minutes; saved event
   evidence is retained, and expiration does not grant an approval.
   The verified citizen anchor reference can be copied and returned out of band.
   It contains the citizen AID, the hexadecimal sequence number, and the event
   digest. Copying is available only after checking the accepted event and its
   witness evidence. The proofer still obtains and verifies the actual KEL;
   the reference alone is not proof.
4. In the proofer wallet, ensure the citizen KEL and witness evidence have been
   received and accepted by keripy. Resume the original session, enter the
   citizen anchor sequence number in decimal, and choose **Check binding**.
   The event must be the current canonical accepted event at that sequence
   number and satisfy the native witness check.
5. Load the published IAR schema and configure the session proofer as its local
   issuer. Choose **Issue IAR…**, fill the proofing attributes, and issue and
   grant the credential using the existing credential flow. The dialog fixes
   the IAR schema and citizen recipient and passes the session nonce as the
   credential's top-level ``u``. Issuance itself is not an authority decision.
6. In the citizen or an independent verifier wallet, import the same OOB
   citizen AID, proofer AID, and nonce as a session. Neither AID needs to be
   local for an imported session. Receive and accept the ordinary IAR through
   the existing credential flow, obtain the accepted citizen KEL and witness
   evidence, then enter its SAID and anchor sequence number and choose
   **Check binding**. The received inventory must authenticate the issuer;
   the IAR schema, ``u``, ``a.i``, and issuer must match this session.

Successful receipt binding records ``awaiting_authority``. An imported session
does not let an independent wallet anchor as the citizen. Generating a challenge
requires a local proofer, and creating the citizen interaction requires a local
individual citizen identifier that permits interactions.

Trust and workflow limits
-------------------------

The receiving application must determine whether the proofer is authorized for
its purpose and how it trusts the supplied key state or authority evidence.
Authenticating the IAR issuer does not establish that permission. This workflow
adds no proofer allowlist or authority approval control.

The dialog stops at challenge and receipt binding. It does not issue State
entitlements, prepare presentation-registry proofs, enforce an age policy, or
complete registration. Graph verification and supported operators are determined
by the locked keripy dependency. Applications must retain required authority
checks rather than replace an unsupported operator with an unconstrained edge.
