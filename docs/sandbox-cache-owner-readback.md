# Closed Cache-owner named readback

`AOSCRB01` is a non-authorizing, fixed-size statement from a physical Cache
owner holding its `.owner.lock` flock. The owner rechecks the fixed mode-0700
root, named mode-0600 lock, and replayed `owner-state` head before and after
signing. The signature binds a root-session nonce, held-cut commitment,
physical owner limits, fixed root/lock identities, manifest head, and a
nonzero Cache signer generation. The distinct `AOSCPK01` public credential
cannot be parsed as a deployment or project policy signer credential.
The older `AOSCOR01` magic belongs to the Cache atomic-record format and is
rejected as a signed readback.

Deployment may now provision a separate Cache signing seed and `AOSCPK01`
public credential. Controller startup verifies the pair and forgets the seed;
root persists the exact public pin after checking its deployment/project pins
and rejects key reuse or rotation. The separate `AOSPHQ05` exchange can spend a
fresh root-writer challenge epoch, authenticate the Controller socket peer,
and verify one signed readback under the fixed pin. Its acknowledgement is
non-authorizing; `AOSPHQ04` does not consume it.
The seed is an external system credential, not a repository or Nix-store
literal. `aos-sandbox-policy-key-pin cache` creates the public credential from
an externally derived Ed25519 public key. The Controller and policy-authority
module options must name the same public credential; the private seed is never
loaded by policy-authorityd.
The codec's verifier checks framing, the signature, and its supplied challenge;
it does not independently resolve Cache names or establish that the signer held
the flock. A caller-supplied verification credential is not an authority root.
Public Create and `AOSPCB02` publication remain closed.

The approved authority rule delegates only *named physical Cache currentness*
to that signer; root does not pretend it independently performed DAC-protected
lookups. Controller rejects reuse of its broker-plan signing key; root rejects
reuse of deployment/project signing keys. The Cache owner currently shares the
Controller UID, so a signature alone does not isolate it from compromise of
another process with that UID. Separate Cache-process custody is not yet
provided by the current Controller-resident owner.

The Q05 root challenge binds only root-authenticated deployment and V2 project
source records, the fixed Cache signer pin, and a durable spent epoch. The
Controller-side client can sign only through a locally held physical Cache
snapshot, which rechecks the fixed root, lock flock, manifest and owner limits
before and after signing. Root verifies the signature, expected Controller UID,
nonce and root-source cut, but cannot independently establish from that packet
that the protected Cache quota/head or other owners were held at one cut.

Live Q04 admission still needs Controller, source-domain, protected Cache
journals, and the physical Cache flock held in canonical order through root CAS
and a recoverable effect handoff; root verification of the exact current
protected Cache quota envelope; and crash/replay checks binding every owner to
that same cut. The root-only idmapped Cache view now permits policy-authorityd
to resolve the four protected journal names while the on-disk directory stays
mode 0700 and the service stays cap-empty. Its read-only opener checks the fixed
mount, owner, mode, and independently re-resolved names, then reuses the Cache
authority and typed-history verifier without repairing a tail or taking the
Controller lock. A separate observation replays the exact active hold from
the fourth name, compares its project, partition, and head with the unique
healthy replayed Cache partition, and checks all four names and the mount
again. It returns the hold's binding and epoch as Cache-owned facts only. A
future root CAS must compare those values with root-owned expectations under
the complete owner cut. Independent read-only replay cannot itself establish
one held Controller cut for Q04 or public Create.

The Controller-resident Cache cut now borrows its existing protected owner and
physical owner together. Its V2 callback retains the state, authority, clock,
hold, and physical lock writers; replays the exact held project head; commits
every node quota in canonical partition order; compares the resulting complete
envelope with the physical owner's actual limits; and rechecks all names and
the physical manifest after the callback. The clock samples time without
advancing its journal while the cut is held, because normal advancement drops
and reopens that writer. This callback returns only typed, nonauthorizing
facts. The old standalone V2 signer opener is removed: reopening these already
held writers and physical flock cannot succeed in a live Controller. No V2
packet is issued until a root CAS transport can retain the wider owner cut.

The closed protected Cache owner also retains an exact `AOSCPH01` policy hold
in its own `policy-hold.journal`. A held record names the project, partition,
replayed Cache head, proposed root binding, and epoch. Cache state and manifest
commits and compaction check that journal under its writer lock, including
after restart; only the monotone clock floor may advance. Fresh installation
creates a genesis record before any Cache journal history, and an absent hold
journal alongside existing history fails closed. An exact offline root readback
can retire the hold only when the proposal never committed at that epoch or its
matching inert root hold was durably released.
Offline retirement replays the immutable Cache partition and quota under the
clock, authority, and state locks, comparing the exact held head before root
readback. It can do so after the historical Replay scope expires, but it does
not renew that scope or make normal Cache mutation/currentness valid again.

This remains a split-authority cut. The Controller-owned Cache writer can
release its hold, but cannot read root custody; cap-empty policy-authorityd can
read its root journal but cannot open the writable Controller-owned Cache
journals. The root read-only Cache view now includes an observation-only live
hold witness, but no versioned cross-process release exchange exists. Q04 does not
consume this hold, and neither public Create nor `AOSPCB02` publication is open.
