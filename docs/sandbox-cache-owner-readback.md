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
that same cut. A privileged read-only
idmapped Cache view would instead permit root to resolve names itself while
keeping on-disk mode 0700 and policy-authorityd cap-empty, but it introduces a
trusted mount setup and still needs non-mutating protected journal replay.
