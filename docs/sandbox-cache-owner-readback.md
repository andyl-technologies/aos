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
and rejects key reuse or rotation. No service transports the packet or accepts
it in `AOSPHQ04`.
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

Even after that decision, live admission needs a root-generated fresh nonce
under its writer; Controller, source-domain, protected Cache journals, and the
physical Cache flock held in canonical order through root CAS and a recoverable
effect handoff; root verification of the exact current protected Cache quota
envelope; and crash/replay checks that cannot reuse an old cut. The current
packet supplies none of those owners or effects. A privileged read-only
idmapped Cache view would instead permit root to resolve names itself while
keeping on-disk mode 0700 and policy-authorityd cap-empty, but it introduces a
trusted mount setup and still needs non-mutating protected journal replay.
