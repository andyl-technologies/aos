# Closed Cache-owner named readback

`AOSCOR01` is a non-authorizing, fixed-size statement from a physical Cache
owner holding its `.owner.lock` flock. The owner rechecks the fixed mode-0700
root, named mode-0600 lock, and replayed `owner-state` head before and after
signing. The signature binds a root-session nonce, held-cut commitment,
physical owner limits, fixed root/lock identities, manifest head, and a
nonzero Cache signer generation. The distinct `AOSCPK01` public credential
cannot be parsed as a deployment or project policy signer credential.

No service currently provisions a Cache signing seed, loads an `AOSCPK01`
verification credential, transports the packet, or accepts it in `AOSPHQ04`.
The codec's verifier checks framing, the signature, and its supplied challenge;
it does not independently resolve Cache names or establish that the signer held
the flock. A caller-supplied verification credential is not an authority root.
Public Create and `AOSPCB02` publication remain closed.

Before root could rely on this route, deployment would need a new Cache-only
signing seed confined to the protected Cache-owner process and a separately
provisioned, role-pinned public credential held by policy-authorityd. Both
deployment and protected root-journal admission must reject reuse of either
existing deployment/project signing key and must fail closed on rotation. The
reviewed authority rule would have to delegate *named physical Cache
currentness* to that signer, rather than pretend the root independently
performed DAC-protected lookups. This is a substantive trust decision: the
Cache owner currently shares the Controller UID, so a signature alone does not
isolate it from compromise of another process with that UID.

Even after that decision, live admission needs a root-generated fresh nonce
under its writer; Controller, source-domain, protected Cache journals, and the
physical Cache flock held in canonical order through root CAS and a recoverable
effect handoff; root verification of the exact current protected Cache quota
envelope; and crash/replay checks that cannot reuse an old cut. The current
packet supplies none of those owners or effects. A privileged read-only
idmapped Cache view would instead permit root to resolve names itself while
keeping on-disk mode 0700 and policy-authorityd cap-empty, but it introduces a
trusted mount setup and still needs non-mutating protected journal replay.
