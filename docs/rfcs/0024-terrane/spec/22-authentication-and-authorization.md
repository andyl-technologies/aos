# 22 — Authentication and authorization

This file owns how a principal proves who it is, how that identity becomes a
capability token, how grants on refs and roots are expressed and evaluated,
and where in the system authorization is enforced. It defines one token
type, one grant shape, and one enforcement point. Trust in the *content* a
principal may read is a separate concern owned by
[`23-provenance-and-trust.md`](23-provenance-and-trust.md); the boundary
within which bytes may be shared is owned by
[`24-disclosure-domains.md`](24-disclosure-domains.md).

## Model

Three kinds of [principal](02-glossary.md#security-vocabulary) reach a
Terrane store: humans, workloads, and services. Each authenticates in the
way natural to it, and each is normalized at the edge into the same
[capability token](02-glossary.md#security-vocabulary). Everything past the
edge sees only tokens.

A token carries [grants](02-glossary.md#security-vocabulary). A grant is a
pair of a pattern over ref names or root paths and a verb. Because write
authority in the tree model is already per root
([`08-properties.md`](08-properties.md)), permissions are grants on roots
and refs and nothing finer. Authorization data is stored in the tree itself
as `acl` properties on roots, so a permission change is a commit with
provenance and a diff, and there is no authorization database to run or
keep consistent.

Tokens are offline-attenuable: any holder may derive a narrower token
without contacting an issuer. This is what lets an orchestrator holding
authority over a family of branches hand each job a token for exactly one
branch that dies with the job, and what lets a host derive a read-only
token for a surface from its own broader token, all without a token service
on the request path.

Authorization runs in exactly one place: the `guard` store combinator
([`11-store-trait.md`](11-store-trait.md)), and it does nothing else. Bulk
byte reads are delegated to the bucket through
[presigned reads](02-glossary.md#distribution-vocabulary) that the `serve`
role mints only after `guard` has authorized the request
([`18-protocol.md`](18-protocol.md) PROTO-55), so the bucket enforces what
`guard` decided. Surfaces never see tokens; a host process
holds them and a realized mount is itself the capability.

## Principals and authentication

- **[AUTH-1]** An implementation MUST support three principal kinds:
  `human`, `workload`, and `service`. A token MUST record which kind its
  subject is. *See:* §Principals.
- **[AUTH-2]** A human principal MUST authenticate through OpenID Connect.
  A command-line client SHOULD use the OAuth 2.0 device authorization grant
  (RFC 8628). A browser client MUST NOT receive a long-lived token; it
  receives a session that is exchanged for short-lived tokens (§Browser
  sessions). *Gate:* `gate:auth-oidc-login`.
- **[AUTH-3]** A workload principal MUST authenticate by presenting a
  token minted by a configured issuer for that workload. The issuer MUST
  bind the token to a workload identity claim (for example a job, run, or
  pod identifier) and MUST set an expiry no later than the workload's
  expected lifetime plus a bounded margin. *Gate:* `gate:auth-workload-mint`.
- **[AUTH-4]** A service principal MUST authenticate with mutual TLS 1.3
  and a client certificate whose subject is mapped to a principal name by
  configuration. A service certificate MUST NOT be accepted as a human or
  workload principal. *Gate:* `gate:auth-mtls`.
- **[AUTH-5]** Whatever the authentication method, the result at the edge
  MUST be one capability token as defined in §Capability tokens. No component
  past the `guard` combinator MAY inspect an OIDC token, a session cookie, a
  client certificate, or a surface-specific credential.
- **[AUTH-6]** A protocol surface that accepts a foreign credential (for
  example a Nix `netrc` entry, a Remote Execution API header, or a cache
  service token) MUST map it to a capability token at the surface boundary
  and MUST NOT retain the foreign credential after the mapping. *See:*
  [`30-surface-protocols.md`](30-surface-protocols.md).

## Capability tokens

A capability token is a signed statement of grants with an expiry, in the
style of Biscuit tokens: a chain of blocks where each block may only narrow
what the previous blocks allow, verified with public keys alone.

- **[AUTH-7]** A token MUST be a chain of one or more blocks. The first
  block (the *authority block*) is signed by an issuer key. Each subsequent
  block (an *attenuation block*) is signed by an ephemeral key whose public
  half is bound into the preceding block, so the chain is verifiable with
  the issuer's public key and nothing else. *Gate:* `gate:auth-token-chain`.
- **[AUTH-8]** The authority block MUST contain: the issuer identifier, the
  subject principal name and kind, the subject's group claims, a not-after
  time, a token identifier, and the initial grant set. It MAY contain a
  not-before time and a workload identity claim.
- **[AUTH-9]** Every block MUST be encoded under the canonical encoding
  profile in `reference/terrane-v1.cddl` so that two implementations compute
  the same signature preimage. The token media type is registered in
  `reference/property-registry.md` §media types.
- **[AUTH-10]** Token signatures MUST use Ed25519. An implementation MUST
  reject a token whose signature algorithm is not registered for the
  token's media-type version, regardless of whether a parser for that
  algorithm happens to be available.
- **[AUTH-11]** Token verification MUST be a pure function of the token
  bytes, the issuer public keys, and the current time. It MUST NOT require
  network access, a database, or a filesystem, so that it can run in a
  `no_std` environment and in a WebAssembly worker
  ([`38-wasm-and-edge.md`](38-wasm-and-edge.md)). *Gate:*
  `gate:auth-verify-pure`.
- **[AUTH-12]** A verifier MUST reject a token that is expired, not yet
  valid, signed by an unknown issuer, has a broken chain, or contains an
  unregistered block field. Rejection is not distinguishable to the caller
  by cause beyond "unauthorized"; the cause is logged
  ([`34-observability.md`](34-observability.md)).
- **[AUTH-13]** Issuer public keys MUST be configured per store, MUST be
  identified by a key identifier carried in the authority block, and MUST
  support rotation by holding more than one active key. A key MUST NOT be
  accepted after its configured retirement time.

### Attenuation

- **[AUTH-14]** Any token holder MAY derive a new token by appending an
  attenuation block. The derived token MUST be valid for the same or a
  narrower set of operations than its parent. Specifically, an attenuation
  block MAY only: reduce the not-after time, add a not-before time, remove
  grants, narrow a grant's pattern to a sub-pattern, narrow a grant's verb
  set, or add a caveat (§Caveats). *Gate:* `gate:auth-attenuation-monotone`.
- **[AUTH-15]** A verifier MUST evaluate a token as the intersection of all
  its blocks. A block that attempts to widen authority MUST cause the whole
  token to be rejected rather than be ignored.
- **[AUTH-16]** Attenuation MUST NOT require contacting an issuer or any
  server. *Gate:* `gate:auth-attenuation-offline`.

### Caveats

A caveat is a predicate an attenuation block adds that every request under
the token must satisfy. Caveats are how a token is bound to a context.

- **[AUTH-17]** The caveat vocabulary is closed and registered in
  `reference/property-registry.md` §token caveats. The initial vocabulary
  is: `before(time)`, `after(time)`, `ref(pattern)`, `root(pattern)`,
  `verb(set)`, `domain(name)`, `surface(name)`, `locality(label)`,
  `epoch(ref, n)`. An unregistered caveat MUST cause rejection.
- **[AUTH-18]** `epoch(ref, n)` binds a token to writer epoch `n` of `ref`
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)). A commit under such a
  token MUST fail once the ref's epoch exceeds `n`. This is the mechanism by
  which a superseded writer is fenced without revocation.

## Grants

- **[AUTH-19]** A grant is `(pattern, verbs)`. `pattern` is a glob over
  either ref names (`refs/heads/pr/*`) or root paths within a named ref
  (`refs/heads/main:/nix/store`). `verbs` is a non-empty subset of
  `{read, fork, commit, tag, admin}`. *See:* §Verbs.
- **[AUTH-20]** Pattern matching MUST be performed on the canonical byte
  form of ref names and paths. A pattern MUST NOT match across a `/`
  boundary with a single `*`; `**` matches any depth. A pattern with no
  `:` applies to the ref as a whole and to every root beneath it.
- **[AUTH-21]** Grants MUST be evaluated as a union: a request is
  authorized if any grant in the effective token authorizes it and no
  caveat forbids it.

### Verbs

| Verb | Authorizes |
| --- | --- |
| `read` | Reading the ref, its reflog, and every object reachable from its commit within the matched roots; negotiating content; minting presigned reads for that content |
| `fork` | Creating a new branch whose first commit is the matched ref's current commit |
| `commit` | Advancing the matched ref by conditional write, including merges into it, and writing packs, trees, and commits it will reference |
| `tag` | Creating a tag pointing at a commit reachable from the matched ref |
| `admin` | Changing `acl` and other authority-bearing properties on matched roots, deleting refs, and forcing a ref to an arbitrary commit |

- **[AUTH-22]** `commit` MUST imply `read` for the same pattern. `admin`
  MUST imply every other verb. `fork` and `tag` MUST NOT imply `commit` on
  the source ref; they imply `read` on it.
- **[AUTH-23]** A `fork` grant on `refs/heads/main` alone MUST NOT authorize
  the resulting branch's ref writes. The forking principal MUST also hold
  `commit` on a pattern matching the new branch name. The canonical CI policy
  in §Example makes this explicit.
- **[AUTH-24]** Writing an object (chunk, tree node, manifest, commit) to a
  store MUST be authorized only as part of a `commit`-authorized operation
  against a specific ref, and an implementation MUST bound the bytes a
  principal may write ahead of its ref update by the root's quota properties
  ([`08-properties.md`](08-properties.md)). Immutable objects that are never
  referenced by a committed ref are reclaimed by
  [`17-garbage-collection.md`](17-garbage-collection.md).

## ACL properties

- **[AUTH-25]** Authorization policy is stored as the `acl` property on
  roots ([`08-properties.md`](08-properties.md)). Its value is a list of
  `(principal-or-group, verbs)` pairs. It inherits to descendant roots and
  MAY be overridden or extended by a descendant; a descendant MUST NOT
  remove a verb the ancestor granted to `admin` principals.
- **[AUTH-26]** The effective authority of a token over a root MUST be the
  intersection of the grants the token carries and the `acl` of that root
  (after inheritance). A token asserting `commit` on a root whose `acl` does
  not name the token's subject or one of its groups for `commit` MUST be
  denied. *Gate:* `gate:auth-acl-intersection`.
- **[AUTH-27]** Group membership MUST come from group claims in the
  token's authority block, placed there by the issuer from the identity
  provider. An implementation MUST NOT resolve group membership at request
  time from any external directory.
- **[AUTH-28]** Changing the `acl` property of a root MUST require `admin`
  on that root or an ancestor and MUST be recorded as an ordinary commit,
  so that the reflog and commit graph are the audit trail
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)).
- **[AUTH-29]** Because a root is the unit of authorization, an
  implementation MUST NOT offer per-entry permissions. A namespace that
  needs a permission boundary at a path MUST make that path a root with a
  `tree` entry ([`06-tree-format.md`](06-tree-format.md)).
- **[AUTH-30]** When a token's grants and the tree's `acl` disagree because
  the `acl` was changed after the token was minted, the current `acl` MUST
  win. Authority shrinks immediately; it never grows retroactively.

## Enforcement

- **[AUTH-31]** The `guard` combinator
  ([`11-store-trait.md`](11-store-trait.md)) MUST be the only component that
  evaluates tokens against grants and `acl` properties. Every store
  operation reachable from an untrusted network path MUST pass through a
  `guard`. *Gate:* `gate:auth-single-enforcement`.
- **[AUTH-32]** `guard` MUST fail closed: any error in token parsing,
  verification, `acl` resolution, or clock lookup MUST result in denial.
- **[AUTH-33]** A presigned read minted after `guard` authorizes a bulk
  read ([`18-protocol.md`](18-protocol.md) PROTO-55) MUST be scoped to the
  exact byte ranges authorized, with a lifetime no longer than the token's
  remaining validity and no longer than a configured maximum that SHOULD be
  measured in minutes. An implementation MUST NOT mint a presigned write.
- **[AUTH-34]** Presigned reads are bearer capabilities. An implementation
  MUST NOT log presigned URLs in full, MUST NOT place them in shared caches,
  and MUST bind them to a single pack key. Leakage is bounded by lifetime
  and scope, and is analyzed in
  [`25-threat-model.md`](25-threat-model.md).
- **[AUTH-35]** A host process that realizes surfaces MUST hold the tokens
  it uses on behalf of consumers. A consumer of a realized surface (a
  process inside a sandbox or virtual machine) MUST NOT receive a token,
  presigned URL, bucket credential, or issuer key. The mount is the
  capability; its scope is the view the host authorized.
- **[AUTH-36]** A surface that permits writes MUST attach the host-held
  token that authorized the exposure to every resulting commit, attenuated
  with `ref(<the exposure's ref>)` and `epoch(<ref>, <current>)`, so that a
  commit from a surface can never reach a ref the exposure was not opened
  for. *Gate:* `gate:auth-surface-commit-scope`.
- **[AUTH-37]** A store in a tier list that is not the authority for a ref
  MAY cache authorization decisions for the lifetime of the token and no
  longer, keyed by the token identifier, ref, verb, and the `acl`-bearing
  commit hash. A change in the commit hash MUST invalidate the cached
  decision.

## Browser sessions

- **[AUTH-38]** A browser client MUST authenticate through the same OIDC
  provider as command-line humans. The gateway MUST hold the resulting
  identity in a server-side session bound to a cookie with the `Secure`,
  `HttpOnly`, and `SameSite=Strict` attributes.
- **[AUTH-39]** Every API call from a browser MUST be made with a
  short-lived capability token exchanged from the session, with a lifetime
  that SHOULD NOT exceed fifteen minutes. The browser MUST NOT be issued a
  token whose not-after time exceeds the session's own.
- **[AUTH-40]** The web surface
  ([`30-surface-protocols.md`](30-surface-protocols.md) §WEB) MUST serve
  content bytes through presigned redirects minted under the exchanged
  token, never by proxying bytes through the session.

## Revocation

There is no revocation list. Authority is bounded by time and by epochs.

- **[AUTH-41]** Issuers MUST mint tokens with lifetimes short enough that
  expiry is the primary revocation mechanism. Workload tokens SHOULD expire
  within hours; human command-line tokens SHOULD expire within a day and
  be refreshed by re-authentication; browser tokens per AUTH-39.
- **[AUTH-42]** A writer's authority over a ref MUST be revocable
  immediately by advancing the ref's writer epoch
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)); every token carrying
  an `epoch` caveat for a lower value is thereby fenced. This is the only
  synchronous revocation the model offers and it is scoped to one ref.
- **[AUTH-43]** An `acl` change is effective for every subsequent request
  (AUTH-30). Combined with AUTH-41 and AUTH-42, an implementation MUST
  document the maximum window between a policy change and its effect for
  each principal kind.
- **[AUTH-44]** An issuer key that is compromised MUST be retired by
  configuration (AUTH-13). Retiring a key invalidates every token whose
  chain begins with it.

## Interactions

- [`08-properties.md`](08-properties.md) defines the `acl` property, its
  inheritance, and quota properties referenced by AUTH-24.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines writer epochs
  used by AUTH-18 and AUTH-42.
- [`11-store-trait.md`](11-store-trait.md) defines the `guard` combinator.
- [`18-protocol.md`](18-protocol.md) defines presigned reads and how tokens
  are carried on the wire.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md) consumes the
  token's subject and issuer as provenance on commits.
- [`24-disclosure-domains.md`](24-disclosure-domains.md) adds the `domain`
  caveat and constrains what `has` may reveal.
- [`26-surfaces.md`](26-surfaces.md) and the surface files rely on AUTH-35
  and AUTH-36.
- [`38-wasm-and-edge.md`](38-wasm-and-edge.md) relies on AUTH-11.

## Informative: the CI policy example

An organization runs untrusted pull-request jobs against a shared baseline
branch. Three grants express the whole policy:

```text
principal group org-members:
  read   refs/heads/main

principal workload pr-job (attenuated per job to one branch):
  fork   refs/heads/main -> refs/heads/pr/<n>
  commit refs/heads/pr/<n>

principal workload post-merge-job:
  commit refs/heads/main
```

The orchestrator holds a token with `commit refs/heads/pr/**` and, for each
job, appends an attenuation block with `ref(refs/heads/pr/1234)`,
`before(<job deadline>)`, and `epoch(refs/heads/pr/1234, 1)`. The job can
read everything `main` has, write only its own branch, and cannot outlive
its deadline or a replacement writer. Folding the branch into `main` needs
`commit refs/heads/main`, which only the post-merge job holds, so untrusted
output cannot reach the baseline except through a trusted principal. The
provenance consequences of that fold are in
[`23-provenance-and-trust.md`](23-provenance-and-trust.md).

## Informative: why there is no authorization service

A relation-graph authorization service was considered and rejected
([`39-decision-register.md`](39-decision-register.md)). Roots already form
a hierarchy with inheritance, so an `acl` property on roots expresses the
same policies as a relation graph for this system's needs, with three
advantages: policy is versioned and diffable like everything else, there is
no service whose unavailability turns into denial or, worse, into a
fail-open cache, and evaluation is a pure function usable at the edge. The
cost is that per-entry permissions are not expressible, which AUTH-29 turns
into a modeling rule rather than a limitation.
