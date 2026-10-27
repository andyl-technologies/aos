# 23 — Provenance and trust

This file owns what a store records about who produced each commit and each
entry, how that record is protected, and how a reader decides whether to
believe an entry. Provenance answers "where did this come from"; trust
answers "do I act on it". Both are distinct from authorization, which
answers "may I read this ref" and is owned by
[`22-authentication-and-authorization.md`](22-authentication-and-authorization.md).

## Model

Every [commit](02-glossary.md#the-five-nouns) is signed by the key of the
capability token that authorized it, and records the issuer, subject,
subject kind, workload identity, and process that produced it. An
[entry](02-glossary.md#the-five-nouns) inherits the provenance of the commit
that introduced it, and keeps that provenance when later commits carry it
forward unchanged. Provenance is therefore a fact about content, attached
once, and survives forks, merges, and folds.

A [trust selector](02-glossary.md#security-vocabulary) is a predicate over
provenance that a reader applies when resolving entries. A view whose
selector requires "committed by a signed baseline job" simply does not see
entries introduced by an untrusted job, even if the reader is authorized to
read the ref they sit in. Selectors are chosen per view or inherited as a
property on a root, so the same tree can be consumed at different trust
levels by different consumers without copying anything.

When a trusted principal folds an untrusted branch into a baseline, the
fold commit is signed by the trusted principal, and the entries it carries
keep their original provenance while the fold commit's parents record the
untrusted commit. A reader's selector can thus distinguish "introduced by an
untrusted job and later accepted by a trusted one" from "introduced by a
trusted one", and policy decides which it requires.

## Commit provenance

- **[PROV-1]** Every commit MUST carry a provenance record containing: the
  issuer identifier and token identifier of the authorizing token, the
  subject principal name and kind, the subject's workload identity claim if
  present, a process descriptor (an implementation-defined string naming the
  program and surface that produced the commit), the commit time as
  observed by the committer, and the writer epoch of the ref at commit
  time. *See:* `reference/terrane-v1.cddl` §commit.
- **[PROV-2]** Every commit MUST be signed. The signature MUST be made with
  the ephemeral key of the last attenuation block of the authorizing token,
  or the issuer-bound subject key if the token has no attenuation block,
  and the token's public chain MUST be embedded in the commit so that the
  signature is verifiable from the commit alone plus issuer public keys.
  *Gate:* `gate:prov-commit-signature`.
- **[PROV-3]** The signature preimage MUST be the canonical encoding of the
  commit with the signature field absent, under the encoding profile in
  `reference/terrane-v1.cddl`. The commit's identity
  ([`04-content-model.md`](04-content-model.md)) is the hash of the encoded
  commit including the signature.
- **[PROV-4]** A store MUST verify the signature and the embedded token
  chain of every commit before accepting a ref update that points at it, and
  MUST reject a commit whose embedded token would not have authorized
  `commit` in its original authoring context at that epoch. Every new
  authored commit MUST carry the signed `commit-context` in its profile pair:
  the original canonical ref, producing surface, locality and affected
  absolute root paths with effective disclosure domains under PROV-31.
  Roots are sorted uniquely by unsigned `(path bytes, domain bytes)`.
  Admission MUST verify those root/domain pairs against the canonical
  candidate and previous trees and check the current ACLs separately; a
  signed domain assertion is not a tree witness. A legacy draft record
  without this context MAY be
  verified only with a trusted complete original context, and MUST NOT be
  admitted as a newly authored contextless commit. Reading, forking, tagging
  or carrying a historical commit MUST verify its original context rather
  than substitute the destination ref, current epoch, surface or locality.
  The current operation still requires its own grants and current ACL
  intersection. *Gate:* `gate:prov-commit-verify`.
- **[PROV-5]** A commit produced by a merge or fold MUST list every input
  commit as a parent, in a stable order: the target's previous commit first,
  then the merged commits in the order given to the merge. A merge commit
  MUST NOT omit a parent to hide where content came from.
- **[PROV-6]** A commit MUST carry a `source` field from the closed set
  `{built, uploaded, imported, merged, derived, migrated}` describing how its
  tree came to be, so that selectors can distinguish, for example, a
  content import from a build result. `derived` is used by tree jobs
  ([`32-tree-jobs.md`](32-tree-jobs.md)) and rulesets
  ([`31-routing-rulesets.md`](31-routing-rulesets.md)); `migrated` by
  [`33-migrations.md`](33-migrations.md).

## Affected root authorization

- **[PROV-31]** Signed `commit-context` pairs MUST name actual root
  occurrences, never ordinary entry paths. For an ordinary advance, admission
  and historical verification MUST derive affected root units from the
  canonical candidate and the canonical first parent's tree. An entry
  addition, removal, content or metadata change affects its containing root.
  Changes to root properties or graft overrides affect their root units and
  every descendant whose effective inherited policy changes. Materializing
  the same effective implicit owner under DOM-1 MUST NOT add an ancestor
  policy change. *Gate:* `gate:prov-commit-verify`.

  A graft target digest change caused only by changes within the same child
  root occurrence MUST NOT require authority on the containing ancestor root
  when its descriptor metadata, overrides and effective policy are unchanged.
  Root introduction, removal, moves and other descriptor changes still affect
  their containing root and the changed root units. Removed and moved roots
  use their prior occurrence policies; introduced roots use candidate
  policies. Replacements and domain changes check both sides, including
  descendants whose effective policy changes. Unchanged siblings MUST NOT
  become affected solely because their ancestor's digest changes.

  Every signed claim MUST be witnessed as an actual root occurrence in the
  candidate or prior tree with its claimed effective domain. Every affected
  root/domain pair MUST be covered by a signed same-domain root claim at that
  occurrence or a canonical ancestor occurrence. Verification MUST evaluate
  the embedded token in its original authoring context on every signed claim
  and every affected actual root/domain pair. Broader valid historical root
  claims remain acceptable; a claim alone is not a canonical change witness.
  Admission MUST separately evaluate the current operation token and current
  ACLs for every affected actual root/domain, and enforce applicable `admin`
  requirements for authority-bearing property changes, before uploads and
  final CAS. Requested file paths MUST resolve to their actual containing
  root for grant and ACL checks; entry reachability is a separate check.
  These rules preserve AUTH-29's prohibition on per-entry permissions.

  Original-context verification MUST also enforce the embedded token's
  applicable `admin` requirements for ACL edits and delegation under AUTH-28
  and PROP-16, using prior canonical authority and the trusted original
  bootstrap baseline where required. Current-operation credentials MUST NOT
  substitute for this original authority. Merely changing the `store` property
  does not add an `admin` requirement: affected-root `commit` authorization
  and PROP-5's effective storage placement still apply, and a backend MUST
  refuse placement it cannot honor.

  Initial tree publication MUST authorize the view root and all affected
  root units. An unchanged-tree authored record MUST still carry a nonempty
  authorized actual-root context. ALG-32's constant-cost copied-tree fork
  retains its specified source and destination authorization; computing an
  empty change set MUST NOT require scanning that unchanged tree.

  If a complete verified PROV-29 batch makes the exact first parent an
  audit-only boundary, verification MUST treat the candidate as a complete
  fresh materialization with view-root publication scope and all required
  entry and attribute evidence. It MUST NOT fetch private evidence or infer
  unchangedness from unavailable history. An audit-only second parent does
  not replace the publicly retained first-parent change baseline. A bounded
  session scope MUST NOT confer authority or replace verification of all
  actual changes. Unreachable staged uploads MUST be rejected; newly reachable
  reused bytes require scoped verified availability evidence or fresh
  verified upload, never namespace membership alone.

## Entry provenance

- **[PROV-7]** Every entry MUST resolve to the identity of the commit that
  introduced it (its *introducing commit*). A signed entry receipt in the
  commit's profile pair MUST identify a new introduction as `current`,
  meaning the containing commit's externally calculated identity, or name
  a verified source commit, root, and path. An entry MUST NOT embed the
  containing commit's identity in its own tree, which would create a hash
  cycle. An entry is introduced when a
  commit adds the key or changes the entry's content identity; a change
  only to attributes or metadata MUST NOT change the introducing commit and
  MUST instead be recorded as an attribute provenance (PROV-9).

Receipts are keyed by `(root identity, relative path bytes)` and sorted by
unsigned byte order of that pair, with duplicates rejected. Paths may be
ordinary namespace paths or opaque index keys; their meaning is verified
against the identified root. A source receipt requires a verified signed
source commit and a canonical tree witness for the source root and path,
with the same content identity as the carried entry. A source root MUST be
reachable from that source commit. A certified disclosure instead uses the
checked attestation boundary in PROV-26 to PROV-30; it does not require
destination readers to fetch the private source graph. An explicit prior
`prov` remains valid only when that introducing commit and the carrying
history are verified.

An unchanged entry without a receipt inherits its unambiguous introduction
through parent history. New or content-changing entries, explicit
reintroductions, and merge choices with ambiguous parent introductions MUST
have receipts. Missing, cyclic, contradictory, or unverifiable evidence
MUST fail closed; selecting the first parent arbitrarily is not evidence.
Metadata-only changes preserve the introduction and may supply separate
attribute origins in the receipt. Source edges make provenance reachable
independently of parent edges; `accepted-by` still requires an ancestor of
the view that demonstrably carried the entry.
- **[PROV-8]** A merge, fold, graft, or flatten that carries an entry
  forward unchanged MUST preserve its introducing commit. A `map` transform
  that changes an entry's content MUST set the introducing commit to the
  commit that records the transform. *Gate:* `gate:prov-entry-preserve`.
- **[PROV-9]** Derived attributes ([`10-derived-data.md`](10-derived-data.md))
  MUST record the commit that produced them, separately from the entry's
  introducing commit, so that a selector can require that a hash or
  classification was computed by a trusted job. A side-only attribute's
  producer MUST be authenticated by its detached terminal-key signature over
  the record and a canonical tree witness that the producer commit reached
  the same object. The producer commit's token, original context and
  signature MUST verify. A claimed producer hash, recomputation, or equality
  with another record alone is not producer evidence. An unsigned legacy
  record can establish producer provenance only through matching verified
  inline value and attribute-origin history. Selector context identities
  MUST distinguish the exact side record and its verified object/domain
  evidence.
- **[PROV-10]** Because entries reference commits by identity, and commits
  are reachable from refs, an implementation MUST treat every introducing
  commit referenced by a live entry, and every source commit named by a
  live signed receipt, as a garbage-collection root, except exact source and
  original-introducer audit identities behind a verified disclosure boundary
  ([`17-garbage-collection.md`](17-garbage-collection.md)), so that
  provenance can always be resolved for live content.

## Durable disclosure evidence

- **[PROV-26]** A disclosure certificate MUST be signed by an explicitly
  configured source disclosure authority. Trusted configuration MUST bind
  its Ed25519 public key and canonical source domain unambiguously to the
  exact physical source repository/domain. An ordinary token terminal key,
  embedded bare key, or issuer key alone MUST NOT confer this role. The
  destination MUST retain scoped historical verification keys independently
  of private source storage and verify authority at the certificate's
  observed issue time. Ordinary key rotation MUST NOT invalidate accepted
  historical certificates; explicit revocation policy MAY do so. *Gate:*
  `gate:prov-disclosure-boundary`.
- **[PROV-27]** A certificate MUST use the sixth receipt element and the
  `disclosure-proof` and `disclosure-statement` schemas in
  `reference/terrane-v1.cddl`. It MUST occur only on a `current` receipt
  with `reintroduced_from` and the exact `provenance.reintroduced-from`
  attribute. The statement MUST bind the source witness, original
  introducing identity, actual destination root/path/domain, original
  authoring ref, content projection and complete destination commit.
  The source authority MUST verify the source's original introduction at
  issuance; the destination verifies that attestation and matching
  attribute without re-fetching the private source. *Gate:*
  `gate:prov-disclosure-boundary`.

The destination binding is BLAKE3-256 over ASCII
`terrane-disclosure-target-v1`, one zero byte, and the canonical unsigned
destination commit. Normalization omits commit signature key 8 and replaces
every typed disclosure-proof signature in its profile receipts with exactly
64 zero bytes. It changes no other field, including opaque token, property
or recipe blobs. All commit fields and certificate metadata are finalized
before computing this binding. The binding is derived externally; it is not
stored inside the projection. Each source authority signs ASCII
`terrane-disclosure-proof-v1`, one zero byte, and canonical CBOR of its
`disclosure-statement`. The destination commit then signs the real complete
certificates normally under PROV-3. Both purposes are registered in
`reference/bucket-key-registry.md`; neither creates an immutable kind.

- **[PROV-28]** A verifier MUST check the signed destination commit, embedded
  token and original context, complete canonical destination tree, every
  proof-bearing receipt, actual target root/path/effective domain, matching
  original-introducer attribute, content projection, scoped historical
  authority and certificate signature before exposing a verified boundary.
  Removing or changing any field covered by the normalized unsigned projection
  or certificate metadata MUST invalidate its whole-commit binding. Omitted
  and zeroed signature slots MUST independently verify under their respective
  actual preimages. Invalid signatures, unknown keys
  and contradictory evidence MUST fail closed. Private provisional batch
  validation MAY resolve candidate origins, but MUST expose no evaluator,
  history or collector authority until all entry and attribute origins
  validate. Unchecked certificate presence MUST NOT skip source lookup.
  *Gate:* `gate:prov-disclosure-boundary`.
- **[PROV-29]** A checked disclosure receipt MUST make the destination commit
  the actual introducing commit and terminate only its exact certified
  source and original-introducer proof edges. Audit MUST expose the source
  identities and authority as an attested boundary, never fabricate a
  verified private commit, its subject, signature or complete ancestry.
  When a certified source commit is also a signed input parent, its exact
  parent identity MUST remain recorded under PROV-5 and PROV-17. That parent
  edge MAY be audit-only after complete candidate validation: every entry
  MUST have an explicit publicly retainable verified source receipt, a
  verified current certificate, or a current reintroduction with fully
  verified publicly retainable source evidence. Unavailable parent evidence
  MUST NOT prove absence, newness or unchangedness. Receiptless inheritance,
  uncertified current newness, source receipts into the cut boundary, and
  uncovered private attribute origins MUST fail closed. A certificate for
  one entry MUST NOT authorize sibling content. An unanchored private input
  parent MUST NOT be skipped. Checked boundaries MUST apply consistently
  even when private objects happen to be available. *Gate:*
  `gate:prov-disclosure-boundary`.
- **[PROV-30]** A disclosure certificate MUST NOT authenticate an attribute
  producer or grant acceptance through private ancestry. Copied attributes
  MUST have destination-current provenance or independent verified,
  publicly retainable producer evidence under PROV-9. Selectors MUST use the
  public introducing commit and checked public ancestry; `strict` MUST NOT
  substitute the attested private introducer. Memoization MUST distinguish
  the exact signed destination and its verified boundary context. A
  directory projection certifies only its marker, never descendants or
  absence; a symlink projection certifies only raw target bytes, never target
  access. Tree, whiteout, conflict and index entries MUST NOT use these
  registered projections. Their disclosure still requires independently
  verified safe materialization or authorized full-source retention; this
  certificate does not relax their existing requirements. *Gate:*
  `gate:prov-disclosure-boundary`.

## Trust selectors

A selector is a predicate over the provenance of an entry's introducing
commit, the commit's ancestry, and the entry's attribute provenance.

- **[PROV-11]** The selector language is closed and registered in
  `reference/property-registry.md` §trust selectors. A selector is a
  boolean expression over the following atoms: `issuer(id)`,
  `subject(pattern)`, `kind(human|workload|service)`,
  `group(name)`, `source(value)`, `signed-by-key(id)`,
  `accepted-by(selector)` (true if some ancestor commit that carried the
  entry forward matches the inner selector), `attested(claim)` (true if the
  workload identity claim carries a registered attestation), and
  `attr-by(name, selector)` (true if attribute `name` was produced under a
  commit matching the inner selector). Combinators are `all`, `any`, `not`.
  The identifier in `signed-by-key(id)` is the lowercase 64-character
  hexadecimal encoding of the terminal Ed25519 public key that signed the
  commit, not the issuer's rotation key identifier.
- **[PROV-12]** An implementation MUST provide the following named
  **trust presets**, and MAY register more: `any` (every entry), `signed-baseline`
  (introduced by, or accepted by, a principal in the root's configured
  baseline group), `strict` (introduced directly by a principal in the
  baseline group; acceptance does not suffice), and `attested` (the
  introducing workload carries a registered attestation). *Gate:*
  `gate:prov-selector-presets`.
- **[PROV-13]** A selector MUST be evaluable from data reachable from the
  view's commit without contacting an issuer or external service. If a
  required commit is unavailable, the selector MUST evaluate to false for
  the affected entry.
  Source identities behind checked disclosure boundaries are audit evidence,
  not required private commits; scoped historical authority keys are retained
  trusted configuration, not an online issuer service.
- **[PROV-14]** The effective selector for a read MUST be the conjunction
  of the selector on the view and the `trust` property of every root on the
  path from the view's root to the entry
  ([`08-properties.md`](08-properties.md)). A view MAY narrow trust; it MUST
  NOT widen what a root's property requires.
- **[PROV-15]** An entry that fails the effective selector MUST be
  presented as absent by every surface: lookups fail with not-found,
  directory listings omit it, negotiation does not admit its content, and
  presigned reads for its content are not minted. It MUST NOT be presented
  as present-but-unreadable, since that would leak existence
  ([`24-disclosure-domains.md`](24-disclosure-domains.md)).
- **[PROV-16]** Selector evaluation MUST be memoized by disclosure domain,
  immutable view commit, introducing commit, effective selector identity,
  baseline configuration identity, and acceptance and attribute-origin
  context identity. Entries with identical verified contexts share an
  evaluation. The memo MUST be keyed on content identities only and MUST
  NOT be shared across disclosure domains. An introducing commit and
  selector alone do not identify view-dependent acceptance evidence.

## Folding and acceptance

- **[PROV-17]** A fold of branch `B` into branch `A` MUST produce a commit
  signed by the folding principal, with parents `[A_prev, B_head]`, source
  `merged`, and a tree in which entries carried from `B` retain their
  introducing commits from `B`. The fold commit is what `accepted-by`
  matches. *Gate:* `gate:prov-fold-acceptance`.
- **[PROV-18]** A folding principal MAY instead re-introduce entries by
  applying a `map` that sets their introducing commit to the fold commit,
  which is the operation that makes untrusted content satisfy `strict`.
  An implementation MUST make this an explicit option on the fold, off by
  default, and MUST record the original introducing commit as an attribute
  `provenance.reintroduced-from` when it is used, so that history is not
  erased.
  The `current` receipt MUST include the original source commit, root, and
  path, whose verified introduction MUST equal that attribute's value.
  A durable disclosure MAY supply this source introduction through PROV-27's
  verified source-authority attestation instead of retaining private history.
- **[PROV-19]** Conflict resolution during merge
  ([`07-tree-algebra.md`](07-tree-algebra.md)) MAY use provenance as a
  policy input, for example "prefer the candidate whose introducing commit
  matches `signed-baseline`". The resolution policy MUST be recorded in the
  merge commit's message field in the registered form so that the choice
  is auditable.

## Audit

- **[PROV-20]** The complete provenance history of an entry MUST be
  derivable by walking parent and signed source-receipt edges from the
  view's commit to the
  entry's introducing commit and inspecting each commit's provenance record.
  An implementation MUST provide this walk as an operation of the wire
  protocol ([`18-protocol.md`](18-protocol.md)) and of the command-line
  interface.
  At a checked disclosure boundary, this walk MUST return the typed attested
  source identities and authority, explicitly distinguishing them from
  independently verified private signatures or complete private ancestry.
- **[PROV-21]** A ref's reflog
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)) is the audit trail of
  authority changes on that ref: because `acl` changes are commits
  (AUTH-28), every permission change is discoverable from the reflog with
  its signer.
- **[PROV-22]** Provenance records and signatures MUST be retained for as
  long as the commit is retained, and a commit MUST be retained for as long
  as any live entry names it as introducing (PROV-10) or any tag or reflog
  entry within the retention property references it.
  Exact audit identities behind a checked disclosure boundary do not require
  retention of private source objects. The destination certificate,
  introducing commit and independently retained scoped verification keys
  MUST remain available for the live entry.

## Separation from authorization

- **[PROV-23]** Authorization (may this principal read this ref) MUST be
  evaluated before trust (does this reader believe this entry). A reader
  without `read` on a ref learns nothing about its entries, including
  through selector outcomes.
- **[PROV-24]** Trust MUST NOT be used as a substitute for authorization. A
  root whose `acl` denies a principal MUST remain denied regardless of the
  selector the principal asks for.
- **[PROV-25]** Foreign credentials mapped by protocol surfaces
  (AUTH-6) MUST NOT contribute to provenance beyond the capability token
  they were mapped to. The provenance record names the Terrane principal,
  never the foreign credential.

## Interactions

- [`04-content-model.md`](04-content-model.md) defines commit identity used
  by PROV-3.
- [`07-tree-algebra.md`](07-tree-algebra.md) defines merge, fold, graft,
  flatten, and map, whose provenance behavior PROV-8, PROV-17, PROV-18, and
  PROV-19 constrain.
- [`08-properties.md`](08-properties.md) defines the `trust` and `baseline`
  properties.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) defines the commit
  object, parents, reflog, and writer epochs.
- [`10-derived-data.md`](10-derived-data.md) defines attribute provenance.
- [`17-garbage-collection.md`](17-garbage-collection.md) must honor PROV-10
  and PROV-22 as roots.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)
  supplies the token chain embedded by PROV-2.
- [`26-surfaces.md`](26-surfaces.md) requires every surface to honor
  PROV-15.
- [`31-routing-rulesets.md`](31-routing-rulesets.md) `provenance` matchers
  use the selector language of PROV-11.

## Informative: reading the same tree at three trust levels

A baseline branch `main` contains entries introduced by trusted build jobs
and entries folded in from pull-request branches. Three consumers open
views on the same commit:

| Consumer | Selector | Sees |
| --- | --- | --- |
| A developer's workstation | `any` | everything, including content a pull request produced that was later folded |
| A release builder | `signed-baseline` | trusted-built content, plus folded content because the fold was signed by a baseline principal |
| A signing service | `strict` | only content whose introducing commit was itself a baseline principal; folded pull-request content is absent unless it was re-introduced under PROV-18 |

No bytes are copied and no second tree exists. The selector is evaluated
against a handful of distinct introducing commits, memoized, and applied at
lookup.
