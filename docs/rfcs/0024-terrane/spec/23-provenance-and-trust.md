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
  `commit` on that ref at that epoch. *Gate:* `gate:prov-commit-verify`.
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

## Entry provenance

- **[PROV-7]** Every entry MUST carry the identity of the commit that
  introduced it (its *introducing commit*). An entry is introduced when a
  commit adds the key or changes the entry's content identity; a change
  only to attributes or metadata MUST NOT change the introducing commit and
  MUST instead be recorded as an attribute provenance (PROV-9).
- **[PROV-8]** A merge, fold, graft, or flatten that carries an entry
  forward unchanged MUST preserve its introducing commit. A `map` transform
  that changes an entry's content MUST set the introducing commit to the
  commit that records the transform. *Gate:* `gate:prov-entry-preserve`.
- **[PROV-9]** Derived attributes ([`10-derived-data.md`](10-derived-data.md))
  MUST record the commit that produced them, separately from the entry's
  introducing commit, so that a selector can require that a hash or
  classification was computed by a trusted job.
- **[PROV-10]** Because entries reference commits by identity, and commits
  are reachable from refs, an implementation MUST treat every introducing
  commit referenced by a live entry as a garbage-collection root
  ([`17-garbage-collection.md`](17-garbage-collection.md)), so that
  provenance can always be resolved for live content.

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
- **[PROV-12]** An implementation MUST provide the following named
  profiles, and MAY register more: `any` (every entry), `signed-baseline`
  (introduced by, or accepted by, a principal in the root's configured
  baseline group), `strict` (introduced directly by a principal in the
  baseline group; acceptance does not suffice), and `attested` (the
  introducing workload carries a registered attestation). *Gate:*
  `gate:prov-selector-profiles`.
- **[PROV-13]** A selector MUST be evaluable from data reachable from the
  view's commit without contacting an issuer or external service. If a
  required commit is unavailable, the selector MUST evaluate to false for
  the affected entry.
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
- **[PROV-16]** Selector evaluation MUST be memoized per (introducing
  commit, selector) so that a large tree with few distinct introducing
  commits costs few evaluations. The memo MUST be keyed on content
  identities only and MUST NOT be shared across disclosure domains.

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
- **[PROV-19]** Conflict resolution during merge
  ([`07-tree-algebra.md`](07-tree-algebra.md)) MAY use provenance as a
  policy input, for example "prefer the candidate whose introducing commit
  matches `signed-baseline`". The resolution policy MUST be recorded in the
  merge commit's message field in the registered form so that the choice
  is auditable.

## Audit

- **[PROV-20]** The complete provenance history of an entry MUST be
  derivable by walking the commit graph from the view's commit to the
  entry's introducing commit and inspecting each commit's provenance record.
  An implementation MUST provide this walk as an operation of the wire
  protocol ([`18-protocol.md`](18-protocol.md)) and of the command-line
  interface.
- **[PROV-21]** A ref's reflog
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)) is the audit trail of
  authority changes on that ref: because `acl` changes are commits
  (AUTH-28), every permission change is discoverable from the reflog with
  its signer.
- **[PROV-22]** Provenance records and signatures MUST be retained for as
  long as the commit is retained, and a commit MUST be retained for as long
  as any live entry names it as introducing (PROV-10) or any tag or reflog
  entry within the retention property references it.

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
