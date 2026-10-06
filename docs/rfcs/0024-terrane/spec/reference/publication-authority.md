# Reference: checked publication and current collection authority

This protocol completes REF-5 to REF-7, REF-12, REF-21 to REF-23,
BKT-4, BKT-5, BKT-14, BKT-17, GC-4, GC-29, ALG-29 and ALG-32 under D-79.
It defines backend publication selection, retained absent-ref history and
privately checked lineage. Its records are in
[`terrane-v1.cddl`](terrane-v1.cddl); its names are registered in
[`bucket-key-registry.md`](bucket-key-registry.md). A record's bytes or
digest do not independently establish authority.

## Publication selection

The authority is a contiguous chain of immutable create-once
`publication/commits/<revision>` slots, beginning at revision zero. A
`PublicationCommit` binds its revision, exact predecessor digest and an
immutable `PublicationTransaction` key and digest. The transaction binds
its secure nonce, exact old and new `PublicationState`, sorted unique
logical-key changes, checked proof and exact predecessor slot. Each
change carries whole expected and new bytes, or explicit absence.

All immutable payloads, selected logs, catalogs, proofs and the transaction
are durably stored and verified before installing a commit slot.
Create-if-absent at the exact next revision is the sole commit point.
Revision arithmetic is checked. Slots cannot have gaps, be overwritten,
deleted, recreated or imported into an active registration. A losing
slot installation resolves the winning transaction and revalidates before
retrying. An indeterminate result follows REF-12's authoritative reread
rule; an unavailable read does not establish absence.

Current state is discovered by exact consecutive GETs from verified genesis,
or a previously verified contiguous prefix, until the first absent slot.
A cached prefix is valid only with independently checked immutable slot
and transaction evidence still retrievable. A digest-only checkpoint,
LIST maximum, `publication/CURRENT` or `publication/STATE` cannot select
authority. Those two mutable records are optional caches. Old secondary
writes cannot replace the selected immutable slot.

Every ref, advisory sidecar, collector lease, catalog selector, complete ref
inventory and portable selected-history read resolves the selected bytes from
the transaction chain. Expected bytes in a transaction equal the selected
logical state. Familiar physical payload keys may be materialized as
caches, but cannot fill missing selected logical values after genesis.
Recovery replays the selected chain and refreshes caches; unselected
transactions and proposals never become history or roots.

Genesis requires explicitly fresh administrative backend registration and
complete validated version-2 payload evidence under actual exclusion. Its
transaction includes a full sorted snapshot of CAPABILITIES, every
inventoried current ref or its explicit absence, selected MANIFEST and
catalog artifacts, current collector lease or absence, and portable selected
history. Expected values are null because no prior logical state exists;
its predecessor state and slot are also null. A null catalog is permitted
only with authoritative fresh-empty evidence. Existing payload bytes are checked
before their inclusion; opening an existing directory alone proves nothing.
Unknown namespaces or incomplete legacy history cannot authorize exhaustive
collection. Restart of the same registration resolves the existing chain;
missing or malformed selected evidence never triggers fresh initialization.
In-place activation preserves the checked current lease. Fresh-copy genesis
explicitly selects lease absence and discards copied collector state and
physical intent; only a fresh independently authorized lease may enable
destination collection.

Activation records CAPABILITIES key 11 equal to 1. Absent key 11 is legacy
unregistered publication authority, not a claim that the control chain is
empty. Registration of existing payload requires an external quiescent
fence over prior readers, writers and effects until complete verification
and activation finish; incompatible clients cannot resume. Filesystem
activation retains the same actual stable exclusion. A provider's marker
CAS alone cannot revoke an already submitted independent legacy write;
without genuine external fencing, activation is unsupported. Interrupted
activation reestablishes that fence and resolves exact selected evidence
before admission. Unknown markers refuse writes and destructive maintenance.

Publication revision advances on every logical mutation. Availability-loss
generation advances on loss or quarantine. Verified monotone admission
preserves existing placements and does not advance loss generation.
Unrelated refs and admissions preserve unaffected checked lineages.
Raw RefStore CAS participates in this protocol and removes the target's
checked lineage; it cannot certify a graph or create checked lineage.

Every transition checks that the new revision is exactly its predecessor
plus one and that the actual backend binding is unchanged. Ref names and
history rows are sorted uniquely; the branch history contains exactly the
branch classes in the complete CAPABILITIES inventory. Inventories never
lose a name. Present heads equal their retained selections; explicit
absence preserves prior selected history. Every selected lineage names
the exact current source record and current qualified loss generation.
The complete portable history and its origin stamp agree with the new
state. Profile, layout and publication markers cannot silently change.

Proof case 0 permits raw logical mutation without creating checked lineage
or changing the selected Guard. Loss or quarantine advances loss generation
and invalidates every affected lineage; raw mutation cannot certify
preservation. Verified monotone catalog admission proves complete existing
placements and exclusions preserved before retaining unaffected evidence.
GC-29's privately qualified pre-ownership restore is an explicit exception
for the one exact active exclusion it clears with restored eligible index
entries. It MUST preserve every existing serving placement, quarantine,
other exclusion and permanent burn/owner under complete current qualification
and actual backend exclusion. This availability gain uses proof case 0,
unchanged loss generation and only already selected unaffected source lineage;
it creates no new lineage. Public raw mutation cannot certify this exception.
D-78 cancellation and D-82 irreversible ownership rules remain mandatory.
Proof case 1 requires the private completed candidate check, exact current
source dependencies and durable signed graph before installing lineage.
Proof case 2 requires complete current collection qualification and exact
removed-index witnesses before carrying sources to a new loss generation.
Proof case 3 requires the D-82 private completed sweep/copied ownership check,
exact immutable authorization, complete current fence and permanent
burn publication. It uses case 2's complete source-preservation checks
when carrying lineage through a loss-generation transition.
Proof case 4 requires actual trusted Guard installation and complete checks
of every carried source dependency; affected sources lose lineage. Public
proof tuples or digest equality cannot substitute for any private check.

The backend proves actual linearizable create-if-absent and exact reads for
these control keys. Opaque ETags remain transport observations; equal ETags
or mutable bytes do not prove a distinct incarnation or a cross-key fence.
Unsupported primitives follow BKT-10 and BKT-11's refusal or single-writer
rules. A filesystem transaction retains the actual stable namespace
exclusion through final comparison and publication. Explicit version-1
read-only access refuses all protocol mutations.

## Retained history across absence

`PublicationState` key 5 contains every inventoried branch name, including
absent names, sorted uniquely by unsigned UTF-8 bytes. Branch classes are
heads, jobs, conflicts and derived. Each `committed-selection` is exactly:

| Value | Meaning |
| --- | --- |
| `[0]` | No head has ever been selected. |
| `[1, RefRecord]` | The exact whole last-selected head and candidate selector. |
| `[2]` | Pre-protocol historical selection is unknown. |

A present branch has `[1, current head]`. Removal atomically retains that
selection while installing ref absence; it does not select a removal
proposal or advance the committed sequence. Tags and advisory notes do not
acquire candidate histories. Unknown selection cannot authorize exhaustive
GC or recreation until an authoritative migration resolves it. New
protocol operations never manufacture unknown selection.

Reflog reading and retention begin at the exact last-selected whole record
even when the ref is absent. Its canonical selected log must match that
whole record. Duration, newest-record count and forever follow the selected
chain under the effective authenticated retention policy; an absent ref
does not acquire a current-head content root. Expired content may become
collectible while chain metadata remains readable. Unselected proposals,
LIST and the greatest proposed sequence never select history.

Recreation of an absent name with retained history uses new optional
RefLogRecord key 7 for the exact retained committed predecessor. Key 6
continues to encode the actual CAS expectation, explicitly null. Key 7
equals the selected `[1, last head]`, is forbidden for a nonnull expectation
and for a never-selected name, and agrees with key 2's previous commit.
The new sequence is checked predecessor sequence plus one; epoch cannot
regress and home changes require the existing authorized migration rule.
Fresh names still start at sequence one with null previous commit and no
key 7. Existing record bytes without key 7 retain their interpretation.

Traversal chooses key 7 when present, otherwise key 6, verifies each exact
selected candidate or registered legacy log and complete record equality,
and decreases sequence by exactly one. Missing records, cycles, mismatched
candidate IDs, home or epoch violations and previous-commit disagreement
are corruption. Null current expectation is not a fabricated live ref.
The current ref, retained selector and portable history change in one
selected transaction. Recreation still requires current ACL, signatures,
locality and migration authorization independently of retained selection.

## Backend and original authority bindings

Backend binding is local case 0 or remote case 1. Local binding carries
normalized absolute root bytes and the actual root and stable coordination
device/inode pairs, rechecked under held exclusion. Remote binding carries
the configured S3/GCS provider, exact endpoint, bucket resource and prefix,
and protected resource/coordination registration nonces. Endpoints and
bucket names are nonempty UTF-8 of at most 4096 bytes; prefix bytes are
0..4096 and coordination-key bytes 1..4096. Nonces are secure fresh 32-byte
values privately bound to genuine registration. Aliases and noncanonical
resource identities are rejected. A URL, issuer label, copied nonce or
synthetic filesystem identity does not establish this capability.

Backend-only binding supplies no signing, domain or original ACL authority.
Ordinary raw publication can therefore fence lineage before a Guard exists.
Original authority is independently checked by a private trusted factory.
Its existing nine-element local registration bytes remain unchanged.
Remote registration case 2 requires genuinely protected provider-backed
registration under the qualified selected-publication primitive; it does
not populate local inode fields. A public tuple constructor is not a factory.

Original bootstrap, association, import, import-binding and import-trust
records retain their existing canonical local bytes. The remote import
version 2 explicitly carries the registered binding union; local version 1
does not silently broaden. Source/destination IDs, exact import digest,
association ref/epoch and ordered ACL are checked independently. Public
historical keys survive source private-key deletion, while current
revocation remains effective. Copying private records to another physical
registration never creates original authority or repairs missing history.

## Complete Guard snapshots and used evidence

An immutable `GuardSnapshot` contains the actual original registration,
issuer keys and retirement times, disclosure roles and validity intervals,
complete trusted configuration, and configured registry inputs. Configuration
contains store name, private-domain hint, all optional locality labels,
ordered initial ACL, minimum chunk size, physical storage domain, selected
chunk profile name, all six profile parameters including its seed, and
optional policy authority. Derived gear/masks are recomputed from the
registered algorithm. Minimum and profile consistency are validated.
Absent locality labels and null policy authority are preserved exactly.

The private-domain hint is not immutable ownership evidence. Effective
defaults use the independently checked view's domain; property home is the
configured region or `local`, while placement checks use full locality.
Initial ACL supplies only newly authored bootstrap policy. Historical ACL
comes from the exact separately retained original baseline and cannot be
reconstructed from current configuration or candidate properties.

Configured registry inputs separate actual behavioral property names,
registered attribute/selector/tree/chunk semantics and identity profile
from trusted later preserve-only names. Property semantics revisions are
the exact immutable vocabularies in `property-registry.md` (PROP-30).
Property revision 1 retains the pre-D-101 33 names; revision 2 adds only
`index-roots`; revision 3 adds only `index-gaps` and its auxiliary-root-only
placement. Attribute revision 1 retains the existing value/function names
and namespaces; revision 2 adds only the contextual `index.occurrences`
structural metadata in `property-registry.md`. Active typed carrier
interpretation requires property revision 3 and attribute revision 2.
Selector, physical tree and chunk semantics remain revision 1. Physical tree
semantics fix Node/Entry encoding, boundaries and physical TreeUse; they do
not make structural auxiliary edges into namespace grafts. Current
closed property resolution has all registered behavioral names and an
empty later-name set. Later preserve-only names acquire no behavior from
their presence, even when newer code recognizes them. Unknown semantic
revisions refuse verification; names
acquiring behavior require an explicit registered revision. No invented
mutable current-property map replaces actual root-property evidence.

Structural index pointers grant no namespace authority. Typed auxiliary
loading and proof caches keep role, attribute/value/object parameters,
expected source namespace root and current occurrence/view contexts distinct
from raw byte identity. An empty Node can have the same bytes and identity
under ordinary and Index roles. A first-match untyped receipt location or
Digest-only role cache MUST NOT grant auxiliary role or PROV-31 affected-root
authority. Older recorded semantic revisions keep later names inert even if
new code recognizes their spelling; their schemas and identities are unchanged.

Nested consumed-root/view records have no separate property revision. Their
unfenced intrinsic checks retain the original revision-1 behavioral vocabulary
and preserve other canonical names as data. Complete used-input and lineage
records MUST apply their enclosing explicit behavioral/later-name fence before
granting any newer property semantics. Nested decoding MUST NOT impose the
latest compiled vocabulary ahead of that enclosing fence (PROP-30).

Issuer rows are sorted uniquely by issuer/key ID. Disclosure rows are
sorted uniquely by repository/domain/key/not-before. Validity ends are
strictly later than starts; the same domain/key cannot identify distinct
physical repositories. Repository identities are lowercase 64-hex original
authority IDs. Text is exact UTF-8 without normalization or label substitution.

`CheckedLineage` binds an exact source name and whole RefRecord bytes,
signed Commit ID and canonical bytes, GuardSnapshot ID, availability-loss
generation, exact control dependencies and actual original binding. Its
used-input summary comes only from completed genuine verification and
includes consumed issuer/role rows, registry/configuration inputs and
authenticated root-policy occurrences and ancestor layers. Root occurrence
paths remain distinct even when their digests coincide. Each view's
independently resolved default domain is retained. Canonical property maps
and overrides remain existing property encodings, not caller assertions.

Required control pins distinguish registration, bootstrap, association,
import, import-binding and import-trust. Each binds its actual checked
retention owner, exact relative key and raw BLAKE3 of canonical bytes.
Pins sort uniquely by kind, canonical owner bytes and key. An empty list
does not prove exhaustive verification. Every used record must remain
independently readable and byte-identical under the protected control fence;
unrelated additions are not source dependencies.
The lineage's key 7 and used-input key 9.3 contain the same exhaustive
canonical pin set; contradictory sets are rejected.

A changed complete snapshot hash alone cannot decide source reuse.
Unrelated retained-key additions may be carried forward only by a private
held preservation check proving every actually used key, role, control
record, policy and serving dependency unchanged, and checking the new
candidate under current authority. It writes new immutable lineage bound
to the new snapshot. It cannot edit an old lineage or trust an arbitrary
digest. Used-key retirement, revocation, missing history, affected ACL/domain
or placement/profile changes invalidate old evidence. Pure recomputation
from exhaustive retained policy inputs may prove that a changed unused
default was overridden; incomplete evidence requires ordinary validation
or refusal. Fresh clock, token and request checks remain operation inputs.

## Current collection fences and cold forks

`GcFence` binds whole selected CAPABILITIES, exact selected MANIFEST or
authoritatively fresh-empty evidence, every inventoried whole ref or absence
and retained selection/log, Guard snapshot, complete PublicationState,
selected GcRoots/GcState key/digest, backend binding and all exact control
pins used by complete mark verification. The manifest requires verified
complete container inventory, physical exclusions and selected artifacts.
Unknown legacy completeness is unsupported, never an empty set. Pins
include every actual consumed original/import dependency, not a guessed
pair of record kinds or a global retained-row listing.

PublicationState key 6 selects the current GuardSnapshot, or is null before
trusted Guard registration. Actual trusted configuration installation and
reload publish this selector through a private checked transition, invalidate
affected lineages, and stop old cycles. A stale process cannot substitute
its old in-memory Guard for the selected configuration. A raw mutation
preserves this selector and cannot install another configuration. A complete
current fence's Guard identity equals that selected value and its actual
checked inputs. Collector lease acquisition, replacement and renewal also
use selected logical transactions and advance revision. A separately updated
physical lease cache cannot leave an old collection fence current after
takeover. Lease expiry still requires a fresh actual clock check; the
transaction chain does not manufacture elapsed or unexpired permission.

Every local destructive effect and restart checks the current live whole
lease and complete current root, catalog, retention and trust proof under
the same actual exclusion as final checked head publication. D-78 physical
intent, old marks and a returned digest cannot replace this proof. A changed
fence requires fresh complete reconciliation with the retained verified
index witness, including after physical containers are absent.
For the additive D-82 local copied-burn-v2 case only, each effect/restart
uses an actual complete CURRENT CopiedPlacementFence under that same held
namespace exclusion, plus permanent selected owner/burn and whole live
lease. It certifies physical serving closure, not foreign signed history.
Ordinary local D-78-v1 current-root/trust/journal/effect rules remain
unchanged; a legitimate unburned replacement cannot use this exception.
Local-v1 GcReconciliation binds that current collection fence, immutable
authorization, original pack/cycle/epoch and detached index identity.
D-82 permanent-v2 passes bind their actual owner and current permission;
local copied-burn progress additionally binds its current placement fence.

GC may carry source lineage to a new loss generation only after complete
ordinary root/context visitation of every carried source and proof that
every member of each removed actual detached index is unmarked. For D-82
proof case 3 only, marked members may instead have complete verified
eligible fresh unburned placements, with no live dependency resolving
through the retired keys. Initial nonburned tombstoning still follows
GC-14, and proof case 2 keeps its existing all-unmarked rule. Copied
retirement instead proves complete current physical placement closure
without an old index/witness; nonempty carry still requires its separate
complete current lineage fence and ordinary independent source contexts.
Witness-only
source traversal or a marked root digest alone cannot qualify preservation.
New lineages, catalog and selected state publish atomically. Affecting loss
or quarantine invalidates unmatched lineages. Derived Attribute/Memo/Bundle
relationships come from complete verified identities and signed recipes,
not a second guessed mutable catalog. Independent host/regional/redundant
participants require complete compatible roots and exclusion; absence of
support forbids combined destructive collection.

D-82 CopiedPlacementFence is a distinct private CURRENT destination
root/history/serving placement check. Actual fresh-copy registration and
current administrative/control authority are required; copied bytes cannot
mint permission. The missing retired pack/index/witness is not required.
It certifies no foreign original authorization or graph lineage. Nonempty
case-3 carried lineage for copied retirement additionally requires the
complete independently checked CurrentCollectionFence and ordinary source
context visitation, never inferred source OriginalBootstrap or ACL.

A cold unchanged-root fork reads the exact current source whole record,
selected lineage, signed source Commit/recipe and actual current Guard and
dependencies. It validates the new signed candidate and canonical recipe
by recomputation, checks current source Fork and destination Commit authority,
and compares the final selected stamp and loss generation. It performs zero
TreeNode reads or writes, including after unrelated admission/ref changes,
unrelated retained-key additions with checked carry-forward, and qualified
source-preserving GC. Initial legacy lineage needs complete validation once;
normal unrelated mutations do not justify repeatedly rescanning the source.

## Portable payload and protected control

STORE-13 and BKT-3 preserve ordinary quiescent byte-for-byte directory copy.
Publication slots, lineage, Guard, deletion operations and creation journals
live outside the portable local bucket root in configured protected control,
independently of Guard availability. Local control is operator-owned mode
0700 with protected ancestry; record files are nofollow regular mode 0600,
single-linked and owned by the configured operator. Backend and original
controls are separately registered even if an operator configures one
protected parent. Their actual identities are revalidated under exclusion.

The default local backend control directory is the protected sibling
`.terrane-control:<root-digest>`, where the digest is lowercase hexadecimal
raw BLAKE3-256 of the normalized absolute bucket-root bytes. A configuration
may select another protected external control directory. A root without a
qualifiable external control location refuses write-capable registration.
The backend control contains registered publication/fence records and
`.terrane-creation/<key-digest>` journals; original-authority records remain
under their independently configured protected owner. Neither a missing
same-root control nor a caller-supplied registration permits recovery by
discarding the old selected chain. Read-only payload compatibility creates
no protected authority and performs no control mutations.

The ordinary `publication/SELECTED-HISTORY` payload is updated in every
selected branch transaction, equals the state's complete branch-selector
map, and includes absent-name history. Its origin stamp equals the selected
state's backend binding. It carries portable data, not authority. Normal
copied payload opens for ordinary reads with fresh destination backend
registration after complete payload validation. It imports no lineage,
physical age, lease, original baseline or private signing trust. Same-root
missing or malformed control refuses mutation or requires exact recovery;
it cannot be mistaken for a fresh copy. Copied protected binding bytes
cannot mint authority at a new root.

A local origin stamp naming the current normalized root cannot qualify a
fresh copy, even if its inode has changed. A different source stamp only
identifies the proposed copy; genuine fresh administrative destination
registration and complete payload validation remain independently required.
Changing that stamp or supplying a caller tuple cannot establish freshness.
The private factory requires independent fresh administrative destination
authorization bound to the actual opened root, stable coordination and
protected control owner. Missing control alone is not such authorization.
Under the activation fence it durably retains the exact pending registration
as protected `backend-registration.cbor`, then durably refreshes the portable
stamp to its actual destination binding
before committing genesis. Interrupted activation recovers that exact
pending registration; it cannot reinterpret stale copied bytes as a second
fresh destination. Write admission, collection and completed portable
snapshot exposure wait until genesis and all payload cache flushes finish.
Only then may registration become Active with the exact genesis slot digest.
Its backend binding and any nonnull genesis digest never change; Pending
cannot authorize a new registration, and Active does not substitute for
verification of the actual selected immutable chain.

A fresh-copy factory durably stages and verifies its complete
destination-origin checkpoint, exact genesis transaction and fixed protected
`publication/ACTIVATION` record before recording Pending. Under D-108,
ACTIVATION uses the existing `PublicationCommit` encoding with revision zero
and a null predecessor. It is create-once nonauthoritative staging data,
never a commit slot. The Pending registration binds the raw canonical digest
of this exact proposed genesis record in its existing genesis field.
Recovery under the actual existing activation fence reads that fixed key,
checks its digest against the unchanged Pending registration, follows and
verifies its exact transaction and snapshot and complete payload/log closure,
makes the destination portable pointer durable, then installs the identical
record at `publication/commits/0`. It flushes every selected cache before
Active. Missing, unavailable or conflicting staging does not establish
absence or permission to begin another registration. Staging alone cannot
create a registration or select authority. Before Pending exists, orphaned
staging grants no admission. Existing empty-genesis Pending records with a
null genesis field retain their existing interpretation and recovery rules.

Ordinary payload includes an immutable `PortableSnapshot` and exact
`publication/PORTABLE` pointer. Its complete resolved projection contains whole
selected CAPABILITIES, every inventoried ref or absence, selected history
and the exact selected MANIFEST/catalog projection. It excludes private
lineage, Guard, physical age, deletion ownership and source collector state;
its collector lease is explicitly absent. Its revision, origin binding,
history and catalog selector agree with the staged selected transaction.
The projection excludes its own pointer and protected control, avoiding
circular encoding. Snapshot key 4 null means a complete checkpoint; otherwise
it binds the exact immutable prior snapshot key/digest and key 3 carries a
sorted unique logical delta. Resolution verifies the acyclic predecessor
chain and applies only these exact deltas to a verified complete checkpoint.
Ordinary deltas bind the previous selected transaction's snapshot and advance
revision by exactly one. They preserve unchanged catalog bytes rather than
rewriting catalog-sized metadata on a fork. A checkpoint is permitted only
after exact complete selected-projection verification under the same fence.
Every predecessor snapshot needed to resolve the current projection remains
retrievable. Snapshot ancestry retains projection metadata, not historical
content roots. Overwritten or removed values do not keep expired content
live, and validation checks payload closure only after resolving the complete
current projection. Its current immutable payloads and selected log-chain
metadata remain durably available and independently verifiable.

Each transaction durably stages this exact snapshot before its protected
commit slot; key 7 binds the snapshot key and raw canonical digest. Only a
winning slot may update the portable pointer. On a filesystem, the same
held exclusion durably updates that one pointer before changing individual
ref/history/catalog caches, causing physical availability loss or reporting
publication success. A crash before pointer update leaves the previous
complete projection and an indeterminate source publication; recovery
projects the actual selected chain. A crash after pointer update cannot
make partially flushed individual caches authoritative in a copy. Losing
snapshots, LIST maxima and proposed revisions never select a projection.
Recovery makes the current selected projection durable before allowing any
further physical effect or reporting a known committed outcome. Availability
loss, deletion and cache removal cannot outrun that pointer: the older
projection must remain readable until the current one is durably selected.

Fresh destination registration reads the pointer's exact snapshot and
verifies its complete payload/log closure; it ignores inconsistent individual
cache files. The portable projection proves readable data only, never private
authority or current source lease. Activation's destination-origin rewrite
creates a fresh snapshot and updates this same atomic pointer before genesis
under the pending administrative fence; it does not expose a completed
destination until activation finishes. A copy of a stopped source therefore
retains a complete selected portable view even after interrupted cache
projection, without importing protected control. Gates must exercise every
pointer/cache crash boundary and subsequent ordinary directory copy.

All local payload cache effects retain the stable namespace exclusion,
including flushing before a qualified snapshot. A concurrently changing
ordinary directory copy is not an atomic snapshot. A remote portable export
derives exact logical bytes from the selected chain; mutable remote cache
bytes cannot establish snapshot authority. Physical collection additionally
requires qualified backend incarnation and effect semantics. Publication
slots alone do not qualify remote deletion or exempt it from eventual GC.
D-82's [remote deletion authority](remote-deletion-authority.md) defines
irreversible selected ownership, permanent physical burns and owner map,
repeatable typed reconciliation passes for all future residue
without changing local v1 records.
