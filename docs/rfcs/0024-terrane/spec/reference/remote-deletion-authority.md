# Reference: permanent ownership, copied retirement and reconciliation

D-82 completes GC-4, GC-7, GC-10, GC-12, GC-14 to GC-16, GC-22 to
GC-24, GC-26, GC-29, BKT-2, BKT-4 to BKT-9, BKT-14, BKT-17, STORE-13,
PACK-2, PACK-15, PACK-18 and PACK-20. Exact additive formats are in
[`terrane-v1.cddl`](terrane-v1.cddl); existing key names/classes remain in
[`bucket-key-registry.md`](bucket-key-registry.md). Local D-78-v1 record
bodies, ordinary local cancellation, clocks and per-effect exclusion stay
unchanged. The new disjoint v2 alternatives cover ordinary remote sweep
and separately qualified retirement of copied burned placements at actual
local or remote destinations. These are format contracts, not implementation
or provider qualification. Public bytes never mint private capabilities.

## Permanent placement and key-family scope

MANIFEST optional key 7 is the complete permanent burn set, sorted uniquely
by unsigned pack-ID bytes and preserved by every selected transition.
Present `[]` is known empty; absence is legacy unknown. Unknown completeness
refuses destructive collection and same-ID readmission until genuine fenced
migration resolves it. LIST/missing records do not prove empty completeness.
All serving, get/has/list, import, inventory, cache, member/whole-pack/index,
fallback and commit-admission paths MUST consult current selected burns.
A burned P can NEVER become a live physical placement, regardless of later
root, policy, lease, data arrival or backend modification time. Eligible
same content may use fresh PACK-2 IDs with matching PACK-15 indexes.

PublicationState optional key 7 is a sorted unique recoverable selector map
whose IDs equal MANIFEST burns. Authoritatively fresh-empty null catalog
selects `[]`; its first manifest initializes complete empty burns. Selector
`[1, operation-key, raw authorization digest]` is the exact immutable owner
chosen by the first winning checked case-3 slot. That authorization and
transaction remain retrievable forever; owner mapping is never removed or
replaced. The selector omits its own selecting digest to avoid a hash cycle.
Actual checked chain resolution identifies that slot; later Owned records
retain its revision/digest. A mutable operation/pending cache, expired roots,
GcState `done`, empty pass or trash absence cannot end ownership or fairness.
Re-registration/alias/new nonce at the same physical keys cannot evade it.

Selector `[0]` is visibility-only copied burn plus pending DESTINATION
retirement duty, not source owner permission. Only genuinely fresh-copy
genesis installs it from the verified portable projection. Current reads and
writes honor the burn from genesis onward. A current collector MUST fairly
attempt the destination protocol below; ordinary sweep's missing pack/index
predicates MUST NOT strand this valid case. Only a new genuinely checked
case-3 destination ownership may promote `[0]` once to `[1, ...]`; it never
clears the burn. Source private owner/witness, journal, clock, lease and
original signing baseline are not imported. Missing same-root control is
exact recovery/refusal, never new fresh-copy registration.

Both authorization cases permanently own the same exact pack-ID key family
under one actual registered physical backend: `objects/pack/<aa>/<P>.pack`,
its matching `.idx`, and EVERY canonical `trash/<cycle>/<P>` key for unsigned
cycle values. Field 13 is exactly `1`. Scope includes ALL present/future
object versions, deletion markers and unversioned/local residue at that
family, not a frozen version list. Every observed trash key MUST match its
actual canonical cycle and exact owner P. It cannot authorize another ID,
resource, arbitrary prefix or malformed/nonregistered name. Stale other-cycle
trash and abandoned destination barriers at the SAME P belong to this duty.
No content-reader path exposes trash as a root or admits old P from it.
Uncommitted multipart parts are separate BKT-9 storage/accounting, not object
versions silently covered by this scope.

After selection every physical incarnation at the family is permanently
unservable. Initial identities/sizes/witness qualify ordinary FIRST sweep
ownership, not every future residue. Later bytes need not match them before
recovery may remove them. Genuine observed key/resource/version association
and current permission are still required; a copied marker or handle cannot
provide those checks. No owner can delete a fresh Q merely sharing a digest.

## Ordinary remote sweep remains artifact-qualified

Initial nonburned tombstoning keeps GC-14: all members unmarked, FULL G
qualified, actual complete current roots/history/regions/redundancy and
selected exclusion before durable matching trash. The remote elapsed method
observes the exact immutable pack AND detached index for FULL G using one
actual configured monotonic clock. FULL D observes exact durable immutable
trash under its active exclusion. D >= G > enforced C. Backend metadata,
continuity and checked arithmetic remain genuine; GC-9 still forbids reading
chunk bodies just to mark. No DELETE precedes selected ownership or full D.
Missing trash cannot backfill old time/incarnation. Before ownership a single
checked restore may cancel intent, restore eligible otherwise-unserved old
entries, clear exact key 6, and preserve fresh placements/quarantine.

Later first ownership may see newly marked hashes served in fresh Q. Every
marked member of the retained verified detached-index witness MUST have its
actual uses served through verified eligible fresh UNBURNED placements. No
live dependency, including metadata, receipts, policy proof and regional
promises, may require old P/index. Complete CURRENT roots and retained absent
history, serving/catalog/trust/quarantine/redundancy, selected Guard/actually
used controls, backend/exclusion and current whole lease remain mandatory.
Initial GC-14 and proof case 2's all-unmarked rule are not weakened.

RemoteSweepDeleteAuthorization retains exact initial pack/index/trash
associations, bounded verified index witness, actual authorizing whole lease,
current CurrentCollectionFence and live completed G/D bounds. Stage Proposed
revision 0 with null owner/pass pointers, complete burn/owner map and portable
projection before the exact next case-3 slot. The private final check compares
current fence, controls, exact exclusion/trash, whole live lease and wait.
Restore/admission conflicts win first or force requalification; losing or
indeterminate proposals cannot dispatch. Resolve exact authoritative chain;
unavailable is not absence. Winning selection installs permanent owner/burn
and advances loss generation by one. Nonempty carried lineage needs complete
ordinary source/context visitation and exact independently trusted inputs.
Unsupported carry loses lineage; a digest alone never creates it.

## Separate copied-placement destination preparation

A copied burn may have pack only, index only, trash only, neither artifact,
missing/different source trash, or finite delayed residue arriving later.
It MUST NOT require a source detached witness, guessed old member set, old
pack/index identity, imported owner or artifact age. It is NOT fresh sweep
of an eligible young pack. Source burn bytes supply denial visibility only.
The actual new destination administrative registration/maintenance factory
must independently authorize permanent physical retirement under its actual
backend/control owner, current selected Guard and whole live lease.
Neither accepting caller fields nor reading a copied `[0]` is that factory.

The collector constructs a CopiedPlacementFence using the actual active
fresh-copy BackendRegistration/genesis and CURRENT selected state, complete
CAPABILITIES/ref inventory, every present ref or retained absence/history,
actual current destination retention/policy/Guard inputs, complete roots and
placement traversal, manifest/shards/inventory, used control pins and exact
portable projection. Complete destination root/retained-history and metadata
placement closure MUST be independently verified against actual canonical
identities and current serving policy. Every live use resolves through
eligible unburned placement; every serving/admission/import/fallback route
excludes P. Required metadata/proof dependencies remain available under their
actual applicable rules; unknown root inventory, unresolved LIVE data or a
claimed fresh row refuses qualification. It is not enough to inspect one
merged hash row or only the current head. Regional/redundant participants
require complete compatible placement/exclusion authority.

This is a CURRENT physical placement check, not certification of foreign
history's original signed ACL/issuer authority or creation of CheckedLineage.
Fresh administrative registration admits portable DATA under independently
trusted destination policy; it does not manufacture OriginalBootstrap,
OriginalAssociation, import trust, historical source permission or disclosure
keys. Public/copy records cannot repair a missing trusted baseline. The
placement factory MUST NOT require source protected owner/witness or original
bootstrap merely to retire an already forbidden P: D-79's genuine complete
readable-copy projection and actual CURRENT destination root/serving inputs
are its data evidence. Any historical verification required for an actual
consumed trust/policy/pruning decision still requires independent configured
inputs; the factory MUST neither guess them nor claim lineage certification.
If a separate complete current lineage-preservation check cannot qualify,
retirement uses an EMPTY carried-source array and loses affected lineage.
Copy data safety is established by current complete physical placement
closure and permanent admission denial, not inferred foreign authorization.
This fence performs DATA placement verification, not a new GC-30 proof-edge
pruning decision. It MUST preserve required destination proof/metadata in
unburned placements and MUST NOT use missing foreign authority to discard it,
probe a forbidden private source, or grant serving/fork/commit permission.
An unavailable foreign original signing baseline alone is not a prerequisite
for deleting only universally inadmissible P; it remains a prerequisite for
any separate operation that actually certifies that foreign history.

The roots/state pointers use the existing version-one `GcRoots` and `GcState`
schemas, with the distinct copied-placement meaning in D-113. The destination
factory MAY conservatively retain every current commit-bearing value and every
selected historical new or predecessor commit without applying foreign age or
retention claims. In this mode, `current` identifies a present selected value;
`forever` identifies a historical value deliberately held without expiry by
this physical check, not a verified foreign `retain=forever` property. Every
such root has the unbounded `null` parent cutoff. Unknown selected history
still refuses; an unselected proposal MUST NOT become a root. Opaque advisory
sidecars retain their exact inventory and bytes without invented commit edges.

The complete placement traversal records only actual canonical DATA expansions
and verified eligible destination placements. It carries no proof context or
proof-edge pruning decision; a completed frontier is empty only after every
required physical dependency is accounted for. Required mark checkpoints retain
their exact sorted hashes, reconstructed filters and raw-byte integrity
pointers. The selected cycle, epoch and snapshot time come from the actual
destination session, not imported artifact age. These records are usable only
with the independently checked `CopiedPlacementFence`; decoding them, or
reusing their expansions, MUST NOT qualify an ordinary `CurrentCollectionFence`,
historical authorization or carried lineage. Ordinary GC-3/GC-5/GC-30 retention
and authenticated traversal rules are unchanged. Any consumed policy/trust
decision still requires its actual independent inputs; conservative retention
neither invents them nor permits forbidden private-source probes.

Select CopiedRetirementPreparation Preparing at revision 0 under a fresh
operation nonce and NEW destination `[P, cycle, epoch]` binding. Its plan
binds actual destination genesis, exact current placement fence, whole live
lease, trusted G/D settings and the canonical NEW destination Tombstone.
The transaction compares complete current selected inputs and preserves the
burn `[0]`, current eligible placements and all required histories. The
barrier's `index entries removed` is exactly ZERO because there are no live
P rows: it is not a guess at source member count. Any copied source key-6
binding is retired/replaced only in this genuine selected transition; source
trash never acquires a destination incarnation or clock.

Selected preparation MUST precede creation of its NEW trash barrier under
a genuinely fresh canonical destination cycle/key. Existing collisions use
another fresh cycle, never overwrite or reinterpret old trash. Actual
create-if-absent installs and durably verifies exact plan bytes. Local
creation follows real D-78 Pending/Committed journal and nofollow/file/directory
synchronization rules for this NEW trash only; copied pack/index journals
are not invented. Remote creation proves actual immutable conditional
backend installation. No physical deletion occurs during preparation.
Preparation and decoded plan are not ownership or elapsed permission.

Observe this genuinely created exact immutable destination barrier for a
FULL G AND FULL D using one live monotonic instance; D remains >= G and
G > enforced C. The waits can share the same start, but both checked lower
bounds must hold. Actual backend creation/version evidence and immutable
continuity are verified. This is a NEW destination retirement delay, NOT a
claim that absent/copied pack/index bytes are old. Missing old pack/index,
source witness or old trash is not a failed age predicate. No timestamp,
source slot, absence, elapsed integer or clock capability is imported.
The copied burn and actual new exclusion prevent old-ID admission throughout.
A pre-genesis finite delayed creation at the forbidden family can arrive
before/after these waits; it is inadmissible residue, not a committing writer's
eligible new placement. This is the explicit GC-10/12/15/16/29 copied-placement
alternative, not reinterpretation of ordinary sweep age or local-v1 journal.

Final qualification constructs CopiedRetirementAuthorization with actual
NEW barrier evidence, current whole lease/final CopiedPlacementFence, actual
destination genesis and prior preparation slot, and genuine FULL G/D bounds.
Pack/index artifact positions are explicit null and there is NO witness key.
Neither null nor missing artifacts grants permission: the private destination
factory and complete current root/serving/exclusion proof do. Copied local
binding requires actual new committed trash journal identity; copied remote
binding requires genuine actual remote barrier identity. Backend associations,
plan/Tombstone/settings/binding and selected preparation all agree. Same-owner
lease renewal retains preparing holder/epoch while final authorization uses
the actual CURRENT whole lease and expiry; it MUST NOT reset valid barrier
age. Epoch/holder takeover needs a genuinely current new selected preparation
and fresh cycle/barrier rather than rewriting the original plan.

The winning case-3 transaction compares whole Preparing bytes/state and
selects Proposed at the NEXT checked revision with immutable copied
retirement authorization and null future owner/pass pointers. It promotes
`[0]` once, preserves burn visibility and advances loss generation by one.
Its authorization refers only to EARLIER destination genesis/preparation
slots and final PREDECESSOR fence, never its own future selecting slot.
Nonempty carry additionally requires authorization key 17's complete current
CurrentCollectionFence, ordinary independent source/context verification
and no live old-key dependency; the physical-only fence cannot certify it.
Without that additional qualification all existing carried lineage is dropped.
Losing/indeterminate proposals cannot delete. A stale Preparing/null cache
cannot establish that ownership never won.

A cancelled/failed attempt selects Abandoned only before actual ownership;
it does not clear `[0]` or admit P. Restart/clock uncertainty resets live waits.
Finite failures permit a current collector to resume exact genuine barrier
qualification or create a fresh selected plan/cycle/nonce, rather than demand
missing source artifacts. All stale same-P trash barriers are eventually
covered by the winning permanent owner. Actual fresh-copy authority, complete
current roots/policy/placement, live lease and excluded keys remain required;
unsupported input is not successful GC, but PARTIAL OLD ARTIFACT absence alone
cannot make this supported protocol unavailable.

## Wait continuity and immutable physical premises

G/D conversion, subtraction, products and revisions are checked. No live
clock capability/tick persists. Restart, reboot, changed/regressed clock,
failed/cancelled timing, changed physical/coordination binding or uncertain
artifact continuity resets the relevant observation. Ordinary unrelated
publication, same-owner lease renewal or release/reacquire of the SAME valid
namespace lock MUST NOT alone reset proven immutable-artifact continuity.
The collector need not hold a global lock during waits; final current live
exclusion and selected fence remain necessary. Current setting changes need
properly qualified current bounds, not edited immutable authorization.

All participants obey PACK-2 and BKT-2/BKT-6 immutable create-if-absent.
No new pack/index creation at a burned ID, nor new creation at ANY already
owned family key, is permitted. This includes retry, multipart completion
initiation, copy/repair/import and re-registration. Copied `[0]` preparation
may create only its NEW selected barrier; that does not recreate an owned
source artifact. During real artifact observation a qualified conditional
pre-burn create cannot overwrite a present initial artifact. Uncontrolled
earlier overwrite/DELETE that defeats initial continuity is not qualified.
D-79 legacy activation still genuinely fences incompatible clients/effects;
metadata rollback and serving/admission bypass are never protected by a burn.

A finite already-submitted conforming pre-burn/pre-genesis create may finish
AFTER old-key deletion. Universal definitive create drain or proven provider
deadline is not an ownership precondition. New post-burn creations remain
forbidden. Permanent owner covers every late family residue; later fair
passes genuinely observe and reclaim it, with no guessed causal request ID.
Actual immutability, finite admitted effects and eventual observation/delete
remain qualification premises, never inferred from timeout or provider label.

## Permanent operation and repeatable passes

PermanentDeleteOperation is the v2 alternative to local-v1 map; immutable
authorization never changes. States Proposed/Owned/Cancelled have no Done.
Proposed/Cancelled encode null owner/pass; actual selected ownership is the
Proposed/null value described above. Later first Owned progress selects exact
nonnull owner proof and an initial Open pass. Copy's selected preparation is
a separate type, not mutable authorization. Every next operation revision
increments by one checked; first pass revision equals the selected owner
revision plus one (ordinary sweep 1, ordinary copied preparation then owner 2).
Only unselected ownership proposals may cancel; actual owner never does.
Restores after ownership verify eligible available bytes and durably admit
fresh secure Q/index through a current checked generation; extraction failure
cannot advertise missing data. No owner can readmit/recreate old P. Key 6 may
clear after current exact no-old-serving/inventory catalog confirmation;
key 7/owner remain forever. PACK-18/20 content-row tombstone cleanup still
needs genuine deletion confirmation at its observation, not future absence.

PermanentDeletePass is the v2 GcReconciliation alternative at registered
`gc/<original-cycle>/reconcile/<event-proposal-id>/<revision>` keys. Original
owner identity/cycle stays fixed; proposal-ID is a fresh secure nonce matching
field 12 and creating transaction, NOT the owner nonce. Losing immutable
events cannot occupy a future selected revision forever; retry stages a NEW
nonce with fresh predecessor/lease. Selected pass bytes bind original owner,
current predecessor slot/state, live whole lease/backend, checked pass/event,
Open/PassCompleted, bounded actual observation DELTA and three coverage rows.
The predecessor contains the OLD pointer; the following transaction selects
the new digest, avoiding a pass/State hash cycle. Physical CAS is a cache.

Pass/event starts 0/0; same-pass event advances by one, new pass after completion
advances pass by one/resets event to zero. Immutable selected history retains
unresolved requests, not one unbounded all-version array. Traversal may span
bounded events/live genuine pagination; restart/invalid continuation resumes
conservatively without dropping duties. No per-pass cap may strand supported
versions. Checked allocation/format bounds refuse exhaustion, not wrap/Done.
Progress case 0 validates actual existing selected owner/current inputs and
preserves owner, burn, Guard, loss generation and lineage; it cannot create any.

EVERY new discovery/delete/confirmation/retry request and selected progress
MUST verify actual current whole LIVE lease, actual backend and selected
immutable owner/burn and a fresh complete current selected stamp. Progress
compares exact current lease and predecessor. Losing renewal/expiry stops new
requests/writes. Already submitted effects may complete after takeover at
owned keys only. New epochs use current permission without rewriting original
owner epoch. Local copied-burn EVERY effect/restart additionally checks a genuine complete
CURRENT CopiedPlacementFence for roots/history/policy/serving under the same
held stable namespace exclusion. Progress key 13 binds that exact predecessor
fence; a later effect requalifies its current fence without inventing old
marks or source authority. The current fence's checkpoint cycle belongs to the
actual independently qualified destination collection under the live session;
it MAY differ from the immutable owner's original cycle. Its fence, roots and traversal
pointers MUST agree on that current checkpoint cycle and the fence revision
MUST equal the current predecessor revision. The original owner and
reconciliation event-key cycle remain unchanged. These associations MUST be
checked alongside the actual whole live lease, current complete DATA closure,
backend, selected predecessor and all consumed Original pins; a decoded later
cycle is not current permission.

Existing CreateOnce roots MUST NOT be overwritten or relabeled. Their exact
bytes MAY be reused only after independent current qualification verifies the
same complete physical closure and recorded inputs. Changed roots require a
genuine fresh destination collection cycle with its own actual roots and
traversal checkpoints, rather than a fabricated suffix or reuse of stale marks.
This distinction changes neither permanent ownership nor the mandatory current
qualification at every new request, retry and progress selection.

Local effects hold exclusion through final comparison/effect, verify exact
registered paths with normal nofollow/regular-file/owner rules, and synchronize affected
directories. Permanent key scope cannot follow a symlink or delete another
placement. Ordinary local-v1 replacement/journal semantics are untouched.

Observation states are Planned/ConfirmedAbsent/Indeterminate/Deferred.
A deletion request requires prior selected Planned evidence plus new current
permission. Stale/indeterminate plans require genuine reobservation before
retry. Targets are actual pack/index, or trash at an ACTUAL observed canonical
cycle for this P, with an observed unversioned/local target or opaque actual
retained object/marker handle. Local binding accepts only unversioned/local
instance `[0]`. Verify exact resource/key/kind associations, sort uniquely by
unsigned artifact kind/cycle-if-trash/instance kind/version kind/handle bytes.
Caller handles are never authority. Old cached cycle arrays are not exhaustive.

Coverage rows are pack/index/TRASH FAMILY in order: Unknown,
CandidateTraversalCompleted, or QualifiedAllVersionAbsenceAtObservation.
Candidate LIST supplies observations only; exhausting it does not prove all
versions/cycles absent. Last coverage requires genuine complete evidence at
its observation, never proof no future residue. PassCompleted leaves no
unresolved Planned item anywhere in that pass and completes candidate walks
for all three scopes; Indeterminate/Deferred and incomplete absence remain
duties. Partial traversal remains Open. No completed/empty pass stops future
passes. Every owner, outstanding target and future family discovery is visited
fairly under current leases; new owners/cycles cannot starve old ones.

Every retained object version and deletion marker belongs to the duty.
Current-key absence or installing a marker is not complete reclaim. Qualified
deletes must reclaim actual observed versions/markers, not deliberately
create replacement markers/storage. Genuine current observations may remove
later young residue without NEW G/D under GC-10/12/15/16 recovery; it never
inherits fictitious old age. Old digests may be live in Q now, so retries do
not require global unmarked status or reuse old marks. Missing protected
owner/pass evidence is exact recovery/refusal, never empty ownership.

## Copies and eventual physical GC

D-79's ordinary quiescent copy/portable export continues to preserve complete
readable current payload/log projection and burn visibility, not private
source control. Fresh destination genesis clears copied lease/collector
intent and creates `[0]`, using independently authorized actual registration.
It cannot import OriginalBootstrap or fabricate source permissions. Genuine
new destination placement preparation/owner above supports pack-only,
index-only, trash-only, mixed stale cycles, all-absent and future finite residue
WITHOUT source protected witness. Newly available OLD bytes stay unservable;
otherwise eligible content restore only uses fresh Q. Source registrations
keep their own permanent reconciliation duty; copying discharges none.

Local portable pointer is durable before cache removal or physical loss;
remote export resolves actual selected projection, not mutable caches.
Burns persist in every projection. Snapshot metadata does not retain expired
content roots. Unsupported unknown inventory, missing LIVE closure, unavailable
actual destination authority, permanent hold or unqualifiable backend is still
refusal, not positive liveness; ordinary valid copies with merely missing old
retired artifacts MUST have the genuine destination path just registered.

With finitely many pre-burn/pre-genesis effects that settle, there exists a
last residue-creation time without a client proof/deadline. Under renewable
current leases, fair request/publication/family discovery, genuine eventual
observation and permitted deletion after finite faults, the finite residual
object/version/marker set is eventually removed. Current-key absence cannot
prove last creation has happened; owners and future empty passes persist.
That metadata is not unreclaimed pack/index/trash bytes. Infinite external
rewriting, permanently hidden versions or indefinite holds defeat qualification.
BKT-9 incomplete multipart abort/accounting remains separately required for
complete storage GC; these records do not silently qualify its implementation.
No universal S3/GCS capability claim follows.

Existing gates MUST eventually cover ordinary artifact-qualified sweep and
copied destination barriers for pack-only/index-only/trash-only/all-absent,
future finite residue AFTER an empty pass, and stale other-cycle trash/version
markers; missing source witness/owner; no false baseline/clock authority;
complete current roots/history/placement/Guard/control inputs; restore/owner
slot races; genuine local barrier journals and namespace exclusion; clock/
renewal/restart; immutable losing-event retries; finite-fault eventual GC.
`gate:gc-singleton-lease` separates stale new request/progress refusal from
harmless already-submitted late completion. Actual provider immutability,
version observation, request/delete scope, and fairness evidence plus new
format vectors and runtime fault tests remain pending. Simulator/local-v1
or Unsupported-only gates cannot claim copied-v2 or remote runtime completion.
