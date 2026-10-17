# Advisory trigger schema transition for review

**Status:** Proposed; no migration, schema identity change or serving transition
has been installed. This review covers a prerequisite for durable advisory-feed
triggers in RFC-0026. The serving lineage remains
`aos-hub/canonical-serving/18`.

## Requested implementation

Add generation nineteen with one compact table. A source response continues to
retain its exact normalized record and raw evidence under the existing immutable
identities. The additional row records that the source revision's scheduling
meaning has already contributed an input mutation in this resource incarnation.
The table does not authorize a source, scan, database restore or release.

```sql
CREATE TABLE assessment_advisory_inputs(
  partition_key KEYTEXT128 NOT NULL,
  semantic_digest KEYTEXT128 NOT NULL,
  provider KEYTEXT128 NOT NULL,
  advisory_id KEYTEXT128 NOT NULL,
  record_digest KEYTEXT128 NOT NULL,
  admitted_at INTEGER NOT NULL,
  PRIMARY KEY(partition_key, semantic_digest),
  FOREIGN KEY(partition_key, record_digest)
    REFERENCES assessment_objects(partition_key, object_digest)
);
```

The semantic digest is the shared
`AdvisoryRecordV1::change_digest()` commitment. It includes the exact native
modification identity and all normalized assertions, excluding only raw response
custody. The original record digest remains the evidence identity and is retained
as a foreign-key-bound proof for the first semantic admission. Equivalent raw
re-encodings may add immutable records without replacing that original proof.

Within the existing checked provider-result admission transaction, the
coordinator locks the exact assessment resource, increments its
`resource_version` only when the semantic row is absent, and inserts that row
with conflict-safe first-admission semantics. It does not change
`next_generation`. The existing continuous-review watermark therefore observes
an input mutation and requests bounded work under the original reviewed
selector, acquisition intent and credential deadline. All current source,
claim, inventory, policy, generation and IAM guards remain in that transaction.
A refused admission rolls back custody publication, the input mutation and
semantic row together. Replaying an admitted attempt or re-encoding unchanged
meaning causes no additional input mutation.

First-admission serialization requires the exact resource lock before evaluating
whether a semantic row is absent. A conditional counter update followed by a
conflict-safe insert alone is insufficient proof of concurrency safety on every
backend. The checked transaction must retain the lock through the row's
admission and roll back the increment when its exact admission guard fails.

Schedule advancement must acknowledge the input basis captured for the original
slot, including after coordinator interruption. It must not acknowledge a newer
feed revision that arrived after the slot froze its evaluation. Any additional
private slot commitment needed for this fence must preserve existing review
identity, credential expiry and restart compatibility. A later revision remains
pending until another bounded slot assesses it; neither recovery nor a completed
older scan can erase that obligation.

This first integration conservatively wakes continuous reviews in the affected
resource incarnation. It does not create a tenant-wide feed subscription,
automatically enroll an unreviewed resource, extend source freshness or change
cadence-only reviews. Source modification identity is part of the commitment:
a later genuine revision returning to an earlier assertion remains a new input.
A repeated identical source revision is coalesced. The input counter is retained
independently of scan allocation, avoiding a scan-generation feedback loop.

## Compatibility changes requiring review

1. Append one migration without changing generations seventeen or eighteen.
2. Set the new serving identity to `aos-hub/canonical-serving/19`; retain the
   generation-eighteen archive identity explicitly.
3. Add generation-nineteen snapshot classification and object requirements for
   all six columns. These rows are retained application dependencies; they
   cannot be discarded as a cache during authenticated snapshot processing.
4. Preserve exact generation-eighteen classifier, coverage, migration hashes,
   PostgreSQL catalogue hash and archive readers. Add generation-nineteen
   readers and make new capture writers select nineteen.
5. Calibrate the new PostgreSQL catalogue hash using the production catalogue
   normalizer against a fresh, private, source-built PostgreSQL fixture. Do not
   install a placeholder expectation or admit archive-supplied SQL.
6. Keep Native SQL and Worker HubDb on the same checked transaction and migration
   lineage. Hybrid continues to hold this state in the Native coordinator.

## Serving transition and operational risk

Hub currently admits an empty database or the exact current identity and
migration singleton. It refuses another nonempty lineage before bookkeeping
writes. Adding generation nineteen does not authorize an in-place upgrade of a
nonempty generation-eighteen database. Starting the new server against one would
refuse serving and require an explicit transition; deploying without that
transition risks downtime.

No reset, data deletion, automatic migration of an existing serving database,
import or production activation is included in this implementation proposal.
The source database and authenticated recovery evidence must be preserved.
Existing databases require a separately reviewed explicit fresh initialization
or manual import path. Authorization to implement the new schema contract does
not authorize destroying or resetting any existing database.

## Acceptance checks before publication

- Verify unchanged historical migration and catalogue hashes.
- Verify no-write refusal when new serving initialization sees a nonempty
  generation-eighteen fixture, preserving its original rows and ledgers.
- Qualify the new table, first-admission concurrency, replay, rollback and
  continuous-review coalescing on SQLite, real PostgreSQL and the MySQL backend.
- Preserve original source custody across equivalent response re-encoding and
  include changed severity, withdrawal and native modification revisions.
- Verify feed arrival after evaluation freeze and before interrupted-slot
  advancement, including restart: the newer revision must remain pending.
- Verify file reopen, unchanged credential expiry, scoped current authority,
  bounded schedule fairness and absence of refresh feedback.
- Check Worker/Console WASM, production Native/Worker/Console builds, all
  application test targets and the retained-pages KVM/fleet suite.

Implementation remains pending explicit approval of this schema addition and
compatibility transition. Public permission grants remain a separate review.
