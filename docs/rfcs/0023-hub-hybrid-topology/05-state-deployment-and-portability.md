# State, deployment, and portability

## Hybrid state ownership

Hybrid has one logical Native Hub service and one PostgreSQL system of record.
All authoritative Hub rows, including identity, authorization, topology,
publication, indexing, inventory, and job state, live in that database. The
service may have several GCP replicas, but replicas share the same database and
must not make an in-process lease or cache an authority. Durable Objects hold
reconstructable parse results separately from permanent identity reservations,
per-authority issuance and object-effect journals. Those external correctness
authorities retain epoch/time floors, cutoffs, pending effects, incarnations and
terminal receipts across SQL restore. KV and edge caches remain projections.
The Worker cannot accept a control mutation while
Native or PostgreSQL is unavailable.

The baseline hosted deployment is the Native Hub on the GCP application
platform, a Cloud SQL PostgreSQL instance placed near it, and a Cloudflare
Worker bound to the public hostnames and object storage. Keep the GCP service
private to the Worker ingress identity. A deployment records the Native origin,
Worker storage-work endpoint, database identity, object-store bindings, and
protocol compatibility as one reviewed configuration. Worker-to-Native calls
and Native-to-Worker storage work have separate credentials and audiences.

The Native service artifact execs the Hub directly with deployment-supplied
configuration and private credential files. JWT and instance sealing keys are
stable external credentials shared by every Native replica. Hybrid startup
must reject an absent key rather than generate one under an ephemeral root:
sealed SQL secrets and authenticated sessions must survive a revision change.

The existing [`Backend`](../../../crates/aos-hub-core/src/backend/mod.rs)
and [`Database::connect`](../../../crates/aos-hub-core/src/db/mod.rs) already
support PostgreSQL behind a feature. The Native `serve`, `index`, `init`, and
administrative commands currently open `hub.db` directly, however, and the
Native server provisions a local filesystem default binding at startup. Hybrid
must select the database through an explicit deployment configuration, build
with PostgreSQL support, and provision an object-store binding without silently
creating local storage authority. Database pools need a bounded connection
budget across all replicas and background workers. Schema migration runs once
under a database lock before a new application revision serves traffic.

Background indexing, inventory, GC, and delivery tasks need database-backed
claims, idempotent receipts, and expiration so multiple Native replicas do not
duplicate an authoritative commit. A Worker may execute object work in
parallel; Native commits its results only after checking the current binding,
placement, publication, and job generation. The shared database is expected to
scale these short transactions and read queries; the RFC does not promise
unbounded write scale from a single PostgreSQL primary.

## Cloudflare resource provisioning

The infrastructure deployment owns the Cloudflare resources as well as the GCP
resources. Registered OpenTofu modules provision private R2 buckets, exact-origin
upload CORS, bounded abandoned-multipart cleanup, and the queues required by the
storage executor. Worker deployment binds those declared resources and their
compatible Durable Object classes. Existing buckets can be explicitly adopted
into infrastructure state; adoption does not recreate a bucket, reset a journal,
or establish its storage authority. Destruction requires a separate reviewed
retirement operation. Lifecycle rules must not expire published objects or
correctness journals merely because an upload staging policy exists.

Credential bootstrap is also automated. A separately supplied account
provisioning credential permits the deployment to create an R2 S3 credential
limited to the selected bucket's object read/write operations. The deployment
stores its value in the approved secret service and delivers an immutable secret
version to the storage executor. It publishes only secret references and public
resource coordinates in deployment contracts. Secret values must not appear in
source, ordinary plan output, logs, or public configuration. Native does not
receive the R2 signing credential. Rotation follows the existing issuance,
cutoff, and retirement barriers; creating a replacement credential cannot reset
an object-effect journal or cancel an already issued upload grant.

The initial account provisioning credential remains an explicit operator
bootstrap prerequisite. A Wrangler session that manages buckets may lack the
permission to create API tokens; deployment must report that distinction rather
than require manual bucket and S3-key creation for each Hub. Emulated fleet
qualification can proceed without hosted credentials. Hosted acceptance still
requires the actual bucket, signing credential, Worker binding, and measured
provider behavior before enabling direct uploads.

## Permanent journal lifetime and partitioning

The fixed metadata ledger is an implementation foundation, not proof that an
external execution protocol or provider readiness exists. Intended scalable
admission separates the rare identity registry, per-authority issuer and local
object guards. Moving to that topology requires a reviewed continuity protocol
bound to actual immutable configured resources; matching labels or a SQL
acknowledgement is insufficient.

The issuer and object-guard protocol is runtime-neutral, with intended Native
and Workers adapters; Native-only deployment does not require Cloudflare. Its
Native durable journal backing must be an independently retained resource whose
identity and history remain outside Hub SQL snapshot/reset authority, preserving
the same exclusivity, cutoff, unknown-effect and receipt invariants. Durable
Object classes and object IDs implement the Workers adapter rather than a
mandatory Native dependency. A Native journal adapter is not yet implemented or
qualified; managed external execution through that adapter stays disabled until
its actual backing and full protocol pass the same lifetime and all-writer gates.

Preserve permanent alias reservations, authority IDs, namespace/executor links,
full publication and control receipts, latest generation/digest and recorded
issuance/cutoff/time floors. Preserve every original object guard's namespace,
authority/full-key address, incarnation counter, unknown intent and terminal
receipt. A new issuer address does not select new key guards or excuse missing
history. An empty destination journal is never fresh qualification for a reused
bucket/prefix, and restoring any of these journals backwards is unsupported.

Partition installation must verify linked irreversible global reservations and
current authoritative continuity evidence before execution activates. Rebinding
classes/deployments, key rotation and failure recovery preserve this lifetime;
partial migration stays closed rather than rolling ownership back. Old issuer
keys/leases and already admitted provider work must be accounted for under the
reviewed cutoff/settlement policy. A SQL-only restore cannot issue a lower epoch,
clear pending work, infer drain or restart leases from cached publication.

A whole-Hub snapshot preserves SQL references to these authorities, not their
execution power. Issuer private keys stay outside general archives and Native
metadata credentials cannot replace them. Reusing storage reconciles against
live authoritative journals; copying into a truly fresh namespace establishes
a separate reviewed authority. No reset silently adopts unmanaged old storage.

## Initial deployment and reset

Live, automatic migration from Worker-only or Native-only is not required for
the first hybrid release. Staging may start with a new empty PostgreSQL database
and new logical object-store resources, then bootstrap its owner, bindings,
routes, and registries and republish the required immutable release surfaces.
An operator explicitly identifies the environment and records what state is
being discarded. Changing topology is not an implicit data conversion or a
silent fallback when the selected database is unavailable.

The merged serving schema has identity `aos-hub/canonical-serving/8`.
Two historical branches used `aos-hub/production-baseline/1` and migration
version two for different DDL. Neither the integer version nor the historical
identity can authorize an automatic upgrade. Canonical migration scripts
001–007 and the appended master channel script remain unchanged. A fresh
initializer applies all eight scripts, then stamps the new serving identity
with a checked driver statement.

The driver acquires its migration lock before reading the owned schema, and
keeps the same connection through initialization. It accepts an empty schema
or the exact new identity and current version singletons. Other nonempty
schemas, including interrupted implicit-DDL initialization, require explicit
reset or separately reviewed manual import before any bookkeeping DDL. This
rule is a serving eligibility check, not an attestation of arbitrary catalogue
integrity. SQLite, PostgreSQL and MySQL-family implementations preserve their
existing SQL support; actual engine receipts distinguish exercised MariaDB
from unexercised genuine MySQL.

Genuine generation-three through generation-seven archives retain their
original identity, scripts and authenticated verification contracts. Generation
eight is a separate current contract with the new identity. Verifying an old
archive does not rewrite it or authorize serving. A manual import into a fresh
current database must explicitly adapt retained data to the new contract;
provider authority, outstanding effects and credentials still require their
independent reconciliation.

A database-native backup before reset is a useful low-cost safeguard when the
source supports it. It is not a portable Hub snapshot: it omits object bytes
and may only restore into the same database engine and deployment identity.

The initial rollout order is:

1. Provision Cloud SQL, the GCP Native service, storage bindings, and separate
   ingress and storage-work identities. Keep public routing closed.
2. Initialize and migrate the database; bootstrap the root administrator and
   configure the intended topology. Verify Native health, database reachability,
   object-store access, and protocol compatibility.
3. Deploy the Worker with a private origin target and storage-work endpoint.
   Probe internal authorization and verify it rejects direct unauthenticated
   access, stale deployment identities, and incompatible protocol versions.
4. Republish or restore required immutable objects, verify indexed generations
   and public read-back, then switch the public hostname to the Worker.
5. Exercise parallel upload, indexing, authenticated pages, downloads, and
   failure handling at staging load before treating hybrid as production-ready.

The production requirements in
[RFC-0017](../0017-canonical-hub-publishing/README.md) and the
[Hub backup runbook](../../maintainers/aos-hub-backup-recovery.md) still govern
production trust and recoverability. A staging reset does not authorize
discarding a nonempty production Hub. The operator must have a separately
tested recovery route before putting irreplaceable state on a new topology.

## Portable whole-Hub snapshot and restore

A portable snapshot is desirable but is a **later phase of this RFC**, not a
prerequisite for the first staging hybrid deployment. Provider-native SQLite
PITR or PostgreSQL backups remain useful for in-place recovery; neither alone
is a topology-independent Hub export. The current
[`export_org`](../../../crates/aos-hub/src/export.rs) covers an organization
and copyable registry surfaces, not a complete Hub instance.

The intended operator interface is a versioned `aos-hub snapshot export`,
`verify`, and `import` command family. An administrator UI may later guide an
operator through the same planned operation and display progress and receipts.
The browser must not relay the database or object bytes. The command path is
the authoritative, scriptable workflow; the UI presents it rather than defining
a second restore protocol.

An export contains a consistent logical database image, a closed inventory of
every referenced immutable or mutable object, schema and format versions,
database generation, binding and placement identities, content digests, and a
manifest that ties the pieces to one quiescent point. It includes the state
needed to preserve users, IAM, topology, publication generations, retention
roots, audit evidence, and trust metadata. It excludes live authentication
sessions, disposable projections, cached parse results and queue delivery state;
those are invalidated or reconstructed after import. Native orchestration leases
may be invalidated only while retaining durable operation/claim identities,
frozen inputs and replay evidence. This never retires an external pending effect,
issuer cutoff or guard receipt. Provider credentials and
private signing material travel only through separately controlled secret
backup and rebinding, never inside a general-purpose export archive.

Mutation guards and physical storage admission are durable external authorities,
not disposable projections. A database snapshot retains their permanent
identities and reviewed desired revisions, but cannot replace the live remote
watermark, pending-effect fences or terminal receipts. Reusing physical storage
preserves that ledger and requires reconciliation before accepting writes;
copying into a fresh namespace requires a separately reviewed authority. See
[physical storage authority](03-object-compute-and-lifecycle.md#external-physical-storage-authority).

The first portable move may require stopping writes and draining or recording
pending jobs. Export verifies that every database reference has its required
object, copies object bytes through a storage-to-storage path when available,
and signs or otherwise authenticates the complete manifest. Import validates
the format and hashes before installing authority, rebinds storage locations
and external secrets, reconciles inventory, rebuilds derived indexes where
necessary, and performs isolated read-back before opening traffic. A move that
preserves the Hub identity fences the old deployment before the target serves
writes. A clone with a new identity and changed trust roots is a separate,
explicit operation.

The same logical format must eventually support Native SQLite, Worker HubDb
SQLite, and Native PostgreSQL. It is not a raw SQL dump translated between
dialects. The first implementation can use an offline CLI and manual object
copy; a resumable UI wizard and online snapshot coordination are optional
improvements once the format and restore checks are established.

Native SQLite input opens an existing file read-only without invoking the Hub's
migrating initializer or changing journal mode. One read transaction spans
lineage validation, exact compiled-schema comparison and every bounded row
page. Unknown or incomplete schema rejects; integers, bytes, text, finite reals
and null retain their original value classes. Cell and page limits are checked
before variable payloads are loaded. Normal SQLite WAL lock coordination is
allowed; the reader does not write database or WAL contents. This database
input contract alone does not classify secrets, close object references or
authorize a restored deployment.

### Direct runtime qualification and Native guard configuration

Hybrid direct uploads require an independently reviewed acceptance artifact in
addition to the ordinary logical ingress and storage-work configuration. Native
uses `HUB_DIRECT_UPLOAD_ACCEPTANCE_FILE` for the bounded version-one acceptance
set, `HUB_DIRECT_UPLOAD_REVIEW_KEYS_FILE` for a separate operator-selected map of
reviewer identities to hexadecimal Ed25519 public keys, and
`HUB_DIRECT_UPLOAD_GUARD_KEY_FILE` for the protected readback authentication key.
Configure all three together. Leaving them absent preserves the ordinary Native
and Worker configurations. The guard key differs from the broker's
`HUB_STORAGE_WORK_KEY`; it does not confer provider credentials on Native.

The acceptance file is the shared closed `DirectWorkerQualificationArtifact`,
including its exact deployment/executor coordinates, source and hosted script
identities, reviewer identity, bounded clock/runtime/queue/provider measurements,
full protected profiles, validity interval, canonical evidence commitment and
Ed25519 signature. Native resolves `reviewerKeyId` against its independently
configured review key map and invokes the shared artifact verifier. The Worker
checks the same artifact against separately installed reviewer trust and the
actual running source/script identity. The shared domain-separated
`signing_bytes()` encoder defines the signature contract; independently reviewed
artifact publication does not redeploy the measured Worker version. A file
cannot introduce a review key. No provider credentials or private signing seeds
belong in the artifact.

An operator first collects actual ordinary-SDK upload/checksum, private-stage
policy, independent durable guard, clock, cancellation/settlement, and bounded
runtime/concurrency evidence from the exact provider/runtime being deployed.
An independent reviewer accepts those measured limits and the complete
protected profile, including credential revisions and executor coordinates.
Native then obtains fresh authenticated Worker discovery and requires exact
profile equality before admitting new effects. Changing credentials, origin,
private policy or runtime ceilings requires another acceptance. Discovery is
shared only within one original invocation; each use rechecks current acceptance
and invocation expiry. It is never a mutation permission or a persisted cache.

Hosted managed acceptance requires an actual Managed R2 profile.
`emulated_external` accepts only an
External profile whose provider closure contract starts with `emulated-` and
whose read/write DNS aliases are `localhost`, end in `.localhost`, or end in
`.test`. That class can qualify a separately measured emulator deployment; it
cannot qualify Managed R2 or a production provider endpoint. Hosted external acceptance cannot relabel an `emulated-` contract as production evidence. Configured fixture
names, certificates, synthetic timing bounds or SDK package availability are
not measured qualification. Hosted R2 acceptance remains a separate explicit
input until genuine live evidence is reviewed.

Before logical visibility, Native independently challenges the physical stage,
original baseline reservation/current witness, and final guard journal using
the guard key. Final readback binds the immutable original admission, exact full
selected Complete, original destination reservation, independently verified
source hash/size/incarnation, and exact final key/incarnation/ETag. A broker MAC,
configured profile digest, stage visibility or old HEAD cannot replace that
fresh terminal readback. Live target IAM and placement fences execute atomically
with target accounting and the retained session receipt.

Discovery advertises `minimumObjectBytes: 1` whenever any required placement is
external. Native refuses an empty object before retaining an admission, preparing
a publication pointer, or reserving cache/OCI accounting. External empty-object
deletion has no independently qualified exact-incarnation settlement receipt.
Managed-only plans advertise zero and retain their qualified SDK deletion path.
The complete physical plan is pinned across publication preparation; a changed
plan requires fresh admission rather than substituting storage after the check.

Acceptance expiry stops new effects. It neither proves outstanding delegated
URLs or multipart sessions have settled nor releases pending, unknown-effect,
cleanup or guard journals. Exact terminal replay preserves its original receipt
and requires current actor/target IAM without issuing provider readiness probes.
