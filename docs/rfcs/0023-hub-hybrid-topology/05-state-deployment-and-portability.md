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
