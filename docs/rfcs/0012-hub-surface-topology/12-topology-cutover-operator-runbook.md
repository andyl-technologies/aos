# Topology cutover operator runbook

This runbook is the normative production procedure for the one-shot RFC-0012
topology cutover. It is a maintenance-mode replacement, not an expand/contract
migration. The transformer may read legacy state only inside the maintenance
operation. The target runtime has one topology model, one API, and no legacy
parser, route, schema, flag, alias, or dual-read branch.

The signed plan and report conform to:

- [`hub-topology-cutover-plan-v1.schema.json`](hub-topology-cutover-plan-v1.schema.json); and
- [`hub-topology-cutover-report-v1.schema.json`](hub-topology-cutover-report-v1.schema.json); and
- [`hub-topology-cutover-digest-verification-v1.schema.json`](hub-topology-cutover-digest-verification-v1.schema.json).

Production tooling must run `aos hub topology cutover verify` over the closed
bundle before it is allowed to close write admission. The trusted root public
key, its SHA-256 fingerprint, and the running verifier executable are
out-of-band inputs. The root first authenticates the external bundle-manifest
envelope, then the root-signed signer-key map authorizes one plan/report
authority and a cryptographically distinct verification authority. The
verification payload binds the authenticated plan and report payload and raw
signature digests, and its validated `authored_at` is after report completion.
Only authenticated bundle bytes may define a
schema, ruleset, fixture, evidence node, or document relationship. The
manifest's single `verifier` entry must be byte-for-byte identical to the
running executable; the verifier reports the SHA-256 of those bytes.

## Safety invariants

The operator aborts before the switch if any invariant cannot be proved:

1. Every source resource and immutable generation has exactly one final stable
   identity and owner scope. The plan contains the complete source and target
   identity sets, their ordered mapping, and zero missing, duplicate, or
   unplanned members; a digest-only sample is not a totality proof.
2. Every organization, project, surface, binding provider identity, binding
   capability observation, purpose credential generation, binding write
   revision, consumer grant/default, placement, write authority, placement
   policy/equivalence generation, delivery endpoint, domain, network boundary,
   gateway, route, registry-cache publication/population/retention relation,
   and inventory generation has an unambiguous final record.
3. Target permissions are a subset of source permissions for every principal
   and scope. A route is equally or more restrictive after transformation.
4. No credential value, signing key, password, session, bearer token, cookie,
   connection string, presigned URL, or secret-bearing URI enters a plan,
   report, log, or evidence bundle. Only stable credential references, versions,
   and metadata digests are permitted.
5. Writes remain quiesced across every declared database, Durable Object,
   object store, queue, alarm, cron trigger, and direct-write credential from
   the consistency point used by the backups until either rollback completes
   or all post-switch gates pass. Opening target writes is the irreversible
   rollback boundary: after the first target write, restoration of the old
   deployment is forbidden unless an independently reviewed forward-recovery
   plan accounts for those writes.
6. Destructive cache GC is disabled before maintenance and remains disabled at
   the switch. It is enabled only through the final first-sweep plan and
   acknowledgement workflow after fresh retention roots and complete,
   deletion-safe multi-placement inventory exist.
7. The old and new runtimes never write the database concurrently.
8. Before the rollback boundary, failure restores every verified backup and the
   old deployment as one rollback. The new runtime never reads legacy state
   after the switch. A report cannot say `succeeded` if any planned check,
   smoke, backup, mapping, or resource is missing, unplanned, failed, or not run.

## Artifact rules

Plans, reports, verification payloads, and the signer-key map use the closed
`aos-cutover-jcs-ascii-v1` dialect: RFC 8785 JSON Canonicalization Scheme over
integer-only UTF-8 I-JSON with ASCII-only object member names. ASCII member
names therefore have identical UTF-8 byte and RFC 8785 UTF-16 sort order; the
parser rejects duplicate members and the canonicalizer rejects any non-ASCII
member name instead of silently defining a second ordering. They are complete
unsigned payloads: none contains a self-hash or its own signature identity, and
every signature envelope has `omitted_json_pointers: []`. The detached Ed25519
signature signs a domain-separated SHA-256 of the complete canonical payload.
The final root-signed manifest is outside the directory it authenticates and
lists every regular file in that directory by node ID, relative path, media
type, role, exact size, and SHA-256. Every bundle, source, recipe, trust, and key
file must have link count one, and no file identity may occur twice within or
across those inputs. Undeclared files, absent files, duplicate paths or nodes,
hard links, symlinks, special files, and graph edges to undeclared nodes fail
closed. Bundle and source roots and every descendant directory and present file
are opened without following links and retained by descriptor for the complete
command. Reads use retained file descriptors and publications use retained
parent descriptors; a final namespace and identity check rejects replacement
after admission.

Every named reference is typed against that entry's exact kind, role, and
media type. In particular, each backup destination must match its plan
`expected_media_type`: D1 export nodes use `application/sql`, and Durable
Object logical-export nodes use `application/vnd.aos.do-export+json`.
Evidence, source-export, transformer/verifier, interface-manifest, ruleset,
fixture-manifest, metaschema, schema, and document references likewise use
their declared exact triples; mere node-ID membership is insufficient.
One classifier map is normative for both generation and verification. It also
covers every structural reference: document payload and signature-envelope
nodes, trust key-map payload and envelope nodes, signer public-key nodes, and
each envelope's document-specific raw-signature node. No secondary lookup may
weaken these triples to node membership or media-type-only validation.

Validated schema and document nodes have exact, non-interchangeable roles:

| Node ID | Required role |
| --- | --- |
| `schema/bundle` | `bundle_schema` |
| `schema/bundle-generation` | `bundle_generation_schema` |
| `schema/fixtures` | `fixture_schema` |
| `schema/plan` | `plan_schema` |
| `schema/report` | `report_schema` |
| `schema/signature-envelope` | `signature_envelope_schema` |
| `schema/signer-key-map` | `signer_key_map_schema` |
| `schema/verification` | `verification_schema` |
| `document/plan` | `plan_payload` |
| `document/report` | `report_payload` |
| `document/verification` | `verification_payload` |

All entries in this table use `application/json`; schema entries have kind
`schema`, and document entries have kind `document`.

Before canonicalization, arrays are sorted by these keys:

| Arrays | Sort key |
| --- | --- |
| `source.databases`, plan/report `backup`, `rollback.database_restores`, `database_restore_validation.proofs`, `durable_object_aggregates` | `stable_id` or `database_stable_id` |
| source resource nodes | `(resource_kind, node_id)` |
| `scope.resource_stable_ids` | `(kind, stable_id)` |
| mapping edges | `(target_resource_kind, target_stable_id)` |
| `transform.stable_id_rules` | `resource_kind` |
| `instances`, `organizations`, `projects`, `surfaces`, `bindings`, `binding_capability_observations`, `credential_generations`, `binding_write_revisions`, `binding_grants`, `storage_defaults`, `placements`, `write_authorities`, `delivery_endpoints`, `domains`, `network_boundaries`, `gateways`, `routes`, `route_configurations`, `placement_policies`, `equivalence_sets`, `registry_publications`, `publication_bindings`, `population_targets`, `placement_manifests` | `stable_id` |
| retention subscriptions | `(cache_stable_id, registry_stable_id, stable_id)` |
| inventories | `(cache_stable_id, generation)` |
| inventory `placement_manifests` references | `(placement_stable_id, manifest_stable_id)` |
| credential references | `(purpose, stable_id, version)` |
| source principals and scopes, permissions, route backend placement IDs, GC check-ID partitions, rollback backup/database IDs, validated schema/document node IDs | bytewise string value |
| expected principal/scope pairs | `(principal_stable_id, scope_stable_id)` |
| principal proofs | `(scope_stable_id, principal_stable_id)` |
| route proofs | `route_stable_id` |
| required/reported checks, GC enablement checks | `check_id` |
| plan/report smoke tests | `test_id` |
| count and digest invariants | `name` |
| maintenance targets | `(kind, stable_id)` |
| attempts | `ordinal` |
| attempt transition ledger | `sequence` |
| blockers | `blocker_id` |
| Durable Object `object_manifests` | bytewise JCS value of the complete object |
| verification source cardinalities | `source_node_id` |
| verification reference categories | `category` |
| fixture cases | `case_id` |
| mutations within one fixture case | declared execution order; order is semantic and must not be sorted |
| signer keys | `key_id` |
| signer roles | bytewise role name |
| generation layout and bundle entries | `node_id` |
| generation and bundle edges | `(from_node_id, relation, to_node_id)` |

The sort-key table is exhaustive: an artifact schema revision may not add an
array without adding its deterministic sort key. Object members always use
RFC 8785 ordering; sorting an array never substitutes for validating duplicate
keys or semantic ordinals.

Every digest input is encoded as
`SHA-256(UTF8(domain) || 0x00 || preimage)`. Document preimages are the complete
integer-only JCS payload. Set preimages are a JCS array after sorting each item
by its own JCS bytes, under domain `aos.hub.topology-cutover.set/v1`. The
Durable Object aggregate preimage is JCS of
`{database_stable_id,object_manifests,recomputed_object_count,recomputed_row_count}`
under `aos.hub.topology-cutover.do-aggregate/v1`; `object_manifests` is ordered
by the bytewise JCS value of each complete object, exactly like every set
preimage.

Fixture source marker `derive:sha256:<label>` means exactly
`SHA-256("aos.hub.topology-cutover.fixture-value/v1" || 0x00 || UTF8(label))`.
Marker `derive:domain-sha256:<domain-b64url>:<preimage-b64url>` decodes
canonical unpadded base64url components and applies the general digest rule
above. Generation rejects padding, noncanonical encodings, malformed UTF-8
domains, and any marker that survives materialization.
The authenticated bundle graph records every input artifact and validator
output; no node reference may cite an entry absent from that graph.

Duplicate sort keys are invalid even when JSON Schema `uniqueItems` would regard
the complete objects as different. Timestamps are validated UTC instants with
a trailing `Z`; chronology compares parsed calendar components and fractional
seconds after zero-padding to equal precision, never raw strings.
Integers remain within the I-JSON exact integer range. Evidence contains typed
counts, digests, status codes, and stable identifiers rather than raw response
bodies or database values.

Run a recursive secret scanner before signing. It rejects property names equal
to `secret`, `password`, `passwd`, `token`, `cookie`, `authorization`,
`private_key`, `client_secret`, `access_key`, or `session`, case-insensitively.
It rejects string values matching PEM headers, bearer credentials, assignments
to those sensitive names, common cloud-key formats, URI userinfo, or query
parameters used for signatures. A match is a blocker; redaction after signing
is not permitted.

Every URI in an artifact is an origin or path-only HTTPS URI. URI userinfo,
queries, fragments, percent-encoded `@`, and percent-encoded `?` are forbidden
regardless of parameter name. Connection strings and presigned URLs are never
artifacts. The secret scanner decodes percent escapes before applying this
rule and recursively scans both property names and string values.

## Executable semantic validation contract

The pinned semantic validator fails the artifact unless all of these checks
hold. These rules are part of schema version v1 even where JSON Schema cannot
compare two arrays or two property values:

1. `scope.resource_stable_ids`, `topology.mapping_edges`, and every typed
   topology array are duplicate-free, canonically ordered, and form the same
   total target set. Every edge names one enumerated source node, exact target
   kind and stable ID, owner scope, ordinal, and derivation rule. Each source
   node's declared outgoing cardinality and contiguous ordinals recompute
   exactly; at least one source proves the supported one-to-many case.
2. Every reference resolves to a member of the typed target set and every
   immutable generation referenced by an authority, policy, equivalence,
   binding, route, retention relation, or inventory is explicitly present.
3. Principal proofs cover the complete Cartesian set of effective source
   principals and authorization scopes. Route proofs cover every route. Both
   sets are non-empty, their coverage counts/digests recompute, target
   permissions are subsets of source permissions, and route policies are equal
   or narrower under the pinned partial order below.

   The closed route-policy value has exactly one field, `access_policy`, whose
   value is `public`, `hub_authenticated`, `origin_authenticated`, or
   `private_network`. `public` is the sole least-restrictive value and may
   narrow to any of the other three. Each non-public value is comparable only
   with itself: Hub identity, origin credentials, and network membership are
   independent authorities and no transition between them is inferred to be
   narrower. Every proof commits the complete canonical source and target
   policy configurations by SHA-256; the target digest must equal the selected
   route configuration. An incomparable transition blocks cutover.
4. `source.databases` and `backup` have the same non-empty database-ID set.
   D1 plus each declared Durable Object namespace are separate members with
   separate backups and isolated restore evidence. For Durable Objects, the
   external verifier records the exact ordered object identities, schema
   revisions, row counts, logical digests, object-set digest, aggregate manifest
   digest, aggregate row count, and object count in the signed verification
   payload.
   The report must match that externally computed identity exactly; equality
   between two report assertions is not proof of an aggregate.
5. The report's planned and observed resource, check, smoke, database, and
   backup set digests equal the signed plan. A successful report has zero
   missing, unplanned, failed, or not-run members; every check and smoke result
   is `pass`; every blocker is resolved; and every backup restore passed.
6. `succeeded` requires target writes to open exactly once after all gates and
   closes rollback unused. `rolled_back` requires target writes to remain zero,
   all databases and the old deployment to be restored and verified, and old
   writes to reopen only after restore verification. `failed_closed` requires a
   typed failure stage/code, closed writes, and no claim of successful switch.
7. GC remains disabled at switch. Inventory or retention may be `blocked` in a
   successful topology cutover only when `gc_gate.readiness` is `blocked` and
   the corresponding post-cutover required checks remain outstanding. GC
   readiness may be `ready` only with complete inventory, fresh retention, and
   an absent first-sweep acknowledgement; GC is still disabled until a later
   reviewed acknowledgement applies.
8. The legacy absence proof covers source files, generated code, linked symbols,
   build features, database tables/views/triggers, HTTP/RPC routes, CLI aliases,
   environment flags, configuration keys, migrations, Worker bindings, and
   deployed route manifests. Every category reports zero matches.
9. `source.resource_nodes` is the independently enumerated source graph. Its
   `(source_resource_key, resource_kind, source_locator_digest)` set equals the
   mapping-edge source set exactly, and every node's declared outgoing
   cardinality equals the number of mapping edges actually leaving it. Counts
   or digests copied from the transform are not accepted as enumeration proof.
10. Every authority and serving reference resolves at its exact immutable
    generation. A write authority's desired and observed placements belong to
    its surface and binding; its active write revision belongs to that same
    binding and generation. Route placements belong to the route surface,
    credential references match purpose/version/metadata digest, registry
    publications reference registries, inventories reference caches, and every
    route pins one configuration generation whose policy and digest match the
    route and route proof.
11. Every delivery smoke result carries the exact route, placement, and binding
    stable IDs exercised. Each route-backend placement has a successful smoke;
    public routes have anonymous success, while each non-public route has both
    anonymous denial and authorized success. API and CLI control-plane smokes
    carry null route, placement, and binding IDs.
12. A report is one immutable attempt in the plan's namespace. Ordinals are
    bounded, retries name a predecessor, discarded attempts carry a discard
    timestamp, and the idempotency digest equals the plan derivation. The signed
    transition ledger is continuous, chronological, and outcome-specific:
    success opens target writes exactly once after validation; rollback never
    opens them and terminates `rolled_back`; switch failure never opens them and
    terminates `failed_closed`. Admitted target-write count remains zero across
    rollback-capable outcomes.
13. Every source database has exactly one typed backup result and one typed
    rollback result that pins the same database kind, artifact ID, artifact
    hash, and source logical digest. `not_run` is truthful only when rollback is
    unused or not required; an executed rollback records restored digest, row
    count, and evidence for every database.
14. Plan and report blockers have the same stable-ID set and all report blockers
    are resolved with evidence. GC checks are partitioned into cutover and
    post-cutover sets: every cutover check passes in the report, and the
    outstanding set equals the declared post-cutover set. Each outstanding
    check is present exactly once as `not_run`, never in the cutover-pass set.
15. The root-authenticated bundle graph contains every payload, schema,
    interface and fixture manifest, public signer key, signature envelope, raw
    signature, verifier executable, transformer, source export, backup,
    evidence node, and ruleset. The root key and running executable remain
    outside that graph as the trust base; the bundle cannot authorize either.

The repository checks in source fixtures, not precomputed signed outputs.
`derive:sha256:<label>` values are deterministically materialized before schema
validation and signing; bundle-byte and running-executable markers are resolved
from the actual bytes. The fixture manifest currently contains 77 cases. The
verification sidecar's case, passed, and failed counts are recomputed from
those actual case results and must equal `77`, `77`, and `0`; declared counts
are not trusted. The matrix
covers success, rollback,
failed-closed, native zero-Durable-Object operation, schema closure, mapping
cardinality and target typing, references, exact restore proofs, recomputable
Durable Object aggregates, evidence, blockers, retries, idempotency,
transitions, GC partitions, post-sign tampering, bundle closure, signer-role
widening, and verifier byte mismatch.

## 1. Build and approve the plan online

The preflight is read-only and runs against the still-serving old deployment.

1. Pin the exact source deployment revision, source schema revision, target
   deployment revision, target schema revision, API manifest, CLI schema, and
   native/Worker/Web route manifests.
2. Export a canonical, secret-free logical topology snapshot. Resolve
   credentials to `{stable_id, purpose, version, metadata_digest}` references;
   never export the sealed or plaintext value.
3. Enumerate every resource and immutable generation named in safety invariant
   2. Record binding provider identity separately from capabilities, credentials,
   write revisions, grants, and defaults; record placement membership separately
   from write authority; and record publication, population, and retention as
   independent registry-cache relationships.
4. Derive stable IDs. Prove the total deterministic mapping between source and
   final resource sets, including declared one-to-many expansions. Recompute
   ordered source/target counts and digests. Collisions, omissions, extra target
   rows, inferred ownership, reused slugs with different owners, and orphaned
   rows are blockers.
5. Resolve each legacy binding-plus-prefix into explicit binding and placement
   records. Multiple placements are preserved; they are not collapsed into a
   preferred placement. Conflicting writer evidence is a blocker.
6. Resolve every effective HTTP path into an explicit final route, frontend
   kind, access policy, domain, and ordered placement set. Record direct,
   static-CDN, Hub binary, and Worker paths independently so they can operate
   simultaneously. A URL with no final mapping is a blocker.
7. Transform each registry/cache retention input into an independent retention
   subscription with an exact selector digest, registry source revision,
   removal grace, and expected root count. Publication and population are not
   inferred from retention.
8. Capture one complete inventory generation per cache and a manifest for every
   applicable placement. Every object selected for destructive deletion later
   requires a strong backend identity. Incomplete or weak inventory blocks the
   cutover's GC readiness, although the topology switch may proceed with GC
   disabled when the plan declares the blocker and its post-switch resolution.
9. Compute non-vacuous authorization proofs. For every effective
   `(principal, scope)`, verify
   `target_permissions` is a subset of `source_permissions`. For routes, use the
   approved access-policy partial order; incomparable policies require explicit
   security review and otherwise block.
10. Produce the typed side-by-side transform artifact. It declares its source
    and target schema revisions, input and expected-output digests, stable-ID
    rules, collision policy `abort`, and no legacy write path.
11. Generate plan checks and smoke tests in two orthogonal groups. Delivery
    tests for Git, Nix cache, and Web are bound to real route, placement, and
    binding IDs and collectively cover every route, frontend kind, backend
    placement, and backend binding kind in the plan.
    Every public route has an anonymous success; every non-public route has an
    anonymous denial and an authorized success. Control-plane API and CLI tests
    use no delivery route and separately prove denied anonymous API access and
    successful least-privileged CLI access. The full matrix also covers
    retention freshness, inventory completeness, route parity, and
    legacy-route absence.
12. Canonicalize, digest, scan, and sign the plan and transformer. An operator
    who did not generate the plan verifies both signatures and all open blockers.

The online phase must not mutate schema, routes, credentials, placement state,
retention heads, or inventory heads. Any source digest change after plan
creation invalidates the plan.

## 2. Enter maintenance and prove quiescence

1. Disable scheduled and operator-triggered destructive GC.
2. Close every write-admission path in every process and database:
   Web/API/CLI mutations, Git publication,
   cache PUT, presigned PUT issuance, multipart initiation/completion,
   population, replication, repair, retention refresh, background reconciliation,
   and queue/cron consumers that can write topology or storage.
3. Revoke or wait out every previously issued direct-write capability. Abort
   multipart uploads or retain their durable mutation fences. A request count of
   zero is insufficient while an unexpired write capability exists.
4. Wait for database transactions, D1 bookmarks, Durable Object events and
   alarms, queues, and object
   mutation fences to reach a terminal state. Record zero in-flight writes and
   mutations with signed evidence.
5. Re-export the logical source snapshot. Its digest must equal the approved
   plan input and source topology digests. Otherwise leave maintenance, rebuild
   the plan, and repeat approval.

The old runtime remains available for read-only traffic only if the backend can
prove reads do not cause writes. Otherwise stop it before backup.

## 3. Take and verify the backup

Every database in `source.databases` has one corresponding backup plan and
evidence record. The backup set is usable only after isolated restores produce
the same schema
digest, logical-data digest, and row count as the quiesced source. Merely creating
or listing an export is not verification.

### SQLite

Checkpoint WAL with a completed truncate checkpoint when WAL is enabled. Use
SQLite's online-backup API or `.backup` while writes remain closed; do not copy a
live database file independently of its WAL. Record page count and
`PRAGMA integrity_check = ok`, hash the backup, restore it to a new path, repeat
integrity checking, and compare canonical schema/data digests and counts.

### Cloudflare D1

Create a D1 export after write admission and all Worker/queue writers are
closed. Record the export bookmark or consistency identifier and export digest.
Import into a separate temporary D1 database, run the complete schema and
referential checks there, and compare canonical logical digests and counts.
Production is not the restore-test target.

### Durable Object SQLite

There is no assumed file-level snapshot across Durable Objects. Close routing,
alarms, queues, and mutation issuance, advance and record a quiesce epoch, then
invoke the versioned application-level logical export on every object in the
declared namespace. The export includes object stable ID, schema revision,
row-count/digest manifest, and no secrets. Replay into an isolated namespace,
verify every object manifest and the aggregate digest, and prove the expected
object count. A missing or newly discovered object blocks cutover.

### PostgreSQL

With application writes closed, capture a consistent snapshot and WAL LSN and
produce a custom-format `pg_dump`. Record a digest of the snapshot identifier,
not its raw value. Verify `pg_restore --list`, restore into an isolated database,
run constraints and schema checks, and compare canonical logical digests and
counts. Replication lag must be zero if the switch changes database endpoints.

### MySQL

With application writes closed, take a single-transaction consistent dump with
stored objects required by the schema and record digests of the GTID set and
binlog coordinate. Restore into an isolated database, run constraints and
schema checks, and compare canonical logical digests and counts. Do not use a
nontransactional dump when any source table lacks transactional snapshot
semantics; that condition is a blocker.

For every backend, sign the backup digest and restore-verification evidence,
place them in immutable retention at least through the rollback deadline, and
confirm the old deployment artifact is independently available and signed.
Then compute and sign the ordered aggregate backup-set digest. A successful D1
backup without every declared Durable Object namespace backup is impossible.

## 4. Perform the side-by-side transform

1. Verify the transformer's digest and signature again from the maintenance
   environment.
2. Create target tables or an isolated target namespace without changing the
   old runtime's read targets. The namespace is not a compatibility schema and
   is never queried by the old runtime.
3. Run the transformer exactly once against the quiesced source snapshot. It
   reads legacy rows and writes only target rows. It records zero legacy writes,
   exact input/output digests, mapping digest, source/target counts, and rejected
   rows.
4. Abort on any rejected row, stable-ID collision, ambiguous binding, ambiguous
   writer, missing credential reference, unmapped URL, authorization widening,
   stale retention source, incomplete required inventory, or digest mismatch.
5. Re-run in verification mode from the same input. The canonical output digest
   must be identical. The verification run does not write production state.

The transform artifact is a deployment tool, not a runtime library. No parser
or data type that understands the legacy shape may be linked into the final
Hub binary, Worker, CLI, or Web application.

## 5. Validate target state

Validation is read-only and produces typed, signed evidence:

- all schema constraints and foreign keys pass;
- stable-ID mapping is collision-free and total;
- binding owner/grant and credential-purpose references resolve;
- every placement belongs to the intended surface and binding, and write
  authority is singular and observed rather than inferred;
- route/domain/backend relationships resolve, canonical routes are singular by
  surface/audience, and all planned HTTP paths retain their intended status,
  range, cache, and authentication behavior;
- principal and route authorization proofs contain zero widening;
- retention selectors reproduce expected current catalog, channel, explicit
  tag, SemVer, and recent-release roots from the pinned registry source;
- shared-cache roots retain registry provenance without exposing it to an
  unauthorized reader;
- inventory placement set, object counts, manifest digests, strong-identity
  counts, and aggregate generation digest match the plan;
- all background writers remain stopped and destructive GC remains disabled;
  and
- native and Worker route/API manifests equal the approved target manifests and
  contain no removed method or path.

Expected/actual resource counts must match unless the plan declares a typed
one-to-many expansion, such as one legacy binding/prefix relation becoming a
binding plus placement. Every such expansion has its own digest invariant.

## 6. Run pre-switch smoke tests

Start the target runtime against the target namespace on an isolated listener
with write admission closed. Run the plan's deterministic smoke matrix:

- Web navigation and default settings routes;
- CLI list/get and JSON-schema conformance;
- API list/get, cursor pagination, and authorization denial;
- Git smart/dumb HTTP discovery as configured;
- Nix cache info, narinfo, NAR HEAD/GET, range, ETag, and cache behavior;
- Hub proxy, Worker proxy, direct-origin, static-CDN, and private-network paths;
- public anonymous success and private anonymous denial;
- credential-reference resolution without emitting credential material; and
- removed Web, CLI, and API paths returning absence rather than redirects or
  compatibility responses.

Record only method class, path digest, route stable ID, auth context, status,
response digest, and evidence artifact. Do not record authorization headers,
cookies, response bodies, presigned URLs, or private origin addresses.

Any failed smoke test aborts the switch.

## 7. Switch once

1. Confirm the backup restore test, target validation, and all smoke tests still
   pass; blockers are resolved; write admission and destructive GC are closed.
2. Stop the old runtime and prove it cannot restart or consume queues.
3. Atomically select the target schema/namespace and target deployment. There is
   no request-by-request feature flag and no fallback read to legacy tables.
4. Start native and Worker runtimes at the exact signed target revision.
5. Switch traffic once, then run the smoke matrix through production routes.
6. Keep general writes closed until production smoke, queue ownership, route
   observations, retention freshness, and inventory gates pass.
7. Open ordinary writes. Keep destructive GC disabled.

If the switch mechanism cannot make old-writer shutdown precede new-writer
startup, it is not acceptable for this cutover.

## 8. Close or execute rollback

Rollback remains possible only while new-runtime writes are zero. During that
window, failure means:

1. close traffic and verify both runtimes have zero writers;
2. stop the new deployment;
3. discard the target database/namespace rather than translating it backward;
4. restore the verified pre-cutover backup into a clean source database;
5. restore the exact signed old deployment and its route/queue ownership;
6. validate source schema/data digests and run the old-runtime smoke matrix;
7. reopen traffic and writes only after those checks pass; and
8. record `rolled_back` with signed restore evidence.

After any new-runtime write is admitted, database rollback is closed. Recovery
then uses the new model's ordinary backup/restore procedures; the legacy runtime
must not be reintroduced. A successful cutover report is finalized only after
this closure is explicit as `closed_unused` and the old deployment/backup
retention decision is recorded.

## 9. Enable GC separately

Topology cutover success does not enable destructive GC. For every cache:

1. complete a fresh registry-root refresh pinned to the current retention-source
   generation;
2. complete a cache-wide physical inventory across every applicable placement,
   with strong deletion identities or an explicitly blocked backend;
3. resolve all coverage failures and active object-mutation fences;
4. create and review the immutable first-sweep GC plan;
5. apply the separate first-sweep acknowledgement; and
6. enable GC only through its normal plan/apply API.

The cutover report records GC as disabled. Later GC enablement belongs to its
own signed operation and audit record.

## 10. Prove final legacy removal

Before merging or deploying final HEAD, a repository guard scans executable
source, generated code, schemas, route manifests, CLI parsers/help/completions,
Worker bindings, migrations, fixtures, and runtime feature declarations. It
must report zero:

- legacy topology parsers or model types;
- legacy database reads/writes or schema objects;
- old API package/service routes;
- old CLI command variants, flags, JSON keys, or aliases;
- old Web routes, redirects, form actions, or overloaded handlers;
- compatibility feature flags, environment variables, or fallback branches;
  and
- runtime references to the one-shot transformer.

Historical RFC prose and the immutable signed cutover bundle may name removed
concepts, but are never compiled, routed, or loaded at runtime. The guard emits
the scanned final HEAD revision, rule-set digest, zero match counts, and signed
evidence. Any allowlist entry outside those two non-runtime locations is a
cutover blocker.

## Validation and bundle generation

The checked
`hub-topology-cutover-bundle-generation-v1.fixture.json` is the complete
fixture layout and graph. Assemble an immutable source directory containing the
fixture-source payloads and generation schemas. Separately assemble a fresh
bundle directory at the declared paths with the interface manifests, evidence
fixtures, contract schemas, and release public key. Invoke
`materialize-verifier` through the installed `aos` wrapper to install the exact
executable bytes at the recipe's declared verifier path. Generated documents,
envelopes, and signatures are absent until one generation transaction writes them.
Private keys and the
out-of-band root public key are never bundle entries.

Before the source tree is made immutable, the independent verification
authority runs the declared evidence and digest procedures and authors the
verification source payload after the report is complete. All three document
source payloads are final before generation. `generate` captures the complete
source and bundle descriptor graphs once, then creates the key map, plan,
report, verification, and final manifest in dependency order without releasing
that snapshot. This single transaction is the source-freeze receipt.

Generate the authenticated artifacts in dependency order:

1. Materialize the exact running verifier at the recipe-declared path.
2. Generate all authenticated artifacts and the external root-signed manifest
   in one descriptor-frozen transaction.
3. Invoke a fresh process of the exact bundled verifier against the closed
   directory and external envelope.

The materialization, generation, and verification interfaces below are exact.
The first command must be invoked through the installed `aos` wrapper: that
wrapper `exec`s the packaged unwrapped executable, so the materializer observes
and copies the same executable bytes that the eventual bundled process runs.

```sh
aos hub topology cutover materialize-verifier \
  --bundle /approved/cutover-bundle \
  --bundle-recipe /approved/bundle-generation.json

aos hub topology cutover generate \
  --bundle /approved/cutover-bundle \
  --bundle-source /approved/cutover-source \
  --bundle-recipe /approved/bundle-generation.json \
  --bundle-manifest-output /approved/cutover-bundle.manifest.json \
  --root-signing-key /operator/keys/release-root.pk8 \
  --document-signing-key /operator/keys/document-signer.pk8 \
  --verification-signing-key /operator/keys/verification-signer.pk8 \
  --trusted-root-public-key /operator/trust/release-root.pub \
  --root-signer-key-id key/root/example \
  --document-signer-key-id key/release/example \
  --verification-signer-key-id key/verification/example

/approved/cutover-bundle/bin/aos hub topology cutover verify \
  --bundle /approved/cutover-bundle \
  --bundle-manifest /approved/cutover-bundle.manifest.json \
  --trusted-root-public-key /operator/trust/release-root.pub \
  --trusted-root-sha256 "$AOS_CUTOVER_TRUST_ROOT_SHA256"
```

The root signs only the key map and bundle root. The document authority signs
plan and report; the distinct verification authority signs only verification.
All three verifying keys and signer IDs differ; paths or IDs alone do not
establish cryptographic separation.
The immutable source tree, recipe, three private signing keys, trusted root public key,
and fresh final manifest output all live outside the bundle. Generated payloads
are read from the source tree and written to fresh paths in the closed bundle.
Before its first write, generation proves that all 12 payload, raw-signature,
and envelope leaves are absent. Any preexisting generated leaf fails, even when
its bytes equal the candidate. A late `EEXIST` may leave a partial untrusted
bundle; that directory is never resumed or verified, and replay against it must
fail preflight. Operators assemble a fresh bundle directory instead. Bundle and
source stages use descriptor-relative, no-follow
access; publication uses a no-replace atomic link followed by parent-directory
synchronization. A preexisting final-manifest path always fails, including when
its bytes equal the candidate manifest, and an `EEXIST` race never counts as a
successful retry.
Generation canonicalizes and materializes source fixtures before signing.
Verification performs no network I/O and emits exactly one closed JSON result.
Any parse, custom-dialect schema, unsupported keyword, canonicalization,
bundle-closure, graph-reference, Ed25519, signer-role, fixture, semantic, or
running-executable identity failure exits nonzero. A success result reports
`signatures_verified: 5`: the root signature on the external manifest plus the
four detached signatures on the key map, plan, report, and verification
payloads. The count is derived from those completed verification stages.

For a fast developer diagnostic, validate JSON syntax and run the semantic
matrix from the repository root:

```sh
jq empty docs/rfcs/0012-hub-surface-topology/*.json

jq -n -L docs/rfcs/0012-hub-surface-topology \
  --slurpfile plan docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-plan-v1.fixture-source.json \
  --slurpfile report docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-report-v1.fixture-source.json \
  --slurpfile verification docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-digest-verification-v1.fixture-source.json \
  --slurpfile fixtures docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-fixtures-v1.json \
  --slurpfile recipe docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-bundle-generation-v1.fixture.json \
  -f docs/rfcs/0012-hub-surface-topology/run-topology-cutover-fixtures.jq
```

The JQ runner is diagnostic only. It evaluates semantic-stage mutations and
marks schema, signature, and bundle cases as delegated; only the authenticated
Rust verifier can evaluate those stages from actual bytes. CI must assemble,
sign, and verify the closed bundle, require every declared fixture case to match its
declared result and failure code, and rerun with a separately copied verifier
whose bytes differ to prove the out-of-band byte-identity gate.
