# Hub topology cutover

This page specifies the signed evidence bundle for the one-shot,
maintenance-mode migration of a Hub deployment that predates the current
[topology](topology.md) model, and the `aos hub topology cutover` commands
that generate and verify it. The migration is a maintenance-mode replacement,
not an expand/contract migration. The transformer may read legacy state only
inside the maintenance operation. The target runtime has one topology model,
one API, and no legacy parser, route, schema, flag, alias, or dual-read branch.

What this repository implements:

- The offline bundle commands `aos hub topology cutover materialize-verifier`,
  `generate`, and `verify`, in
  `crates/cli/aos-cli/src/commands/hub_cutover_verify/`. They are described
  under [Validation and bundle generation](#validation-and-bundle-generation).
- The closed schemas, fixture sources, and web route ledger in
  `crates/cli/aos-cli/hub-topology-cutover/`, exercised by
  `crates/cli/aos-cli/tests/hub_topology_cutover.rs`.

What it does not implement: the transformer, and the backup, quiescence, and
switch steps of the migration. A bundle refers to the transformer only as an
authenticated node (`transformer_node_id` in the plan), and the fixture bundle
carries a placeholder for it. The safety invariants and validation rules below
state what a bundle's evidence must prove about those steps; they do not
describe migration code in this tree.

The identifiers on this page are the bundle's own closed vocabulary, defined
by the plan and report schemas, and some differ from the running Hub's names.
The bundle's database kinds are `sqlite`, `d1`, `durable_object_sqlite`,
`postgres`, and `mysql`, although the current Worker stores its database in a
Durable Object ([runtime.md](runtime.md#cloudflare-worker)). The bundle's
route `access_policy` values are `public`, `hub_authenticated`,
`origin_authenticated`, and `private_network`, whereas the runtime names its
route access policies `public`, `hub_auth`, `external_provider`, and
`private_network`.

The signed plan, report, and verification documents conform to the closed
`aos-cutover-schema/v1` schemas in
[`crates/cli/aos-cli/hub-topology-cutover/`](../../../crates/cli/aos-cli/hub-topology-cutover/):

- [`hub-topology-cutover-plan-v1.schema.json`](../../../crates/cli/aos-cli/hub-topology-cutover/hub-topology-cutover-plan-v1.schema.json);
- [`hub-topology-cutover-report-v1.schema.json`](../../../crates/cli/aos-cli/hub-topology-cutover/hub-topology-cutover-report-v1.schema.json); and
- [`hub-topology-cutover-digest-verification-v1.schema.json`](../../../crates/cli/aos-cli/hub-topology-cutover/hub-topology-cutover-digest-verification-v1.schema.json).

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
   policy/equivalence generation, endpoint, domain, network policy,
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
`aos-cutover-jcs-ascii-v1` dialect: RFC 8785 JSON Canonicalization Scheme
(JCS) over integer-only UTF-8 I-JSON with ASCII-only object member names.
ASCII member
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
| `instances`, `organizations`, `projects`, `surfaces`, `bindings`, `binding_capability_observations`, `credential_generations`, `binding_write_revisions`, `binding_grants`, `storage_defaults`, `placements`, `write_authorities`, `endpoints`, `domains`, `network_policies`, `gateways`, `routes`, `route_configurations`, `placement_policies`, `equivalence_sets`, `registry_publications`, `publication_bindings`, `population_targets`, `placement_manifests` | `stable_id` |
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

## Validation and bundle generation

The checked
`crates/cli/aos-cli/hub-topology-cutover/hub-topology-cutover-bundle-generation-v1.fixture.json`
is the complete fixture layout and graph; the packaged `aos` build and
`crates/cli/aos-cli/tests/hub_topology_cutover.rs` exercise it. Assemble an immutable source directory containing the
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

The integration test assembles, signs, and verifies the closed fixture bundle,
requires every declared fixture case to match its declared result and failure
code, and reruns with a separately copied verifier whose bytes differ to prove
the out-of-band byte-identity gate.
