# Storage work protocol

Hybrid mode gives the Native Hub one system of record and gives Workers the
object-store data plane. The Native Hub decides what work is authorized, which
physical placement to use, and what the result means. A Worker opens the
selected R2 or S3-compatible object, performs bounded storage-local work, and
returns a compact result or serves the bytes to their final consumer. This
boundary is a versioned protocol, not a second Hub database or an invitation to
run arbitrary code beside the bucket.

## Boundary and execution model

The public edge and storage executor may initially be one Worker deployment.
Their routes are nevertheless separate: public delivery requests go through
the edge router, while `/_internal/storage/v1/*` reaches an authenticated
storage executor before any Native proxy fallback. The endpoint is reachable
over HTTPS so the Native Hub can call it from GCP, but possession of the URL
does not authorize a request. A deployment may later run multiple storage
executor Workers with the same protocol and storage bindings. No executor
requires an affinity to a particular Native replica.

The Native Hub owns admission, authorization, quotas, the index generation,
anti-rollback floors, jobs, durable claims, and SQL commits. The executor owns
provider I/O, byte verification, parsing of supported storage formats, and
bounded filtering or aggregation. It cannot update Hub SQL. Each result names
the exact plan, operation, selected placement, physical object identity,
parser version, and bytes observed. Native accepts a result only for the
generation and placement it issued, then applies existing policy and commits
the result transactionally.

The protocol permits three kinds of output:

1. **Small semantic result:** selected fields, matches, counts, hashes, and
   proof metadata needed for an index or inventory decision. Result size is
   capped independently of the source object size.
2. **Bounded page:** an ordered page and opaque continuation token for a list
   or a large result set. Native explicitly asks for subsequent pages.
3. **Byte delivery:** a stream to an authorized client, another object store,
   or an explicitly selected destination. Native receives the final receipt,
   never the stream body in hybrid mode.

No operation may silently return a whole source object to Native when its
projection is too large or unsupported. It returns a typed limit or unsupported
error, allowing the caller to choose a narrower plan, split the work, or report
that the workflow needs implementation. This is the enforcement point for the
hybrid GCP egress budget.

## Native-issued work plans

`StorageWorkPlan` is a closed, versioned request body authenticated with a
short-lived Native service credential. A canonical encoding binds the signature
to the HTTP method, route, request body hash, audience, issuer, issue and expiry
times, nonce, and deployment identity. The Worker validates the caller and plan
before opening storage. Clock skew allowance and maximum lifetime are small;
neither a browser session nor a public API token may call these routes.

```text
StorageWorkPlan v1
  plan_id, operation_id, idempotency_key
  issuer, audience, deployment_id, issued_at, expires_at
  org_id, surface_id, registry_id (where applicable)
  placement_id, placement_resource_version, observation_version
  binding_id, binding_resource_version, binding_revision
  binding_snapshot_revision, credential_reference
  placement_prefix, operation_kind, object_selector
  expected_object_identity, parser_schema_version
  projection, filters, page_cursor
  limits: objects, source_bytes, result_bytes, CPU, duration, fanout
```

`object_selector` is a canonical surface-relative path or a restricted prefix
and range, never an arbitrary URL. The executor joins it to the frozen
placement prefix using the same normalized key rules as public delivery. It
rejects path traversal, encoded separators, another tenant's prefix, and a
selector outside the operation's admitted namespace. A plan cannot select the
current writer implicitly or substitute a healthier placement.

The placement and binding fields carry the [RFC-0012](../0012-hub-surface-topology/01-domain-model.md)
resource fences. A binding snapshot is a signed, revisioned, nonsecret
description of provider kind, endpoint, bucket, prefix, capabilities, and the
exact credential reference that the executor may resolve. Workers receive
these snapshots and purpose-scoped secrets through an authenticated control
channel or deployment bindings; they do not query the Native SQL database on
each object read. A plan naming a missing, expired, or different snapshot or
credential revision fails closed. The Worker never receives a storage secret
inside a work plan or returns one in a result. `deployment_r2` resolves to its
bound R2 bucket; portable `r2` and `s3` bindings resolve to an admitted
S3-compatible endpoint and exact read or write credential revision.

Snapshot distribution is part of topology reconciliation. Native publishes a
new immutable snapshot before issuing plans for its revision, waits for the
executor to acknowledge availability, and withdraws retired or revoked
revisions from future use. A revocation or placement fence change must reach
the executor promptly enough to reject still-unexpired plans; otherwise Native
stops issuing work and waits out their maximum lifetime before considering the
change complete. The executor does not infer current authority from a stale
snapshot. External S3 storage may be far from Cloudflare compute and may
charge provider egress. Such placements remain supported, but their read
location, transfer cost, and latency must be measured; the protocol does not
promise R2-like locality for every binding.

The Native Hub rechecks the relevant placement, binding, authority, and job
generation before accepting a result. Worker-side validation prevents
unauthorized provider I/O; Native-side validation prevents an old result from
changing current state. Existing `FrozenSurfaceAccess` and conditional-delete
claims are the model for destructive operations. A delete plan additionally
requires the reviewed inventory identity, strong provider condition, and
durable claim ID. The executor never turns a conditional mismatch into an
unconditional retry.

## Closed operation set

The first protocol version has explicit operation families. Each has a schema,
purpose-specific capability, source and result limits, and a documented
idempotency rule.

| Operation | Worker execution | Native result |
| --- | --- | --- |
| `head` and `list_page` | Inspect provider metadata or enumerate a placement prefix in bounded pages | Exact object version, size, presence, and ordered keys |
| `inspect_registry` | Fetch and verify selected Git loose objects, bundle entries, channel partitions, or signed semantic files | Typed fields needed by the shared indexer, with source digest and parser evidence |
| `inspect_oci` and `inspect_cache` | Parse admitted OCI descriptors, manifests, closure metadata, narinfo, or other versioned small semantic formats | Typed, bounded catalog or index projections |
| `filter_object` | Apply an admitted schema-specific predicate and field projection to one verified object | Matching records or an ordered page, not source bytes |
| `verify_object` | Stream source bytes locally while hashing and checking expected identity | Digest, size, version, and placement evidence |
| `copy_object` | Stream from a selected source placement to an authorized destination | Destination identity and verification receipt |
| `put_metadata` | Write a Native-authored Nix base32 narinfo of at most 128 KiB through the object-scoped storage guard after checking its exact SHA-256 | Bounded acknowledgment; Native verifies the stored object before committing its write ticket |
| `delete_if_matches` | Use the reviewed conditional-delete capability and exact object condition | Provider acknowledgment and independently observed evidence |

Client upload bodies enter through Worker upload routes or narrowly scoped
direct-storage grants, using Native-issued tickets. They are not sent from
Native in a `StorageWorkPlan`. The executor's write, multipart completion,
abort, and final verification operations use those ticket constraints and
return receipts to Native before any SQL publication commit. Their wire
schemas and idempotency rules are part of the storage protocol even though
the client supplies the bytes on a separate route.

The operation names describe intended state, not a claim that all parsers or
provider combinations exist today. The first implementation should cover the
actual indexer's object classes and its largest data-transfer paths, then add
formats deliberately. Predicates are a typed, schema-specific expression such
as selected package names or Git OIDs; there is no general SQL, JavaScript,
Wasm upload, regular-expression program, unrestricted field path, or arbitrary
HTTP fetch. An unsupported predicate fails rather than forcing a full-object
return.

### Indexer integration

Today `aos_hub_core::indexer` consumes `SurfaceFetch`, whose `fetch` and
`fetch_bounded` methods return bytes. `ObjectReader::preload_bundles` can read
an aggregate bundle or up to 256 shard bundles before a walk. Simply placing
an HTTP implementation of `SurfaceFetch` between Native and R2 would send
those bundles into GCP and retain the cross-cloud round trips this topology is
meant to remove.

Introduce a typed `SurfaceInspection` port alongside `SurfaceFetch`, with
local adapters for Native-only and Workers-only modes and a remote adapter for
hybrid mode. Refactor the indexer's object reader and semantic loaders to ask
for verified objects or projections by identity in batches. In hybrid mode,
the executor selects bundle entries and parses them beside storage; it returns
only the requested decoded objects or narrower index fields. The Native Hub
continues to resolve trust anchors, verify signed claims where the compact
inputs permit it, enforce the rollback floor, choose the index snapshot, and
commit SQL. Where a large object cannot be cryptographically checked from its
projection, the Worker performs the byte-level hash and parser checks using
shared code and returns authenticated observed evidence. Native does not infer
verification from a filename or a claimed expected digest.

Batch plans amortize cross-cloud latency. A plan may contain several explicit
selectors within one placement and one parser family, subject to per-plan
limits. The executor may fan out storage reads within its own subrequest and
CPU budgets or enqueue bounded follow-on work with durable results. Native
does not make one GCP-to-Worker call per package or per channel partition.
Results preserve deterministic order so retries produce the same logical
snapshot. Existing index caps, including branch, release, package, listing,
and semantic-object limits, remain upper bounds rather than being replaced by
larger remote limits.

## Idempotency, failures, and compatibility

Read and inspection plans are safe to retry against the exact object version.
Mutating plans require a durable Native operation ID and an executor-side
idempotency receipt or a provider condition sufficient to prove a repeated
attempt safe. A retry may resume a page or operation but must not select a new
object version under the old plan. Native verifies receipts before marking a
job complete. Expired plans are reissued from current SQL state; they are not
extended by Workers.

Results distinguish absence, version mismatch, authorization failure, quota
or limit exhaustion, unsupported operation, transient provider failure,
verified corruption, and an uncertain mutation outcome. Native may retry only
the documented transient classes and only while the placement and object
fences still match. A partial page or response cannot be committed as a
complete inventory. A placement change, key rotation, credential revocation,
or executor protocol mismatch stops affected work until a new plan is issued.

The Native and Worker deployments exchange supported protocol and parser
versions at startup and expose them in health status. The Native Hub issues
only operations supported by the deployed executor; the Worker rejects
unknown fields and newer incompatible versions. Rolling a Worker independently
must preserve already issued plan versions until their short expiry, or the
Native Hub must stop issuing work during that window. Each work call records
plan ID, operation class, placement and object identity, source bytes read,
result bytes sent to Native, duration, cache status, and error class without
logging credentials or sensitive payloads.
