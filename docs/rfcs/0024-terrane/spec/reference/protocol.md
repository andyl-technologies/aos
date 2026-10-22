# Reference — Wire schema

This document is the normative schema for the Terrane wire protocol
specified in [`18-protocol.md`](../18-protocol.md). It gives the services
and messages of package `terrane.v1` in protobuf syntax with field numbers,
the error details, the request and response headers, and the presigned read
contract. An implementation MUST generate its wire encoding from a schema
equivalent to this one; a field number, once published, is never reused.

Hashes are 32-byte binary values of the content-model digest domain in
[`04-content-model.md`](../04-content-model.md). Pack ids are 16-byte
binary values per [`12-pack-format.md`](../12-pack-format.md). Commit ids are
hashes.

## `publisher-local-v1`

This registered host-local transport implements PROTO-56 to PROTO-59. Its
only endpoints are the configured `serve` and `publish` roles on one host.
It cannot carry Distribution service calls or act as a surface. The socket
is Linux `AF_UNIX`, `SOCK_SEQPACKET`; its configured parent is protected
against replacement by either unauthorized users or consumers. Only the
configured role identities may connect. Both peers verify `SO_PEERCRED`
against the configured opposite identity; claimed UID or PID fields are not
credentials. A connection MUST NOT be inherited or forwarded to consumers.

One packet is one protobuf `PublisherPacket`, at most 65,536 payload bytes,
with at most two `SCM_RIGHTS` descriptors. Receivers use close-on-exec
descriptor reception. Truncated payload or ancillary data, excess or missing
descriptors, unknown ancillary types, unknown protocol versions, unknown
operations, zero request IDs, duplicate active request IDs and invalid field
combinations are rejected before effects. All descriptors received with a
rejected packet are closed. Version 1 rejects unknown message fields rather
than applying Distribution's PROTO-51 permissive-field rule; extending this
closed native-command vocabulary after its initial protocol freeze or a
conforming release requires a new transport version. No
message contains a filesystem path, process pointer or executable callback.

```protobuf
syntax = "proto3";
package terrane.publisher.local.v1;

enum PublisherOperation {
  PUBLISHER_UNSPECIFIED = 0;
  PUBLISHER_PROBE = 1;
  PUBLISHER_PUBLISH = 2;
  PUBLISHER_ADOPT = 3;
  PUBLISHER_INSPECT_BODY = 4;
  PUBLISHER_RETIRE = 5;
  PUBLISHER_RESTORE = 6;
  PUBLISHER_FINISH_RETIREMENT = 7;
  PUBLISHER_DRAIN = 8;
  PUBLISHER_INVENTORY = 9;
  PUBLISHER_RESUME = 10;
  PUBLISHER_INSPECT_PENDING = 11;
  PUBLISHER_INSPECT_QUARANTINE = 12;
  PUBLISHER_QUARANTINE = 13;
}

enum PublisherBodyKind {
  PUBLISHER_BODY_UNSPECIFIED = 0;
  PUBLISHER_BODY_SEALED = 1;
  PUBLISHER_BODY_CHUNK = 2;
  PUBLISHER_BODY_PACK = 3;
}

message PublisherBodyKey {
  PublisherBodyKind kind = 1;
  bytes descriptor = 2;       // existing canonical descriptor, sealed/chunk
  uint32 codec = 3;           // existing codec identifier, chunk only
  bytes pack_id = 4;          // existing 16-byte pack ID, pack only
}

message PublisherClaim {
  bytes descriptor = 1;       // existing canonical inline/manifest descriptor
  string chunk_profile = 2;   // configured registered profile
  uint64 plaintext_size = 3;
  uint64 manifest_offset = 4; // range in optional read-only metadata-pack FD
  uint64 manifest_length = 5;
  bytes retention_id = 6;     // 16-byte cache-owned reconstruction pin ID
}

enum PublisherResult {
  PUBLISHER_OK = 0;
  PUBLISHER_INVALID = 1;
  PUBLISHER_DENIED = 2;
  PUBLISHER_NOT_FOUND = 3;
  PUBLISHER_CONFLICT = 4;
  PUBLISHER_UNSUPPORTED = 5;
  PUBLISHER_RESOURCE_EXHAUSTED = 6;
  PUBLISHER_UNAVAILABLE = 7;
}

message PublisherPacket {
  uint32 version = 1;         // exactly 1
  uint64 request_id = 2;      // nonzero, scoped to connection
  PublisherOperation operation = 3;
  string domain = 4;          // canonical configured disclosure-domain label
  bytes cache_incarnation = 5; // 16-byte random owner incarnation
  uint64 wait_budget_ms = 6;  // bounded wait, never effect cancellation
  PublisherClaim claim = 7;
  PublisherBodyKey body = 8;
  bytes body_incarnation = 9; // 32-byte opaque publisher-issued token
  bool response = 10;
  PublisherResult result = 11; // responses only; requests have zero
  uint32 verity_algorithm = 12; // successful sealed/probe responses only
  bytes verity_digest = 13;
  bytes inventory_cursor = 14; // opaque connection/domain/incarnation cursor
  repeated PublisherBodyKey inventory = 15; // at most 64 keys, responses only
}
```

The configured domain selects physical roots, never a request path or another
domain's fallback. Invalid combinations are rejected: a chunk key has a
chunk descriptor and registered codec but no pack ID; a sealed key has a
chunk or manifest descriptor but no codec or pack ID; a pack key has only a
pack ID. A pack incarnation covers its associated detached index as one
retirement unit. Keys use existing identity and layout rules unchanged.

| Operation | Request descriptors | Success descriptors | Meaning |
| --- | --- | --- | --- |
| Probe | none | one read-only probe inode | Independently establish kernel seal capability on the configured filesystem |
| Publish, inline | one read-only regular source | one read-only canonical inode | Copy, verify and complete HOST-7 |
| Publish, manifest | source, then read-only metadata pack | one read-only canonical inode | Verify manifest range and exact plaintext under HOST-7 |
| Adopt, inline | none | one read-only canonical inode | Independently verify existing content, seal and durable binding |
| Adopt, manifest | one read-only metadata pack | one read-only canonical inode | Adopt using verified retained reconstruction metadata |
| InspectBody, chunk or pack | none | one read-only existing body | Bind a checked configured key to a publisher-issued inode incarnation |
| InspectBody, sealed | as Adopt | one read-only canonical inode | Adopt and bind a checked sealed-body incarnation |
| Retire | none | none | Move that exact body incarnation to pending-delete without replacement |
| Restore | none | none | Restore that exact pending incarnation without replacement; no service until adoption |
| FinishRetirement | none | none | Complete the authorized wipe policy and removal of that exact pending incarnation |
| Drain | none | none | Complete earlier accepted work and establish the owner-incarnation barrier |
| Inventory | none | none | Enumerate at most 64 configured body keys for recovery; no content or serving authority |
| Resume | none | none | Leave recovery custody after actual cache state reconciliation |
| InspectPending | none | none | Retain a pending inode incarnation for non-serving lifecycle recovery |
| InspectQuarantine | none | one read-only unverified quarantine inode | Observe existing publisher-owned sealed-body quarantine custody; no lifecycle token |
| Quarantine | none | none | Move the exact retained canonical sealed inode or encoded body unit into quarantine without replacement |

Error responses carry no descriptors, binding or body-incarnation token.
Replies echo version, request ID, operation, domain and cache incarnation.
Only successful Probe, Publish, Adopt, InspectBody and InspectQuarantine
replies carry a descriptor. Body-incarnation tokens are unguessable, scoped to the publisher
instance, domain, key, retained inode and lifecycle state; callers cannot mint
them by supplying device/inode numbers. They are invalid after publisher
restart. A fresh InspectBody or verified Adopt is required after recovery.
The same token follows that retained inode through canonical, pending-delete
and restored states; each command checks legality against the publisher's
current state. Retirement does not consume the token. Final removal, quarantine or
replacement of the inode invalidates it.

Only `serve` sends requests and only `publish` sends responses. Clients
reject unsolicited replies, mismatched correlation fields and wrong response
direction, closing all received descriptors. All packets require version,
nonzero request ID, operation, domain and a 16-byte cache incarnation.
Request wait budgets are 1 to 300,000 milliseconds. Response wait budgets
are zero. Claims, bodies and tokens are absent unless required below.

| Operation | Additional request fields | Additional successful response fields |
| --- | --- | --- |
| Probe | none | verity binding |
| Publish, Adopt | claim and sealed body with identical descriptors | body-incarnation token and verity binding |
| InspectBody, sealed | claim and matching sealed body | body-incarnation token and verity binding |
| InspectBody, chunk or pack | body | body-incarnation token |
| Retire, Restore, FinishRetirement | body and body-incarnation token | none |
| Drain, Resume | none | none |
| Inventory | optional inventory cursor | inventory and optional next cursor |
| InspectPending | body | body-incarnation token |
| InspectQuarantine | sealed body and optional 32-byte quarantine name suffix | none |
| Quarantine | sealed, chunk or pack body and body-incarnation token | none |

Claim profile and plaintext size must agree with configured profile and
verified content. Inline claims have zero manifest offset/length and no
retention ID. Manifest claims have a nonzero manifest length and a 16-byte
retention ID. Only manifest claims carry the metadata descriptor indicated
above. Claims, body keys and request tokens are not echoed in responses.
Verity bindings are exactly algorithm 1 with 32 bytes or algorithm 2 with
64 bytes. Tokens are exactly 32 bytes. Inventory cursors are opaque bounded
values of at most 64 bytes, issued by this publisher for this connection,
domain and cache incarnation; they cannot contain caller paths. An absent
next cursor marks the final inventory page. Inventory lists key names only;
they are not verified content, incarnation tokens or permission to serve.
All operation-specific fields are absent on errors. Unexpected fields or
descriptor combinations are invalid, including a verity binding for an
unsealed chunk or pack.

Probe creates an empty private inode, closes every writer, enables and
measures real fs-verity, synchronizes it, and removes its private name before
replying. The receiver independently measures the returned descriptor and
checks its device against retained host-layout descriptors. A probe is not a
canonical backing handle and grants no content access.

For Publish and Adopt, the claim descriptor and active chunk profile are
verified using the existing content formats. A manifest range is canonical
metadata from an ordinary cached metadata pack, not assembled plaintext.
The receiver checks range bounds and manifest identity before using it. The
cache MUST durably retain and pin that metadata under HOST-31 before sending
the command, and retain it while any dependent sealed body remains. The
retention ID identifies this actual cache-owned pin; a random ID or claimed
boolean alone is not a retention receipt. Native composition validates the
pin's domain, descriptor and physical completion before submission. Passing
the pack descriptor does not itself prove retention or synchronization.
Configured metadata resource bounds may produce RESOURCE_EXHAUSTED before
publication; no partial metadata can be acknowledged. Incoming descriptors
are read-only regular files. Read-only access does not imply immutable
content: copy into private staging and verify the destination, or establish
HOST-8's genuine source immutability before reflinking.

The publisher derives all body paths from trusted roots and registered keys.
InspectBody verifies the canonical key-to-inode namespace binding, retained
regular inode, configured domain and native custody before issuing its token.
For an unsealed chunk or pack this is an incarnation observation, not content
identity verification or authority to serve its bytes; the cache independently
performs HOST-14 verification, including dictionary resolution. Sealed bodies
also pass full adoption. Retire, Restore and FinishRetirement
compare their retained inode incarnation before mutation. The cache retains
pin, reservation, grace and recovery exclusion until the actual namespace
effect and coordinated state are durable. No retirement method silently
substitutes unlinking for zero wiping. Neither returning a descriptor nor
unlinking its name revokes existing open descriptors or mappings.

InspectQuarantine opens only an existing publisher-owned regular file under
that domain's configured `quarantine/` root, using the digest of a registered
sealed-body key. An optional 32-byte value in `body_incarnation` selects the
public hexadecimal name suffix of a previously quarantined incarnation; here
it is only a name selector, never lifecycle authority. Without that suffix,
the legacy digest-only name is selected. The read-only descriptor is an opaque custody observation:
its bytes may be corrupt or unsealed. No content verification, verity binding,
body-incarnation token, restore, retirement, pin or serving authority follows.
The receiver independently checks its actual device, inode, project and
namespace custody before using it for recovery accounting. The operation
creates, renames and deletes no entry and leaves publication records unchanged.
It is permitted in recovery and running custody. Unknown operation values
remain rejected; an older receiver cannot substitute another operation.

Quarantine requires the publisher's existing token for an actually retained
canonical body unit. For a sealed body, the publisher compares that original
inode with its canonical directory entry, then moves it without replacement to
`quarantine/<hash>.<incarnation>`, where the suffix is the token's 64 lowercase
hexadecimal digits. Both directories are synchronized before success and the
old lifecycle token is removed. Earlier quarantined copies of the same hash
remain intact, including a legacy `quarantine/<hash>` entry. A conflicting
quarantine name is refused without replacement. A successful response carries
no descriptor, binding or token. Quarantine grants no permission to serve,
restore, wipe or remove that inode, and does not revoke descriptors already
held by readers. The cache must independently revoke its affected read views
and retain the original allocation and funding under HOST-15 and HOST-27.

For an encoded chunk or pack/index pair, the same operation retains the exact
original members observed by InspectBody. Each destination is
`quarantine/encoded.<canonical-filename>.<incarnation>`, preserving the chunk
codec or the pack/index extension. Every original and every destination is
checked before the first move; each move is no-replace and both directories
are synchronized. A partial filesystem failure retains the original unit's
actual member locations and descriptors for cold reconciliation. After any
failed encoded exchange the old token cannot authorize another mutation in
that owner. An incomplete pair supplies no authority to restore or delete its
surviving member. Encoded quarantine does not verify bytes, issue a verity
binding, release original funding or grant content-serving authority (D-131).

InspectPending is permitted during recovery custody. It independently opens
the domain's pending entry through its typed key and verifies directory-relative
inode custody before issuing a fresh token after restart. It returns no file
descriptor, verity binding, content-validity receipt or serving authority,
including for a pending sealed file. Restore is then permitted during recovery
custody, but restores only the namespace; a sealed body MUST subsequently pass
canonical adoption before any backing descriptor is returned. Pending pack
pairs are reconciled under HOST-28 before restoration or final removal.

Dropping a waiter, expiring its wait budget, losing a connection or shutting
down a caller runtime does not release an accepted operation's physical
ownership. The native owner finishes or cleans up before releasing its holds;
late reply descriptors are closed. A new cache incarnation MUST first use
Drain; the publisher rejects conflicting work until all prior-incarnation
commands finish. Drain then grants the new incarnation exclusive recovery
custody: Inventory, Probe, InspectBody, InspectPending, InspectQuarantine and
Adopt are permitted.
Quarantine is permitted only for a canonical body incarnation actually
retained by that publisher after Drain; a token from before Drain is invalid.
Restore and FinishRetirement of verified pending incarnations are permitted;
ordinary publication and new retirement remain blocked. The cache reconstructs its real
durable state and pins before sending Resume. Resume succeeds only for that
incarnation after its recovery native operations complete; the native cache
owner MUST validate actual reconciliation completion before submission.
Resume does not itself prove cache durability. A lost reply is
resolved by inspection/adoption and durable recovery, never assumed success
or rollback. A publisher restart invalidates all tokens and requires the
same recovery before new work. The channel conveys no capability tokens and
cannot bypass repository authorization performed by `serve`.

## `host-quota-local-v1`

This registered transport implements PROTO-60 only. A host-supplied helper
with kernel quota-query privilege serves configured Terrane role identities
over Linux `AF_UNIX/SOCK_SEQPACKET`. It is not a Terrane role and performs
no content, ref, publisher or quota-configuration mutation. Terrane roles
retain no capabilities. Socket parent custody and both peers' `SO_PEERCRED`
checks follow the host's explicit helper and client identity configuration.
The helper accepts only its protected host configuration, never a
client-selected filesystem, project number or quota command.

One packet is one protobuf message below, at most 16,384 bytes, with no
descriptors or ancillary data. Truncation, unknown fields, duplicate singular
fields, wrong wire types, zero request IDs, bad lengths and unexpected
ancillary data are rejected. Every received descriptor is closed on rejection.
The client permits one outstanding request per connection; the server sends
exactly one correlated response. Unknown versions are rejected, not guessed.

```protobuf
syntax = "proto3";
package terrane.host.quota.v1;

message QuotaQuery {
  uint32 version = 1;          // exactly 1
  uint64 request_id = 2;       // nonzero
  bytes configuration_epoch = 3; // exactly 16 bytes, supplied by host
  string owner_id = 4;         // 1..256 UTF-8 bytes, configured identifier
  string domain = 5;           // canonical configured disclosure domain
}

enum QuotaResult {
  QUOTA_OK = 0;
  QUOTA_INVALID = 1;
  QUOTA_DENIED = 2;
  QUOTA_UNSUPPORTED = 3;
  QUOTA_UNAVAILABLE = 4;
  QUOTA_STALE = 5;
}

message QuotaRoot {
  string role_directory = 1;   // host-layout label from the list below
  uint64 device = 2;           // currently retained native descriptor's st_dev
  uint64 inode = 3;            // currently retained native descriptor's st_ino
  bool project_inherit = 4;    // actual native inheritance flag
}

message QuotaObservation {
  uint32 version = 1;
  uint64 request_id = 2;
  bytes configuration_epoch = 3;
  string owner_id = 4;
  string domain = 5;
  uint64 query_sequence = 6;   // strictly increasing per connection/epoch
  QuotaResult result = 7;
  bytes filesystem_uuid = 8;   // 16 bytes, verified against provisioned ledger
  uint32 project_id = 9;       // actual host-configured nonzero project
  bool accounting = 10;
  bool enforcement = 11;
  uint64 hard_limit_bytes = 12;
  uint64 charged_reserved_bytes = 13;
  uint64 hard_inode_limit = 14; // zero means no inode-specific limit
  uint64 charged_inodes = 15;
  repeated QuotaRoot roots = 16; // complete configured owner roots, at most 32
  uint64 tier_charge_budget_bytes = 17;
  uint64 configured_limit_sum_bytes = 18;
}
```

All query fields are required. The server verifies the authenticated client's
configured owner/domain authorization, exact configuration epoch and actual
native root/project binding before querying the kernel. Successful replies
echo the request correlation fields and report freshly queried accounting,
enforcement, limits and usage. The helper verifies the complete configured
project partition, including its checked hard-limit sum, rather than trusting
an amount supplied by the client. A finite nonzero hard byte limit and a
complete root set with matching project identity and inheritance are required
for admission. Each reply's complete root set means every root assigned to
that configured owner by the host ledger. The root labels are `chunks`,
`objects`, `sealed`, `staging`,
`quarantine`, `pending-delete`, `state`, `layout-root` and
`administrative-root`; labels select configured roots,
not caller paths. If a host splits these classes across projects, every
project is a separately configured owner included in the same finite budget.
`layout-root` identifies the actual domain-layout directory, not a new child
name, so its inode allocation is explicitly charged. Every domain layout has
this observation in addition to its seven allocation-class roots. An optional
`administrative-root` identifies a separately configured host scaffolding
directory outside the selected data layout; its inode and scaffold allocation
are also charged to a finite compatible owner project. These are logical query
labels, not filesystem names or bucket keys. A helper MUST NOT infer permission
to assign a common ancestor such as a host's general state directory.

The helper checks complete allocation-class coverage over the entire
configured partition; admission checks observations for every owner whose
allocation it will increase. Project partitioning preserves the immutable
charge owner of inodes across required link and rename operations: staging,
sealed insertion, quarantine, pending-delete and restoration destinations
for one inode must have compatible project assignments. Duplicate labels
within an owner, missing allocation classes in the partition, unsupported
project quotas, disabled enforcement, unlimited required limits, overflow or an
excessive sum prevent successful verification.

Errors carry only version, request ID, epoch, owner, domain, query sequence
and result; quota observations and roots are absent. Stale epochs produce
QUOTA_STALE. Clients reject unsolicited or mismatched replies and sequence
replay on the authenticated connection. A sequence number is correlation,
not proof of freshness: every success requires an actual query. A query
does not atomically snapshot concurrent filesystem writers; serialized native
admission custody and kernel hard-limit enforcement remain necessary.

The host provisions a durable root/domain/charge-owner ledger outside the
content layout, preserving assignments across helper and tier restart. The
helper checks filesystem UUID, actual roots, project IDs and configuration
epoch against this ledger. Missing or conflicting assignments fail closed;
reusing a path for another disclosure domain is not a new empty cache.
Provisioning is a host administrative operation, not a protocol method.
A privileged-opened descriptor or static provisioning record does not grant
unprivileged kernel query permission or replace live quota observations.

## `host-quota-local-v2` census

Version 2 adds optional read-only original-inode census on the same authenticated
host quota socket. Version 1 packets retain the schema and checks above. A helper
without explicitly configured census bounds returns `QUOTA_UNSUPPORTED` for a
valid version 2 request. Older helpers reject the unknown version. Neither peer
guesses a version or falls back after submitting an accepted request.

The version 1 packet size, descriptor prohibition, protected socket parent,
kernel peer authentication, owner/domain authorization and exact epoch checks
also apply. Version 2 additionally requires canonical protobuf encoding: fields
appear in tag order, singular fields occur at most once, default scalar fields are
omitted, varints use their minimal representation, and unknown fields are
rejected at every level. Repeated identities retain request order. The closed
schema is:

```protobuf
syntax = "proto3";
package terrane.host.quota.v2;

message CensusInode {
  uint64 device = 1; // nonzero original native device
  uint64 inode = 2;  // nonzero original inode, including all 64 bits
}

message CensusQuery {
  uint32 version = 1; // exactly 2
  uint64 request_id = 2;
  bytes configuration_epoch = 3;
  string owner_id = 4;
  string domain = 5;
  repeated CensusInode excluded = 6; // 1..512 distinct original identities
}

message CensusObservation {
  uint32 version = 1; // exactly 2
  uint64 request_id = 2;
  bytes configuration_epoch = 3;
  string owner_id = 4;
  string domain = 5;
  uint64 query_sequence = 6;
  int32 result = 7; // registered QuotaResult codes
  terrane.host.quota.v1.QuotaObservation quota = 8;
  repeated CensusInode excluded = 9;
  uint64 retained_inodes = 10;
}
```

Correlation fields have the version 1 bounds. Errors carry correlation and
result alone, with no quota, exclusions or retained count. A successful response
contains a valid complete version 1 quota observation with the same correlation
and sequence, and exactly echoes the ordered exclusions. Each exclusion belongs
to the observed native device. The nonzero retained count MUST NOT exceed the
fresh kernel project inode charge. Bare decoded messages grant no native
authority; the physical owner consumes only authenticated correlated evidence.

Only protected host configuration chooses traversal roots, filesystem, project
and resource bounds. No request supplies a path, descriptor, project number,
traversal budget or mutation. The helper rechecks the complete configured quota
partition and durable native project claims, then retains distinct non-excluded
inodes through the kernel quota query. Every alias of an excluded identity is
excluded. Counted descriptors remain held through native binding checks around
that query. The returned quota charges MUST come from this held-inode query,
rather than an independent sample taken before or after it.

Host configuration bounds retained descriptors, visited entries including
aliases, and traversal depth. At most one census holds its additional descriptor
budget at a time; contention, exhaustion, incomplete native inspection or
unsupported entries yield unavailable evidence. Ordinary quota queries retain
their existing bounded sessions. Production service descriptor limits include
both the existing retained scaffold allowance and the configured census budget.
An incomplete namespace can conservatively prevent closure; a pathname,
policy byte total, deletion notification or estimated allocation cannot replace
the native comparison.

Equality between the retained distinct inode count and the complete charged
project inode count establishes that none of these exact exclusions remained
charged at the observation. A larger charge retains unresolved obligations.
The physical owner MUST first bind the exclusions to its durable original
incarnations and serialized retirement, stop new grants, unlink retired names
and close its own backing descriptors. It MUST preserve the ban on untrusted
project setters. The observation itself performs none of these transitions,
does not identify reference holders, and does not authorize release of any
different inode or policy obligation.

## Common types

```protobuf
syntax = "proto3";
package terrane.v1;

message Hash {
  bytes value = 1;            // exactly 32 bytes
}

message PackId {
  bytes value = 1;            // exactly 16 bytes
}

message Locality {
  string region = 1;
  string zone = 2;            // may be empty
  string host = 3;            // may be empty
}

message Range {
  PackId pack = 1;
  uint64 offset = 2;
  uint64 length = 3;
}

message Span {
  Range range = 1;            // the span actually served; may widen a request
  string url = 2;             // presigned URL, absent when served by GetRange
  google.protobuf.Timestamp expires = 3;
}

message RefValue {
  Hash commit = 1;
  uint64 sequence = 2;
  uint64 writer_epoch = 3;
  string profile = 4;         // tree encoding and chunk parameter profile name
  bytes canonical_ref_record = 5; // complete RefRecord CBOR; required for CAS
}

// The CBOR record is authoritative for whole-record forwarding/CAS. Summary
// fields must agree with it; profile must agree with the verified commit.
// A legacy summary alone cannot establish a whole-record CAS expectation.
message RefState {
  string name = 1;
  RefValue value = 2;         // absent when the ref does not exist
  bool fenced = 3;            // caller's epoch is superseded
  uint32 staleness_ms = 4;    // observed staleness of this read, 0 at home
  Locality home = 5;
}

enum Freshness {
  FRESHNESS_ANY = 0;
  FRESHNESS_BOUNDED = 1;      // requires bound_ms
  FRESHNESS_LINEARIZABLE = 2;
}

enum Priority {
  PRIORITY_NORMAL = 0;
  PRIORITY_HIGH = 1;          // blocking consumer read
  PRIORITY_LOW = 2;           // warming and speculative prefetch
}
```

## `ContentService`

```protobuf
service ContentService {
  rpc Negotiate(NegotiateRequest) returns (NegotiateResponse);
  rpc Has(HasRequest) returns (HasResponse);
  rpc PutPack(stream PutPackFrame) returns (PutPackResponse);
  rpc GetRange(GetRangeRequest) returns (stream GetRangeFrame);
  rpc PresignRead(PresignReadRequest) returns (PresignReadResponse);
  rpc GetBundle(GetBundleRequest) returns (stream BundleFrame);
  rpc GetFilter(GetFilterRequest) returns (stream FilterShard);
  rpc GetIndex(GetIndexRequest) returns (stream IndexShard);
}

message NegotiateRequest {
  repeated Hash have_commits = 1;   // commits the sender knows the receiver has
  repeated Hash roots = 2;          // tree roots the sender intends to reference
  repeated Hash hashes = 3;         // at most 4096 chunk or meta-object hashes
}

message NegotiateResponse {
  repeated Hash known_commits = 1;  // subset of have_commits the receiver has
  repeated Hash missing_nodes = 2;  // frontier nodes the receiver lacks, per root
  bytes missing_bitmap = 3;         // one bit per entry of hashes, 1 = missing
}

message HasRequest {
  repeated Hash hashes = 1;         // at most 4096
}

message HasResponse {
  bytes present_bitmap = 1;         // one bit per entry, 1 = present
}

message PutPackFrame {
  oneof frame {
    PutPackHeader header = 1;
    bytes body = 2;                 // at most 4 MiB per frame
    PutPackTrailer trailer = 3;
  }
}

message PutPackHeader {
  PackId pack = 1;
  uint64 size = 2;
  uint32 format_version = 3;
  bool meta = 4;                    // meta pack rather than data pack
  bool direct_upload_ok = 5;        // client can perform multipart upload
}

message PutPackTrailer {
  bytes index = 1;                  // the per-pack index, see 12-pack-format
  Hash index_hash = 2;
}

message PutPackResponse {
  oneof outcome {
    PackAck ack = 1;
    DirectUpload direct = 2;        // sent after the header when redirecting
  }
}

message PackAck {
  PackId pack = 1;
  string durability = 2;            // achieved level: local|zone|region|regions(k)
  bool already_present = 3;
}

message DirectUpload {
  string upload_id = 1;
  repeated string part_urls = 2;    // presigned multipart part URLs, in order
  uint64 part_size = 3;
  string complete_url = 4;
  string abort_url = 5;
  google.protobuf.Timestamp expires = 6;
}

message GetRangeRequest {
  Range range = 1;
  Priority priority = 2;
}

message GetRangeFrame {
  uint64 offset = 1;
  bytes data = 2;                   // at most 4 MiB
}

message PresignReadRequest {
  repeated Range ranges = 1;
  Priority priority = 2;
}

message PresignReadResponse {
  repeated Span spans = 1;          // covers every requested range
  repeated Range proxied = 2;       // ranges the caller must fetch via GetRange
}

message GetBundleRequest {
  oneof root {
    Hash tree_root = 1;
    Hash commit = 2;
  }
  repeated Hash have_nodes = 3;
  Hash have_commit = 4;
  bool include_profile = 5;
}

message BundleFrame {
  oneof frame {
    MetaObject object = 1;          // node, manifest, or commit
    bytes access_profile = 2;       // final frame when requested
  }
}

message MetaObject {
  Hash hash = 1;
  uint32 kind = 2;                  // registered meta-object kind
  bytes encoded = 3;
}

message GetFilterRequest {
  uint64 since_generation = 1;
}

message FilterShard {
  uint32 shard = 1;
  uint64 generation = 2;
  float false_positive_rate = 3;
  bytes filter = 4;
}

message GetIndexRequest {
  uint64 since_generation = 1;
}

message IndexShard {
  uint32 shard = 1;
  uint64 generation = 2;
  bytes index = 3;                  // merged-index shard including tombstones
}
```

## `RefService`

```protobuf
service RefService {
  rpc GetRef(GetRefRequest) returns (RefState);
  rpc CompareAndSwapRef(CompareAndSwapRefRequest) returns (RefState);
  rpc GetRefLog(GetRefLogRequest) returns (stream RefLogEntry);
  rpc WatchRefs(WatchRefsRequest) returns (stream RefEvent);
  rpc ListRefs(ListRefsRequest) returns (stream RefState);
}

message GetRefRequest {
  string name = 1;
  Freshness freshness = 2;
  uint32 bound_ms = 3;
}

message CompareAndSwapRefRequest {
  string name = 1;
  oneof expect {
    RefValue expected = 2;
    bool absent = 3;
  }
  RefValue value = 4;
  repeated PackLocation introduced = 5;   // packs the new commit introduces
  string message = 6;
}

message PackLocation {
  PackId pack = 1;
  Locality locality = 2;
  string store = 3;                       // store identity within the locality
}

message GetRefLogRequest {
  string name = 1;
  uint64 from_sequence = 2;
}

message RefLogEntry {
  uint64 sequence = 1;
  RefValue value = 2;
  google.protobuf.Timestamp at = 3;
  string principal = 4;
  string message = 5;
  bytes canonical_ref_log_record = 6; // full new/previous record and selector
}

message WatchRefsRequest {
  repeated string patterns = 1;     // glob over ref names
  bool initial = 2;
  bytes resume_token = 3;
}

message RefEvent {
  RefState state = 1;
  bytes resume_token = 2;
  bool deleted = 3;
}

message ListRefsRequest {
  string pattern = 1;
}
```

## `TierService`

```protobuf
service TierService {
  rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse);
  rpc Residency(ResidencyRequest) returns (ResidencyResponse);
  rpc Where(WhereRequest) returns (WhereResponse);
  rpc Warm(WarmRequest) returns (WarmResponse);
  rpc Costs(CostsRequest) returns (CostsResponse);
}

message CapabilitiesRequest {}

message CapabilitiesResponse {
  repeated string packages = 1;         // e.g. "terrane.v1"
  repeated uint32 pack_formats = 2;
  repeated string tree_encodings = 3;
  Locality locality = 4;
  uint32 max_hops = 5;
  uint64 max_pack_size = 6;
  bool presigned_reads = 7;
  bool direct_upload = 8;
  BackendProbe backend = 9;
  repeated string tier_list = 10;       // identities of this tier's own candidates
  string tier_identity = 11;
}

message BackendProbe {
  bool conditional_put = 1;             // put-if-absent supported
  bool conditional_replace = 2;         // compare-and-swap supported
  bool ranged_get = 3;
  bool multipart_upload = 4;
  string backend_kind = 5;              // bucket|disk|shared-dir|blockdev|remote
}

message ResidencyRequest {}

message ResidencyResponse {
  uint64 generation = 1;
  bytes filter = 2;
  Locality locality = 3;
  uint64 capacity_bytes = 4;
  uint64 used_bytes = 5;
}

message WhereRequest {
  oneof view {
    string ref = 1;
    Hash commit = 2;
  }
}

message WhereResponse {
  repeated LocalityFraction fractions = 1;
  uint64 oldest_generation = 2;
}

message LocalityFraction {
  Locality locality = 1;
  float fraction = 2;                   // of the view's packs resident there
}

message WarmRequest {
  oneof target {
    string ref = 1;
    Hash commit = 2;
    PackList packs = 3;
  }
  Priority priority = 4;
}

message PackList {
  repeated PackId packs = 1;
}

message WarmResponse {
  string job_id = 1;
}

message CostsRequest {
  string caller_identity = 1;
  CostVector observed = 2;              // caller's measurement of callee
}

message CostsResponse {
  CostVector observed = 1;              // callee's measurement of caller
}

message CostVector {
  float latency_p50_ms = 1;
  float latency_p99_ms = 2;
  float bandwidth_bytes_per_s = 3;
  float price_per_byte = 4;
  float health = 5;
  uint32 samples = 6;
}
```

`JobService` is specified in [`32-tree-jobs.md`](../32-tree-jobs.md).

## Error details

Attached in status details. `ErrorInfo` is attached to every error.

```protobuf
message ErrorInfo {
  bool retryable = 1;
  google.protobuf.Duration retry_after = 2;
  string trace_id = 3;
}

message Limit        { string name = 1; uint64 limit = 2; uint64 requested = 3; }
message MissingPacks { repeated PackId packs = 1; }
message HopLimit     { uint32 max_hops = 1; repeated string path = 2; }
message Conflict     { repeated string paths = 1; uint32 attempts = 2; }
message Quota        { string root = 1; uint64 limit = 2; uint64 used = 3; }
message Budget       { string budget = 1; }
message Home         { Locality home = 1; }
message Staleness    { uint32 observed_ms = 1; uint32 bound_ms = 2; }
message Versions     { repeated uint32 pack_formats = 1; repeated string tree_encodings = 2; }
```

## Headers

| Header | Direction | Value |
| --- | --- | --- |
| `Authorization` | request | `Bearer <capability token>` |
| `terrane-hop` | request | decimal hop count, starting at 0 |
| `terrane-path` | response | comma-separated `region/zone/host` labels of serving tiers |
| `terrane-served-by` | response | `page-cache`, `disk`, `shared-dir`, `peer`, `bucket`, `remote` |
| `terrane-stale` | response | staleness in milliseconds for ref reads |
| `traceparent`, `tracestate` | both | W3C trace context |

The capability-token bearer value is the unpadded base64url encoding of the
canonical CBOR token bytes. Exactly one `Authorization` field is accepted;
malformed, ambiguous, unknown-issuer, retired-key, or expired credentials produce
the same `UNAUTHENTICATED` status. Anonymous `Capabilities`, when enabled, accepts
an absent credential; a supplied invalid credential is still rejected.

## Presigned read contract

A presigned read is an HTTP `GET` against the URL in a `Span`.

- The client MUST send `Range: bytes=<offset>-<end>` for exactly the span's
  range, where the span is a sub-range of a bucket object, or no `Range`
  header where the span covers the whole object.
- The server that minted the URL MUST have bound it to one object key and,
  where the backend supports it, to the span's byte range; the URL MUST
  expire no later than the `expires` timestamp, which MUST be within 15
  minutes of minting.
- The response MUST be the raw pack bytes; no framing, no compression at
  the HTTP layer beyond what the bucket applies transparently.
- The client MUST verify every chunk it extracts from the span before
  admitting it and MUST discard bytes that fail. A span MAY contain chunks
  the client did not request; those are verified and admitted unpinned.
- A `403` or `404` from the bucket MUST be treated as `NOT_FOUND` for the
  purpose of candidate selection and MUST cause the client to re-request a
  span rather than retry the URL, since the URL may have expired.
- The client MUST NOT log or persist a presigned URL beyond its use.

## Direct upload contract

When `PutPackResponse.direct` is returned:

- The client MUST upload the pack body in parts of exactly `part_size`
  bytes except the last, to `part_urls` in order, with `PUT`.
- The client MUST then `POST` to `complete_url` with the part ETags in the
  backend's completion format, then send the `PutPackTrailer` frame on the
  original stream.
- On any failure the client MUST `DELETE` to `abort_url` so the backend does
  not retain an orphaned multipart upload.
- The server MUST verify the completed object per PROTO-13 before
  acknowledging and MUST delete the object if verification fails.
