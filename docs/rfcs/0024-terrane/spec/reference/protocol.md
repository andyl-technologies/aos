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
}

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
  uint64 since_epoch = 1;
}

message FilterShard {
  uint32 shard = 1;
  uint64 epoch = 2;
  float false_positive_rate = 3;
  bytes filter = 4;
}

message GetIndexRequest {
  uint64 since_epoch = 1;
}

message IndexShard {
  uint32 shard = 1;
  uint64 epoch = 2;
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
  uint64 epoch = 1;
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
  uint64 oldest_epoch = 2;
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
