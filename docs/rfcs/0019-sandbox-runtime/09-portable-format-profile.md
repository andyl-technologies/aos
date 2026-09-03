# Portable format profile

## Scope

Portable policy, filesystem tree, delta, view, environment, sandbox spec,
snapshot, trust-policy, and signature objects use one exact encoding profile so
independent implementations compute identical identities. This profile is
separate from protobuf RPC messages and from the replaceable node-local mmap
index.

The authoritative [portable v1 CDDL](portable-v1.cddl), the rules below, and the
golden vectors in this document form one normative contract. Phase 1 copies
them into conformance tests under `crates/aos-sandbox-core/formats/`; it does
not fill in missing wire semantics. Changing a rule that affects bytes or
semantics requires a new media-type version, not an in-place parser change.

## Envelope and identity

Canonical objects use deterministic CBOR under RFC 8949 section 4.2 with these
additional restrictions:

- definite-length arrays, maps, byte strings, and text strings only;
- shortest integer and length encodings;
- no floating point, bignums, tags, duplicate map keys, or indefinite items;
- integer schema keys in ascending encoded-byte order;
- text only where the schema says UTF-8 text; filesystem names remain bytes;
- unknown map keys fail for canonical authority and data objects; and
- decoder limits apply before allocating claimed collection/string lengths.

An object descriptor is the four-element canonical CBOR array defined by the
CDDL. Its display projection is:

```text
media_type: registered ASCII media type including major version
digest: sha256:<64 lowercase hexadecimal characters>
encoded_size: exact stored object byte length as unsigned 64-bit value
```

The digest preimage is exactly:

```text
ASCII "aos-sandbox-object-v1\0"
u16be media-type byte length
media-type ASCII bytes
u64be stored-object byte length
stored-object bytes
```

and the initial algorithm is SHA-256. The algorithm identifier is part of every
descriptor and signature statement. A later digest algorithm creates a new
descriptor profile; implementations do not accept an unregistered algorithm
because a parser happens to provide it.

Initial media types are:

```text
application/vnd.aos.sandbox.content.v1
application/vnd.aos.sandbox.policy.v1+cbor
application/vnd.aos.sandbox.tree.v1+cbor
application/vnd.aos.sandbox.directory.v1+cbor
application/vnd.aos.sandbox.delta.v1+cbor
application/vnd.aos.sandbox.view.v1+cbor
application/vnd.aos.sandbox.environment.v1+cbor
application/vnd.aos.sandbox.optimization.v1+cbor
application/vnd.aos.sandbox.spec.v1+cbor
application/vnd.aos.sandbox.snapshot.v1+cbor
application/vnd.aos.sandbox.trust-policy.v1+cbor
application/vnd.aos.sandbox.signature.v1+cbor
```

Object size, media type, and digest are verified before semantic use. The
content store keys by the complete descriptor, not digest bytes alone.

The content media type stores raw logical file bytes rather than CBOR. Its
encoded size is therefore the logical byte length. V1 does not register a
compressed content identity: compression is transport framing that is removed
and verified before publication. Whole-file and sparse-extent descriptors must
use this raw media type; an extent descriptor's encoded size must equal its
declared length.

## Common scalar model

Filesystem names are nonempty byte strings of at most 255 bytes. They cannot
contain NUL or `/` and cannot equal `.` or `..`. No Unicode normalization,
case folding, locale conversion, or alternate separator exists in the
canonical model. A complete relative path is the ordered sequence of names;
its encoded byte length, component count, and traversal depth are bounded by
policy.

Integers have schema-specific widths even though CBOR uses shortest encoding:

- file size and extent offset/length: unsigned 64-bit;
- UID/GID: unsigned 32-bit guest-visible identity;
- permission and special mode bits: unsigned 16-bit restricted to the low 12
  bits;
- timestamp seconds: signed 64-bit Unix time;
- timestamp nanoseconds: unsigned 32-bit, less than one billion; and
- counts: unsigned 64-bit with a lower policy bound required for allocation.

Portable metadata includes mode, UID, GID, and `mtime`. It excludes atime,
ctime, inode number, block count, generation, birth time, and storage-private
flags unless a future feature profile adds them. Setuid/setgid and sticky bits
are preserved in data but execution/mount policy independently decides whether
they can have effect.

Xattr names and values are byte strings sorted by name. Duplicate names fail.
`security.*`, `trusted.*`, integrity, and capability xattrs require a named
feature profile and are denied by the generic profile. POSIX ACLs, when the
feature is required, use sorted typed user/group/mask/other entries with no
duplicate qualifier and must agree with the canonical mode bits. Unsupported
metadata is rejection, not silent dropping.

V1 integer registries are closed and have these exact assignments:

```text
resource kind 0..14: sandbox, execution, snapshot, tree, live-export,
  private-delta, secret, device, network-endpoint, ipc-service, cache-read,
  cache-publish, environment, attachment-slot, child-delegation
operation bits 0..14: discover, metadata-read, content-read, execute, create,
  content-write, remove, rename, link, metadata-write, attach,
  lifecycle-control, delegate, publish, live-kernel-coupled-read
view mode 0..4: read-only, read-write, copy-on-write, append-only, service
cache domain 0..3: private, project, trust-domain, public
revocation mode 0..2: deny-new, freeze, stop
selector kind 0..3: resource, tree, path, profile
view action kind 0..3: include, exclude, attach, present
view source kind 0..1: immutable-tree, live-export
view presentation action 0..2: include, exclude, present
view consistency 0..2: immutable, local-live, external-versioned
view mutation 0..4: read-only, read-write, private-cow, append-only, service
identity kind 0..1: private-userns, exceptional-host-identity
unmappable identity policy 0..1: reject, isolated-synthesized-presentation
network kind 0..4: isolated, project, outbound, published, host
limit value kind 0..2: inherited, bounded, unlimited
optimization kind 0..7: prefetch-metadata, prefetch-content, readahead,
  directory-index, passthrough, keepalive, cache-weight, worker-pooling
reason code 0..10: site-ceiling, project-ceiling, ancestor-ceiling,
  caller-grant, resource-limit, disclosure-domain, revocation,
  backend-requirement, attachment-conflict, environment-policy, default
retention kind 0..4: storage-hold, content-lease, nix-gc-root,
  service-receipt, secret-reference
external dependency kind 0..4: immutable-view, package-closure, secret,
  service-endpoint, network-endpoint
consistency 0..2: crash-consistent, application-quiesced, backend-exact
quiesce evidence kind 0..2: none, guest-acknowledged, backend-acknowledged
signature purpose 0..3: policy, tree, snapshot, distribution
ACL tag 0..5: user-object, named-user, group-object, named-group, mask, other
```

Limit dimensions `0..15` are initially assigned to bytes, inodes, processes,
memory, CPU weight, CPU quota, I/O weight, I/O bandwidth, mount count, open
files, FUSE requests, FUSE memory, cache bytes, snapshot count, child count,
and execution count. Values `16..31` are reserved and rejected in v1. The
registry file introduced with the implementation is generated into every
encoder and decoder; numbers cannot be reused or locally reinterpreted.

Every descriptor is also validated against this closed field-role table;
matching digest bytes with the wrong media type is invalid:

| Descriptor field | Permitted media type |
| --- | --- |
| directory child; tree root | directory |
| whole content; sparse extent | raw content |
| delta base/result | tree |
| delta added object | directory, raw content, or another object reachable from the declared result under this table |
| immutable view source | tree |
| environment closure | raw content, tree, or a media type registered by a required environment feature |
| sandbox environment/root view | environment/view |
| tree selector | tree |
| optimization commitment | optimization |
| snapshot spec/policy/environment | spec/policy/environment |
| snapshot private root | tree or delta |
| snapshot attachment | view |
| portable storage state | tree or delta |
| immutable-view/package retention or dependency | view/environment as named by its union arm |
| content retention | raw content or a closed portable object reachable from the snapshot |
| signature verification policy | trust-policy |
| policy explanation source | a descriptor also present in policy input commitments |

`profile-selector.body` and the feature-owned roles above are legal only when
the containing object lists that exact required feature and the registry entry
defines one media type, canonical schema, affected role, version rule, and
golden fixture digest. RFC-0019 registers no generic opaque body and no
backend-exact checkpoint payload. Adding one is a portable-format change with a
checked-in registry entry; arbitrary media types or locally interpreted
feature names fail closed.

### Initial feature registry

Only these exact `(namespace, major, minor)` triples have base-v1 semantics;
all others are unknown required features until a later RFC adds their schema
and compatibility rule:

| Feature triple | Permitted role and v1 meaning |
| --- | --- |
| `aos.sandbox.runtime.linux-systemd, 1, 0` | `sandbox-spec.runtime-profile`; booted Linux userspace with private user/PID/mount/UTS/IPC/network namespaces under the shared-kernel tier |
| `aos.sandbox.identity.posix32, 1, 0` | view identity presentation and identity requirements; exact unsigned 32-bit UID/GID plus the spec's range/unmappable policy |
| `aos.sandbox.metadata.posix-acl, 1, 0` | required by a tree with non-null ACL; the canonical ACL array and mode-mask consistency rules in this profile |
| `aos.sandbox.symlink.absolute, 1, 0` | permits absolute symlink target bytes while retaining ordinary consumer-namespace resolution |
| `aos.sandbox.symlink.parent-escape, 1, 0` | permits a relative target whose lexical components can escape the view root; it grants no extra destination access |
| `aos.sandbox.enforcement.cgroup-v2, 1, 0` | limit enforcement for memory, CPU, process, and I/O dimensions under the cgroup contract |
| `aos.sandbox.enforcement.broker-ledger, 1, 0` | limit enforcement for mount, FD, FUSE, cache, child, snapshot, and execution admissions |
| `aos.sandbox.enforcement.zfs-quota, 1, 0` | storage/snapshot dimensions under the stated ZFS quota and reservation contract |
| `aos.sandbox.residency.node-bounded-shared, 1, 0` | shared immutable cache residency is bounded at node scope with logical consumer reservations; no fair physical memcg attribution claim |
| `aos.sandbox.residency.hard-isolated, 1, 0` | requires a separately proven backing cache identity and enforceable tenant/domain residency bound or placement fails |
| `aos.sandbox.storage.portable, 1, 0` | storage checkpoint whose portable state is a tree or delta and has no backend-private payload |
| `aos.sandbox.storage.zfs-held-snapshot, 1, 0` | same required portable state plus a storage-retention receipt for an exact held snapshot; no dataset name or token enters the object |
| `aos.sandbox.quiesce.guest, 1, 0` | guest acknowledgement plus SHA-256 of the bounded audit transcript retained outside the snapshot |
| `aos.sandbox.quiesce.storage, 1, 0` | backend flush/freeze acknowledgement plus SHA-256 of the bounded audit transcript retained outside the snapshot |

No base-v1 feature registers a `profile-selector.body`, extra environment
media type, opaque backend state, or service checkpoint schema. Such a field is
therefore rejected rather than interpreted by local convention.

Collections whose schema role is a set sort by the complete canonical CBOR
encoding of each element and reject duplicates. This applies to feature sets,
descriptor/object sets, grants, retention claims, external dependencies, and
advisory optimizations. Trust-policy keys sort by stable key ID then generation
and reject either duplicate pair. Environment closure descriptors sort the same
way; environment entries sort by name and reject duplicate names. Limits sort
by dimension, attachment slots and network endpoint IDs by UID, attachment
snapshots by destination slot, and storage checkpoints by backend feature
identity, with duplicate keys rejected. Xattrs, ACLs, directories, sparse
extents, and hard-link member paths use their more specific ordering rules.

Only these arrays are semantic sequences whose order is preserved: path
components, command-search paths, policy input commitments, ordered view
and presentation actions, and ancestry from root to immediate parent. A writer
cannot choose an arbitrary order for any other collection, and a reader rejects
rather than normalizes noncanonical order. Array order is therefore either
explicit semantics or a unique set encoding.

## Tree objects

A tree revision names one root directory descriptor and its required feature
set. A directory object carries its own metadata and an array of entries sorted
by unsigned bytewise name. An entry contains name bytes, node kind, and its
kind body:

- regular file: metadata, exact content layout, and optional hard-link group;
- directory: descriptor of another directory object, which owns that
  directory's metadata;
- symlink: metadata and target bytes, which may contain `/` but not NUL; and
- no other kind in the generic portable profile.

Live sockets, FIFOs, and device nodes are never portable tree entries. An
authorized device is an external typed attachment. A materializer encountering
a source special node either rejects it or applies an explicitly named
source-specific normalization outside the generic profile.

Directory objects may be content-deduplicated, but object aliasing does not
create directory inode identity. Presentation identity is derived from view
revision and full relative path. Directory hard links are prohibited. Graph
validation detects repeated traversal, depth, and total expanded entry limits;
a digest graph cycle is invalid even if constructed through a malicious object
resolver.

Regular file content is represented by exact logical size and either:

- one immutable content descriptor when the source reports no holes; or
- maximal, sorted, non-adjacent non-hole extents plus implicit holes when the
  source reports at least one hole.

Zero-length files always use a whole-content descriptor for the canonical empty
raw object. A nonempty all-hole file uses sparse form with no extents. Every
other sparse extent has positive length, spans the complete maximal data run,
and contains a content descriptor whose size exactly equals that length.
Extents cannot touch, overlap, overflow, or extend beyond logical size. A
source/backend that cannot report stable hole boundaries normalizes the file to
whole content and does not advertise sparse preservation. Thus arbitrary
chunking, a full-range sparse extent, and zero-length extents are invalid rather
than alternate identities. Compression is a transfer/storage property of a
referenced content object, never an ambiguity in logical bytes.

Reported hole topology is intentional portable metadata because consumers may
observe it through allocation and `SEEK_HOLE`; equal logical bytes with
different normalized hole topology may therefore have different identities.

Two paths with equal bytes are not automatically hard linked. A hard-link
group is present only when source semantics require shared inode identity. Its
identifier is `SHA256("aos-sandbox-hardlink-v1\0" || canonical-CBOR([paths,
metadata, content-layout]))`, where paths are sorted by component byte order.
Every member must
appear exactly once within the same tree revision and have identical file
objects and metadata. Presentation inode identity derives from view revision
plus this group identifier; ungrouped files derive it from full path.

Symlink targets preserve bytes. Absolute targets and targets that can walk
above the view root require an explicit presentation feature; ordinary VFS
resolution may still enter another location in the consumer namespace. The
portable format does not claim symlink-based confinement.

## Tree validation and feature negotiation

The root object declares every required semantic feature. Registered feature
IDs have an owner namespace, major version, precise affected fields, and golden
fixtures. A reader rejects unknown required features. Optional provenance or
observation extensions do not alter tree identity or authorize a feature.

Validation is two-pass and bounded. The first pass validates canonical bytes,
descriptors, local types, sizes, ordering, and collection limits. The second
walk validates graph reachability, expanded node/depth bounds, hard-link group
membership, content extents, aggregate logical bytes, feature closure, and the
absence of cycles. No FUSE worker maps or serves an index until both passes and
the index validator succeed.

## Delta objects

V1 deltas are canonical final-tree deltas, not ordered syscall journals. A
delta commits to:

- exact base tree descriptor;
- exact result tree descriptor;
- the set of result graph objects not already reachable from the base;
- required feature set.

Applying a delta verifies the base identity, adds verified immutable objects,
and resolves the declared result. Equivalent final trees therefore have the
same result identity regardless of rename order, overlay whiteouts, ZFS object
numbers, or editor syscall history. Optional transfer/change hints travel in
an unsigned observation or transport sidecar outside the canonical delta. They
never affect delta or result-tree identity and cannot authorize access.

Overlayfs and ZFS are extraction sources. Their whiteouts, redirect xattrs,
opaque directories, inode numbers, and transaction IDs never become portable
semantics.

## View objects

A view object commits to either an immutable tree descriptor or an exact live
export owner/export/generation, an ordered presentation program, consistency
and mutation modes, identity-presentation feature, disclosure domain, and
required features. Presentation includes and excludes use byte-component
source/destination paths; overlapping destinations or a rule that depends on
host path traversal is invalid. The attachment separately commits its
destination slot and may only narrow the view's mutation mode.

An immutable snapshot attachment must use an immutable-tree source. A live
export remains an external dependency even when mounted read-only; serializing
its generation does not make it self-contained. Realizer choice, mount path,
FUSE connection, backing IDs, and cache residency do not enter the object.

## Environment and sandbox specification objects

An environment object commits to immutable package/content closure
descriptors, sorted UTF-8 environment entries, an ordered command-search path,
and required semantic features. It contains no host store path, daemon socket,
credential, or mutable channel. Variable names must satisfy the selected
environment feature in addition to the CDDL length bound; duplicate names are
invalid. Values are data and are never reinterpreted as policy expressions.

A sandbox specification commits to the requested runtime feature, inline
closed identity/resource/network profiles, environment and root-view
descriptors, sorted attachment-slot UIDs, and required features. The identity
profile states the portable ID-range need and fail-closed unmappable policy;
node UID/GID allocation remains assignment state. The exceptional host-identity
union arm contains no inapplicable range or unmappable fields. Resource limits
use the same typed limit schema as resolved policy.

Network endpoint IDs are sorted logical network-policy resources, never
addresses, interfaces, or rules. Isolated and exceptional host-network kinds
require an empty endpoint list; project, outbound, and published kinds list
only resources valid for that profile kind. The spec does not commit placement,
runtime PID, host paths, active credentials, or observed backend state. Those
are assignment or observation data and are re-created during restore.

An optimization object is an advisory, separately addressed list. A policy
may commit to it, but removing or ignoring it cannot add a grant, relax a hard
limit, change a view revision, or satisfy a required enforcement feature.

## Policy objects

Canonical policy encodes the normalized typed result, never the source Nix or
backend option text. It contains:

- policy schema and feature versions;
- node, site/project, ancestor, and request input commitments;
- effective grants and delegable subsets;
- resource bounds and named enforcement mechanism requirements;
- namespace/view actions using logical descriptors and slots;
- disclosure/cache domains;
- revocation and snapshot behavior;
- advisory optimization in a separately committed section; and
- a bounded explanation-reason table.

Sets and maps sort by their canonical key; semantically duplicate grants fail.
`inherit` is eliminated during resolution. `unlimited` retains the authorizing
grant UID. Unknown policy fields, action kinds, selector kinds, enforcement
mechanisms, and required features fail closed.

AOS/Nix/Git-specific predicates live in registered `aos.*` feature profiles
layered over the generic sandbox, view, resource, and lifecycle vocabulary.
Implementations that do not support one reject the required feature without
needing to interpret its body.

## Snapshot objects

The canonical snapshot is execution-independent. It contains exact
descriptors for effective historical policy, private roots/deltas, environment,
attachments, owned storage checkpoints, and external dependencies; sandbox
ancestry; consistency/quiesce evidence; required restore capabilities; and the
source assignment/incarnation as provenance.

It contains no credential, capability handle, secret byte, node path, PID,
namespace/mount ID, unit name, dataset name, cache-residency promise, active
connection, operational hold/lease/service token, or mutable registry tag.
Closed retention-claim unions commit resource identity, immutable version,
non-secret receipt digest, and any availability bound. The usable token remains
in the controller retention ledger and is not derivable from the digest.
Receipt algorithm `1` is SHA-256 over the exact bounded non-secret
acknowledgement bytes stored by that ledger. The digest correlates the manifest
with the acknowledgement; it is neither proof of current availability nor
release authority. Import into another control domain acquires new retention
before that domain marks the snapshot self-contained.

External dependencies use closed kind-specific unions. A required secret names
issuer, secret UID, opaque version, restore scope, and expiry; a service names
an opaque checkpoint version, its SHA-256 digest, and availability; a network
dependency names a logical endpoint and opaque contract version. Null or
inapplicable fields cannot be encoded, and `none` quiesce evidence has no
result field. Restore always performs current authorization and produces new
policy, assignment, and incarnation records.

Portable storage state is a tree or delta. Base v1 has no backend-private
checkpoint field: architecture, CPU/device, kernel, or process-memory state
requires a later snapshot media type and registered compatibility schema. A
held ZFS snapshot accelerates restoration through the controller retention
ledger, but the required portable state remains complete and independently
verifiable.

## Signatures and trust

`application/vnd.aos.sandbox.signature.v1+cbor` contains the explicit
`signature-statement-v1` CDDL object and a 64-byte signature. The statement
binds subject descriptor, trust scope, stable signer key ID, immutable key
generation, public-key SHA-256 fingerprint, typed usage, algorithm, purpose,
issue time, optional expiry, and trust-policy descriptor. V1 uses Ed25519 and
AOS trust-root/key-rotation policy. Signature bytes are detached from the
subject and cannot change its identity.

The fingerprint is SHA-256 over the raw 32-byte Ed25519 public key, not PEM,
DER, a certificate, or a display string.

The Ed25519 input is exactly the ASCII bytes
`aos-sandbox-signature-v1\0` followed by the canonical CBOR encoding of the
`signature-statement-v1` value. Verification never derives a shorter array by
editing a signature object and never signs a re-encoded map, display
projection, or object descriptor alone.

The signer key reference must appear byte-for-byte in the referenced
trust-policy generation, match its scope/purpose and current revocation state,
and carry the corresponding typed usage. Purpose-to-subject rules are closed:
policy signs policy; tree signs tree, directory, delta, view, or environment;
snapshot signs snapshot or spec; distribution signs raw content or any
portable CBOR object while adding no authority. A mismatched purpose, usage,
fingerprint, generation, subject media type, or trust scope fails.

Authorization is not inferred from a valid signature alone. The verifier
checks current key purpose, project scope, revocation/rotation state,
provenance requirements, descriptor, media type, and restore policy. Mirrors
may copy signed bytes but cannot broaden their disclosure domain.

## Distribution envelope

V1 transport is the AOS content-addressed descriptor graph over authenticated
Hub or node protocols. Correctness depends on immutable descriptors and signed
roots, never a mutable tag. HTTP Range, local CAS, ZFS send/receive, NAR, Git,
and OCI are source or transport adapters.

OCI artifact manifests are not the canonical v1 sandbox envelope. A later OCI
mapping may assign artifact/media types and platform fields, but registry
annotations, tags, and optional referrer retention cannot carry semantic or
correctness state. This avoids making an in-flight distribution convention a
dependency of the portable filesystem model.

## Decoder evolution

Canonical v1 objects are strict. Readers do not ignore unknown keys or enum
values and do not rewrite noncanonical encodings into a signed identity. A
future additive semantic format receives a new registered media type or
required feature whose exact canonical fields were reserved by the schema.

Observation extensions and protobuf unknown-field behavior are unrelated to
this rule. No general `Any`, JSON object, source-specific map, or backend option
bag occurs inside authority-bearing canonical objects.

## Golden vectors

These small vectors pin the framing and deterministic integer/array encoding.
Hex is lowercase without separators.

```text
raw content object
media type: application/vnd.aos.sandbox.content.v1
stored bytes: 68656c6c6f
encoded size: 5
framed SHA-256: a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903

empty directory object (mode 0755, uid/gid/mtime zero, no xattrs/ACL)
media type: application/vnd.aos.sandbox.directory.v1+cbor
canonical CBOR: 8301871901ed0000000080f680
encoded size: 13
framed SHA-256: 5853385fc82f12431186748ae0f949dd0c88afd3295ff9b2902bccbb3eacb69d

Ed25519 signature statement (RFC 8032 test-key public key)
public key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
public-key SHA-256: 21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9
statement CBOR: 890184782a6170706c69636174696f6e2f766e642e616f732e73616e64626f782e706f6c6963792e76312b63626f7201582000000000000000000000000000000000000000000000000000000000000000000050000102030405060708090a0b0c0d0e0f8468746573742d6b657901582021fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b900010000f68478306170706c69636174696f6e2f766e642e616f732e73616e64626f782e74727573742d706f6c6963792e76312b63626f72015820111111111111111111111111111111111111111111111111111111111111111100
domain-separated preimage SHA-256: 5e5ec9e08a6b30742772fad729cc3bdbdaa0cd4a90c83f5e8019f04f337450a3
signature: 178954bd499ff335316e416d4b0f35801e04e06ee5978e7305b78b5151f6dac09b8d8520301f64cff1af6d9deecdd39439ceb0b3a48c1358f340eef7ef74e807
```

The signature vector uses syntactically valid synthetic descriptors to isolate
statement encoding and Ed25519 verification. Full graph validation additionally
requires those subject and trust-policy descriptors to resolve and pass their
field-role checks.

The phase-1 conformance suite adds at least one vector for every CDDL union,
integer-width boundary, metadata feature, sparse layout, hard-link group,
policy action, snapshot dependency, equivalent-but-differently-chunked sparse
representation, and invalid noncanonical encoding before a
v1 writer or media type is released. Those additions may improve coverage but
cannot alter these three root vectors or the normative schemas.
