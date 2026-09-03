# Portable format profile

## Scope

Portable policy, filesystem tree, delta, and snapshot objects use one exact
encoding profile so independent implementations compute identical identities.
This profile is separate from protobuf RPC messages and from the replaceable
node-local mmap index.

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
application/vnd.aos.sandbox.environment.v1+cbor
application/vnd.aos.sandbox.optimization.v1+cbor
application/vnd.aos.sandbox.spec.v1+cbor
application/vnd.aos.sandbox.snapshot.v1+cbor
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
- permission and file-type mode: unsigned 16-bit masked by the profile;
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
operation bits 0..13: discover, metadata-read, content-read, execute, create,
  content-write, remove, rename, link, metadata-write, attach,
  lifecycle-control, delegate, publish
view mode 0..4: read-only, read-write, copy-on-write, append-only, service
cache domain 0..3: private, project, trust-domain, public
revocation mode 0..2: deny-new, freeze, stop
selector kind 0..3: resource, tree, path, profile
view action kind 0..3: include, exclude, attach, present
limit value kind 0..2: inherited, bounded, unlimited
optimization kind 0..7: prefetch-metadata, prefetch-content, readahead,
  directory-index, passthrough, keepalive, cache-weight, worker-pooling
reason code 0..10: site-ceiling, project-ceiling, ancestor-ceiling,
  caller-grant, resource-limit, disclosure-domain, revocation,
  backend-requirement, attachment-conflict, environment-policy, default
retention kind 0..4: storage-hold, content-lease, nix-gc-root,
  service-token, secret-reference
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

Every descriptor is also validated against its field role. For example, a
tree root names a directory object, file content names the raw content media
type, a policy optimization commitment names an optimization object, and the
snapshot environment and sandbox specification name their registered media
types. Matching digest bytes with the wrong media type is invalid.

Collections whose schema role is a set sort by the complete canonical CBOR
encoding of each element and reject duplicates. This applies to feature sets,
descriptor/object sets, grants, retention roots, external dependencies, and
advisory optimizations. Environment closure descriptors sort the same way;
environment entries sort by name and reject duplicate names. Limits sort by
dimension, attachment slots by UID, attachment snapshots by destination slot,
and storage checkpoints by backend feature identity, with duplicate keys
rejected. Xattrs, ACLs, directories, sparse extents, and hard-link member paths
use their more specific ordering rules.

Only these arrays are semantic sequences whose order is preserved: path
components, command-search paths, policy input commitments, ordered view
actions, and ancestry from root to immediate parent. A writer cannot choose an
arbitrary order for any other collection, and a reader rejects rather than
normalizes noncanonical order. Array order is therefore either explicit
semantics or a unique set encoding.

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

- one immutable content descriptor; or
- sorted, non-overlapping sparse extents plus implicit holes.

Each extent contains offset, length, and a content slice descriptor whose size
exactly equals length. Extents cannot overflow or extend beyond logical size.
The all-hole file has no content descriptor. Compression is a transfer/storage
property of a referenced content object, never an ambiguity in logical bytes.

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

## Environment and sandbox specification objects

An environment object commits to immutable package/content closure
descriptors, sorted UTF-8 environment entries, an ordered command-search path,
and required semantic features. It contains no host store path, daemon socket,
credential, or mutable channel. Variable names must satisfy the selected
environment feature in addition to the CDDL length bound; duplicate names are
invalid. Values are data and are never reinterpreted as policy expressions.

A sandbox specification commits to the requested runtime profile, descriptors
for identity and resource profiles, environment and root view, sorted
attachment-slot UIDs, optional network profile, and required features. Each
profile descriptor's media type is declared by its required feature. The spec
does not commit placement, runtime PID, host paths, active credentials, or
observed backend state. Those are assignment or observation data and are
re-created during restore.

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
connection, or mutable registry tag. External dependencies name immutable
versions or explicit checkpoint tokens. Restore always performs current
authorization and produces new policy, assignment, and incarnation records.

Backend-local checkpoints are subordinate descriptors with exact backend,
version, architecture, CPU/device, kernel, and compatibility profile. They do
not change the portable snapshot's claims.

## Signatures and trust

`application/vnd.aos.sandbox.signature.v1+cbor` signs a domain-separated
statement containing subject descriptor, project/trust scope, signer key ID,
algorithm, purpose, issue time, optional expiry, and required verification
policy. V1 uses Ed25519 and AOS trust-root/key-rotation policy. Signature bytes
are detached from the subject and cannot change its identity.

The Ed25519 input is exactly the ASCII bytes
`aos-sandbox-signature-v1\0` followed by the canonical CBOR encoding of the
signature array with its final `signature` element omitted. Verification
reconstructs that preimage; it never signs or verifies a re-encoded map,
display projection, or object descriptor alone.

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
```

The phase-1 conformance suite adds at least one vector for every CDDL union,
integer-width boundary, metadata feature, sparse layout, hard-link group,
policy action, snapshot dependency, and invalid noncanonical encoding before a
v1 writer or media type is released. Those additions may improve coverage but
cannot alter the two root vectors or the normative schemas.
