# RFC-0017 architecture

## Artifact pipeline

```text
Nix container definition
        |
        +-- realized AOS reference graph
        |       +-- deterministic store layers
        |
        +-- deterministic root metadata layer
        +-- OCI config and platform manifest
        +-- multi-platform OCI index
                         |
                  OCI image layout
                         |
               aos container publish
                         |
        +----------------+----------------+
        |                                 |
Hub OCI Distribution API             Hub control plane
/v2/...                              Connect RPC and console
Docker-compatible clients            trust, retention, GC
```

The build plane and distribution plane share descriptors and digest validation,
but neither depends on the other. An OCI layout remains useful without Hub, and
Hub accepts conforming OCI clients without invoking Nix.

## Nix evaluation model

Container definitions form a separate module evaluation from AOS system
definitions. This avoids retaining a kernel or bootable toplevel while still
allowing a definition to derive its package policy from a golden system.

The initial evaluation exports:

```text
containerImages.aos.platforms.<aos-system>.ociLayout
containerImages.aos.platforms.<aos-system>.ociArchive
containerImages.aos.platforms.<aos-system>.dockerArchive
containerImages.aos.platforms.<aos-system>.metadata
containerImages.aos.ociIndex
containerImages.aos.checks
```

Flake aliases expose the canonical artifacts without making their derivation
names part of the OCI identity.

The option schema owns:

- name and supported target platforms;
- package roots and exact outputs;
- ordered named layer plan;
- users, groups, directories, files, and executable facade links;
- OCI entrypoint, command, environment, user, working directory, stop signal,
  ports, and annotations;
- AOS CLI/package-manager runtime policy;
- closure, layer-count, and artifact budgets;
- publication metadata and signed-release identity.

There is intentionally no base-image option. Authored files enter through Nix
store derivations and are public image content. Secrets have no representation
in the definition schema.

## Closure inventory

Layer contents come from structured `exportReferencesGraph` output. Each graph
item includes its store path, NAR hash, NAR size, and references. This realized
graph is authoritative because derivation inputs may include build-only tools
and because reference scrubbing can remove declared dependencies from outputs.

Every image emits a companion closure manifest containing:

- store path;
- selected output;
- NAR hash and size;
- direct references;
- owning layer name and digest;
- package name/version/license/source identity where available.

The manifest is used by closure audits, Hub projections, SBOM generation,
source-retention checks, shared-layer reporting, and AOS-aware verification.

## Layer builders

### Store layer

A store layer is defined by `roots` and `subtractRoots`:

```text
contents = closure(roots) - union(closure(subtractRoots))
```

The builder sorts full store paths, verifies every source exists, rejects path
collisions, and stages them as relative `nix/store/<basename>` entries. Store
layers are additive and never need OCI whiteouts.

Archive policy is part of the layer ABI:

- AOS GNU tar 1.35 and AOS gzip 1.13;
- one NUL-delimited member list produced by AOS findutils `find -mindepth 1
  -printf '%P\\0'` and AOS coreutils `sort -z`;
- no implicit root member and no recursive tar traversal;
- GNU tar format with relative names and no leading `./`;
- `--mtime=@1 --clamp-mtime`;
- `--owner=0 --group=0 --numeric-owner` for the initial root-owned image;
- `--no-acls --no-selinux --no-xattrs`;
- `--hard-dereference`, so host Nix-store optimization cannot leak
  nondeterministic cross-path hardlinks into a layer;
- preserved permission bits and symlink targets;
- rejection of sockets, devices, and FIFOs before archiving;
- gzip level 9 with `-n`, fixing the filename and timestamp header fields;
- no PAX headers, host names, absolute member names, atime, or ctime metadata.

The exact tar invocation is:

```text
tar -C root --null --verbatim-files-from --no-recursion --format=gnu \
  --mtime=@1 --clamp-mtime --owner=0 --group=0 --numeric-owner \
  --no-acls --no-selinux --no-xattrs --hard-dereference \
  -cf layer.tar --files-from="$PWD/members"
gzip -n -9 -c layer.tar > layer.tar.gz
```

The `aos.container.layer/v1` golden fixture has these hashes:

```text
uncompressed sha256:6e30729d0413d5fb0dba4d0573093a4950e81cd45d7a9ebc2f62f09746b07ea5
gzip        sha256:1ec9791d8b0b3458830e5156881293d288941e793bb73790f85ad35f168a51d0
```

Changing any command, version, flag, fixture byte, or expected hash is a layer
ABI change. Metadata requiring non-root ownership will use an explicit second
archive policy version rather than silently changing v1.

The SHA-256 of the uncompressed tar is the DiffID. The SHA-256 of the stored
compressed bytes is the OCI descriptor digest. Both are recorded with exact
sizes.

### Metadata layer

The metadata layer supplies the scratch filesystem contract:

- `/bin`, `/usr/bin`, `/usr/sbin`, and optional shell links;
- minimal passwd, group, and shadow files;
- CA trust aliases and environment;
- OS release identity;
- `/tmp`, HOME, work, XDG, APM, profile, and Nix state directories;
- the embedded closure registration stream and container init executable;
- collision-checked executable links into `/nix/store`.

It omits runtime-owned hostname, hosts, and resolver files. Application-specific
metadata is kept in the final layer so it cannot invalidate reusable store
layers.

### Image and index

The image assembler reads layer descriptor files during its build. It writes
canonical compact config and manifest JSON, records ordered DiffIDs, copies
every blob into `blobs/sha256/<digest>`, and emits `index.json` plus
`oci-layout`. Outputs are self-contained regular files rather than links to Nix
inputs.

The multi-platform index points at independently built `linux/amd64` and
`linux/arm64` manifests. The exact AOS target platform remains in an annotation.

## Stable layer families

Layer reuse is explicit rather than optimized independently per image. The
initial policy defines reusable cumulative cohorts:

1. scratch filesystem skeleton;
2. runtime core, including libc/compiler runtime and CA trust;
3. optional shell core;
4. AOS CLI closure minus the preceding roots;
5. future workload-family roots minus the canonical prefix;
6. future application-specific closure delta;
7. final launch, identity, and registration metadata.

Changing an individual package should invalidate only the cohorts whose exact
contents changed. Hub reports potential common cohorts, but adopting one is a
reviewed Nix source change. Automatic greedy packing is prohibited because it
causes unrelated layer digest churn.

## Runtime contract

The `aos` image uses the exact package roots from the production server golden
system. A generated executable facade provides the same interactive command
names, with the AOS profile path ordered ahead of the baked facade so packages
installed later by APM can add commands.

The image authors an empty `0600`
`/nix/var/nix/.aos-container-init.lock`. The initializer recreates and
re-protects that file when an operator replaces Nix state with an empty mount.
It then performs this idempotent transaction while holding the lock
exclusively:

1. validate the immutable golden-root list against the embedded closure;
2. remove readiness state from an earlier PID-1 lifecycle;
3. build a fresh GC-root directory containing one absolute symlink per golden
   package root and atomically replace `/nix/var/nix/gcroots/aos-container-baked`;
4. create the local Nix database if absent;
5. load the embedded registration stream;
6. run a validity check for every baked root;
7. create the user APM, XDG, and profile directories;
8. publish a persistent read-only marker when the store cannot be mutated;
9. publish a readiness marker bound to the current PID-1 start time;
10. release the lock and execute the requested argv without a shell reparse.

Root reconciliation happens on every start, including when an operator mounts
an initially empty Nix database directory. GC-root names are the complete store
basename, roots must appear in the signed embedded list, and a malformed or
missing root aborts init. Root publication precedes database initialization and
registration, so even a concurrent runtime `exec` cannot observe valid baked
paths during an unrooted interval. Tests run Nix GC and APM GC before rechecking
all baked roots and representative commands.

Container runtimes can start a second process while the entrypoint is still
initializing, and that process does not inherit environment changes made by PID
1. Every `aos`, `apm`, and `apr` process with exact
`AOS_RUNTIME=container` therefore consults filesystem state. A process with a
writable state directory waits for a readiness marker matching `/proc/1/stat`
field 22, acquires the init lock in shared mode, and rechecks the marker while
serialized with initialization. It derives read-only admission from direct
state/store write probes and the persistent marker, not only from
`AOS_CONTAINER_READ_ONLY`. Host-only package commands are rejected before the
wait so they cannot use container initialization as an alternate host path.

The marker bytes are versioned data contracts:

```text
/nix/var/nix/.aos-container-ready:
schema=aos.container.ready/v1
pid1_start_time=<decimal /proc/1/stat field 22>

/nix/var/nix/.aos-container-read-only:
schema=aos.container.read-only/v1
```

Malformed persistent markers fail closed. A fully read-only state directory
cannot publish markers, so clients classify it as read-only directly without
waiting for an impossible write.

The entrypoint is intentionally exec-only. It is not a supervisor or
subreaper: the requested program becomes PID 1, receives runtime signals
directly, and determines its own child-reaping behavior. Long-running workloads
that need generic orphan reaping use the runtime's init option, such as Docker
`--init`, or provide an explicit AOS-packaged supervisor in a future image.

The Nix daemon is neither present nor contacted. The default database is
single-user and the build-users group is empty.

### APR credentials and operator-provided tools

The image never contains registry credentials, signing keys, private trust
anchors, or SSH agent sockets. Producer-side APR commands receive those inputs
through explicit runtime mounts:

- mount user registry configuration and pinned public keys below
  `/root/.config/apm`, read-only unless APR must update the configuration;
- mount additional public CA roots at a dedicated path and set
  `SSL_CERT_FILE` and `NIX_SSL_CERT_FILE` to the mounted bundle;
- mount private signing-key files read-only at an operator-selected path and
  reference that path from APR configuration instead of copying key bytes into
  the image or environment;
- forward an SSH agent socket at an operator-selected path and set
  `SSH_AUTH_SOCK` for SSH-backed registry operations; and
- mount any program named by an APR key command or filter, then include its
  directory in `AOS_HOST_PATH`. The hermetic AOS wrapper deliberately restores
  that caller-supplied path only for the configured external command.

Mounts must use the narrowest required permissions. In particular, a signing
key, agent socket, or Hub/APM token is never part of an OCI layer, image config,
label, or default environment value. Consumer-side package installation needs
none of these producer credentials.

`AOS_ROOT` remains unset because the ordinary container store is the canonical
`/nix/store`. System-scope APM and host activation operations detect the
container runtime marker and return an actionable unsupported-operation error.

## Hub ownership and object model

Every OCI repository belongs to one AOS registry. Every registry has exactly
one active OCI delivery authority, either a Hub-provided stable wildcard name
or a custom domain. An authority with the OCI route capability maps to exactly
one registry and must use `/` as its route base; a route with an arbitrary
pre-`/v2` prefix is rejected because standard clients cannot express it.

For a registry whose authority is `r-abcd.containers.hub.example`, the pull
name is:

```text
r-abcd.containers.hub.example/aos:1.0.0
```

The Distribution router resolves the authority to the registry before parsing
the repository. Token service/audience is the canonical lowercase authority.
Token scope is the exact canonical repository local to that registry, for
example `repository:aos:pull`. Native and Worker shard keys are
`(registry stable ID, repository)`. Authority uniqueness prevents collisions
between equal repository names in different registries and makes public/private
lookup occur only after registry selection.

The registry object namespace is:

```text
oci/blobs/sha256/<hex digest>
```

All OCI objects, including configs, manifests, indexes, and artifact
manifests, are immutable blobs. Mutable tags are database pointers and
publication history records, not independently uploaded object bodies.

Normalized catalog projections include:

- OCI repositories and lifecycle state;
- per-registry blob identity and placement;
- repository-to-blob authorization links;
- exact manifest bytes and bounded parsed metadata;
- ordered config, layer, child, subject, and referrer descriptor edges;
- tags and append-only tag history;
- signed AOS release roots;
- upload sessions and quota reservations;
- publication transactions;
- retention policies, leases, and GC generations.

Quota is charged once per registry digest. Linking an existing blob into a
second repository changes logical reachability but not stored-byte usage.
Physical quota is released only after every required placement confirms
deletion.

## Distribution data plane

Hub implements the OCI Distribution API under `/v2/`, including:

- registry discovery;
- blob fetch and existence checks;
- resumable upload and cancellation;
- digest-verified upload finalization;
- cross-repository mount;
- manifest and index fetch, publication, and deletion;
- tag enumeration;
- OCI referrer discovery.

Manifest bytes are preserved exactly because serialization is part of their
digest. Parsed records are bounded projections and never replace the original
body. Schema 1 manifests are rejected; OCI image/index and Docker schema 2
media types are accepted according to an explicit compatibility matrix.

The first-release media-type allowlist is:

- `application/octet-stream`, used only as the generic storage type while a
  Distribution blob upload has not yet been admitted in a repository-specific
  manifest role;
- `application/vnd.oci.image.manifest.v1+json`;
- `application/vnd.oci.image.index.v1+json`;
- `application/vnd.oci.image.config.v1+json`;
- `application/vnd.oci.image.layer.v1.tar`;
- `application/vnd.oci.image.layer.v1.tar+gzip`;
- `application/vnd.oci.image.layer.v1.tar+zstd` for pull/push interoperability,
  although the AOS builder emits gzip initially;
- `application/vnd.docker.distribution.manifest.v2+json`;
- `application/vnd.docker.distribution.manifest.list.v2+json`;
- `application/vnd.docker.container.image.v1+json`;
- `application/vnd.docker.image.rootfs.diff.tar`;
- `application/vnd.docker.image.rootfs.diff.tar.gzip`;
- `application/vnd.oci.empty.v1+json`, whose only accepted body is canonical
  `{}` and which is used as an artifact manifest config;
- `application/vnd.aos.container-release.v1+json`;
- `application/vnd.aos.nix-closure.v1+json`;
- `application/vnd.aos.source-closure.v1+json`;
- `application/vnd.aos.source-closure.v1.tar+gzip`;
- `application/vnd.aos.license-report.v1+json`;
- `application/spdx+json`, restricted initially to SPDX 2.3 JSON;
- `application/vnd.in-toto+json`, restricted to the versioned AOS provenance
  predicate;
- `application/vnd.dsse.envelope.v1+json` for signed attestation envelopes.

Descriptors with external URLs and foreign/nondistributable layer media types
are rejected initially. OCI artifacts use an OCI image manifest with a required
`artifactType` and `subject` plus the canonical empty config. Every artifact
except corresponding source has exactly one bounded JSON payload layer from
the AOS artifact allowlist. A source-closure artifact has exactly two ordered
layers: its bounded JSON inventory followed by its deterministic gzip source
archive; the archive size is controlled by repository quota and descriptor
bounds rather than the JSON limit. The signed
`containers/v1/index.json` sidecar is validated using the
`application/vnd.aos.container-release.v1+json` schema whether it is read from
Git or exposed as a referrer. Adding a media type is an API compatibility change
with parser, runtime, storage, and GC coverage.

Protocol errors use the Distribution error vocabulary: `BLOB_UNKNOWN`,
`BLOB_UPLOAD_INVALID`, `BLOB_UPLOAD_UNKNOWN`, `DIGEST_INVALID`,
`MANIFEST_BLOB_UNKNOWN`, `MANIFEST_INVALID`, `MANIFEST_UNKNOWN`,
`NAME_INVALID`, `NAME_UNKNOWN`, `SIZE_INVALID`, `TAG_INVALID`, `UNAUTHORIZED`,
`DENIED`, `UNSUPPORTED`, and `TOOMANYREQUESTS`. AOS-specific detail is carried
in bounded message/detail fields without inventing incompatible error codes.

### Admission limits

The first release applies these per-object and per-graph limits before
allocation or traversal:

| Limit | Value |
| --- | ---: |
| Manifest, index, config, or artifact JSON | 4 MiB |
| Descriptors in one manifest or index | 1,024 |
| Platforms in one index | 256 |
| Layers in one runnable image | 64 |
| Descriptor graph depth | 8 |
| Reachable descriptors in one publication | 65,536 |
| Annotation key | 1 KiB |
| Annotation value | 4 KiB |
| Total annotations on one object | 64 KiB |
| Repository name | 255 bytes |
| Tag | 128 bytes |
| Upload session lifetime | 24 hours |

Blob size is bounded by registry quota and an explicit deployment maximum,
with checked 64-bit arithmetic. Parsed descriptor counts and sizes are checked
before recursive graph work. Deployments may lower operational byte limits but
cannot raise structural limits without changing this compatibility contract.

### Canonical references

Repository, tag, digest, routing, authorization, and sharding code use one
shared ASCII parser. There is no normalize-and-accept path:

- a repository contains one or more slash-separated lowercase components;
- each component starts and ends with `[a-z0-9]`; interior separators are one
  `.` or `_`, two `_` characters, or one or more `-` characters;
- the total repository is at most 255 bytes, with no empty, `.` or `..`
  component, repeated slash, backslash, control byte, non-ASCII byte, or
  uppercase byte;
- a tag matches `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` and remains case-sensitive;
- a digest is exactly `sha256:` followed by 64 lowercase hexadecimal digits;
- SHA-256 is the only accepted digest algorithm in v1;
- percent-encoded octets are rejected in repository names, tags, and digests,
  including encoded slash or backslash, rather than decoded and reparsed;
- query parameters are decoded once by the HTTP layer and then passed to the
  same canonical tag/digest parser;
- a manifest reference is either a canonical tag or canonical digest, never a
  fallback interpretation after one parse fails.

The raw-path router identifies fixed `/v2/`, `/blobs/`, `/manifests/`,
`/tags/list`, and `/referrers/` separators before handing exact repository
bytes to this parser. Tokens contain the same validated repository bytes, and
the authorization check compares them without case folding or percent
decoding.

The bearer challenge exchanges an existing authenticated Hub identity for a
short-lived OCI token with an exact service audience, repository, and action
set. Public pull may be anonymous. Private blob access always verifies a
repository link even when the caller knows a shared digest. A cross-repository
mount requires pull on the source and push on the destination.

## Transactional publication

AOS-generated artifacts know all digests and sizes before upload:

1. query the destination registry for existing descriptors;
2. reserve quota and placements for missing blobs;
3. upload and verify layers and configs;
4. upload and verify platform manifests;
5. upload and verify the multi-platform index;
6. validate the closed descriptor graph and signed provenance;
7. confirm every required placement;
8. atomically update the tag, history, catalog root, and outbox.

Unknown-digest standard-client uploads use bounded staging objects and are
promoted only after final digest verification. No tag is visible before its
entire graph is durable on required placements.

## Signed release representation

A versioned signed release sidecar, initially `containers/v1/index.json`,
binds:

- AOS package and release;
- logical container name, initially only `aos`;
- OCI index and per-platform manifest descriptors;
- Nix definition and output provenance;
- full-closure package mapping, corresponding-source, and license
  qualification, with `readyForVerifiedPublication = true`;
- closure manifest and SBOM descriptors;
- source, license, signature, and attestation referrers.

The Hub indexer verifies this sidecar before creating a signed release root.
Generic clients may pull an unverified manual tag, but only AOS-aware
publication creates verified release and channel associations.

Signing and OCI transfer deliberately remain separate transactions. Nix emits
the deterministic unsigned `publicationInputs` graph and
`signature-input.json`; it never receives a private key. The operator first
runs `aos container prepare-signature publicationInputs --output
container-signature.pae`, then signs only that exact file with SSHSIG namespace
`aos-container-signature-dsse-v1`. `aos container finalize-signature
publicationInputs --signer name:Ed25519:BASE64_SSH_KEY_BLOB --signature
container-signature.pae.sig --output FINAL_BUNDLE` verifies the public identity,
namespace, and exact PAE bytes before it writes anything. It validates the
complete qualified graph and atomically installs a no-overwrite bundle with
`layout/`, `image.oci.tar`, `container-release.json`, and
`signature-input.json`. Neither AOS command accepts a private-key path or SSH
agent.

After the external signature has been verified and assembled, the producer
runs `aos container publish
--stage-only` to upload the complete immutable graph by digest without a tag or
control-plane mutation. The paired `apr release --container-release
FINAL_BUNDLE/container-release.json --container-signature-input
FINAL_BUNDLE/signature-input.json`
arguments then validate their exact unsigned identity and qualification and
commit the canonical sidecar under the release lock before creating the signed
release tag. Resume proves the tagged commit contains the exact same sidecar.
Once the Hub indexer has authenticated it, rerunning `aos container publish`
without `--stage-only` revalidates and idempotently uploads the graph before it
invokes `ContainerService` Begin/Get/Commit. Only the control-plane commit
advances the requested tag and marks the root verified. Neither command
fabricates a signature, and a generic Distribution push never becomes a
verified root.

## Garbage collection

GC uses a fail-closed mark-and-sweep transaction:

1. capture the registry OCI mutation epoch and placement inventory;
2. mark tags, signed release roots, retained referrers, leases, and active
   uploads;
3. traverse every descriptor edge;
4. abort on missing edges, stale inventory, or epoch change;
5. apply the configured grace period;
6. produce a reviewable deletion plan;
7. revalidate roots and exact placement identity;
8. tombstone and delete each physical placement with digest/size/etag
   preconditions;
9. release catalog identity and quota only after all placements report deleted
   or already absent.

Repository and registry deletion are blocked while OCI roots, active uploads,
or untracked physical bytes remain.

## User-facing surfaces

The top-level CLI owns artifact operations:

```text
aos container list
aos container show aos
aos container build aos
aos container inspect <name|path|reference>
aos container pull <reference>
aos container push <name|path> <reference>
aos container publish aos <registry/repository:tag> \
  --release containers/v1/index.json \
  --release-layout <final-signed-layout-or-archive> \
  --signature-input <nix-evidence>/signature-input.json \
  --registry <hub-registry-slug> \
  --idempotency-key <stable-retry-key> \
  --stage-only
apr release <semver> \
  --container-release containers/v1/index.json \
  --container-signature-input <nix-evidence>/signature-input.json
# After APR's signed release is indexed, rerun publish without --stage-only.
```

Only commands that evaluate definitions or build artifacts instantiate Nix.
Inspect, pull, push, and publish work outside a repository and without Nix.
Publish accepts distinct `--registry-origin`/`--registry-token` Distribution
credentials and `--hub`/`--token` control-plane credentials. A stored Hub token
is reused for Distribution only when both normalized origins are exactly equal;
a dedicated registry authority requires an explicit registry credential.
`--stage-only` can operate with only explicit Distribution credentials and
makes no Connect call.

Hub administration remains under `aos hub registry container`, with repository,
tag, publication, retention, and GC operations following existing
plan/apply/idempotency/resource-version conventions. `aos image` remains the
system-disk namespace. APR remains package-registry porcelain. Its paired
container flags commit exact canonical release bytes into the signed Git
release; APR does not become an OCI transfer client or a DSSE signer.

The Hub console renames the current area to "System images" and adds
"Containers" pages for repositories, tags, platforms, config, layers, shared
bytes, closure packages, source/licenses, provenance, referrers, publication
health, tag history, retention, and GC. Browser uploads are out of scope.

## Generated and checked surfaces

Adding the OCI data and control planes requires updating every checked surface,
not only the primary protobuf and router:

- `crates/aos-proto/src/proto/aos/hub/v1/hub.proto`;
- `crates/aos-proto/build.rs` and `crates/aos-proto-types/build.rs`;
- the manual remote method/path map in `crates/aos-remote/src/hub.rs`;
- native Connect route registration and its proto-coverage test;
- RFC-0012 API and route-capability manifests;
- the retained-control classification fixture and coverage test;
- native/Worker request routing and repository-aware sharding;
- the Hub console contract, public browse routes, and console workflows;
- SQLite/PostgreSQL/MySQL migration and dialect gates;
- native and Worker end-to-end deployment fixtures.

Phase reviews treat a missing generated or checked surface as blocking rather
than accepting a native-only partial implementation.
