# 30 — Surfaces: protocols

This file owns the surfaces that speak public protocols over a view: the Nix
binary cache protocol (`NIX`), the Remote Execution API (`REAPI`), the
GitHub Actions cache API (`GHA`), git upload-pack (`GIT`), OCI Distribution
(`OCI`), and the HTTP browse and console API (`WEB`). Each section gives the
surface's schema (the path layout and attributes it requires of the view's
root), its mapping from protocol verbs to tree operations, its credential
mapping, and what it means for the surface to be writable. Every one of them
is a mapping onto the repository layer and inherits authorization, trust,
tiering, and consistency from [`26-surfaces.md`](26-surfaces.md). The
registry entry for each is in
[`reference/surface-registry.md`](reference/surface-registry.md).

## Common rules

- **[NIX-1]** Every protocol surface in this file MUST satisfy SURF-1
  through SURF-32. In particular, each MUST map incoming credentials to a
  capability token per request (SURF-20) and MUST commit only through the
  single commit path (SURF-16).
- **[NIX-2]** A protocol surface MUST serve bulk content by presigned
  redirect ([`18-protocol.md`](18-protocol.md)) whenever the protocol allows
  a redirect and the client is not known to reject one; otherwise it MUST
  stream through the repository's ranged read. A surface MUST NOT buffer an
  entire object in memory to serve it.
- **[NIX-3]** A protocol surface MUST apply the view's trust selectors
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)) to every
  entry it returns. An entry filtered by trust MUST be reported to the client
  as absent, not as forbidden.

## `nix-cache`: the Nix binary cache protocol

### Schema

```text
<root>/
  nix-cache-info                    entry attrs: store_dir, priority, want_mass_query
  <hash>-<name>                     one entry per store path, kind = file or
                                    directory tree (NAR adapter), attrs:
                                      nar.hash_sha256, nar.size,
                                      nar.references[], nar.deriver,
                                      nar.signatures[], nar.ca (optional),
                                      nar.file_hash, nar.file_size,
                                      nar.compression
```

A store path is one entry whose content is the NAR serialization of the
path. The NAR is the object; its chunks are the NAR's chunks. The narinfo
fields are entry attributes so that serving a narinfo never fetches content.

- **[NIX-4]** The surface MUST require, per store-path entry, the attributes
  `nar.hash_sha256`, `nar.size`, and `nar.references`; the others are
  optional. It MUST require the root to carry the `nix-cache-info`
  attributes `store_dir` and `priority`. *Gate:* `gate:surface-schema`.
- **[NIX-5]** The mapping from a store path to its NAR object and back MUST
  be the NAR adapter registered in [`10-derived-data.md`](10-derived-data.md):
  the tree entry's object is the NAR bytes, and the entry's `nar.hash_sha256`
  is the SHA-256 of those bytes.

### Reads

| Request | Tree operation |
| --- | --- |
| `GET /nix-cache-info` | root attributes, rendered |
| `GET /<hash>.narinfo` | lookup entry by hash prefix; render attributes; `URL` points at `nar/<object hash>.nar.zst` |
| `GET /nar/<object>.nar.zst` | ranged read of the object's chunks, served as concatenated zstd frames |
| `GET /nar/<object>.nar` | ranged read, decompressed by the surface |
| `HEAD` variants | same lookups without content |
| `GET /<hash>.ls` | rendered from the NAR adapter's listing attribute if present |

- **[NIX-6]** The surface MUST serve `.nar.zst` by concatenating the
  object's stored per-chunk zstd frames in manifest order with no
  recompression. A sequence of complete zstd frames is a valid zstd stream,
  so this is zero CPU per byte beyond copying. *Gate:*
  `gate:nix-frame-concat`.
- **[NIX-7]** The narinfo `FileHash` and `FileSize` MUST describe the bytes
  the surface actually serves for the compressed URL. Because the
  concatenated stream is deterministic for a given object and chunking
  profile, the surface MUST record these as derived attributes
  (`nar.file_hash`, `nar.file_size`) the first time they are computed and
  MUST serve them from the attributes thereafter.
- **[NIX-8]** Signatures in `nar.signatures` MUST be served verbatim. The
  surface MAY add a signature under a key configured for the exposure; if it
  does, it MUST sign the canonical narinfo fingerprint and MUST record the
  signature as an attribute so repeated requests return identical bytes.
- **[NIX-9]** Lookups by store-path hash MUST be served from an index tree
  ([`10-derived-data.md`](10-derived-data.md)) keyed by hash, or from a
  path-keyed lookup when the root's entry names begin with the hash. The
  surface MUST NOT scan the root.

### Writes

The write side is the upload protocol used by `nix copy` to an HTTP cache:
`PUT /<hash>.narinfo` and `PUT /nar/<file>`.

- **[NIX-10]** A writable `nix-cache` exposure MUST accept `PUT /nar/…`
  by chunking the uploaded NAR (decompressing first if the upload is
  compressed), verifying the declared hash, and staging the object; it MUST
  accept `PUT /<hash>.narinfo` by creating the entry with attributes parsed
  from the narinfo and binding it to the staged object by `nar.hash_sha256`.
  A narinfo whose `NarHash` does not match a staged object MUST be rejected.
- **[NIX-11]** The exposure's writer mode governs when the commit occurs
  (SURF-17). A `nix copy` client treats a successful `PUT` as durable, so
  an exposure intended for `nix copy` MUST use `sync` mode or MUST declare
  otherwise in its configuration and documentation.
- **[NIX-12]** References named in an uploaded narinfo MUST resolve to
  entries in the same root at commit time (closure integrity). The surface
  MUST reject a commit that would leave a dangling reference unless the
  exposure sets `allow_dangling_references = true`.

### Credential mapping

- **[NIX-13]** The surface MUST accept a Terrane token as an HTTP bearer
  credential and MUST accept HTTP basic credentials mapped through the
  exposure's configured issuer or pre-attenuated token table (SURF-21).
  Unauthenticated requests use the exposure's `anonymous` token if present.

## `reapi`: the Remote Execution API

### Schema

```text
<root>/
  cas/<digest-function>/<hex>      one entry per blob; object is the blob
  ac/<digest-function>/<hex>       one entry per ActionResult; object is the
                                   serialized ActionResult; attrs:
                                     reapi.output_digests[] (all blobs the
                                     result references)
  capabilities                     root attrs: digest_functions[],
                                   max_batch_total_size, symlink_absolute_path_strategy
```

- **[REAPI-1]** The surface MUST require `cas/` and `ac/` directories and
  the root `capabilities` attributes. The `<digest-function>` segment MUST
  be one of the REAPI digest function names the exposure advertises. *Gate:*
  `gate:surface-schema`.
- **[REAPI-2]** Because REAPI identifies blobs by SHA-256 (or another
  advertised function) and Terrane identifies objects by BLAKE3, every
  `cas/` entry MUST carry the advertised digest as its path and the surface
  MUST maintain the `hash.sha256` (or other `hash.*`) derived attribute so the two
  identities are bound ([`10-derived-data.md`](10-derived-data.md)).

### Reads and writes

| RPC | Tree operation |
| --- | --- |
| `FindMissingBlobs` | batched `has` on `cas/<fn>/<hex>` entries |
| `BatchReadBlobs`, `ByteStream.Read` | ranged reads of the entries' objects |
| `BatchUpdateBlobs`, `ByteStream.Write` | stage objects; add `cas/` entries |
| `GetActionResult` | lookup `ac/` entry; completeness check; render |
| `UpdateActionResult` | stage; add `ac/` entry with `reapi.output_digests` |
| `GetCapabilities` | root attributes |
| `GetTree` | subtree walk of a Directory blob's referenced blobs |

- **[REAPI-3]** `GetActionResult` MUST perform a completeness check: it MUST
  verify with `has` that every blob named in `reapi.output_digests` is
  present in `cas/` under the view, and MUST return `NOT_FOUND` if any is
  absent. The check MUST touch those entries for cache-recency purposes
  ([`17-garbage-collection.md`](17-garbage-collection.md)). *Gate:*
  `gate:reapi-completeness`.
- **[REAPI-4]** `FindMissingBlobs` MUST be answered from the tree and index
  filters without fetching content and MUST NOT act as an existence oracle
  across disclosure domains: it MUST report a blob as missing if the caller's
  token cannot read the domain in which it exists.
- **[REAPI-5]** Uploads MUST be validated as any other upload
  ([`05-chunking.md`](05-chunking.md)): the surface computes the advertised
  digest over the received bytes and MUST reject a blob whose digest does
  not match the client's claim.
- **[REAPI-6]** The Execution service is out of scope for this surface. An
  exposure MUST advertise only the CAS, Action Cache, and Capabilities
  services, plus `ByteStream`; an implementation MAY forward `Execute` to a
  configured executor but that is not part of this surface.
- **[REAPI-7]** Writer mode for a `reapi` exposure MUST be `sync` when the
  exposure is writable, because REAPI clients treat a successful update as
  durable.

### Credential mapping

- **[REAPI-8]** The surface MUST accept a Terrane token in the
  `authorization` metadata as a bearer credential and MUST accept
  `x-terrane-token` metadata as an alternative for clients that reserve
  `authorization`. Per-request instance names (`instance_name`) MUST select
  among exposures; they MUST NOT select a view within one exposure.

## `gha-cache`: the GitHub Actions cache API

This surface implements the cache service protocol used by the
`actions/cache` client family: reserve, upload in ranges, commit, and
restore by key with prefix fallback and version.

### Schema

```text
<root>/
  <version>/<key>                  one entry per cache; object is the
                                   uploaded archive; attrs:
                                     gha.key, gha.version, gha.size,
                                     gha.created_at, gha.scope
```

- **[GHA-1]** The surface MUST require entries to be located at
  `<version>/<key>` where `<version>` is the client's cache version hash
  and `<key>` is the exact key. It MUST require the attributes `gha.key`,
  `gha.version`, and `gha.size`.

### Scope semantics through refs

The protocol's notion of scope (a cache saved on a branch is visible to that
branch and to the default branch's descendants but not to siblings) maps
directly onto refs:

```text
refs/heads/main                    the trusted baseline
refs/heads/pr/<n>                  forked from main for a change; the job's
                                   token may commit only here
```

- **[GHA-2]** A restore request MUST be resolved against the exposure's
  view. A view for a change SHOULD be a branch forked from the baseline, so
  that the change sees every baseline cache and its own saves without any
  copying.
- **[GHA-3]** A save request MUST commit into the exposure's view only. A
  job MUST NOT be able to save into the baseline by any request the protocol
  offers. Enforcement is the exposure's token (SURF-12), not surface logic.
- **[GHA-4]** Folding a change's caches into the baseline after the change
  is accepted MUST be performed as a merge
  ([`07-tree-algebra.md`](07-tree-algebra.md)) by a principal holding
  `commit` on the baseline, outside this surface. The surface MUST NOT
  expose a fold operation to protocol clients.
- **[GHA-5]** Restore key matching MUST implement the protocol's exact-then-
  prefix search: an exact key match under the requested version, then the
  most recently created entry whose key begins with each restore key in
  order. Recency MUST be taken from `gha.created_at`. Prefix search MUST be
  a range scan of the tree, not a listing.

### Reads and writes

| Request | Tree operation |
| --- | --- |
| reserve | allocate an upload id; no tree change |
| upload (ranged PATCH) | append to the staged object |
| commit | verify size; chunk; add `<version>/<key>` entry; commit per writer mode |
| restore | resolve key (GHA-5); presigned redirect or stream |

- **[GHA-6]** A reserved upload that is not committed within
  `upload_deadline` (default 1 hour) MUST be discarded and its staging space
  released.
- **[GHA-7]** Writer mode SHOULD be `sync` for this surface; the client
  treats commit as durable.

### Credential mapping

- **[GHA-8]** The surface MUST accept the client's bearer credential and map
  it through the exposure's configured issuer (SURF-21 (b)), which is
  expected to exchange a job identity for a token attenuated to that job's
  view. The surface MUST NOT accept a bare Terrane token from the protocol
  client unless the exposure enables `accept_raw_tokens`.

## `git`: git upload-pack

This surface lets a git client fetch a view as a git repository. It is a
read projection: git tree and blob objects are derived from the Terrane tree
on demand and are never stored as the source of truth.

### Schema

- **[GIT-1]** The surface requires no particular layout. It MUST require the
  root's `hashes` property ([`08-properties.md`](08-properties.md)) to list
  `git-blob-sha1` (and `git-blob-sha256` if the exposure advertises the
  SHA-256 object format) so that every regular file entry carries the
  derived attribute `hash.git-blob-sha1` (and `hash.git-blob-sha256`) per
  [`10-derived-data.md`](10-derived-data.md) DRV-7. A root whose `hashes`
  omits them MUST fail schema validation for this surface.

### Projection

- **[GIT-2]** A git tree object for a directory MUST be computed as the
  canonical git encoding of the directory's entries taken from a range scan
  of the Terrane tree: names, modes (`100644`, `100755`, `120000`, `040000`,
  and `160000` for `tree` entries the exposure maps to submodules), and the
  child object ids. The result MUST be memoized as a derived object keyed
  by the hash of the Terrane subtree it was computed from
  ([`10-derived-data.md`](10-derived-data.md)), so unchanged directories are
  never re-hashed.
- **[GIT-3]** A git blob's id MUST be served from the entry's `hash.git-blob-*`
  attribute. The surface MUST NOT compute a blob id at request time; a
  missing attribute is a completeness fault reported in status and the
  affected fetch MUST fail rather than serve an incorrect id.
- **[GIT-4]** A git commit object MUST be projected from the Terrane commit:
  tree id from GIT-2, parents from the commit's parents, author and
  committer from provenance
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)), message
  verbatim, and a deterministic timestamp from the commit. The projection
  MUST be memoized by Terrane commit hash.
- **[GIT-5]** Ref advertisement MUST map `refs/heads/*` and `refs/tags/*`
  of the view's ref namespace to the same names, subject to the token's
  `read` grants. `HEAD` MUST point at the exposure's view ref.

### Protocol

- **[GIT-6]** The surface MUST implement the smart HTTP transport
  (`info/refs?service=git-upload-pack` and `git-upload-pack`) with protocol
  version 2. It MAY implement the `git://` and SSH transports.
- **[GIT-7]** Pack generation MUST stream objects in the order the client's
  wants and haves require and MUST NOT materialize a full pack before
  sending. Blob content is read through the repository's ranged reads.
- **[GIT-8]** The surface is read-only in version 1.0. `git-receive-pack`
  MUST NOT be advertised.

### Credential mapping

- **[GIT-9]** HTTP basic and bearer credentials MUST be mapped as NIX-13.

## `oci`: OCI Distribution

### Schema

```text
<root>/oci/
  blobs/<algorithm>/<hex>          one entry per blob; object is the blob
  repositories/<name>/
    manifests/<digest>             entry whose object is the manifest bytes;
                                   attrs: oci.media_type, oci.subject (opt)
    tags/<tag>                     symlink entry -> ../manifests/<digest>
    referrers/<digest>             directory of symlinks to manifests whose
                                   subject is <digest> (derived)
```

- **[OCI-1]** The surface MUST require the `oci/blobs` and
  `oci/repositories` directories and the manifest attributes above. Blob
  entries MUST carry the derived `hash.sha256` attribute binding the OCI digest
  to the object ([`10-derived-data.md`](10-derived-data.md)). *Gate:*
  `gate:surface-schema`.
- **[OCI-2]** A tag MUST be a symlink entry to the manifest entry it
  currently names. Retagging is a commit that rewrites the symlink; the
  previous target remains reachable through the commit graph.

### Reads and writes

| Request | Tree operation |
| --- | --- |
| `GET /v2/` | authentication probe |
| `HEAD`/`GET /v2/<name>/blobs/<digest>` | lookup `oci/blobs/…`; presigned redirect or stream |
| `HEAD`/`GET /v2/<name>/manifests/<ref>` | resolve tag symlink or digest; serve manifest with `oci.media_type` |
| `GET /v2/<name>/tags/list` | range scan of `tags/` |
| `GET /v2/<name>/referrers/<digest>` | range scan of `referrers/<digest>/` |
| `POST`/`PATCH`/`PUT` blob upload | stage; verify digest; add `oci/blobs/…` entry |
| `PUT /v2/<name>/manifests/<ref>` | verify referenced blobs exist; add manifest entry; set tag symlink; commit |
| `DELETE` manifest or tag | remove entry or symlink; commit |

- **[OCI-3]** A manifest `PUT` MUST verify that every blob and manifest the
  manifest references exists under `oci/blobs` or `oci/repositories/<name>/
  manifests` in the view before committing, and MUST reject the upload with
  `MANIFEST_BLOB_UNKNOWN` otherwise.
- **[OCI-4]** Blobs are shared across repositories in one root by
  construction. Repository-level visibility MUST be enforced by the token's
  grants on `oci/repositories/<name>` roots, which SHOULD be `tree` entries
  so that each repository is a root with its own properties and ACL
  ([`08-properties.md`](08-properties.md)).
- **[OCI-5]** Writer mode for a writable `oci` exposure MUST be `sync`.
- **[OCI-6]** The `referrers/` directory is derived
  ([`10-derived-data.md`](10-derived-data.md)) from manifests' `oci.subject`
  attributes and MUST be maintained at commit; the surface MUST NOT scan
  manifests to answer a referrers request.

### Credential mapping

- **[OCI-7]** The surface MUST implement the token-based authentication
  challenge of the distribution specification, directing clients to the
  exposure's configured issuer, and MUST accept the resulting bearer token
  as a Terrane token or map it through the issuer (SURF-21).

## `browse` and `api`: HTTP for humans and consoles

### `browse`

- **[WEB-1]** The `browse` surface requires no schema. It MUST serve, for
  any path under the view: a directory listing (HTML and, with
  `Accept: application/json`, JSON) showing name, kind, size, and mode; for
  a regular file, a presigned redirect to the object's bytes or a streamed
  response when the client cannot follow redirects; for a symlink, the
  target as text or a redirect within the view when `follow_symlinks` is
  set.
- **[WEB-2]** The surface MUST never serve a path outside the view's subtree
  and MUST treat `..` and encoded traversal as not found.
- **[WEB-3]** Listings MUST be served from the tree and MUST NOT fetch
  object content. A listing of a directory with more than `page_size`
  entries (default 1000) MUST be paginated by a continuation token that is a
  path, so that a page is a range scan.
- **[WEB-4]** The surface SHOULD expose commit history, diffs between
  commits, and property completeness for the view under `/.terrane/…`
  paths, rendered from the repository without any additional API.
- **[WEB-5]** Human authentication MUST be by the exposure's configured
  issuer (an OpenID Connect provider) producing a session that the surface
  exchanges for a short-lived Terrane token per request. The surface MUST
  NOT store long-lived tokens in browser-accessible storage.

### `api`

- **[WEB-6]** The `api` surface MUST expose the wire protocol of
  [`18-protocol.md`](18-protocol.md) over HTTP with the encodings that
  protocol defines, including the browser-compatible encoding, restricted
  to the exposure's view and token. It exists so that consoles and out-of-
  process surfaces have one API; it MUST NOT define operations beyond the
  wire protocol.
- **[WEB-7]** The `api` surface MUST send cross-origin headers only for
  origins listed in the exposure's `allowed_origins` option.

## Interactions

- [`10-derived-data.md`](10-derived-data.md): every protocol surface that
  speaks a foreign digest depends on derived attributes and index trees.
- [`18-protocol.md`](18-protocol.md): presigned reads and the `api`
  surface.
- [`20-consistency.md`](20-consistency.md): writer modes named per surface.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md):
  issuers and token exchange.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md): trust
  filtering on every read.
- [`reference/surface-registry.md`](reference/surface-registry.md): the
  registered names and endpoint kinds.
