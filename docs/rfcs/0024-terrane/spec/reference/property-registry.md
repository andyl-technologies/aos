# Reference: property registry

The authoritative list of names that [`../00-conventions.md`](../00-conventions.md)
CONV-3 requires to be registered before use, other than identity domains,
bucket keys, surfaces, and gates, which have their own registries. A name
absent from this document is unregistered. Adding a name is a `MINOR`
specification change ([`../README.md`](../README.md) §versioning); changing
the meaning of a registered name is a `MAJOR` change.

Each table names the owning file. Where a table restates a rule from an
owning file, the owning file's text governs the semantics and this registry
governs the name.

## Properties

Copied from [`../08-properties.md`](../08-properties.md) §Property summary
(PROP-28) with encoding and inheritance added. Every property inherits from
the nearest ancestor root unless overridden (PROP-2); `acl` additionally
may only narrow `commit` and `admin` in a descendant (PROP-16). Values are
encoded as `property-value` in
[`terrane-v1.cddl`](terrane-v1.cddl) using the CBOR type in the third column.

| Property | Class | CBOR type and values | Default | Owner |
| --- | --- | --- | --- | --- |
| `store` | storage, boundary | `tstr`: store expression name | the instance's authority | 08, 11 |
| `chunk` | storage | `tstr`: chunk profile name (§chunk profiles) | `cdc-1m` | 05, 08 |
| `compression` | storage | `tstr`: `raw` \| `zstd` \| `zstd:<class>` | `zstd` | 05, 08 |
| `encryption` | storage | `tstr`: `none` or `<scheme>:<key-id>` (§encryption) | `none` | 08, 24 |
| `retain` | storage | `retain` in the CDDL: `gc` \| `lease` \| `forever` \| `["ttl", seconds]` | `gc` | 08, 17 |
| `domain` | storage, boundary | `tstr`: `public` \| `tenant:<name>` \| `group:<name>` \| `private:<id>` | `private:<id>` | 08, 24 |
| `dedup` | storage | `tstr`: `global` \| `domain` \| `none` | `domain` | 08, 24 |
| `redundancy` | storage | `tstr`: `none` \| `replicated(n,ack=k)` \| `striped(k,parity=m)` | `none` | 15 |
| `degraded` | storage | `tstr`: `allow` \| `refuse` | `refuse` | 15 |
| `durability` | storage | `tstr`: `local` \| `zone` \| `region` \| `regions(k)` | `region` | 20 |
| `replicate` | storage | `tstr`: `async` \| `sync(k)` \| `none` | `async` | 19 |
| `home` | storage | `tstr`: region label | authority's region at first write | 19, 09 |
| `warm` | storage | `[* tstr]`: locality labels | `[]` | 19 |
| `quota` | storage | `{1: bytes-per-root, 2: bytes-per-principal-unreferenced}` | unlimited | 14, 22 |
| `compaction_threshold` | storage | `uint`: utilization in basis points (5000 = 0.5) | 5000 | 17 |
| `whole_pack_threshold` | storage | `uint`: basis points of a pack needed to fetch it whole | 5000 | 21 |
| `gap_merge_bytes` | storage | `uint` | 262144 | 21 |
| `span_max_bytes` | storage | `uint` | 16777216 | 21 |
| `trust` | trust | `selector` in the CDDL, or `tstr` preset name (§trust selectors) | `any` | 23 |
| `baseline` | trust | `tstr`: group name for `signed-baseline` and `strict` | none | 23 |
| `merge` | trust | `[+ merge-policy]` (§merge policies) | `["prefer-trusted", "keep-conflict"]` | 07 |
| `writers` | trust | `tstr`: `one` \| `many` | `one` | 20 |
| `reflog_retain` | trust | `uint` seconds, or `["count", n]` | 7776000 (90 days) | 09 |
| `prefetch` | realization hint | `tstr`: `profile` \| `rules` \| `none` (§realization hints) | `profile` | 31, 27 |
| `reassembly` | realization hint | `tstr`: `never` \| `smart` \| `always` | `smart` | 14 |
| `passthrough` | realization hint | `tstr`: `auto` \| `force` \| `off` | `auto` | 27 |
| `wipe` | realization hint (mandatory when set, PROP-15) | `tstr`: `none` \| `zero` \| `discard` \| `volatile` | `zero` for `private:*`, else `none` | 14, 24 |
| `on-release` | realization hint | `tstr`: `keep` \| `commit` \| `discard` | `keep` | 20 |
| `acl` | authority, boundary | `[* [principal-or-group: tstr, verbs: uint]]`, verbs as the grant bitmask | inherited | 22 |
| `hashes` | requirement | `[* tstr]` from §hash names | `[]` | 10 |
| `classify` | requirement | `[* tstr]` from §classifiers | `[]` | 10 |
| `index` | requirement | `[* name]`: attribute names to index | `[]` | 10 |
| `strict-attrs` | requirement | `bool` | `false` | 06 |

Boundary properties (`store`, `domain`, `acl`) mark a root that `flatten`
MUST NOT inline across ([`../08-properties.md`](../08-properties.md)
PROP-17).

## Chunk profiles

Named by the `chunk` property and recorded beside the identity profile in
the store profile record
([`terrane-v1.cddl`](terrane-v1.cddl) `store-profile`). Parameters are
fixed for the life of any chunk cut with the profile
([`../05-chunking.md`](../05-chunking.md) CDC-3).

| Name | Minimum | Target | Maximum | Window | Normalization | Seed |
| --- | --- | --- | --- | --- | --- | --- |
| `cdc-1m` | 262 144 | 1 048 576 | 4 194 304 | 48 | 2 | 32 zero bytes |

The gear table for a profile is derived from its seed as in
[`golden-vectors.md`](golden-vectors.md) §gear-table.

## Codecs and dictionary classes

Codec bytes ([`../05-chunking.md`](../05-chunking.md) §Compression):
`0x00` raw, `0x01` zstd, `0x02` zstd with dictionary. Dictionary classes
are the `class.magic` values in §classifiers; the `compression` property
`zstd:<class>` requests the deployment's trained dictionary for that class.
This version registers no default dictionaries: a dictionary is a
deployment artifact stored as an attribute record named `zstd-dictionary`
(CDC-9), and a reader always fetches it by identity.

## Hash names

Names accepted in the `hashes` property and as keys of a manifest's hash map
([`../04-content-model.md`](../04-content-model.md) OBJ-14,
[`../10-derived-data.md`](../10-derived-data.md) DRV-6, DRV-7).

| Name | Function | Length |
| --- | --- | --- |
| `blake3` | BLAKE3-256 of plaintext; REQUIRED in every manifest | 32 |
| `sha256` | SHA-256 of plaintext | 32 |
| `sha512` | SHA-512 of plaintext | 64 |
| `git-blob-sha1` | SHA-1 of `blob <len>\0` followed by plaintext | 20 |
| `git-blob-sha256` | SHA-256 of `blob <len>\0` followed by plaintext | 32 |

The derived attribute that carries a hash is `hash.<name>`.

## Derived attributes

Copied from [`../10-derived-data.md`](../10-derived-data.md) §Registered
derived attributes. Each is a pure function of plaintext (DRV-2) and is
stored as an `AttrRecord` keyed by object hash.

| Attribute | Function | Value type |
| --- | --- | --- |
| `hash.sha256` | SHA-256 of plaintext | `bstr .size 32` |
| `hash.sha512` | SHA-512 of plaintext | `bstr .size 64` |
| `hash.git-blob-sha1` | git blob SHA-1 | `bstr .size 20` |
| `hash.git-blob-sha256` | git blob SHA-256 | `bstr .size 32` |
| `class.magic` | content classifier over the first 64 KiB | `tstr` from §classifiers |
| `class.elf` | ELF header parse | `{1: class, 2: machine, 3: type, 4: interpreter, 5: [* needed]}` |
| `class.shebang` | first-line parse | `{1: interpreter, 2: argument}` |

### Classifiers

Values of `class.magic` and names accepted by the `classify` property
(DRV-8): `elf`, `shebang`, `ar`, `zstd`, `gzip`, `tar`, `text`, `other`.
A `content_magic` matcher ([`../31-routing-rulesets.md`](../31-routing-rulesets.md)
RULE-6) names one of these values; an absent attribute is treated as
`other` at `on_realize`.

## Adapter and writer-supplied attributes

Copied from [`../10-derived-data.md`](../10-derived-data.md) §Registered
adapter and writer-supplied attributes. They are validated by the surface
schema that requires them, not by recomputation.

| Namespace | Attributes | Supplied by |
| --- | --- | --- |
| `nar.` | `hash_sha256`, `size`, `references`, `deriver`, `signatures`, `ca`, `file_hash`, `file_size`, `compression` | NAR adapter, `nix-cache` surface |
| `nix-cache-info` (root) | `store_dir`, `priority`, `want_mass_query` | `nix-cache` surface |
| `reapi.` | `size_bytes`, `output_digests` | `reapi` surface |
| `gha.` | `key`, `version`, `scope`, `size`, `created_at` | `gha-cache` surface |
| `oci.` | `media_type`, `subject`, `annotations` | `oci` surface |
| `tag.` | any name | ruleset `tag` actions |
| `provenance.` | `reintroduced-from` | fold with re-introduction (PROV-18) |
| (bare) | `uid`, `gid` | live-filesystem adapters (TREE-9) |
| (bare) | `zstd-dictionary` | dictionary identity (CDC-9) |

## Reserved names

These names are reserved for the native working tree described informally
in [`../40-risks-and-open-questions.md`](../40-risks-and-open-questions.md)
§Informative: the shape of a native working tree. A 1.0 implementation MUST
NOT assign them another meaning. They are not defined by this version.

| Name | Kind | Intended meaning |
| --- | --- | --- |
| `owner`, `group` | attribute | principal-named ownership for roots homed away from the pool that presents them, mapped to numeric ids at the graft |
| `idmap` | graft property | the user and group identity mapping applied when a root is grafted, realized as an idmapped mount |
| `bsd.flags` | attribute | BSD `chflags` bits, stored as an integer |
| `record-size` | property | the granularity at which a live tree buffers small overwrites before rechunking |
| `mount.nosuid`, `mount.nodev`, `mount.noexec` | graft property | per-graft mount attributes, today set per exposure (FUSE-43) |
| `native` | surface name | an in-kernel client surface |

## Media types

Media types for Terrane objects. Object identity never depends on a media
type; these names label bytes in transport, in `manifest` key 4, and in
conformance claims. The token media type is the one
[`../22-authentication-and-authorization.md`](../22-authentication-and-authorization.md)
AUTH-9 registers; the policy media type is the one
[`../31-routing-rulesets.md`](../31-routing-rulesets.md) RULE-25 registers.

| Media type | Object | CDDL type |
| --- | --- | --- |
| `application/vnd.terrane.manifest.v1+cbor` | manifest | `manifest` |
| `application/vnd.terrane.node.v1+cbor` | tree node | `node` |
| `application/vnd.terrane.commit.v1+cbor` | commit | `commit` |
| `application/vnd.terrane.ref.v1+cbor` | ref record | `RefRecord` |
| `application/vnd.terrane.reflog.v1+cbor` | reflog record | `RefLogRecord` |
| `application/vnd.terrane.snapshot.v1+cbor` | snapshot envelope | `SnapshotEnvelope` |
| `application/vnd.terrane.attr.v1+cbor` | attribute record | `AttrRecord` |
| `application/vnd.terrane.memo.v1+cbor` | recipe memo | `memo` |
| `application/vnd.terrane.bundle.v1+cbor` | bundle | `bundle` |
| `application/vnd.terrane.filter.v1+cbor` | filter | `filter` |
| `application/vnd.terrane.index-manifest.v1+cbor` | index generation manifest | `IndexGenerationManifest` |
| `application/vnd.terrane.capabilities.v1+cbor` | capabilities record | `Capabilities` |
| `application/vnd.terrane.token.v1+cbor` | capability token | `token` |
| `application/vnd.terrane.policy.v1+cbor` | ruleset or policy object | `ruleset` |
| `application/vnd.terrane.pack.v1` | pack file | binary, §pack in the CDDL |
| `application/vnd.terrane.index.v1` | per-pack index or merged shard | binary |
| `application/octet-stream` | content with no declared type | — |

Content media types carried in a manifest (for example
`application/x-nix-nar`) are those of the public protocol a surface
implements and are listed with that surface's schema in
[`surface-registry.md`](surface-registry.md).

## Token caveats

The closed caveat vocabulary of
[`../22-authentication-and-authorization.md`](../22-authentication-and-authorization.md)
AUTH-17, encoded as `caveat` in the CDDL.

| Caveat | Arguments | Satisfied when |
| --- | --- | --- |
| `before` | timestamp | the request time is before the timestamp |
| `after` | timestamp | the request time is after the timestamp |
| `ref` | pattern | the request's ref matches the pattern |
| `root` | pattern | the request's root path matches the pattern |
| `verb` | bitmask | the request's verb is in the mask |
| `domain` | name | every root touched has that effective `domain` |
| `surface` | name | the request arrives through the named surface |
| `locality` | label | the serving store's locality matches every field given |
| `epoch` | ref, n | the ref's writer epoch is at most `n` (AUTH-18) |

Grant verbs and their bitmask values: `read` 1, `fork` 2, `commit` 4,
`tag` 8, `admin` 16 (AUTH-19).

## Trust selectors

The selector language of [`../23-provenance-and-trust.md`](../23-provenance-and-trust.md)
PROV-11, encoded as `selector` in the CDDL.

| Atom | Arguments | True when |
| --- | --- | --- |
| `issuer` | id | the introducing commit's token issuer is `id` |
| `subject` | pattern | the subject name matches |
| `kind` | `human` \| `workload` \| `service` | the subject kind matches |
| `group` | name | the subject's group claims include the name |
| `source` | value | the commit's `source` equals the value |
| `signed-by-key` | key id | the commit signature verifies under that key |
| `accepted-by` | selector | some ancestor commit that carried the entry forward matches |
| `attested` | claim | the workload identity claim carries the registered attestation |
| `attr-by` | name, selector | attribute `name` was produced under a commit matching |
| `all`, `any`, `not` | selectors | boolean combinators |
| `preset` | name | the named trust preset below |

Registered trust presets (PROV-12):

| Preset | Meaning |
| --- | --- |
| `any` | every entry |
| `signed-baseline` | introduced by, or accepted by, a principal in the root's `baseline` group |
| `strict` | introduced directly by a principal in the `baseline` group |
| `attested` | the introducing workload carries a registered attestation |

Registered attestation claims: none in this version.

## Merge policies

Values of the `merge` property and of `ref-policy` key 2
([`../07-tree-algebra.md`](../07-tree-algebra.md) ALG-17): `prefer-ours`,
`prefer-theirs`, `prefer-trusted`, `prefer-newer`, `keep-conflict`,
`error`. Policies are tried in order; the first that resolves a conflict
value wins.

## Commit sources and reflog reasons

`commit-source` (PROV-6): `built` 1, `uploaded` 2, `imported` 3,
`merged` 4, `derived` 5, `migrated` 6.

`reflog-reason` (REF-21): `commit`, `merge`, `fold`, `rollback`,
`job-checkpoint`, `migrate`.

## Realization hints

| Property | Value | Meaning |
| --- | --- | --- |
| `prefetch` | `profile` | prefetch from the view's learned access profile and from ruleset `prefetch` actions |
| | `rules` | prefetch only what ruleset `prefetch` actions name |
| | `none` | no prefetch beyond kernel readahead |
| `reassembly` | `never` | serve every file from its chunks |
| | `smart` | reassemble when uniqueness is at least 0.9, size is at least 16 MiB, or the file was previously read; never below 64 KiB ([`../14-host-tier.md`](../14-host-tier.md)) |
| | `always` | reassemble every file on first open |
| `passthrough` | `auto` | use kernel passthrough where supported ([`../27-surface-fuse.md`](../27-surface-fuse.md)) |
| | `force` | refuse to serve without passthrough |
| | `off` | never register passthrough |
| `wipe` | `none` | unlink without overwrite |
| | `zero` | overwrite before removal |
| | `discard` | issue a device discard before removal |
| | `volatile` | never written to persistent storage |
| `on-release` | `keep` | leave the upper in place when an exposure is released |
| | `commit` | commit the upper on release |
| | `discard` | delete the upper on release |

## Retention

Values of `retain` ([`../17-garbage-collection.md`](../17-garbage-collection.md)
GC-3): `gc` keeps reflog entries for the configured duration, `lease` while
a lease is held, `["ttl", seconds]` for a fixed time from creation,
`forever` indefinitely.

## Encryption

Schemes accepted by the `encryption` property
([`../24-disclosure-domains.md`](../24-disclosure-domains.md) DOM-21). This
version registers none; the only valid value is `none`. A registered scheme
will name a cipher, a key-derivation rule, and the keyed-hash function used
for index keys (DOM-22).

| Scheme | Status |
| --- | --- |
| `none` | the only value in 1.0 |
