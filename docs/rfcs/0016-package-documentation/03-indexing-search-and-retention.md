# Indexing, search projections, retention, and garbage collection

## Shared ingestion path

Documentation indexing belongs in `aos-hub-core`, beside signed registry
indexing. Native Hub supplies filesystem/S3-compatible surface readers and SQL
backends; Worker supplies R2/S3-compatible readers and D1. All semantic work is
shared and `wasm32` clean.

For each signed platform entry with documentation, the indexer:

1. validates `DocumentationArtifactMeta` and the feature/version contract;
2. resolves the documentation store hash through the registry's store
   realization graph;
3. fetches and verifies its narinfo through the selected registry/cache surface;
4. rejects any store-path, NAR hash/size, reference, compression, or signature
   disagreement;
5. streams the bounded NAR through the strict single-file decoder while hashing
   the uncompressed NAR and extracted document;
6. checks exact declared sizes and digests;
7. parses canonical JSON into the closed versioned model;
8. cross-checks package/version/platform, declaration schema, ownership,
   config/expose runtime facts, and semantic schema digest;
9. derives deterministic browse summaries and search rows;
10. applies package rows, artifact rows, documentation locators, and search
    projections in the same registry snapshot transaction.

An invalid required document fails the index generation. Hub continues serving
the last fresh complete generation rather than publishing a partially updated
package corpus. Error records identify registry, commit, package, platform,
artifact digest, phase, and a sanitized reason.

## Bounded Worker-safe NAR reader

The shared decoder accepts only the documentation NAR profile from the previous
chapter. It is a small state machine over streamed bytes, not a general-purpose
NAR unpacker. It validates archive tokens and lengths before allocation and
emits the root file into a bounded digesting buffer.

Native and Worker adapters both use `SurfaceFetch::size`, `fetch_stream`, and
snapshot/ETag evidence where available. The reader verifies:

- declared object length before read;
- streamed byte cap and exact completion length;
- immutable snapshot evidence where the backend can provide it;
- NAR SHA-256 and uncompressed NAR size;
- single regular-file structure and non-executable mode;
- document SHA-256 and document size;
- canonical JSON and schema limits.

The Worker does not need a Nix daemon, filesystem extraction, `zstd`, libarchive,
or a native FFI dependency. The decoder has one corpus of golden and malicious
NAR fixtures compiled against native and `wasm32` targets.

## Database model

SQL stores identity, location, visibility, and disposable search projections.
It does not store the canonical JSON blob. Representative records are:

```text
package_documentation_artifacts
  registry_id, indexed_commit, package_name, package_version, platform,
  format, store_path, nar_hash, nar_size, document_sha256, document_size,
  semantic_schema_sha256, visibility, ordinal

option_search_documents
  documentation_artifact_id, option_ordinal, display_path, package_name,
  type_kind, type_signature, owner_package, owner_root, interface_abi,
  visibility, contributable, deprecated, activation_kind, summary_text

option_search_terms
  documentation_artifact_id, option_ordinal, term, field, weight, position
```

Rows have generation/registry foreign keys and are replaced atomically with the
indexed snapshot. SQL dialect CHECK constraints and Rust enums admit the same
closed documentation and artifact kinds. The object locator makes fetching the
full document cheap without turning SQL into a blob store.

`option_search_documents.summary_text` is a bounded plain-text derivative used
for result snippets. It is not returned as authoritative full documentation.

## Deterministic search

Tokenization and base ranking live in shared Rust. The portable algorithm:

- Unicode-normalizes and case-folds with a versioned routine;
- splits option path segments, package names, titles, enum values, and prose;
- retains exact path and prefix forms;
- assigns fixed field weights: exact path, path prefix, package, title/type,
  description, conceptual text;
- adds deterministic boosts for the selected platform/channel and non-deprecated
  public options;
- uses stable tie-breakers: score, package, display path, version, platform,
  document digest, ordinal.

The portable `option_search_terms` query is normative. PostgreSQL, MySQL, SQLite,
and D1 may use backend full-text features as an optimization only when
conformance fixtures prove the same result ordering and highlight ranges. A
backend without FTS remains fully functional.

Queries support exact and fuzzy text plus structured filters:

- package, version, platform, registry, release, or channel;
- result kind: package, option, service, credential contract, capability, or
  conceptual section;
- option type and owner root/package;
- public/internal visibility permitted to the caller;
- contributable, deprecated, required, or activation effect;
- changed relative to another exact document.

Highlight ranges index plain result text. Hub never returns or stores
package-supplied HTML snippets.

## Rebuild and recovery

An operator can delete every documentation/search projection and re-index from
the signed Git tree plus store objects. The resulting locators, terms, ranks,
ordinals, and API resources must be byte-equivalent apart from operational
timestamps.

Index generations include the signed registry input identity and document model
version. A model/tokenizer migration builds a new generation beside the old one,
checks parity/expected changes, then atomically selects it. It does not rewrite
documentation objects.

## Release artifact enumeration

Documentation must be a first-class release artifact kind. The indexer's
`release_snapshot_artifacts`, catalog enumeration in snapshot application, SQL
constraints, API models, GC root explanations, and Web views all add:

```text
documentation
```

The implementation must simultaneously close the adjacent omission for signed
companion objects:

```text
config_module
expose_artifact
```

The complete release artifact set therefore includes at least runtime output,
source derivation, config module, expose artifact, documentation, image, and
other signed delivery artifacts. A release snapshot must not retain a package
payload while collecting the configuration, exposure, or documentation objects
needed to use and understand it.

## Hub/cache retention and GC

A documentation object is retained by the same provenance-bearing reasons as
its package artifact:

- the currently indexed registry catalog;
- an immutable release snapshot;
- a channel frontier selecting that release;
- a cache retention subscription selecting the package/release;
- an explicit manual root with actor/reason/expiry;
- a local installed APM profile generation.

Population and retention remain independent under RFC-0012. A registry may
advertise a documentation artifact not yet populated into an optional consumer
cache, but a publication surface that claims the object must have verified
presence before its pointer advances. Cache GC explains the exact retaining
registry/release/package/artifact relation.

When the final root disappears, normal grace/lease policy applies and the NAR
and narinfo become collectable. SQL search rows are removed with their registry
index generation and do not retain an otherwise unreachable object.

## Installed profiles and offline retention

System package reconciliation records the signed `DocumentationArtifactMeta`
beside the selected package/config/expose pins. The profile generation holds a
direct store reference and exposes a deterministic link such as:

```text
/var/lib/profiles/system-packages/current/share/aos/documentation/nginx.json
```

The link target is the exact store object; the file is not copied into mutable
state. Upgrade adds the new object before selection. Rollback restores the old
profile and document. Profile GC removes documentation only with the generation
that retained it.

Image-seeded packages follow the same model: their documentation objects are in
the image closure/profile. Legacy installed packages without documentation show
a clear unavailable state and may use package summary metadata; APM must not
fetch "latest" and present it as exact offline documentation.

Operators may prefetch uninstalled docs with:

```text
apm registry sync --documentation=all
```

That cache is optional and separately collectable. Installed-package docs are
guaranteed.

## Content and HTTP caching

The immutable document endpoint is keyed by document digest and returns a strong
ETag. Native Hub may keep a bounded in-memory decoded-document cache. Worker may
use Cache API/R2-backed HTTP caching. Both caches are performance layers and
must revalidate identity against the indexed locator.

Mutable package/channel routes return the exact selected digest, use ordinary
short/revalidation caching, and never make the mutable URL the document's
identity. Private/internal documents use authorization-aware cache keys and are
never placed in a public shared cache.
