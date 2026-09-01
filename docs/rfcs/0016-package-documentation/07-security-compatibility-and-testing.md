# Security, compatibility, failure behavior, and testing

## Trust boundary

Package documentation is publisher-authored untrusted content authenticated to
a release. Authentication answers which publisher/release supplied the bytes;
it does not make those bytes safe HTML, code, or operational advice. Every
consumer therefore treats the document as bounded data in a closed schema.

The trusted computing base is:

- restricted Nix/base-lib extraction;
- the publisher's validator/canonical encoder and store materializer;
- signed package/release and store-realization verification;
- the shared NAR/document decoder and semantic validator;
- authorization-aware Hub services and safe renderers;
- APM profile retention and local verification.

Package prose, examples, links, source locators, search tokens, and documents are
not trusted code.

## Threats and controls

### Artifact substitution or partial publication

The signed platform entry binds store path, NAR identity, document digest,
schema, and semantic digest. The indexer checks the store graph, narinfo, streamed
NAR, canonical document, and cross-artifact facts before atomic snapshot
selection. Missing or mismatched bytes fail closed and leave the previous index
generation live.

### Parser resource exhaustion

The reader checks declared sizes before allocation and streamed sizes while
reading. It limits JSON nesting, strings, option/section/runtime collection
counts, type recursion, search terms, code blocks, and total text. The single
regular-file NAR profile excludes recursive filesystem extraction and
decompression bombs.

### Web content injection

Raw HTML, Markdown, script, style, and data URLs are not representable. Shared
renderers escape all text and validate explicit links. Pages use a strict CSP,
first-party content-addressed assets, no package-selected templates, and no
inline event handlers. Search highlights are numeric ranges over escaped plain
text.

### Terminal, pager, and roff injection

Terminal output strips or escapes control characters according to a shared
policy unless the renderer itself emits a known sequence. Roff generation
escapes control-leading lines, backslashes, and macro input. Package content
cannot select a shell command, pager option, man macro, or URL opener.

### Source and link confusion

Repository paths are relative, normalized, and traversal-free. Source links are
constructed only from authenticated repository/commit identity. External links
are explicit `https` values displayed with their destination and governed by Hub
link policy. Package links cannot escape the reserved registry browse namespace.

### Secret disclosure

Extraction cannot see secret values. Documents encode credential contracts only.
The publisher rejects store-context strings and secret-shaped defaults/examples.
Hub never indexes configuration values. Web drafts remain client-local unless an
explicit APM action is invoked. LSP requests never upload workspace values for
ordinary completion/hover.

### Private registry disclosure

Search, compare, source identity, artifact fetch, HTML, and API methods apply the
same resource authorization before revealing package existence, terms, snippets,
or counts. SQL projections retain registry/scope identity. Public and private
results are never combined into a public cache entry.

### Stale or confused selection

Every response carries exact commit/release, version, platform, and digest.
Mutable channel routes are resolved once per request/index generation. APM and
LSP prefer exact installed/cached identities and never label latest docs as
installed docs.

### Misleading documentation authority

Cross-checks prevent prose metadata from widening configuration ownership,
credential access, artifacts, or expose permissions. The UI labels generated
configuration validation as advisory until authoritative evaluation. Verified
means the bytes and publisher identity verified; it does not mean every
operational recommendation is correct.

## Compatibility

### Legacy packages and clients

Packages without `documentation` remain readable through existing package
summary/runtime metadata. UI and CLI show “structured documentation unavailable
for this release” and do not substitute a different version. Indexing remains
compatible until a package advertises the required documentation feature.

New publishers add `package-documentation-v1` to `requires-features` when the
document is required to safely present/use that package. Older consumers reject
the package under the existing fail-closed feature mechanism rather than
ignoring a critical companion artifact.

### Schema evolution

Readers dispatch on exact format/schema identifiers. Version 1 rejects unknown
fields. A future version can coexist as another document artifact format while
Hub migrates search projections. The API exposes source schema and returns a
stable view-resource version, allowing server-side conversion only when it is
lossless and policy-approved.

### Option ABI evolution

Rich types refine the existing signed declaration schema and do not replace its
resolver role. Semantic digest changes power comparison and client cache
invalidation. Existing module ABI compatibility remains the configuration
admission boundary.

### Native/Worker and SQL backends

All parsers, normalization, tokenization, ranking, view models, and rendering
compile for native and `wasm32-unknown-unknown`. SQL-specific full-text engines,
JSON operators, filesystem reads, native Nix libraries, or task-local state may
not become required semantics.

## Failure behavior

| Failure | Required behavior |
| --- | --- |
| Required doc metadata absent | Reject package/index generation once feature is required |
| NAR/narinfo/store graph mismatch | Reject generation; retain last complete index |
| Oversize/malformed/non-canonical document | Reject generation with bounded sanitized diagnostic |
| Document/config/expose disagreement | Reject publication or indexing, never prefer prose |
| SQL projection transaction fails | Do not select partial index generation |
| Immutable document fetch unavailable after indexing | Return service-unavailable/integrity state; do not synthesize full docs from rows |
| Search projection absent | Rebuild or serve bounded fallback from verified cached documents; never claim completeness silently |
| Hub/network unavailable locally | Serve exact installed/cached docs offline |
| Installed legacy package has no docs | Show explicit unavailable state and package summary |
| LSP cannot understand dynamic Nix | Withhold advisory diagnostic; offer authoritative APM evaluation |

## Acceptance test matrix

### Producer and object identity

- two isolated builds of the same inputs produce byte-identical canonical JSON,
  store path, NAR hash, document digest, and semantic digest;
- prose-only changes change the document identity but not semantic digest,
  runtime measurement, unit fingerprint, or activation action;
- type/ownership/runtime changes change semantic digest and comparison output;
- unsafe defaults, secret material, store context, exact store-path/hash
  references, mismatched declaration paths, and unbounded fields fail
  publication;
- packages with and without config/expose artifacts produce valid appropriate
  documents.

### Publication and indexing

- pointer visibility is withheld after failure at every upload/object/commit
  boundary and a retry is idempotent;
- tampered store path, narinfo, NAR hash/size, document digest/size, NAR node
  type, trailing bytes, reference set, canonical JSON, or schema fails;
- native and Worker ingest the same fixture corpus and commit identical rows;
- malformed objects remain bounded under fuzzing and memory/time limits;
- a complete SQL reset and re-index reproduces search results and order.

### Retention and GC

- catalog, immutable release, channel, subscription, manual root, and installed
  generation independently retain documentation;
- output, config module, expose artifact, and documentation all appear in release
  artifact snapshots and GC explanations;
- removing the final root plus grace collects the documentation object;
- upgrade and rollback switch exact payload/config/expose/docs identities;
- installed docs remain readable after deleting registry worktrees, network
  access, and discretionary caches.

### Search/API/Web

- deterministic ranking, filters, highlight ranges, and cursor invalidation pass
  across native/Worker and all SQL backends;
- public/private/internal visibility never leaks through results, counts, errors,
  caches, or deep links;
- API golden fixtures cover JSON, Connect, ETag, immutable/mutable cache policy,
  pagination, and error contracts;
- no-JavaScript search, package, option, services, compare, and integrity pages
  contain complete useful content;
- enhanced UI passes keyboard, screen-reader, zoom, reduced-motion, contrast,
  responsive, focus, CSP, and content-injection tests;
- configuration drafts/credential refs never enter URLs, logs, telemetry, or
  server search requests.

### CLI/offline/man/LSP

- terminal, JSON, JSONL, and man golden fixtures render from one document model;
- terminal/roff hostile-input fixtures cannot inject control or macros;
- loopback docs server binds loopback by default and serves installed docs with
  no Hub;
- LSP fixtures cover completion, resolve, hover, availability, ownership,
  deprecation, credential shapes, definition, and advisory/authoritative labels;
- an offline editor uses installed docs; an online editor respects digest/ETag
  and private-registry authorization;
- dynamic shell completion is bounded, side-effect free, and degrades quickly
  when remote service is unavailable.

### Documentation migration

- every public package option has generated description/type/ownership;
- generated runtime pages cover all signed units, artifacts, paths, credentials,
  ports, and capabilities;
- each handwritten package guide is compared against the generated result and
  unique conceptual content is migrated before deletion;
- repository lint prevents reintroducing package option/reference tables outside
  the structured authoring API after cutover.
