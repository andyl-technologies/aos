# RFC-0015: Package documentation as authenticated Nix objects

- **Status:** Proposed (design-only).
- **Date:** 2026-08-28.
- **Audience:** package authors; APM, registry, AOS Hub, Web UI, CLI, and
  language-tooling maintainers; release and cache operators.
- **Depends on:** RFC-0005's store realization graph, RFC-0011's package-owned
  configuration modules, and RFC-0012's shared native/Worker Hub topology.
- **Implementation:** none in this RFC. The runtime-module work in pull request
  #218 lands unchanged; the migration from its handwritten package guides is a
  later, explicitly gated phase of this proposal.

## Summary

AOS package documentation becomes a versioned, canonical, structured document
produced from package and Nix module declarations. The trusted publisher stores
that document as an independent content-addressed Nix store object, signs its
identity alongside the package's other platform artifacts, and uploads its NAR
and narinfo through the ordinary registry/cache publication path.

The document, not Markdown or a database row, is the authority. AOS Hub verifies
and reads the object during registry indexing. It may materialize disposable
search projections into SQL, but deleting those projections and re-indexing the
signed registry must reproduce the same browse and search corpus. Native Hub and
Cloudflare Worker use the same bounded fetch, strict single-file NAR decoder,
schema validator, search model, API resources, and server-rendered Web views.

One authenticated object then drives all presentation surfaces:

- a polished public and authenticated Hub package/options browser;
- a stable Connect/HTTP documentation and schema API;
- local and remote `apm`/`aos hub` commands;
- offline terminal and generated man-page documentation for installed packages;
- shell completion and an AOS language server for completion, hover,
  diagnostics, source navigation, and configuration snippets.

Documentation is generated before indexing. Hub never evaluates package Nix,
executes a derivation, or interprets untrusted Markdown. Runtime ABI and TPM
measurement remain bound to executable/configuration semantics; prose-only
documentation changes do not churn a service or change its measured runtime
identity.

## Load-bearing decisions

1. **Structured canonical JSON is the source format.** Its initial media/schema
   identifier is `aos.package-documentation/v1+json`.
2. **Every documentation document is a separate Nix store object.** The signed
   package platform entry associates that object with the exact package version
   and platform.
3. **Generation is a publication step, not a Hub indexing step.** The publisher
   evaluates the restricted documentation view and materializes the returned
   pure data. Hub remains evaluator-free and works identically on native and
   Worker deployments.
4. **SQL is an index, never the documentation authority.** Search rows contain
   locators, sortable fields, and normalized terms. The canonical document stays
   in the binary cache and is fetched by authenticated digest.
5. **Installed-package docs are offline and generation-correct.** APM profiles
   retain the exact documentation store object selected with the package, so
   upgrade and rollback switch code and documentation together.
6. **All user interfaces share one semantic model.** Web, API, CLI, man-page
   rendering, completion, and LSP behavior may format differently but must not
   invent different option types, defaults, visibility, or ownership rules.
7. **Handwritten per-service option references are transitional.** They are
   removed only after generated documentation reaches acceptance parity. Unique
   conceptual and operational prose is migrated into structured package
   sections or retained cross-package guides first.

## Topic files

| File | Contents |
| --- | --- |
| [`00-goals-and-invariants.md`](00-goals-and-invariants.md) | Goals, non-goals, terminology, and invariants |
| [`01-document-object.md`](01-document-object.md) | Canonical schema, option type algebra, runtime surface, and authoring rules |
| [`02-generation-and-publication.md`](02-generation-and-publication.md) | Restricted Nix extraction, store-object materialization, signed metadata, and atomic publication |
| [`03-indexing-search-and-retention.md`](03-indexing-search-and-retention.md) | Native/Worker verification, SQL search projections, release retention, profile retention, and GC |
| [`04-web-experience.md`](04-web-experience.md) | World-class public and authenticated Web information architecture and interaction design |
| [`05-api-cli-and-offline.md`](05-api-cli-and-offline.md) | Connect/HTTP resources, CLI design, offline docs, and generated man pages |
| [`06-language-tooling.md`](06-language-tooling.md) | Language-server, editor, schema, and dynamic completion contracts |
| [`07-security-compatibility-and-testing.md`](07-security-compatibility-and-testing.md) | Trust boundary, compatibility, privacy, limits, failure modes, and acceptance matrix |
| [`08-implementation-plan.md`](08-implementation-plan.md) | Phased implementation and the explicit handwritten-documentation removal inventory |
| [`09-decisions-and-open-questions.md`](09-decisions-and-open-questions.md) | Locked choices, rejected alternatives, and bounded questions |

## Relationship to current code

The current tree already contains most of the required seams:

- `PlatformEntry` authenticates payload, expose, and configuration-module
  companion artifacts. RFC-0015 adds a generic documentation artifact beside
  them so packages without configuration modules can also publish docs.
- `ConfigModuleMeta.declaration_schema` carries sorted option paths and stable
  type signatures. It is the compatibility index, but not rich enough to be the
  human and tooling document proposed here.
- `SurfaceFetch::fetch_bounded` gives shared native/Worker code a size-checked
  path for small semantic objects. The documentation reader extends that model
  with a bounded, streaming, single-file NAR verifier.
- the shared Hub indexer already derives release artifact snapshots and applies
  them atomically. Its artifact enumeration currently covers output,
  source-derivation, and image objects; it must add documentation and also close
  the adjacent config/expose retention gap.
- shared Hub browse pages already render from indexed data without JavaScript,
  while the static registry Web generator produces content-bearing HTML and JSON
  snapshots. RFC-0015 preserves that floor and adds progressive enhancement,
  not a client-only replacement.
- the existing `aos-doc` crate scans a mutable source checkout, optionally
  evaluates modules, caches a timestamped Markdown-bearing `DocIndex`, and
  provides `aos doc` search/TUI views for Nix functions, types, language,
  modules, and packages. That remains useful developer documentation, but it is
  not release-authenticated or Worker-safe as-is. RFC-0015 extracts a shared
  structured model and adds exact installed/Hub backends without treating the
  source cache as package-release authority.

This RFC does not make generated prose canonical for AOS concepts that span
packages. Architecture, security model, tutorials, incident procedures, and
multi-package workflows remain authored documents. It removes duplicated
package option/service reference pages, not deliberate human explanation.
