# Decisions, rejected alternatives, and open questions

## Locked decisions

1. Documentation is generated from Nix/package declarations before Hub
   indexing.
2. The canonical document is a closed, canonical JSON format, initially
   `aos.package-documentation/v1+json`.
3. The document is one independent content-addressed Nix store object selected
   by signed per-platform package metadata.
4. The v1 NAR is uncompressed and contains exactly one non-executable regular
   file with no references.
5. Canonical document bytes remain outside SQL. SQL holds locators and
   reproducible search projections only.
6. Native and Worker share decoding, validation, indexing, search, API resources,
   and render/view semantics.
7. Installed APM generations directly retain the exact documentation object.
8. Web, API, CLI, terminal, man, shell completion, and LSP consume one semantic
   model.
9. Server-rendered no-JavaScript pages are the functional floor; interactive UI
   is progressive enhancement.
10. Documentation prose does not participate in runtime measurement, unit
    fingerprints, or module ABI. A separately computed semantic schema digest
    identifies tooling-relevant interface changes.
11. Credential documentation describes opaque contracts only and never contains
    secret values.
12. Handwritten per-package reference pages are removed only after generated
    parity and migration of unique conceptual content.

## Rejected alternatives

### Generate documentation during Hub indexing

Rejected because it would require a Nix evaluator and package source/evaluation
context in native Hub and Worker, make indexing execute publisher-controlled
logic, and break reproducibility from the signed object set.

### Store parsed documentation only in SQLite/D1

Rejected because database rows would become the sole mutable authority, could
not naturally travel with installed packages, would complicate release/GC
identity, and would make backend migrations a content preservation mechanism.
SQL remains an acceleration index that can be recreated.

### Reuse the existing source-tree `DocIndex` as the signed format

Rejected because it contains build timestamps, Markdown bodies, stringly typed
metadata, and checkout-relative results gathered by filesystem scanning and
optional local evaluation. It remains a useful disposable developer index. The
implementation shares/refactors safe presentation code around the new closed
model rather than authenticating the mutable cache format.

### Put docs inside the runtime or config output

Rejected because prose changes would rebuild or churn runtime/config identities,
packages without config modules would not fit, and independent content-addressed
cache/retention would be lost.

### Publish Markdown and render it everywhere

Rejected because Markdown is not a complete type/schema contract, creates
renderer/security differences among Web/terminal/man/editor clients, and
encourages duplicate option tables. A small structured prose AST provides the
needed presentation without raw markup.

### Store only JSON Schema

Rejected because Nix module semantics include ownership, contribution, option
merge behavior, activation effects, credentials, services, availability, and
conceptual/runtime information that JSON Schema alone cannot represent. The AOS
model may expose JSON-schema-like projections for compatible tools.

### Make the LSP authoritative

Rejected because static tooling cannot safely reproduce unrestricted Nix
evaluation and module merging. It supplies high-quality structural advice and
invokes APM for authoritative results.

### Require JavaScript or Hub for documentation

Rejected because OS/package reference material must work in recovery, offline,
minimal, accessibility, and Worker-degraded contexts. Server HTML and local
terminal docs are complete.

### Pre-generate and commit man pages/HTML/SQL rows

Rejected because those are presentation derivatives and create multiple sources
of truth. They may be cached or image-built from the authenticated document.

## Bounded open questions

### Exact v1 limits

The design ceiling is 4 MiB for the uncompressed single-file documentation NAR.
Phase 0 measurements must choose exact document, string, collection, nesting,
and search-token limits that comfortably cover current packages under Worker
budgets. Limits become part of the versioned ingestion policy.

### Canonical JSON specification

The implementation must choose whether to adopt a compatible external
canonical-JSON profile or specify an AOS subset. In either case, one shared
encoder and byte fixture corpus is normative; "object key order does not matter"
is not acceptable for content identity.

### Documentation-only release UX

The object can change without runtime artifacts. Release/channel policy must
decide how to label and promote documentation-only corrections without implying
a software update, while preserving signed historical identity.

### Cross-registry option search

Global search can return several visible packages declaring the same path.
Product work must finalize grouping and default registry/channel selection. It
may not collapse distinct signed identities into one synthetic option.

### Public package prose links

The schema permits validated HTTPS links. Instance policy must decide whether to
render them directly, interpose a destination warning, or restrict allowed
domains. Source/package/option links remain first-class typed links.

### Static registry search depth

The static registry surface can pre-render package pages and summaries without
Hub. A bounded client-side search index may be useful, but it must be generated
from the same documents, content-addressed, optional, and not required for the
no-JavaScript browsing floor.

### Richer semantic validation

Future tools may use a sandboxed authoritative evaluator for explicit editor
actions. That is separate from the schema/LSP path and must reuse APM's exact
evaluation, authorization, timeout, and secret boundaries rather than adding a
Hub-side general Nix evaluator.

None of these questions changes the core object, trust, native/Worker, offline,
or single-authority decisions and therefore does not block accepting the RFC.
