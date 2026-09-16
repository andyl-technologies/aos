# Goals, terminology, and invariants

## Problem

RFC-0011 makes package-owned Nix configuration a real product interface. Today
the interface is described in handwritten Markdown alongside the Nix options
that actually define it. Those representations drift, cannot be queried by
tools, are not automatically tied to a package version, and do not travel with
an installed package for offline use.

Hub currently indexes package summaries and artifact identities, but it has no
authenticated, structured option corpus. The browser, API, CLI, shell, and
editors would each have to rediscover or manually encode package semantics. A
database-first solution would make a mutable Hub database the only surviving
copy of data that was originally declared in Nix and would complicate parity
between native SQL backends and Worker D1.

## Goals

- Extract complete, deterministic package documentation from the same Nix code
  that declares package configuration and exposure policy.
- Represent the result as a versioned machine-readable contract suitable for
  people, Web rendering, APIs, CLIs, man pages, completion, and language tools.
- Authenticate the exact document to a package version and platform and retain
  it through ordinary Nix object, release, profile, and garbage-collection
  lifecycles.
- Keep the canonical bytes outside mutable SQL while still supporting fast
  full-text and structured search.
- Serve the same behavior from native AOS Hub and Cloudflare Worker without a
  Nix evaluator, Nix daemon, host filesystem dependency, or native-only parser
  in the Worker.
- Make installed-package documentation fully available without a registry or
  network and exact across upgrade and rollback.
- Provide a polished, accessible, progressively enhanced package and option
  browser with stable deep links.
- Give editors and automation a digest-addressed schema/hint API without
  pretending that hints replace authoritative `apm config` evaluation.
- Remove duplicated handwritten package/service reference documentation once
  the generated surfaces meet explicit completeness and usability gates.

## Non-goals

- Evaluating Nix on Hub, in a Worker isolate, in the browser, or in an editor.
- Serializing arbitrary Nix values or functions.
- Publishing secret values, credential contents, host facts, evaluated runtime
  configuration, or operator configuration.
- Replacing RFCs, conceptual guides, tutorials, runbooks, or incident response
  documentation with generated option listings.
- Making documentation prose part of a runtime module ABI or TPM measurement.
- Making an LSP or JSON-schema-like client authoritative for configuration
  acceptance. Restricted Nix evaluation remains authoritative.
- Requiring JavaScript, an online Hub, `man`, or a particular SQL full-text
  extension to read package documentation.

## Terminology

**Documentation document**
: The canonical JSON value describing one package version/platform's authored
  metadata and independent integrity identity. It is not mutated to carry the
  package ability contract.

**Package tooling response**
: The versioned, checked response that binds one authenticated documentation
  object to one checked `PackageAbilityReference` and mechanically derives its
  option and exported-method schemas. It is a disposable projection, not a
  third authored package artifact.

**Documentation object**
: The content-addressed Nix store regular-file object whose bytes are the
  canonical documentation document.

**Documentation artifact reference**
: Signed package metadata that binds a documentation object store path, NAR
  identity, content digest, format, and limits to a platform entry.

**Semantic schema digest**
: The documentation object's digest over its own configuration-independent
  semantic fields. Option and method identity comes from the separately checked
  ability manifest and package digest; the tooling response binds all of these
  identities rather than pretending one documentation digest covers both
  artifacts. Editorial prose is excluded from the documentation semantic
  digest.

**Search projection**
: Disposable SQL rows derived deterministically from authenticated documents.
  They accelerate search but are not a source of truth.

**Installed documentation root**
: The APM profile reference that retains and exposes the exact documentation
  object for an installed package generation.

## Invariants

### One authenticated authority

For a selected `registry/package/version/platform`, authored package prose and
metadata come from the documentation object named by that signed platform
entry. Option and method schemas come only from the checked ability reference
for the same signed coordinate. The versioned tooling response binds both
identities and recomputes all schema rows. Hub rows, rendered pages, browser
caches, CLI caches, generated man pages, and LSP caches are discardable
derivatives.

### Documentation never executes

The document is data with a closed schema. Readers do not execute Nix, render
Markdown as HTML, follow arbitrary external includes, interpret template code,
or load scripts named by a package.

### Publication is complete before visibility

A registry commit or release cannot become visible when its signed
documentation object, narinfo, provenance binding, or required search projection
is missing or invalid. Publication may upload objects in any retryable order,
but the mutable Git/channel pointer advances only after the complete typed
inventory has been verified.

### Native and Worker parity

The same `aos-hub-core` logic parses, verifies, normalizes, tokenizes, ranks, and
renders documentation on native and `wasm32-unknown-unknown`. Runtime adapters
only fetch bounded byte streams and persist typed projections.

### Runtime identity separation

Changing only a description, example, source link, or conceptual section may
produce a new documentation object and signed release metadata. It must not
change the runtime payload root digest, configuration binding measurement,
service unit fingerprint, restart decision, or module ABI.

Changing a path, structured type, contribution boundary, or provided/consumed
ability semantic changes the corresponding checked identity and is visible to
compare and tooling. Concrete activation remains a deployment-plan fact.

### Offline fidelity

If package generation `G` is installed, its documentation object is retained and
readable without any registry. Rolling back to `G` restores both its executable
and its documentation identity. APM never silently substitutes documentation
from a newer package version.

### Secret-free and context-free data

Defaults and examples enter the document only when they are bounded,
JSON-serializable, free of Nix store string context, and proven not to contain a
secret. The complete encoded file is scanned to reject exact store paths and
store-hash components. Credentials are documented only as names, purposes,
accepted opaque reference schemes, required modes, and activation behavior.

### Bounded resource use

Documents, NARs, strings, collections, nesting, search terms, snippets, and API
pages have versioned hard limits. Size declarations are checked before
allocation and streamed bytes are independently capped and hashed.

### Stable addressability

Human routes may select mutable channels, but every schema response exposes its
exact registry commit/release, package version/platform, documentation store
path and NAR hash, document and semantic digests, ability manifest digest, and
ability package digest. Digest routes are immutable and cacheable.
