# Implementation plan

Pull request #219 implements this plan after rebasing onto the unchanged
runtime-module work from pull request #218. The completed checklist below is the
acceptance inventory: canonical objects, Hub surfaces, offline tooling, editor
integration, fleet coverage, and the handwritten-reference migration landed as
one coordinated cutover.

## Phase 0: characterize and freeze the contracts

- [x] Inventory every package summary, config option, ownership/contribution
      rule, expose artifact, unit, listener, managed path, credential contract,
      capability, activation effect, and unique prose section in current package
      guides.
- [x] Define the closed `aos.package-documentation/v1` data model, canonical JSON
      encoding, semantic schema digest, structured prose/type/path algebras, and
      hard limits.
- [x] Add golden fixtures covering simple packages, typed config owners,
      contributors, wildcard submodules, credentials, exposed services,
      platform differences, deprecation, and legacy packages.
- [x] Characterize current `PlatformEntry`, declaration-schema, store graph,
      publication inventory, Hub index transaction, release artifact snapshot,
      GC, package Web, CLI output, and native/Worker behavior.
- [x] Characterize the existing `aos-doc` source walker, Markdown-bearing
      `DocIndex`, mtime cache, search, output, and TUI contracts; identify the
      compatibility boundary between mutable developer docs and authenticated
      package-release docs.
- [x] Decide exact v1 size/count limits from native and Worker measurements; the
      initial design ceiling is 4 MiB per uncompressed document NAR.
- [x] Add a repository policy that new package option reference content is
      authored in Nix data while transitional Markdown remains readable.
- [x] Close the runnable-service inventory: every package carrying a systemd
      unit must expose a typed package contract, every managed package must be
      present in the documentation catalog, and reviewed on-demand engines and
      test fixtures must have an explicit non-service disposition.

**Done when:** fixtures and the checked schema can represent every interface in
the current package-guide inventory without executing Nix in a consumer.

## Phase 1: extraction and documentation store artifacts

- [x] Extend the restricted base library/options-only evaluation with pure
      documentation constructors and export.
- [x] Implement shared Rust document types, validation, canonical encoding,
      structured prose rendering primitives, and semantic digest computation.
- [x] Split a WASM-safe structured model/search/render core from the native
      `aos-doc` repository walker, Nix evaluation, cache, built-in language data,
      and TUI; migrate shared presentation without making the old `DocIndex` an
      artifact format.
- [x] Cross-check rich option data against `declares`, `declaration_schema`,
      ownership/contribution metadata, config artifacts, credentials, expose
      metadata, and package identity.
- [x] Materialize one empty-reference, non-executable regular-file store object
      after trusted validation.
- [x] Add `DocumentationArtifactMeta` to `PlatformEntry`, feature gating,
      provenance subjects, store graph validation, and registry parsing.
- [x] Make publisher typed inventories upload/verify the docs NAR/narinfo before
      Git/channel pointer movement.
- [x] Generate documents for all configurable packages and summary/runtime docs
      for ordinary packages.
- [x] Extract system/image-owned service documentation from the exact evaluated
      base-library Nix object, bind its NAR hash into the documentation identity,
      and publish named entries such as `aos-hub` without creating a competing
      package configuration owner.
- [x] Reject publication and repository checks when any public configuration
      option lacks a human-authored description; validate summaries and
      structured operational sections for every configurable service.
- [x] Add deterministic-build, tamper, partial-publication, safe-default, and
      prose-versus-semantic-change tests.

**Done when:** a signed registry package selects a verified independent
documentation Nix object and two isolated publications produce identical bytes.

## Phase 2: shared Hub ingestion, search, and retention

- [x] Implement the bounded streaming single-regular-file NAR decoder in
      `aos-hub-core` with native/Worker adversarial fixtures.
- [x] Fetch and verify documentation through `SurfaceFetch` without Nix/FFI or
      general archive extraction.
- [x] Add documentation artifact locators and disposable option/search tables to
      shared migrations for SQLite/D1, PostgreSQL, and MySQL.
- [x] Implement portable tokenization/ranking and prove backend optimization
      parity or use the portable term table.
- [x] Extend release/catalog artifact enumeration and SQL constraints with
      `documentation`, `config_module`, and `expose_artifact`.
- [x] Add registry/release/channel/subscription/manual-root retention and GC
      explanations for all companion objects.
- [x] Atomically select package, artifact, docs, and search rows as one index
      generation; preserve the previous generation on failure.
- [x] Add complete projection reset/rebuild and native/Worker parity tests.

**Done when:** native and Worker index and search the same signed corpus with
identical results, and a database can be destroyed and reproduced from registry
and store objects.

## Phase 3: API and server-rendered Web foundation

- [x] Add shared view resources and `DocumentationService` Connect methods.
- [x] Add public read-only JSON routes with exact identity, ETags, cursor
      pagination, authorization, immutable digest routes, and golden contracts.
- [x] Extend shared server-rendered browse pages with global docs search and the
      package Overview, Configure, Services, Dependencies, Versions, Compare,
      and Integrity routes.
- [x] Render complete content without JavaScript on native Hub, Worker, and
      static registry surfaces.
- [x] Add private/internal visibility and cache isolation tests.
- [x] Add native/Worker HTML and API byte/semantic parity gates.

**Done when:** a keyboard/no-JavaScript browser can discover a package, inspect
every option/runtime fact, compare versions, and verify artifact identity on
either deployment.

## Phase 4: polished interactive Web UI

- [x] Build the progressively enhanced global command search, filters, option
      tree/detail/context workspace, local configuration composer, runtime
      relationship view, semantic comparison, and integrity disclosures.
- [x] Reuse the same shared package view in the authenticated console and public
      browser; add actions only when authorized.
- [x] Keep queries/filters in URLs while keeping configuration values and
      credential refs out of URLs, logs, and telemetry.
- [x] Ship first-party content-addressed assets and a strict CSP.
- [x] Complete keyboard, screen-reader, zoom, contrast, reduced-motion,
      responsive, focus, and no-JavaScript acceptance review.
- [x] Establish performance budgets for cached search, detail fetch, HTML, and
      enhancement assets on native and Worker.

**Done when:** the browser meets the interaction/accessibility/performance
contract in `04-web-experience.md` and does not fork documentation semantics.

## Phase 5: APM, offline docs, and man pages

- [x] Record documentation pins in installed package metadata/profile
      generations and expose deterministic profile links.
- [x] Retain exact docs across install, switch, upgrade, rollback, reboot, and
      profile GC; support image-seeded packages and explicit legacy absence.
- [x] Implement `apm docs`, `apm options`, `apm schema`, cache/sync controls,
      shared terminal/JSON renderers, and `apm show` integration.
- [x] Implement safe shared roff/man rendering without Markdown/Pandoc and a
      complete plain-terminal fallback.
- [x] Implement the loopback-only-by-default `apm docs serve` Web experience.
- [x] Implement `aos hub docs` commands over `DocumentationService` with stable
      JSON/table/JSONL behavior.
- [x] Extend `aos doc` with explicit `source`, `package`, and `hub` backends while
      preserving existing source-tree command behavior through a documented
      compatibility/deprecation window.
- [x] Prove offline installed documentation after all registry/network/cache
      authoring inputs are removed.
- [x] Exercise standalone containerd and kubelet through the public supplemental
      module workflow: diff, dry-run, apply, health/CRI use, invalid replacement,
      valid replacement, retained reboot, disable, and rollback.

**Done when:** an operator can inspect the exact active or rolled-back package
offline through terminal, man, JSON, or the local browser.

## Phase 6: language tooling and dynamic hints

- [x] Implement `aos language-server --stdio` over the shared schema resolver.
- [x] Add completion/resolve, hover, diagnostics, definition, links, symbols,
      deprecation/desired-package/credential code actions, and explicit
      authoritative `apm config diff` actions.
- [x] Implement local-installed, verified-cache, and authenticated Hub schema
      selection with digest/ETag caching.
- [x] Add bounded dynamic shell completion for package/schema-dependent values.
- [x] Publish thin editor-integration guidance and at least one conformance
      client without embedding copied catalogs.
- [x] Test privacy, offline operation, dynamic-Nix uncertainty, identity changes,
      and advisory versus authoritative result labeling.

**Done when:** editors and shells consume the same exact schema as Web/APM and
remain useful offline without claiming to replace Nix evaluation.

## Phase 7: remove superseded handwritten package reference docs

Before deleting any file, compare it with the generated package document and
classify every section as:

1. derived option/runtime/integrity reference, now covered by the object;
2. package-specific conceptual/operational material to migrate into structured
   package sections; or
3. cross-package architecture/tutorial/runbook material to retain in an
   appropriately named authored guide.

- [x] Migrate unique content and then remove
      [`cilium.md`](../../users/aos/cilium.md).
- [x] Migrate unique content and then remove
      [`cloudcore.md`](../../users/aos/cloudcore.md).
- [x] Migrate unique content and then remove
      [`conntrackd.md`](../../users/aos/conntrackd.md).
- [x] Migrate unique content and then remove
      [`containerd.md`](../../users/aos/containerd.md).
- [x] Migrate unique content and then remove
      [`edgecore.md`](../../users/aos/edgecore.md).
- [x] Migrate unique content and then remove
      [`envoy.md`](../../users/aos/envoy.md).
- [x] Migrate unique content and then remove
      [`etcd.md`](../../users/aos/etcd.md).
- [x] Migrate unique content and then remove
      [`garage.md`](../../users/aos/garage.md).
- [x] Migrate unique content and then remove
      [`k3s.md`](../../users/aos/k3s.md).
- [x] Migrate unique content and then remove
      [`krb5-kdc.md`](../../users/aos/krb5-kdc.md).
- [x] Migrate unique content and then remove
      [`longhorn.md`](../../users/aos/longhorn.md).
- [x] Migrate unique content and then remove
      [`mariadb.md`](../../users/aos/mariadb.md).
- [x] Migrate unique content and then remove
      [`nginx.md`](../../users/aos/nginx.md).
- [x] Migrate unique content and then remove
      [`openldap.md`](../../users/aos/openldap.md).
- [x] Migrate unique content and then remove
      [`postgresql.md`](../../users/aos/postgresql.md).
- [x] Migrate unique content and then remove
      [`registry-server.md`](../../users/aos/registry-server.md).
- [x] Migrate unique content and then remove
      [`rsyncd.md`](../../users/aos/rsyncd.md).
- [x] Replace the per-package link inventory in
      [`docs/users/aos/README.md`](../../users/aos/README.md) with the generated
      package browser/CLI entry points while preserving links to conceptual
      guides.
- [x] Update
      [`configuration.md`](../../users/aos/configuration.md) and
      [`package-authoring.md`](../../users/aos/package-authoring.md) to teach the
      generated documentation workflow, structured authoring API, and tooling
      without copying package option tables.
- [x] Keep conceptual Hub deployment documentation such as
      [`docs/users/aos-hub/native.md`](../../users/aos-hub/native.md) unless a
      separately reviewed migration proves its content is package reference
      material.
- [x] Add lint/completeness gates that reject new handwritten package option or
      runtime reference tables after cutover and require generated docs for new
      public configurable packages.

**Done when:** no handwritten file is the authority for a package option or
runtime surface, unique human guidance has a deliberate home, all accepted
surfaces deep-link to generated docs, and deleting the transitional files causes
no information or usability regression.

## Rollout and rollback

The object/API additions remain backward compatible: Hub and APM accept legacy
packages without an advertised documentation artifact and fail closed when an
advertised required artifact is missing or invalid. Hub index generations remain
atomic and rebuildable, and installed profile generations pin the exact document
so package upgrade and rollback move code and documentation together.

The handwritten-reference cutover intentionally leaves one authority. A source
rollback may restore the deleted files together with older tooling, but a running
release never maintains handwritten and generated package references in
parallel.
