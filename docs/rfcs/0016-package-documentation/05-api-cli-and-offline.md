# API, CLI, offline documentation, and man pages

## One resource model

The documentation object model is richer than any individual API response.
`aos-hub-core` defines bounded view resources that the Connect API, public HTTP
JSON, server-rendered Web pages, CLI, and LSP adapters share:

- `DocumentationArtifactRef`;
- `PackageDocumentationSummary`;
- `PackageDocumentation`;
- `OptionSummary` and `OptionDocument`;
- `RuntimeSurfaceDocument`;
- `DocumentationSearchHit`;
- `DocumentationComparison`;
- `DocumentationSourceIdentity`.

Every resource that can outlive a request carries or nests:

- registry and indexed commit/release identity;
- package, version, and platform;
- documentation store path and NAR hash;
- document and semantic schema digests;
- visibility and authorization scope where applicable.

Clients can therefore cache safely and identify when two formatted results come
from the same authority.

## Connect service

The Hub API adds a `DocumentationService` with these initial methods:

```text
SearchDocumentation
GetPackageDocumentation
ListPackageOptions
GetOption
ComparePackageDocumentation
GetDocumentationArtifact
```

Requests select exact versions/platforms or a named release/channel that the
server resolves and reports. Search and list methods use opaque cursor tokens
bound to the registry index generation, query, filters, authorization scope,
and page size. A cursor from a different query or generation fails cleanly.

`GetDocumentationArtifact` returns the verified canonical JSON bytes or a
bounded streamed response plus identity metadata. It does not expose an
unverified cache object merely because a caller knows a store hash.

The Connect service is the authenticated and administrative API. Normal Hub
resource-access policy applies to private registries, internal options, source
identity, and artifact retrieval. Public resources are also exposed through
simple read-only HTTP JSON endpoints for browsers and lightweight tools.

## Public HTTP JSON

Representative routes are:

```text
GET /-/api/v1/docs/search
GET /{registry}/-/api/v1/packages/{package}/documentation
GET /{registry}/-/api/v1/packages/{package}/options
GET /{registry}/-/api/v1/packages/{package}/options/{encoded-path}
GET /{registry}/-/api/v1/packages/{package}/compare
GET /{registry}/-/api/v1/documentation/{document-sha256}
```

Common parameters include `q`, `kind`, `package`, `version`, `platform`,
`release`, `channel`, `owner`, `type`, `contributable`, `page_size`, and
`page_token`. Path encoding is defined over the structured option path, not an
ambiguous dot-separated string.

Responses use:

- strong ETags for immutable document-digest routes;
- exact selection/digest headers on mutable package routes;
- plain text plus numeric highlight ranges, never HTML snippets;
- stable JSON field names and closed enums;
- bounded page sizes and error bodies;
- public-cache headers only for public resources.

The public HTTP handler and Connect implementation invoke the same service
methods. Native and Worker conformance fixtures require identical status,
headers, selection, JSON, pagination, ranking, and authorization outcomes.

## Local APM commands

`apm` reads installed documentation directly from the selected package profile
and can optionally resolve uninstalled documentation through configured
registries:

```text
apm docs nginx
apm docs nginx --version 1.30.4 --platform x86_64-linux
apm docs nginx --section services
apm docs nginx --format terminal|man|json

apm options search 'tls certificate'
apm options search --installed --type opaque-reference
apm options show nginx.virtualHosts.<name>.listenPort
apm options compare nginx --from 1.28.0 --to 1.30.4

apm schema nginx --format aos-json
apm schema --installed --format aos-json
apm schema --desired ./desired.nix --format aos-json

apm docs --open nginx
apm docs serve --listen 127.0.0.1:0
```

Selection rules are explicit:

1. `--installed` or an installed package defaults to the exact active profile
   documentation object.
2. `--generation` selects that retained profile's exact object.
3. an explicit registry/version/platform fetches and verifies that signed
   object, then may place it in the documentation cache.
4. an unresolved package does not fall back to unrelated/latest Markdown.

`apm show` gains a concise documentation/status summary and points to `apm docs`
rather than duplicating the complete renderer.

All commands support existing AOS output conventions where meaningful: human
terminal, table, `--json`, JSON Lines for streams, `--quiet`, and stable exit
codes. JSON returns the shared resource/schema model, not terminal formatting
internals.

## Hub CLI commands

Remote discovery and operator workflows use the existing `aos hub` connection,
authentication, and output model:

```text
aos hub docs search 'network listener' --registry core
aos hub docs package nginx --version 1.30.4
aos hub docs option nginx.virtualHosts.<name>.listenPort
aos hub docs compare nginx --from 1.28.0 --to 1.30.4
aos hub docs fetch nginx --output nginx-docs.json
aos hub docs open nginx
```

The CLI calls `DocumentationService`; it does not scrape Web pages or perform a
second Nix evaluation. `fetch` verifies returned identity and canonical bytes
before writing. `open` prints the URL unless the user explicitly allows opening
a browser in their environment.

## Relationship to the existing `aos doc`

`aos doc` already provides a developer-oriented source-tree index and TUI. It
scans `lib/`, `modules/`, and `pkgs/`, contains built-in Nix language reference
data, optionally enriches options with local evaluation, and invalidates its
JSON cache with filesystem modification times. That is a useful authoring view,
but it describes a mutable checkout and stores Markdown strings; it is not the
authenticated package documentation object in this RFC.

The command becomes a unified human front door with explicit sources:

```text
aos doc source [PATH]                 # existing repository/lib/language view
aos doc package nginx --installed     # exact local APM object
aos doc package nginx --registry core # exact verified registry object
aos doc hub search 'tls listener'     # DocumentationService search
```

Existing `aos doc <path>`, `--search`, `--list`, `--source`, and interactive TUI
behavior remains a compatibility spelling for `aos doc source` during a normal
CLI deprecation window. Package results display their source kind and exact
release/document identity; source-tree results display checkout/source identity
and are never labeled installed or verified-release docs.

The implementation splits the current crate so a closed structured document,
safe renderers, comparison, and deterministic search primitives live in a small
WASM-safe core. The native repository walker, `NixRunner` enrichment, mtime
cache, ratatui UI, and built-in language corpus remain in the native `aos-doc`
layer. `apm docs` is the focused on-host operational interface, while `aos doc`
can browse source, local package, and Hub corpora interactively and `aos hub
docs` remains the stable remote automation family.

## Terminal rendering

The default renderer is deliberately independent of `man` and terminal escape
features. It emits readable headings, wrapped paragraphs, definition lists,
option paths/types/defaults, and tables in plain text. Color and hyperlinks are
optional capability-driven enhancements and never the only signal.

The renderer supports focused sections and paths so a large package need not
flood the terminal:

```text
apm docs nginx --section overview
apm docs nginx --section services
apm docs nginx --option 'nginx.virtualHosts.<name>.tls.enable'
```

Pager use follows existing CLI policy and is disabled for non-interactive output
or structured formats.

## Generated man pages

APM renders man-source or terminal man output dynamically from the same
documentation object. No Pandoc, Markdown converter, or package-authored roff is
in the runtime closure.

The conventional views are:

```text
apm-nginx(5)       package configuration and runtime surface
aos-options(5)     option language, ownership, contribution, and references
```

`apm docs nginx --format man` writes safe generated roff to stdout. `apm docs
nginx` may invoke the installed AOS `man`/pager only when present and requested;
otherwise the plain renderer is complete. All roff control characters and line
starts are escaped by trusted shared code.

Images may optionally build generated compressed man pages for image-seeded
packages from documentation objects, but the canonical object remains JSON.
Generating pages during image assembly is a cache optimization, not a second
authoring source.

## Offline browser

`apm docs serve` provides the shared content-bearing Web renderer over an
ephemeral loopback listener, defaulting to `127.0.0.1` and an allocated port. It
reads installed/cached authenticated documentation only, performs no Nix
evaluation, and does not require Hub.

Remote listening requires an explicit non-loopback address plus the ordinary
AOS service/auth policy; the convenience command does not silently expose local
package inventory. `apm docs --open` can start the loopback server and print or
open its URL. The local UI retains package/configure/services/integrity views and
searches the bounded local corpus.

## Cache and sync controls

Local commands distinguish retained installed objects from a discretionary
registry documentation cache:

```text
apm registry sync --documentation=installed
apm registry sync --documentation=all
apm docs cache status
apm docs cache gc
```

Cache status explains source registry, exact digest, last verification, and
whether a profile currently roots the object. GC cannot remove an installed
generation's documentation root. Cached API/search projections may be rebuilt
from local canonical objects.
