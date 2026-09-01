# Language tooling and hint APIs

## Architecture

AOS supplies one language server:

```text
aos language-server --stdio
```

It implements the current
[Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
and reuses the canonical documentation/schema model, resolver selection rules,
and snippet formatter. It does not embed a Nix evaluator and does not declare a
configuration valid merely because local structural checks pass.

The structured document types, digest rules, comparison, safe text rendering,
and search primitives come from the WASM-safe documentation core split out of
the existing `aos-doc` crate. The language server and Hub never depend on that
crate's native repository walker, `NixRunner`, mtime cache, Markdown parser, or
ratatui TUI.

The server resolves schemas in this order:

1. exact documentation objects retained by the selected/installed APM
   generation;
2. exact objects in the verified local documentation cache;
3. an explicitly configured Hub/registry using the documentation API;
4. summary-only legacy metadata, which provides no option validation.

Workspace settings can pin registry, release/channel, version, platform,
module ABI, and desired package set. Every diagnostic/hover response records the
selected identity internally, and clients can expose it through an AOS status
view.

## Supported document contexts

The first implementation supports AOS runtime-module Nix files and fragments
managed by `apm config`. It recognizes option assignments, attribute sets,
lists, imports, and common literal forms without trying to implement all Nix
evaluation. Later support may include desired-package TOML or other AOS-owned
configuration syntaxes through separate document adapters over the same schema.

When syntax is too dynamic to understand safely, the server withholds a claim
rather than reporting a false error. Authoritative `apm config diff/apply`
evaluation remains available as an explicit command/code action.

## LSP features

### Completion

`textDocument/completion` proposes option segments and values based on the
selected package set and path context. Items include:

- exact path/segment and structured type;
- concise documentation and safe default;
- owner package/root and contributor status;
- availability/deprecation/activation badges;
- version/platform/document digest in resolve data;
- syntax-correct insertion snippets for enums, records, lists, credential
  reference shapes, and wildcard submodules.

`completionItem/resolve` fetches full details lazily from the local object or Hub
API. The server never proposes a foreign root that the selected package set
cannot own or contribute to.

### Hover and signature help

Hover shows type, description, default/default text, example, owner,
availability, deprecation, activation impact, and source locator. Structured
submodules provide field help and enum choices. Large conceptual sections are
linked rather than copied into every hover.

### Diagnostics

Local diagnostics include:

- unknown option/path segment;
- option unavailable for selected version/platform/module ABI;
- structurally wrong literal type or violated simple constraint;
- deprecated option and replacement;
- package root absent from the selected/desired package set;
- contribution owner absent or ABI-incompatible;
- attempt to configure a read-only/internal path;
- malformed opaque credential reference shape;
- obvious conflicting/duplicate assignments.

Each diagnostic states whether it is **structural/advisory** or returned by an
authoritative APM evaluation. The language server must not reproduce the full
Nix module merge algorithm and label that approximation authoritative.

### Navigation and actions

- `textDocument/definition` navigates to a repository-relative declaration when
  the authenticated source identity can resolve it, otherwise to the exact Hub
  option page.
- `textDocument/documentLink` links package/option references to immutable docs.
- code actions replace deprecated paths, insert a package into the desired set,
  create an opaque credential-reference skeleton, and invoke `apm config diff`.
- workspace symbols search visible option paths, packages, services, and
  capabilities.
- semantic tokens may distinguish package roots and option paths, but are not
  required for correctness.

## Schema/hint API

The Hub `DocumentationService` is the language-tooling API; a second bespoke LSP
database is not introduced. `apm schema` provides the same model locally. The
API supports:

- exact package or resolved desired-set schemas;
- option prefix listing and single-option retrieval;
- semantic schema digest and document ETag;
- bounded batch retrieval for editor initialization;
- availability and ownership filtering;
- compare for workspace upgrade previews.

Clients cache by document/semantic digest and use conditional requests. A Hub
response is only accepted when its exact signed identity matches the requested
selection. Private registries use the normal AOS Hub authentication and resource
authorization flow.

## Dynamic shell completion

`aos completions` retains static command grammar generation. Commands whose
values depend on installed packages or registry schemas call a hidden bounded
completion endpoint in `apm`/`aos`, backed by the same local/remote schema:

- package, registry, version, platform, release, and channel names;
- option paths and enum values;
- sections and service names;
- credential handle names (never secret values).

Completion is fast, timeout-bounded, side-effect free, and returns no results
when a remote source is unavailable rather than blocking the shell. Static
completion remains useful offline even without documentation objects.

## Editor integrations

The language server owns protocol semantics. Thin editor extensions may add:

- server discovery/startup;
- registry authentication handoff through existing AOS CLI mechanisms;
- an AOS package/docs explorer populated through LSP custom read-only requests;
- upgrade comparison and authoritative diff actions;
- status display of release/platform/schema identity.

Extensions do not ship copied option catalogs. A new editor can obtain complete
functionality from standard LSP plus the stable Hub/CLI JSON APIs.

## Privacy and resilience

Workspace text, option values, desired config, and credential references are
not uploaded for completion or hover. Remote requests contain package/schema
selectors and path/query prefixes only. Authoritative remote evaluation is a
separate explicit user action governed by APM policy.

The server remains functional with exact local installed docs when Hub is
offline. Stale mutable channel resolution is clearly marked; immutable cached
documents remain valid. If no exact schema exists, the server degrades to Nix
syntax support and package summaries instead of guessing from a newer release.
