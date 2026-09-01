# Interactive Web experience

## Product standard

The documentation browser is a first-class OS interface, not a dump of Nix
option rows. It must answer, with minimal navigation:

- What is this package and can I use it on my selected release/platform?
- How do I install and enable it?
- Which options exist, what do they mean, and who owns or may contribute them?
- What will changing this option reload, restart, recreate, or reboot?
- Which services, listeners, paths, credentials, capabilities, and confinement
  rules does the package create?
- What changed between two versions?
- Which exact signed objects and source produced this page?

The public registry browser and authenticated producer console share page/view
models and components in `aos-hub-core`. The console may add authorized actions;
it may not render a different documentation interpretation.

## Information architecture

The reserved human route space is:

```text
/-/docs
/-/docs/options/{encoded-option-path}
/{registry}/-/packages
/{registry}/-/packages/{package}
/{registry}/-/packages/{package}/configure
/{registry}/-/packages/{package}/services
/{registry}/-/packages/{package}/versions
/{registry}/-/packages/{package}/integrity
/{registry}/-/packages/{package}/compare
```

Global pages search across visible registries. Registry package pages stay under
the existing `/{registry}/-/...` namespace and coexist with packages, images,
channels, releases, and health. Every page has a canonical URL carrying version,
platform, and release/channel selection in explicit query parameters when those
are not implied by the route.

The package workspace has a persistent header and six primary tabs:

```text
Package / version / platform / channel              Verified
Summary                                [Copy install] [Configure]

Overview | Configure | Services | Dependencies | Versions | Integrity
```

The header exposes the exact document digest and selection in a disclosure,
without making raw hashes dominate ordinary navigation.

## Search and discovery

The global search box is available in the page header and through `Cmd/Ctrl-K`
or `/` when focus is not in an input. It uses the same documented ranking as the
API. Results group packages, options, services, capability providers, credential
contracts, and conceptual sections while preserving one total keyboard order.

Search is usable as a no-JavaScript GET form. Progressive enhancement adds an
ARIA combobox with incremental results, recent local queries, filter chips, and
keyboard shortcuts. It never changes result authority or hides a server result
behind a client-only index.

Filters include registry, package, version/release/channel, platform, result
kind, option type, owner, contributable state, deprecation, and activation
effect. Active filters and the query live in the URL. Pagination is cursor-based
and bounded; there is no infinite scroll.

The option deep-link route resolves an exact path across visible packages. When
several packages/versions declare the path, it presents a comparison/selection
view rather than guessing.

## Configure workspace

On wide screens the Configure tab uses three coordinated panes:

```text
+----------------------+----------------------------+-----------------------+
| Option tree          | Selected option            | Configuration context |
| filter + ownership   | type, prose, default,      | composer, owner,      |
| package/root groups  | example, activation        | related options       |
+----------------------+----------------------------+-----------------------+
```

On narrow screens they become one ordered view with a back-to-tree control and
sticky selection summary. Each option has a stable anchor and can be opened in a
dedicated full-width route.

The option tree:

- groups path segments and wildcard submodules without flattening away
  structure;
- distinguishes owned roots and contributed subtrees;
- preserves expansion/selection in the URL or local navigation state;
- shows badges for required, deprecated, read-only, internal, contributable,
  credential-related, and restart/reboot effects;
- supports keyboard tree navigation and a linear accessible fallback.

The detail pane shows:

- exact path with copy action;
- structured type with enum/submodule fields;
- description and conceptual links;
- default/default text and example;
- version/platform/ABI availability;
- owner, contributor policy, and source locator;
- activation impact and affected units;
- deprecation and replacement;
- semantic changes relative to the previously selected release.

## Configuration composer

The context pane can add options to a local draft and emit:

- a Nix runtime-module fragment;
- `apm config add/replace`, `diff`, and `apply` command guidance;
- a shareable file download that contains the draft, never the secret values.

The composer uses the structured type model for client-side hints and local
validation. It clearly labels the result **not yet evaluated** until the user
runs authoritative APM evaluation. It never puts configuration values in the
URL or telemetry. Credential controls accept only opaque references; the UI
does not fetch or preview credential contents.

Copy actions include option path, example value, complete Nix fragment, CLI
command, and immutable documentation URL. Generated snippets are formatted by
shared Rust, not by browser string templates.

## Services workspace

The Services tab turns expose/config metadata into a coherent runtime map:

- workload services, activation sources, helpers, targets, and ordering;
- listeners and ports, including network mode and firewall admission;
- state/cache/log/runtime/config paths and persistence policy;
- configuration artifacts, validators, and reload/restart mapping;
- credential names, purpose, delivery mode, and missing/rotation behavior;
- capability provides/uses, kernel requirements, and host integrations;
- filesystem/network/MAC confinement summary;
- enable, disable, upgrade, rollback, and removal behavior.

A compact relationship diagram is appropriate here because one source often
affects several units and artifacts. The same facts remain available as a table
and definition list for screen readers and no-JavaScript clients. Visualizations
never become the only representation.

## Versions and semantic comparison

The Versions tab selects exact releases/platforms and reports documentation,
runtime, and schema identities. Compare presents typed changes rather than a
line-oriented JSON diff:

- added/removed/renamed/deprecated options;
- type or constraint changes;
- default/default-text and example changes;
- ownership, contribution, ABI, availability, and activation changes;
- service/listener/path/credential/capability changes;
- prose-only changes separately;
- runtime object, config module, expose artifact, and documentation identity
  changes.

Potentially breaking changes are highlighted by explicit rules. The UI does not
claim semantic compatibility solely because version strings follow semver.

## Integrity workspace

Integrity explains why this documentation can be trusted:

- registry and signed commit/release identity;
- package version/platform and required feature set;
- runtime/config/expose/documentation store paths;
- NAR hashes/sizes, document digest, and semantic schema digest;
- source derivation and source commit when available;
- provenance/attestation subjects and verification status;
- release and cache retention reasons;
- current/selected channel relation.

Values link to existing narinfo, release, source, and verification pages when
authorized. Status language distinguishes cryptographic verification, object
presence, provenance policy, and mere metadata declaration.

## Progressive enhancement and deployment parity

Every browse/detail/search/compare page is complete server-rendered HTML with
plain forms and links. A content-addressed, self-hosted first-party JavaScript/
WASM bundle enhances navigation, composer state, keyboard search, and diagrams.
If it fails to load, reading and searching still work.

The shared renderer produces the same page model on native and Worker. The
static registry Web generator may pre-render public pages from authenticated
documents and advertise a Hub API for dynamic search; it retains the same
content-bearing floor. No page references a third-party script, font, analytics
endpoint, or CDN asset.

## Accessibility and interaction requirements

- Follow the WAI-ARIA Authoring Practices patterns for
  [combobox](https://www.w3.org/WAI/ARIA/apg/patterns/combobox/) and
  [listbox](https://www.w3.org/WAI/ARIA/apg/patterns/listbox/) behavior.
- Provide full keyboard operation, visible focus, skip links, landmarks, and
  correct heading hierarchy.
- Never convey ownership, verification, severity, or change kind by color alone.
- Respect reduced-motion, zoom, high-contrast, and narrow-viewport settings.
- Announce asynchronous search/composer results without stealing focus.
- Keep code/path text selectable and horizontally manageable.
- Use semantic tables only for actual tabular relationships.

Automated checks are a floor. Acceptance includes keyboard-only, screen-reader,
zoom, reduced-motion, and mobile-width review of the no-JavaScript and enhanced
experiences.

## Performance and privacy budgets

For a warm indexed registry, the target is useful server-rendered content in
under 100 ms of Hub compute and no document-object read for ordinary search
results. A full detail request may fetch the immutable document through the
bounded digest cache.

Pages paginate bounded sets, stream HTML where supported, and load enhancement
assets only from content-addressed first-party URLs. Search and composer state
stay local unless the user submits a request. Public telemetry, if enabled by
instance policy, records aggregate performance and errors, never option values,
drafts, credentials, private package names, or document prose from hidden
registries.
