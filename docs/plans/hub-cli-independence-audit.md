# Hub CLI independence audit

## Purpose

This audit identifies package, documentation, image, container, registry, and
channel commands that can operate against signed Git or HTTP content without an
AOS Hub. It also separates those reads and uploads from mutations that require
Hub authorization, topology, or compare-and-swap state.

The desired boundary is:

- signed registry metadata and immutable content remain usable through Git,
  dumb HTTP, binary caches, and OCI Distribution;
- Hub discovery is optional when the caller selected a portable content
  source;
- an explicit Hub selection fails closed instead of silently falling back
  after authentication, authorization, or integrity errors; and
- control-plane mutations continue to require Hub when their correctness
  depends on managed policy, topology, receipts, or resource versions.

## Existing portable paths

### APM registry and package operations

The package-manager transport boundary is already portable. `RegistryConfig`
stores a URL whose scheme selects the transport
(`crates/aos-package/src/types.rs:2404`). `apm update` sends both HTTP and Git
sources through the Git-native registry synchronizer
(`crates/aos-package/src/update.rs:186`). Package and source downloads resolve
the committed and client-configured cache stack before falling back to the
registry URL (`crates/aos-package/src/download.rs:155`).

Cache failover has an appropriate safety boundary: only a true not-found
result advances to another mirror. Authentication failures, malformed
metadata, integrity failures, and transport failures stop immediately
(`crates/aos-package/src/download.rs:401`). Optional Hub discovery should use
the same rule: absence can permit a documented portable source, while a failed
explicit Hub operation must remain an error.

The following tests exercise the no-Hub data path:

- `fixture_syncs_git_native_registry_over_static_http` synchronizes and reads a
  package from a static HTTP Git origin
  (`crates/aos-package/tests/registry_e2e.rs:469`).
- `signed_channel_http_e2e_advances_persisted_bucket` follows a signed channel
  over static HTTP (`crates/aos-package/tests/registry_e2e.rs:960`).
- `apr_cache_generate_cli_supports_apm_install_upgrade_and_execution` runs an
  author-to-consumer CLI flow through a static HTTP origin and cache
  (`crates/aos/tests/apr_cache_cli.rs:194`).
- `apr_release_store_path_publishes_signed_cache_channel_and_installs` covers
  the verified signed release and channel variant
  (`crates/aos/tests/apr_cache_cli.rs:587`).

### APR registry and channel authoring

`apr` owns a local registry workspace and signed Git state. In particular,
`apr channel init`, `advance`, and `status` operate on the selected registry
checkout (`crates/aos-package/src/registry_ops.rs:11871`). These commands do not
need Hub control-plane state.

Hub-authored change requests also cross a Git ref namespace. Reading and
promoting those refs should continue to use ordinary Git access; the word
`hub` in `refs/hub/changes/*` describes the producer, not a required RPC
transport.

### Binary caches

`aos cache` selects its backend from the explicit `--to` or `--from` URL and
supports file, HTTP, S3, and SFTP backends
(`crates/aos/src/cli/cache.rs:1`, `crates/aos/src/commands/cache.rs:20`). It does
not require Hub discovery. Tokens and headers are backend credentials rather
than evidence that a Hub is present.

### OCI content operations

Ordinary `aos container inspect`, `pull`, and `push` derive an OCI Distribution
origin from the registry reference when no override is supplied
(`crates/aos/src/commands/container.rs:1284`). A stored profile is used only
when its origin matches the selected registry
(`crates/aos/src/commands/hub_auth.rs:122`,
`crates/aos/src/commands/hub_auth.rs:262`).

Container publication also has a deliberate split. `--stage-only` with an
explicit registry credential uploads immutable OCI content without Hub control
(`crates/aos/src/commands/container.rs:669`). The process test asserts that the
stage operation makes no control calls
(`crates/aos/tests/container_cli_transfer.rs:321`). Final mutable-tag commit
still requires Hub authorization and compare-and-swap state.

## Findings and recommended changes

### 1. Portable system-image consumption implemented

`aos image list`, `show`, and `download` now default to a named configured APM
registry. The shared resolver in `crates/aos-package/src/images.rs` uses the
existing Git/static-HTTP synchronizer, signature and TUF verification, validated
package parser, and the selected registry's committed/client cache chain.
`--hub` or `AOS_HUB` explicitly selects Hub discovery, where `--registry` is an
organization/registry slug. A failed Hub operation never falls back to the
configured registry. Ambient `AOS_TOKEN` is consulted only in Hub mode.

The image cache has per-registry roster continuity, rollout partition, and
channel floor state. It also checks the configured APM consumer's continuity
anchors and immutable release identity before extracted metadata or rotated
keys can be published. Moving selectors share their accepted TUF root anchor
without sharing selected-commit ancestry. Selection
keys use full commit identities and do not include architecture/format filters.
An exact archival release retains its own immutable TUF counters under the
current verified roster; it cannot lower moving-channel counters, reset a
channel floor, renew channel freshness, or change package tracking. APM and
image consumers retain the first freshness observation of an unchanged floor.

The existing secure download path now decodes the declared `none` or `zstd`
NAR transport. It checks the cache narinfo against the signed store identity,
verifies the transport and NAR hashes, extracts only a canonical regular-file
NAR, and checks signed disk size/hash before publishing the final output.
Portable cache URLs retain APM's HTTP/file transport behavior.

`crates/aos/tests/image_registry_cli.rs` exercises a real signed SHA-256 Git
origin and binary cache served by static HTTP. Consumer processes clear their
environment and PATH and run outside a source checkout. Coverage includes
list/show/download, ambiguity and image filters, historical TUF releases,
unchanged registry configuration, explicit Hub authorization failure without
fallback, a new channel after established TUF floors, configured APM TUF
continuity in a fresh image consumer, channel rollback after selector/archive
changes, corrupt NAR refusal, roster downgrade refusal, and signed retag
rejection without changes to extracted metadata, keys, or state. Focused shared parser, extraction, and state
regressions cover the reused implementation.

User-facing usage is documented in [CLI commands](../users/aos/cli.md) and
[image installation](../users/aos/installation.md). Direct URL consumption uses
`apm registry add` to establish the registry name and trusted signing key first.

### 2. Make documentation modes strict

The `aos doc` wrapper treats the positional words `package` and `hub` as modes,
but they remain unvalidated strings. `aos doc hub QUERY` constructs a search
with an optional Hub URL (`crates/aos/src/entry.rs:249`). When `--hub` is
absent, the documentation implementation silently searches installed local
documents (`crates/aos-package/src/documentation.rs:62`).

The wrapper also accepted remote selectors in local modes and exact-document
selectors in searches, where those values were ignored. The corresponding
`apm docs` arguments already require `--hub` for registry/token selectors.
Version and platform are valid filters for exact installed documentation;
they must remain available for installed package lookup.

Represent the wrapper source as an explicit mode and validate its flags:

- package mode reads an installed user or system profile;
- Hub mode requires a resolved Hub origin and registry;
- repository mode continues to use the repository documentation index; and
- remote-only selectors are rejected when the selected mode cannot use them.

Add process tests proving that package mode works with an empty environment and
no repository, that Hub mode cannot silently become local mode, and that
remote-only flags produce an actionable error in local modes.

The wrapper now resolves repository, installed-package, and Hub modes before
constructing a Nix runner. Hub search requires an HTTP(S) origin and registry
slug, rejects installed-profile and exact-document selectors, and never falls
back to local search. Installed mode rejects explicit Hub-only flags but ignores
unrelated `AOS_HUB`/`AOS_TOKEN` environment values. Exact installed version and
platform filters remain supported. Repository-only index controls are rejected
in package/Hub modes. The implementation delegates actual lookup and canonical
document validation to the existing APM documentation commands.

Process regressions in `crates/aos/tests/documentation_cli.rs` cover offline
installed search, exact installed lookup, invalid mode combinations, malformed
remote selectors, and an explicit Hub authorization failure without local
fallback. Configured-registry documentation reads remain a separate task.

### 3. Add configured-registry documentation reads

Remote documentation and option search currently use Hub RPCs, while local
commands only inspect documentation retained by installed packages. Signed
package metadata already identifies the canonical documentation artifact, so a
configured registry can provide an uninstalled document through the same cache
and verification path as other package artifacts.

Add a configured-registry source after the mode validation is fixed. Exact
document lookup should precede broad search. Search can build a bounded local
index from synchronized registry metadata and fetched documentation objects.
`options compare` benefits from a Hub index, but it can also compare two exact
signed versions when both are present in configured registry state.

### 4. Separate OCI origin names from Hub names

The direct OCI commands describe `--hub` as an override for the registry HTTP
origin and bind it to `AOS_HUB` (`crates/aos/src/cli/container.rs:64`). The
implementation passes that value to `RegistryClient`; it is not inherently a
Hub API endpoint.

Rename the content-plane option to `--registry-origin` and use
`AOS_REGISTRY_ORIGIN`, matching the publication command. If compatibility is
needed, retain `--hub` only as a deprecated alias for these three commands.

Credential lookup should also be lazy. A matching expired Hub profile is
currently refreshed before a public registry request, so refresh failure can
block otherwise anonymous content. Attempt anonymous registry access first, or
consult matching stored credentials after an authentication challenge. Keep
explicit token and explicit profile failures visible.

Existing process coverage only proves that an unrelated expired profile does
not block a pull, and it still supplies `--hub`
(`crates/aos/tests/container_cli.rs:57`). Add cases with no origin override or
profile and with a matching expired profile against a public test registry.

### 5. Keep authoritative release mutations on Hub

`apr channel` authors signed Git rollout state, while `aos release channel`
verifies deployment identity and signed receipts before performing a
production compare-and-swap through Hub
(`crates/aos/src/commands/release/channel.rs:90`). The latter dependency is
required for the command's authority and audit guarantees.

Keep the command families distinct in help and documentation:

- use `apr channel` to create signed portable registry state; and
- use `aos release channel` to advance the managed production authority and
  retain release evidence.

## Implementation order

1. Completed: shared portable image resolver and no-Hub image process test.
2. Completed: explicit `aos doc` modes and flag combinations with process tests.
3. Rename the OCI content origin option and defer stored-profile credential
   resolution until needed.
4. Add configured-registry reads for uninstalled documentation and exact
   option comparisons.

