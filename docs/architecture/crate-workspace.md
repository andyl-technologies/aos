# Rust workspace organization

The Cargo workspace contains AOS software, reusable libraries, and independent
projects such as Hub and Crucible. A package's full name identifies its ownership
and purpose without requiring its filesystem path. Directories group packages for
readers; they do not introduce Cargo namespaces.

The [rename reference](crate-renames.md) maps all 67 former packages to their
current owners, including merges and extractions. The
[active inventory](crate-inventory.md) records implemented ownership;
the [validation record](crate-migration-validation.md) distinguishes completed
local checks, baseline failures, and unresolved qualification.

## Naming and ownership

- `aos-<capability>` names a reusable ecosystem library, such as `aos-nar`,
  `aos-transfer`, or `aos-systemd-client`.
- `aos-<subsystem>-<responsibility>` names an AOS implementation, such as
  `aos-activation-sysctl` or `aos-registry-authoring`.
- `aos-hub-*` and `crucible-*` identify their respective projects.
- `aos-core` contains small portable primitives. It does not own terminal output,
  command dispatch, Nix execution, or application policy.
- Generic suffixes such as `model`, `api`, and `runtime` require an explicit owner.
- Production crate directories match their full Cargo package names. Rust
  library names use the corresponding underscore spelling. Nested test fixture
  packages retain descriptive directories beside their owning tests and explicit
  full Cargo names.

Extract a crate when independent consumers, dependencies, platforms, packaging,
licensing, or a stable public boundary justify it. Otherwise organize related code
into modules. Shared libraries may perform I/O; their dependencies must match
their capability rather than an application's deployment requirements.

## Directory groups

The workspace keeps one manifest and lockfile under `crates/`:

```text
crates/
  shared/       reusable libraries and common primitives
  aos/
    cli/        command-line programs and presentation
    modules/    portable module formats and documentation
    activation/ execution and concrete operation handlers
    packages/   package consumption and deployment
    registry/   registry formats, clients, authoring, and static web application
    boot/       boot identity, platform metadata, and installed boot tools
    release/    release formats, coordination, image finalization, and signing
  hub/          Hub domain, persistence, services, clients, and deployments
  sandbox/
    model/      Sandbox models, ownership, and policy compilation
    protocol/   generated APIs, guest/broker/source contracts, and request data
    controller/ domain, runtime, services, client, journals, replay, and coordinator
    host/       broker, Linux primitives, Mount, Network, and Publisher
    guest/      guest effects, root realization, and root measurement
    storage/    Storage and Source/SourceProvider owners
    security/   session custody, ownership deadlines, peers, and signing roles
    filesystem/ portable filesystem formats, views, and FUSE transport
  crucible/
    engine/     deterministic execution and campaign models
    control/    control API, clients, server, sessions, daemon, and CLI
    protocol/   permissive QEMU process-boundary components
    qemu/       host integration and GPL-side plugin/debugger processes
    guest/      optional guest instrumentation
    storage/    Crucible content storage and transports
    testing/    test support and architectural gates
```

A shared domain format can remain under its owning project's directory while
being consumed by another project. Dependencies establish reuse; directory
placement establishes ownership.

`tools/accache` remains an independent Cargo workspace so the compiler cache can
build without the application workspace or its dependencies. Its `accache` and
`accache-frontend` packages already have explicit project ownership. Small Cargo
workspaces under test fixtures remain isolated for the artifact contracts they
exercise. These independent workspaces are outside the application inventory.
The six Sandbox fixture packages, however, are explicit members of the main
workspace and remain nested beside their owning tests.

The [active inventory](crate-inventory.md) lists every package and the implemented
merge and extraction boundaries. Future packages in open PRs are classified in
[the unmerged inventory](unmerged-crates.md).

## Dependency direction

Applications and deployment adapters depend on reusable domain libraries, which
depend on common primitives. Shared libraries must not import an application's
CLI, runtime, or deployment policy. Portable format libraries do not acquire
native drivers merely because their native consumers use those drivers.

Transfer reporting follows that direction: `aos-transfer::progress` defines
observers and cloneable progress handles without terminal or transport drivers.
`aos-cli-ui` implements the renderer adapter with transfer defaults disabled;
registry acquisition accepts observers and retains no terminal dependency.
Registry refresh selection, state persistence, aggregate errors, JSON output,
and recovery commands belong to `aos-package-manager::update`.

Crucible's permissive QEMU protocol and shared-memory components remain separate
from Apache host code and GPL plugin/debugger code. A directory move does not
change license scope or authorize an otherwise invalid dependency.

## Compatibility during migration

Package renames do not imply changes to executable names, serialized schema tags,
hash/signature domains, protocol constants, or persisted content identities.
Those are reviewed compatibility boundaries. Source-input filters, fixture
paths, generated API inputs, specification indexes, and local validation must
track package moves explicitly.

The migration is implemented in reviewable stages: names and locations; small
merges; reusable library extraction; application separation; and large project
refactors. The RFC-0021 branch now carries the Sandbox path/package migration
and separate generated API owner. Other open pull requests receive separate
handoff instructions; their proposed packages are not workspace members.

## Portable data and native effects

`aos-core` is deliberately small and portable. Shared code is classified by
capability rather than being accumulated into a universal core. `aos-nar` owns
NAR/narinfo and cache signing, while `aos-nix` owns native Nix execution. OCI JSON
retains its own dialect because its accepted inputs differ from strict canonical
AOS JSON; exact validation behavior is part of the format contract.

`aos-deployment-format` owns immutable inventory records and deployment schemas.
`aos-deployment` evaluates inputs, retains store references, and performs
activation, accepting inventory data from callers. Registry authoring and release
coordination do not import package installation. Release coordination accepts
domain inputs without a CLI parser. The native registry-authoring crate retains
APR parser and terminal adapters alongside independently callable signing and
local staging operations that accept domain inputs without a printer. Format
libraries remain separate from native signing processes.

`aos-linux-project-quota` is shared for its implemented quota capability. Crucible
storage retains its project scope: its object kinds and persisted identities are
Crucible domain concepts. Future host supervision, RAM authority, sandbox journals,
and descriptor wrappers require API review before promotion to shared libraries.

Prefer direct dependencies on the owning crate. Compatibility facades that retain
an application dependency undermine extraction and should not become permanent.
Large coherent domains use capability modules and focused tests within their crate.

## Sandbox migration boundaries

The current Sandbox package map is
[`sandbox-crate-migration.json`](../../tools/dev/sandbox-crate-migration.json).
It records 45 existing package moves, including six nested fixture packages, and
the separately created `aos-sandbox-api`. The older
[`crate-migration.json`](../../tools/dev/crate-migration.json) remains the initial
base migration plan; replaying it does not perform the base capability splits
or the Sandbox migration.

The Sandbox controller domain, portable model, Guest protocol and Guest-root
measurement now have explicit package names. Coordinator, native Mount,
Publisher, Source and ledger-replay owners remain within Sandbox. This placement
does not promote native owners into shared libraries or enable dormant flows.
A proposed native Cache package is not materialized in this checkout.

The shared systemd client currently retains a Linux dependency on Sandbox's
Linux wrapper and Sandbox-specific resource/custody APIs. That dependency is
recorded extraction debt against the direction rule above. Generic descriptor
and journal extraction require their own API review; a directory move does not
resolve those boundaries. The RFC's compiler, native, portability and lifecycle
qualification remain separate from this source-organization change.
