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
- Each crate directory matches its full Cargo package name. Rust library names
  use the corresponding underscore spelling.

Extract a crate when independent consumers, dependencies, platforms, packaging,
licensing, or a stable public boundary justify it. Otherwise organize related code
into modules. Shared libraries may perform I/O; their dependencies must match
their capability rather than an application's deployment requirements.

## Directory groups

Every application workspace crate lives at `crates/<category>/<package>/`.
The workspace manifest and lockfile live directly under `crates/`.

```text
crates/
  accache/    compiler action cache and compiler argument parsing
  activation/ execution and concrete operation handlers
  artifacts/  artifact evidence, NAR archives, and OCI formats and operations
  bindings/   native library bindings
  boot/       boot identity, platform metadata, and installed boot tools
  cli/        command-line programs and presentation
  core/       portable primitives
  crucible/   deterministic execution, QEMU integration, control, and storage
  hub/        Hub domain, persistence, services, clients, and deployments
  linux/      Linux project quotas and systemd clients
  modules/    module formats and documentation
  nix/        Nix process and store-tool integration
  packages/   package consumption and deployment
  registry/   registry formats, clients, authoring, and static web application
  release/    release formats, coordination, image finalization, and signing
  transfer/   transfer protocols and progress reporting
```

A shared domain format can remain under its owning project's directory while
being consumed by another project. Dependencies establish reuse; directory
placement establishes ownership.

`crates/accache/` is an independent Cargo workspace with its own lockfile and
sibling `accache` and `accache-frontend` crates. The compiler cache must build
without resolving the application workspace or enabling its shared caches.
Small Cargo workspaces under test fixtures remain isolated for the artifact
contracts they exercise. These independent workspaces are outside the application
inventory.

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
refactors. Open pull requests receive separate handoff instructions rather than
edits to their owning checkouts.

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
