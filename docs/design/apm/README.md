# APM — AOS Package Manager

## Overview

`apm` is the package manager for AOS. It manages a registry of named, versioned
packages in a flat namespace and installs/removes them into the Nix store using
GC roots as the unit of package lifecycle.

**Design philosophy:** Do one thing well. `apm` is a *system-wide or per-user,
registry-based binary package installer* — not a build system, not a
configuration manager, not a service manager.

## Implementation

`apm` is implemented as a subcommand of the `aos` Rust CLI tool: `aos package`.
The `apm` binary is a symlink alias installed alongside `aos` in the same Nix
package. When invoked as `apm <subcommand>`, it behaves identically to
`aos package <subcommand>`.

```
aos package install curl    # canonical form
apm install curl            # alias — identical behavior
```

The `aos` binary detects whether it was invoked as `apm` (via `argv[0]`) and
implicitly prepends the `package` subcommand. All documentation uses `apm` for
brevity, but `aos package` is always interchangeable.

### Why a subcommand of `aos`?

- **Single codebase** — Package management shares infrastructure with `aos build`,
  `aos test`, and other subcommands (Nix store interaction, registry access,
  configuration).
- **Single binary** — No separate compilation, packaging, or versioning.
- **Familiar shorthand** — `apm` is shorter and mirrors `apt`, making it feel
  native as a standalone package manager despite being part of `aos`.

## Key Properties

1. **apt-familiar interface** — If you know `apt`, you know `apm`. Command
   names, flags, and output formats mirror Debian's `apt` as closely as
   possible.

2. **Flat package namespace** — Every package has a unique name. No
   source/binary distinction, no epochs, no architecture-in-name hacks.

3. **TOML metadata** — Packages are described by simple TOML files in
   versioned registries. No binary index formats.

4. **HTTP-distributed registries** — Registries are collections of TOML files
   distributed as HTTP bundles (default) or via native git. Registry versions
   are semver tags. Integrity comes from git's object model regardless of
   transport — bundles contain the same git objects as `git fetch`.

5. **Pre-built guarantee** — Every package in a registry has been built and
   tested for its target platform. `apm` never compiles anything locally.

6. **Nix store backend** — Packages are Nix store paths in `/var/lib/store/`.
   Installation creates a GC root in the target profile (system at
   `/var/lib/profiles/system/` or per-user at
   `/var/lib/profiles/per-user/$USER/`); removal deletes it. Multiple users
   installing the same package share a single store path. `aos gc` handles
   actual cleanup.

7. **Closure-based dependencies** — Dependencies are Nix store references
   embedded in each NAR, not named package lists. No SAT solver, no version
   constraints, no conflicts. Each package name has at most one version per
   registry, and all transitive dependencies resolve from the **same registry**
   as the parent package. Each package points to an exact, pre-tested closure.
   If two registries ship an identical package (same inputs, same build), the
   resulting store paths share the same hash and are deduplicated in the store.

8. **Reproducible build provenance** — Every package references its source
   derivation, enabling independent verification that the binary matches the
   source.

9. **Multiple registries with overlay priority** — Like apt sources, registries
   are layered. Higher-priority registries shadow lower ones for same-named
   packages. Each profile's `meta/` directory tracks installed package
   metadata, while `remote/` holds cached registry metadata.

10. **System and user profiles** — `apm` installs to two targets: a system
    profile at `/var/lib/profiles/system/` (requires sudo) or a per-user
    profile at `/var/lib/profiles/per-user/$USER/` (default, no root
    needed). Both are generation-based with a UNIX FHS layout — each
    generation combines GC roots (`usr/{hash}`) with a merged FHS view
    (`bin/`, `lib/`, etc.) and supports atomic switching and rollback.

## Architecture

```
                  +-----------+
                  |  aos CLI  |    aos package install, remove, update, ...
                  +-----+-----+
                        |
                  +-----v-----+
                  |  apm alias |    argv[0]="apm" → implicit "package" subcommand
                  +-----+-----+
                        |
                  +-----v-----+
                  |  Resolver  |    Closure resolution via store references
                  +-----+-----+
                        |
              +---------+---------+
              |                   |
        +-----v-----+      +-----v-----+
        |  Registry  |      |   Store   |
        |   Client   |      |  Manager  |
        +-----+-----+      +-----+-----+
              |                   |
        +-----v-----+      +-------------+    +--------------+
        | Registries |      | /var/lib/   |    | /var/lib/    |
        | (TOML via  |      | store/      |    | profiles/    |
        |  bundles   |      | (NARs)      |    | (generations)|
        |  or git)   |      +-------------+    +--------------+
        +------------+
```

## Design Documents

| Document | Description |
|----------|-------------|
| [cli.md](cli.md) | CLI interface specification and apt comparison |
| [registry.md](registry.md) | Registry structure, bundle distribution, and overlay system |
| [packages.md](packages.md) | TOML package metadata schema |
| [store.md](store.md) | Nix store integration and GC root management |
| [security.md](security.md) | Security model: signing, verification, trust |
| [examples.md](examples.md) | Worked examples and end-to-end workflows |
| [convergence.md](convergence.md) | Convergence with `aos serve` cache server |
| [integration.md](integration.md) | System and user profile mechanisms with multi-user deduplication |
| [phases/](phases/) | Implementation plan: 6 phases, 20 chunks |

## Non-Goals

- **Building packages** — `apm` is binary-only. Use `aos build` for source builds.
- **Configuration management** — Use AOS modules for system configuration.
- **Service management** — `apm` installs binaries, not services. Service
  configuration and lifecycle is the domain of AOS modules and systemd.
- **Development environments** — Use `nix develop` / `aos shell` for dev shells.

## Comparison with Existing Tools

| Feature | apt | nix binary cache | apm |
|---------|-----|------------------|-----|
| Familiar CLI | native | no | yes (mirrors apt) |
| Pre-built guarantee | yes | best-effort | yes (strict) |
| Reproducible builds | no | yes (via drv) | yes (via drv) |
| Registry = versioned metadata | no | no | yes (HTTP bundles or git) |
| Package = TOML file | no (control) | no (narinfo) | yes |
| GC root per package | n/a | no (profile-based) | yes (every closure path) |
| Overlay registries | yes (sources.list) | yes (substituters) | yes (priority) |
| Profile/PATH | yes (/usr/bin) | yes (profile generations) | yes (merged symlink profile) |
| Offline source audit | no | partial | yes (full drv chain) |
