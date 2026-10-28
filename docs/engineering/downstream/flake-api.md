# Downstream flake API

**API version:** 1.0

This page is the contract between AOS and flakes that take AOS as their only
input. It names the builders, package attributes, and flake outputs that
downstream repositories may rely on, the arguments those builders accept, and
the rules AOS follows before changing any of them. Anything reachable through
the flake that this page does not list is an implementation detail.

The [downstream quickstart](quickstart.md) shows the contract in use.

## Flake outputs

| Output | Shape | Contract |
| --- | --- | --- |
| `lib` | `lib.<system>.<name>` | The builder API in [Exported names](#exported-names). |
| `legacyPackages` | `legacyPackages.<system>.<name>` | The complete package set. Only the names in [Package attributes](#package-attributes) are part of the contract. |
| `templates` | `templates.default`, `templates.downstream` | A minimal downstream repository for `nix flake init -t`. |

Supported systems are `x86_64-linux` and `aarch64-linux`. Downstream flakes
should enumerate `builtins.attrNames aos.lib` instead of hard-coding the list.

### Why `lib` is keyed by system

Every builder closes over a package set compiled for one platform: its
compiler wrapper, bootstrap tools, scrubbing tools, and language toolchains.
A system-independent `lib` would need a `system` argument on every call and
would still have to construct a package set behind it. Keying `lib` by system
follows the shape of `packages` and `legacyPackages`, lets downstream flakes
use the same `forAllSystems` helper for every output, and evaluates only the
package sets a consumer touches.

Builders produce packages that run on the `<system>` key's platform.

- `x86_64-linux` builds natively.
- `aarch64-linux` is the package set AOS itself publishes for that platform.
  The AOS bootstrap starts from an i386 seed, so AOS cross-builds
  `aarch64-linux` outputs on `x86_64-linux`, and its derivations, including
  those from `lib.aarch64-linux` builders, are scheduled on an
  `x86_64-linux` builder. Downloading them from the binary cache works on any
  machine; building one locally requires an `x86_64-linux` builder, either
  the local machine or a remote builder. Rebuilding the AOS toolchain itself
  additionally needs QEMU binfmt emulation for `aarch64-linux` in that
  builder's sandbox.

Other cross-compilation targets are not part of this version.

## Exported names

Each row is one name in `lib.<system>`. Names in a namespace use a dotted
path. A check compares this table with the exported attribute set and fails
when either side has a name the other lacks, so the table must keep its fixed
format: one name per row in backticks, a kind (`function`, `namespace`, or
`value`), the API version that introduced it, and a status of `stable` or
`deprecated`.

<!-- downstream-api:exports:begin -->
| Name | Kind | Since | Status | Summary |
| --- | --- | --- | --- | --- |
| `apiVersion` | value | 1.0 | stable | Contract version as `"<major>.<minor>"`. |
| `mkDerivation` | function | 1.0 | stable | Build a package from source with the AOS phase dialect. |
| `mkShell` | function | 1.0 | stable | Development environment for `nix develop`. |
| `callPackage` | function | 1.0 | stable | Import a package function and fill its arguments from the AOS package set. |
| `writeTextFile` | function | 1.0 | stable | Write text to a store path or to a file inside one. |
| `writeShellScriptBin` | function | 1.0 | stable | Install a Bash script as `$out/bin/<name>`. |
| `runCommand` | function | 1.0 | stable | Run one shell script that produces `$out`. |
| `runtimeShell` | value | 1.0 | stable | Absolute path of the AOS-built Bash for generated scripts. |
| `fakeHash` | value | 1.0 | stable | Placeholder SHA-256 hash for discovering a fixed-output hash. |
| `replacePhase` | function | 1.0 | stable | Replace a named phase in a phase list. |
| `addPhaseAfter` | function | 1.0 | stable | Insert a phase after a named phase. |
| `addPhaseBefore` | function | 1.0 | stable | Insert a phase before a named phase. |
| `removePhase` | function | 1.0 | stable | Remove a named phase from a phase list. |
| `mkCargoPackage` | function | 1.0 | stable | Build a Rust package from vendored Cargo dependencies. |
| `mkCargoArtifacts` | function | 1.0 | stable | Build a reusable Cargo target directory for dependency caching. |
| `mkCargoDummySource` | function | 1.0 | stable | Derive a manifests-only workspace source for `mkCargoArtifacts`. |
| `mkCargoNextestCheck` | function | 1.0 | stable | Run a workspace's tests with cargo-nextest. |
| `mkGoPackage` | function | 1.0 | stable | Build a Go module. |
| `fetchurl` | function | 1.0 | stable | Download one file by hash. |
| `fetchCargoDeps` | function | 1.0 | stable | Vendor Cargo dependencies with `cargo vendor`. |
| `fetchCargoVendor` | function | 1.0 | stable | Vendor Cargo dependencies from `Cargo.lock`. |
| `fetchGoModules` | function | 1.0 | stable | Download Go module dependencies. |
| `fetchNpmDeps` | function | 1.0 | stable | Materialize `node_modules` from `package-lock.json`. |
| `ociTools` | namespace | 1.0 | stable | Deterministic OCI image builders. |
| `ociTools.mkClosureLayer` | function | 1.0 | stable | Archive the runtime closure of store paths as one layer. |
| `ociTools.mkMetadataLayer` | function | 1.0 | stable | Root filesystem directories, files, and symlinks as one layer. |
| `ociTools.mkRuntimeClosureAudit` | function | 1.0 | stable | Bound an image's runtime closure size and contents. |
| `ociTools.mkDeploymentArtifact` | function | 1.0 | stable | Describe an image's packages and platform for deployment validation. |
| `ociTools.mkImageLayout` | function | 1.0 | stable | Assemble an OCI image layout from layers. |
| `ociTools.mkMultiPlatformIndex` | function | 1.0 | stable | Combine per-platform image layouts in one OCI index. |
| `ociTools.mkDockerArchive` | function | 1.0 | stable | Convert an image layout into a `docker load` archive. |
<!-- downstream-api:exports:end -->

Builders for Bazel workspaces are not part of this version. The package set's
current Bazel builders serve AOS's own packages; a downstream Bazel interface
will be added to this table when it exists.

## Package attributes

These `legacyPackages.<system>` names are stable. A downstream flake may use
them as build inputs, development-shell tools, or toolchains. The package
behind a name may move to a new upstream version in any AOS release; pin an
AOS revision to hold a version. The documentation check fails when a listed
name is missing from the package set.

<!-- downstream-api:packages:begin -->
| Name | Since | Provides |
| --- | --- | --- |
| `bash` | 1.0 | GNU Bash. |
| `coreutils` | 1.0 | GNU core utilities. |
| `gnumake` | 1.0 | GNU Make. |
| `cc` | 1.0 | The AOS C and C++ compiler wrapper around GCC. |
| `gcc` | 1.0 | GCC. |
| `binutils` | 1.0 | GNU binutils. |
| `glibc` | 1.0 | The GNU C library. |
| `llvm` | 1.0 | LLVM with Clang, LLD, compiler-rt, and libc++. |
| `cmake` | 1.0 | CMake. |
| `ninja` | 1.0 | Ninja. |
| `pkg-config` | 1.0 | pkg-config. |
| `rust` | 1.0 | Rust compiler and Cargo; the `dev` output adds Clippy, rustfmt, rust-analyzer, and the standard library source. |
| `go` | 1.0 | Go toolchain. |
| `nodejs` | 1.0 | Node.js. |
| `pnpm` | 1.0 | pnpm. |
| `python3` | 1.0 | CPython 3. |
| `protobuf` | 1.0 | Protocol Buffers compiler `protoc` and libraries. |
| `openjdk-21` | 1.0 | OpenJDK 21, the JDK Bazel runs on. |
| `bazel` | 1.0 | Bazel. |
<!-- downstream-api:packages:end -->

## Builder arguments

Builders accept attribute sets unless the signature says otherwise. Every
argument not listed is passed to the derivation environment unchanged, so
phase scripts can read it as a shell variable.

### `mkDerivation`

`mkDerivation { pname; version; src; ... }` returns a derivation. Phases run
in order under the AOS-built shell with every dependency's `bin` directory on
`PATH` and its headers, libraries, and pkg-config files on the corresponding
search paths. The AOS compiler wrapper is always available as `cc`. After the
listed phases, a fixup phase strips binaries and shrinks run paths, and a
scrub phase rewrites store references that the output does not declare.

| Argument | Required | Meaning |
| --- | --- | --- |
| `pname` | yes, unless `name` is set | Package name. The derivation name is `<pname>-<version>`. |
| `name` | no | Complete derivation name; overrides `<pname>-<version>`. |
| `version` | no, default `"0"` | Package version. |
| `src` | no, default `null` | Source tree or archive. Directories are copied; `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, and `.zip` archives are unpacked; the build enters a single top-level directory. |
| `buildDeps` | no, default `[]` | Tools needed only while building. |
| `runtimeDeps` | no, default `[]` | Libraries and tools the output uses at run time. Their store references survive the scrub phase. |
| `propagatedDeps` | no, default `[]` | Dependencies that also enter the build environment of every package that depends on this one. |
| `phases` | no | List of `{ name; script; }` records. The default runs `unpack`, then `configure` (`./configure`, CMake, or Meson), `build`, and `install` according to the files the source provides. |
| `outputs` | no, default `["out"]` | Output names; each becomes a shell variable holding its path. |
| `patches` | no, default `[]` | Patch files applied with `patch -p1` after `unpack`. |
| `postPatch` | no | Script run after the patches. |
| `configureFlags`, `cmakeFlags`, `mesonFlags`, `makeFlags`, `installFlags` | no | Strings passed by the default phases to the matching tool. |
| `preConfigure`, `postConfigure`, `preBuild`, `postBuild`, `preInstall`, `postInstall` | no | Scripts run around the phase of the same name. |
| `passthru` | no | Attributes added to the result without entering the derivation. |
| `meta` | no | Package metadata. `meta.mainProgram` names the executable for tools that run a package. |
| `hardeningEnable`, `hardeningDisable` | no | Compiler-hardening tokens to add to or remove from the default set; `hardeningDisable = ["all"]` clears it. |
| `allowedReferences`, `allowedRequisites`, `disallowedReferences`, `disallowedRequisites`, `outputChecks` | no | Nix reference constraints on the output closure. |
| `dontStrip`, `dontPatchELF`, `dontNukeRefs` | no | Set to `true` to skip stripping, ELF run-path shrinking, or reference scrubbing. |
| `nukeRefsKeep` | no | Additional store paths that the scrub phase must keep. |

### `mkShell`

`mkShell { buildDeps; runtimeDeps; shellHook; ... }` returns an environment for
`nix develop`. It cannot be built.

| Argument | Required | Meaning |
| --- | --- | --- |
| `name` | no, default `"aos-dev-shell"` | Shell derivation name. |
| `buildDeps` | no | Tools placed on `PATH`. |
| `runtimeDeps` | no | Tools placed on `PATH` whose headers and libraries also enter `C_INCLUDE_PATH` and `LIBRARY_PATH`. |
| `shellHook` | no | Script run when the shell starts. |

### `callPackage`

`callPackage path overrides` imports the function in `path` and calls it.
Each formal argument is filled from the AOS package set, which includes
`mkDerivation`, `fetchurl`, and `callPackage` itself; an attribute in
`overrides` takes precedence. Pass downstream packages through `overrides`,
because the automatic scope contains only AOS packages.

### Trivial builders

| Builder | Arguments | Meaning |
| --- | --- | --- |
| `writeTextFile` | `{ name; text; destination ? ""; executable ? false; checkPhase ? ""; meta ? {}; }` | Writes `text` to `$out`, or to `$out<destination>` when `destination` starts with `/`. `checkPhase` runs after the write with the file at `$target`. Store references in `text` are kept. |
| `writeShellScriptBin` | `name: text:` | Writes `text` after a shebang for `runtimeShell` to `$out/bin/<name>`, checks its syntax, and sets `meta.mainProgram`. |
| `runCommand` | `name: env: script:` | Runs `script` with `$out` already created as a directory. `env` adds derivation attributes such as `buildDeps`. Store references in the output are kept. |

### Phase helpers

Each helper returns a new phase list and fails evaluation when the named
phase is absent.

| Helper | Signature |
| --- | --- |
| `replacePhase` | `phases: name: newPhase:` |
| `addPhaseAfter` | `phases: afterName: newPhase:` |
| `addPhaseBefore` | `phases: beforeName: newPhase:` |
| `removePhase` | `phases: name:` |

### `mkCargoPackage`

Accepts every `mkDerivation` argument except `phases`, which it generates,
plus the following. Cargo always runs with `--frozen --offline`.

| Argument | Required | Meaning |
| --- | --- | --- |
| `cargoDeps` | yes | Vendored dependencies from `fetchCargoVendor` or `fetchCargoDeps`. |
| `cargoRoot` | no, default `"."` | Directory that holds the workspace `Cargo.toml`. |
| `cargoWorkspaceMembers` | no | Workspace members to keep; the others are removed before building. |
| `buildType` | no, default `"release"` | `"release"` builds with `--release`; any other value uses the dev profile. |
| `checkType` | no, default `buildType` | Profile for tests. |
| `cargoFlags` | no | Extra flags for the default `cargo build`. |
| `cargoBuildCommands` | no | Cargo subcommand lines that replace the default `cargo build`. |
| `buildFeatures`, `buildNoDefaultFeatures` | no | Feature selection. |
| `installBins` | no, default `true` | Install built binaries into `$out/bin`. |
| `installLibs` | no, default `false` | Install built libraries into `$out/lib`. |
| `doCheck`, `doParallelCheck`, `cargoTestFlags` | no | Run `cargo test`, with parallelism and extra flags. |
| `cargoEnv` | no | Environment variables exported before Cargo runs. |
| `cargoArtifacts` | no | A `mkCargoArtifacts` result whose target directory seeds the build. |
| `gitDeps` | no | `{ url; rev; crate; sourceArchive ? null; }` records for Git dependencies vendored by `fetchCargoDeps`. |

`mkCargoArtifacts` takes the same arguments and installs the Cargo target
directory instead of binaries. Build its `src` with
`mkCargoDummySource { srcRoot; name ? "cargo-dummy-source"; cargoRoot ? null; }`,
which keeps manifests and the target layout but not Rust file contents, so
dependency artifacts survive ordinary source edits. `mkCargoNextestCheck`
takes the same arguments plus `cargoNextestProfile`, `nextestFlags`,
`cargoNextestMaxTestThreads`, and `cargoNextestOpenFilesLimit`, and runs the
tests with cargo-nextest without installing anything.

### `mkGoPackage`

Accepts every `mkDerivation` argument except `phases`, plus:

| Argument | Required | Meaning |
| --- | --- | --- |
| `goOutput` | no, default `pname` | Name of the installed binary. |
| `goPackage` | no, default `"."` | Package path to build. |
| `goModules` | no | `fetchGoModules` result. Without it, a `vendor` directory is used when present. |
| `cgoEnabled` | no, default `false` | Enable cgo. |
| `ldflags` | no, default `"-s -w"` | Linker flags. |
| `tags` | no, default `[]` | Build tags. |
| `doCheck`, `doParallelCheck`, `goTestFlags` | no | Run `go test`, default target `./...`. |

### Fetchers

Each fetcher returns a fixed-output derivation identified by `hash`, an SRI
SHA-256 string. Use `fakeHash` once to learn the real value from the error.

| Fetcher | Arguments | Meaning |
| --- | --- | --- |
| `fetchurl` | `{ url or urls; hash; name ?; executable ? false; }` | Downloads one file; `urls` lists mirrors. |
| `fetchCargoVendor` | `{ src; hash; sourceRoot ?; cargoPatches ?; name ?; }` | Vendors every crate in `Cargo.lock`, including Git sources. |
| `fetchCargoDeps` | `{ src; hash; sourceRoot ?; cargoPatches ?; gitDeps ?; name ?; }` | Vendors dependencies with `cargo vendor`; Git sources are listed in `gitDeps`. |
| `fetchGoModules` | `{ src; hash; sourceRoot ?; name ?; }` | Downloads the module graph of `go.mod`. |
| `fetchNpmDeps` | `{ src; hash; sourceRoot ?; omitOptional ? false; requiresGit ? true; localTarballs ? []; name ?; }` | Installs `node_modules` from `package.json` and `package-lock.json`. |

### `ociTools`

The image builders produce deterministic layers with fixed timestamps,
ownership, and compression. A layout is assembled from layers and validated
against its deployment artifact and closure audit.

| Builder | Arguments | Meaning |
| --- | --- | --- |
| `mkClosureLayer` | `{ roots; subtractRoots ? []; pname ?; layerName ?; }` | Layer holding the runtime closure of `roots`, minus the closure of `subtractRoots`. |
| `mkMetadataLayer` | `{ directories ? []; files ? []; symlinks ? []; storeLayers ? []; pname ?; }` | Root-owned filesystem entries outside the store; `storeLayers` lists the `mkClosureLayer` layers that symlink targets resolve into. |
| `mkRuntimeClosureAudit` | `{ name; roots; maxClosureMiB; maxDevelopmentPayloadMiB; }` | Fails the image when the closure of `roots` exceeds the size bounds or carries development payloads. |
| `mkDeploymentArtifact` | `{ platform; packages; scope; pname ?; }` | Records the packages and `{ os; architecture; }` platform an image deploys. `scope` is a list of names that identify the artifact. |
| `mkImageLayout` | `{ layers; runtimeAudit; deploymentArtifact; config ? {}; annotations ? {}; referenceName ? null; pname ?; }` | OCI image layout. `config` takes `entrypoint`, `cmd`, `env`, `workingDir`, `user`, `exposedPorts`, and `stopSignal`. |
| `mkMultiPlatformIndex` | `{ images; deploymentArtifact; annotations ? {}; referenceName ? null; pname ?; }` | OCI index over per-platform image layouts. |
| `mkDockerArchive` | `{ image; references; pname ?; }` | `docker load` archive of a layout with at least one repository tag. |

## Compatibility policy

The contract version has the form `<major>.<minor>` and is exported as
`apiVersion`.

- A **minor** version adds names, optional arguments, or package attributes.
  Existing calls keep their meaning.
- A **major** version removes or renames a name, a documented argument, or a
  package attribute; makes an optional argument required; or changes the
  meaning of an existing argument.
- Fixes that make a builder match this document do not change the version.
- Store paths, derivation hashes, and the upstream versions of packages are
  not part of the contract. They change whenever AOS updates a package or
  its toolchain.
- Within one major version, a downstream flake written against an earlier
  minor version evaluates and builds unchanged.

## Deprecation process

1. Mark the row `deprecated` in [Exported names](#exported-names) and name
   the replacement in its summary. The builder keeps working unchanged.
2. Keep the deprecated name for at least one minor version and at least 90
   days after the AOS release that first marks it.
3. Remove the name in the next major version: delete its row from the export
   table, add it to [Removed names](#removed-names) with the version that
   removed it, and bump `apiVersion`.

The documentation check fails when a removed name is still exported.

## Removed names

<!-- downstream-api:removed:begin -->
| Name | Removed in | Replacement |
| --- | --- | --- |
<!-- downstream-api:removed:end -->
