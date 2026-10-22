# Build definitions and repository structure

## One workspace, package-local ownership

The proposed layout is:

```text
MODULE.bazel
MODULE.bazel.lock
.bazelrc
tools/bazel/
    rules/                   # Thin Rust/native/package/test policy rules
    toolchains/              # Adapters for Nix-supplied tool repositories
    platforms/               # Execution/target constraints and configurations
    metadata/                # Source, target, and package inventory exporters
    tests/                   # Infrastructure and invalidation fixtures
third_party/rust/
    BUILD.bazel              # Dependency specifications and update target
    locks/                   # Resolved dependency graphs by compatible family
    generated/               # Generated BUILD metadata and source fetch inventory
crates/<owner>/<area>/<crate>/
    BUILD.bazel
    src/
    tests/
native/nix-eval/
    BUILD.bazel
    src/
    tests/
    bench/
pkgs/build-support/_bazel/    # Shared Nix implementation
pkgs/tools/nix-eval.nix      # Package policy and Bazel package-target selection
```

Pin Bazel and the rules to tested versions; the AOS Bazel derivation owns the
executable version. The launcher checks that version instead of downloading a
different binary. `MODULE.bazel.lock` locks module resolution, while Rust
dependency locks and the Nix source inventory lock their own layers.

Use ordinary Bazel language rules where possible. Shared wrappers enforce
lint settings, package metadata, feature-family checks, test registration,
and the toolchain contract. They must expose normal Bazel labels and providers
so `query`, `cquery`, and `aquery` remain useful. Avoid a parallel build language
that translates opaque shell commands into one giant action.

Library visibility follows the existing ownership hierarchy. Shared crates
have named consumers or package groups; internal implementation targets stay
private. A Rust crate is a compilation unit, not automatically a Nix package.
C++ libraries follow component boundaries rather than making every source
file a public target.

## Authoritative Rust targets

A migrated crate declares its root, sources, edition, dependencies, procedural
macro dependencies, features, generated inputs, and metadata in Bazel. Unit,
integration, documentation, and feature-matrix tests are explicit targets or
expanded by a transparent test macro. Native link inputs are dependency labels.

The following is illustrative use of the proposed AOS wrapper, not an existing
rule or a complete production target:

```starlark
load("//tools/bazel/rules:rust.bzl", "aos_rust_library")

aos_rust_library(
    name = "library",
    crate_name = "aos_example",
    crate_root = "src/lib.rs",
    srcs = glob(["src/**/*.rs"]),
    edition = "2024",
    deps = ["@aos_rust_native//:serde"],
    proc_macro_deps = ["@aos_rust_native//:serde_derive"],
    license_domain = "apache-host",
)
```

Centralize lint policies in a `rust_lint_config` target. Preserve existing
crate names, public APIs, package versions, license expressions, and required
compile-time metadata. Supply necessary `CARGO_PKG_*` compatibility values
from declared package metadata during conversion; do not infer them from an
ambient manifest or silently replace them with empty strings. Nix packaging
reads the exported metadata instead of independently inventing a version.

## Features and compatible build families

Bazel's `crate_features` does not reproduce Cargo's feature resolver by itself.
For each migrated family, record the current resolved normal, build, and
development dependency features for every supported target. Generate and
compare a Bazel inventory before switching consumers.

Use distinct targets/configurations for materially different variants:
native versus WebAssembly, production versus test doubles, static guest versus
host, and Apache host versus GPL plugin. Optional dependencies and `cfg` values
must change together. Platform-specific flags such as the Worker getrandom
backend become declared platform configuration. Unsupported combinations fail
analysis rather than selecting an approximate default.

Third-party feature resolution is family-local. A native service's TLS or
database features must not enter a Worker or a static guest through a global
union. Within one final Rust dependency graph, a given crate/version must have
a coherent feature variant wherever its types cross API boundaries. Creating
two differently featured copies is not a general substitute for unification.
The dependency exporter checks that invariant and records deliberate duplicate
versions separately.

Avoid a configuration transition on every Rust dependency. Start with named
family roots and explicit variants. Add transitions only for a necessary
execution/target distinction or an identified configuration boundary.

## External Rust dependencies without first-party Cargo manifests

The final authoring surface uses `crate_universe` package specifications and
annotations in `third_party/rust/BUILD.bazel`, with generated repositories for
compatible families. Dependency specs name versions or immutable Git commits,
features, platforms, patches, and exceptional build-script inputs. Preserve a
complete transitive lock and source hashes; version constraints alone are not
a reproducibility contract.

The explicit update tool uses the AOS-built `cargo-bazel`/Cargo resolver to
produce generated BUILD files, resolved locks, and a source fetch inventory.
A Cargo-format lock inside this generated third-party metadata is acceptable;
it is not a first-party workspace lock or an instruction to run Cargo builds.
Upstream manifests remain part of third-party source archives.

Ordinary compilation uses those generated rules and Nix-supplied source
repositories. It neither resolves dependencies nor invokes Cargo. The update
path may temporarily ingest existing manifests to establish migration parity,
but the completed family uses direct specifications and removes that input.
Rule generator, specification, lock, patch, and rendered-output digests are
checked together. Changes to one require regeneration or fail validation.

## Build scripts, generated sources, and native dependencies

Convert first-party `build.rs` work to named Bazel generator targets where
practical. For example, protobuf generation owns its schemas, compiler,
prost/pbjson generator, descriptor output, and postprocessing code; embedding
Hub assets consumes declared JS/Wasm/CSS artifacts. Preserve the existing
generated bytes and behavior through comparison fixtures.

Third-party build scripts can use `cargo_build_script`: Bazel compiles and runs
the script and propagates its results. Declare all scripts' files, tools,
environment, and native dependencies before execution. `rerun-if-changed`
messages are not permission to discover undeclared inputs after a cached
action has already been selected. A script that invokes Cargo requires a
specific replacement or remains outside the migrated build graph.

Expose AOS native libraries through `CcInfo`-providing imports with headers,
link libraries, ABI configuration, and runtime dependencies. Preserve custom
libgit2 options, OpenSSL configuration, SQLite variants, linker scripts, and
other package-specific behavior. Choose one provider per native library
variant; do not accidentally combine upstream vendored and AOS-built copies.
Execution-platform copies used by generators are distinct from target copies.

No action reads the developer's Cargo home, discovers libraries through host
`pkg-config`, or downloads sources while compiling. Generated Rust and C/C++
outputs belong to the action output tree, with explicit consumer edges.

## Native code and hardware configurations

Use `rules_cc` for C/C++, with declared `.S` inputs and assembler toolchains for
assembly. Represent linked Rust/native components in one graph through the
standard providers. Keep the evaluator's implementation, semantic fixtures,
and benchmark sources together under `native/nix-eval/`.

Define portable release, debug, sanitizer, and named CPU-specific profiles.
Explicit CPU/ISA, optimization, LTO, panic, codegen-unit, and PGO inputs form
part of configuration identity. Compiler-specific settings need equivalent
intent, not identical flag spelling. `-march=native` or ambient CPU detection
is not a shareable configuration. PGO training data is a declared artifact
with workload provenance. Experiments do not silently alter package defaults.

## Tests and editor support

Bazel test targets preserve each current suite's selection, environment,
fixtures, timeouts, and exclusion rules. `rust_test` alone does not preserve
nextest's process-per-test isolation and scheduling. Provide a declared test
runner that lists libtest cases and invokes each selected case with exact
filtering, bounded concurrency, and the existing timeout/exclusive-group
policy. Test the runner's handling of ignored tests, failures, crashes, and
zero matches. Reuse an existing runner only if it accepts Bazel artifacts
without invoking Cargo or requiring a Cargo workspace.

Doctests use the selected `rustdoc` and target link environment. Clippy,
rustfmt, documentation generation, and compile-only checks are explicit
targets. Integration fixtures and executables use runfiles, not assumptions
about the current directory or a Cargo `target/` path. The test inventory
must detect omitted integration files and gated tests. KVM, fleet, and other
external-state checks keep their Nix resource requirements and cannot become
ordinary cacheable unit tests.

Generate rust-analyzer project information, procedural-macro configuration,
and C++ compilation databases from selected Bazel configurations. These tools
use the AOS compiler and generated outputs. Editor support is an acceptance
condition for Cargo removal, including generated code and native dependencies.

## License and process boundaries

Use visibility plus an analysis check over the dependency closure to enforce
the existing license domains. Apache host targets cannot depend on QEMU-side
implementation libraries. Protocol crates keep their permissive dependency
closure; the GPL plugin has a separately identified package and source closure.

Building several targets in one Bazel invocation does not authorize linking
them together. Preserve `gate:abi-conformance`, `gate:license-boundary`, and
the Crucible suite's corresponding-source publication rules. Include a
negative fixture that adds a prohibited edge and fails during analysis.
