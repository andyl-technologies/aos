# Rust builds

AOS builds Rust with the source-built AOS toolchain and vendored crates, using
no host tools. Third-party dependencies are compiled into reusable Nix
derivations whose identity excludes first-party Rust source, so an ordinary
implementation edit rebuilds only the workspace's own units. Rust tests run
under cargo-nextest so test processes spread across the builder's cores.

## Builders

`pkgs/default.nix` provides the Cargo builders; the phase scripts they drive
are `cargoPhases` in `stdenv/phases.nix`.

| Builder | Role |
|---|---|
| `mkCargoPackage` | Build a Cargo workspace or package and install its executables and libraries |
| `mkAosCargoPackage` | `mkCargoPackage` for in-repository crates, deriving `src` from the package's Cargo selectors |
| `mkCargoDummySource` | Shape a manifest-only copy of a workspace for dependency builds |
| `mkCargoArtifacts` | Compile a dummy source and publish the reusable Cargo target directory |
| `mkCargoNextestCheck` | Run a workspace's tests with cargo-nextest |

## Dependency artifacts

`mkCargoDummySource` (`pkgs/build-support/_cargo-artifacts.nix`) copies the
Cargo manifests, lockfile, Cargo configuration, toolchain files, and
`[patch.crates-io]` path crates, then replaces every other `.rs` file with a
minimal `fn main() {}`. Its identity therefore changes when a manifest or the
set of Rust target paths changes, but not when Rust implementation code
changes.

`mkCargoArtifacts` builds that dummy workspace with the real commands of its
consumer (for example the release build plus `test --no-run`) and
`CARGO_INCREMENTAL=0`. Its output contains:

```text
target.tar           the complete Cargo target directory, uncompressed
build-messages.jsonl Cargo's JSON messages from the dependency build
contract.json        the compatibility contract below
```

The tarball preserves Cargo's internal file times across Nix store
normalization. Artifact outputs are never stripped, patched, or
reference-scrubbed, because changing files behind Cargo's fingerprints would
make reuse unsound.

A consumer passes the artifacts as `cargoArtifacts`. Its configure phase
extracts `target.tar` into `target/` and then touches every workspace `.rs`
file, so Cargo rebuilds the first-party units against the real source while the
restored registry dependencies stay fresh. Installation reads only the
`compiler-artifact` executables and libraries reported by the consumer's own
build messages, so a dummy or inherited final artifact cannot enter the
package output. The consumer keeps a copy of its build messages in
`nix-support/cargo-build-messages.jsonl`, with store paths redacted and
sorted, and declares the vendor directory, compiler, and artifacts as
disallowed references.

## Compatibility contract

`mkCargoPackage` computes an `aos.cargo-artifact-contract/v1` record for every
build and exposes it as `passthru.cargoArtifactContract`. Its baseline fields
are:

- `system` (host platform);
- `rust` (the Rust toolchain store path);
- `buildType` and `checkType`;
- `buildFeatures` and `buildNoDefaultFeatures`;
- `cargoEnv`, the structured Cargo environment;
- `nativeInputs`, the native build and runtime inputs.

Callers add fields through the `cargoArtifactContract` argument, at least a
`family` discriminator, and may add others such as target or code-generation
settings. A consumer whose contract differs from its artifacts' contract in
any field fails evaluation and names the differing fields. Callers must not
remove fields that affect Cargo unit identity.

## Artifact families

Artifacts are shared only between builds that are compatible; there is no
global feature union. Each family has its own dependency artifacts and
contract. Examples:

- `aos-native-release-and-test` for the `aos`, `apm`, and `apr` package and
  its test derivations;
- `aos-hub-native-postgres-release`, `aos-hub-worker-wasm-release`, and
  `aos-hub-console-wasm-release` for Hub;
- `crucible-apache-host-release-and-test`, `crucible-gpl-qemu-plugin-release-and-test`,
  `crucible-gpl-debug-gateway-release-and-test`, and
  `crucible-static-guest-release-and-test` for Crucible;
- one static family per native provider, such as
  `aos-nix-store-provider-static-release-and-test`.

The Crucible families follow its process and license boundary: Apache host
artifacts never seed the GPL plugin or debug gateway, and targets, Rust flags,
native headers, and libraries are contract inputs (see the
[license map](../../legal/licensing.md)).

`cargo-hakari` is available in the development shell for measuring
family-local feature unification. A workspace-hack crate is worth adding only
when measurement shows a net win.

## Development caches

Development builds through `aos-dev build` replace the immutable artifact seed
with a persistent Cargo target directory, unless `--no-rust-target-cache` is
given. The directory name includes a hash of the contract, vendored
dependencies, Cargo root, flags, build commands, Rust flags, and C compiler,
so incompatible builds never share a tree, while source edits reuse it. Because
Nix normalizes source times, the configure phase touches the source whenever
its recorded source identity differs from the last build, preventing Cargo from
reporting a stale unit as fresh. Incremental compilation is enabled
separately. Release builds (`--release` or `--no-cache`) and artifact-producing
derivations use neither cache. The [`aos-dev` section](../../../AGENTS.md#the-aos-dev-development-entry-point)
of `AGENTS.md` lists the cache controls.

## Tests

`cargo-nextest` is built from source and available in the development shell.
`crates/.config/nextest.toml` holds the repository defaults and per-test
overrides. Setting `cargoNextest = true` (as `mkCargoNextestCheck` does) runs
the check phase with nextest, bounded by `NIX_BUILD_CORES` and an optional
`cargoNextestMaxTestThreads`; with a `cargoNextestProfile`, a failure prints
the failing cases from the JUnit report. Nextest runs each test in its own
process. Tests that share exclusive external state belong in a bounded nextest
test group or override rather than forcing the whole workspace to run
serially.

Nextest does not run doctests, so packages keep an explicit
`cargo test --doc` step. Clippy, rustdoc, ABI conformance, license-boundary,
VM, fleet, and release checks are separate derivations.

`nix-build -A checks.rust` collects the Rust suites, and `aos test rust
[suite]` builds the same attributes. `checks.rust.cargo-artifacts`
(`tests/cargo-artifacts/`) is the regression check for this design. It asserts
that:

- an implementation-only edit keeps the dummy-source identity;
- a manifest edit changes it;
- a consumer builds from restored artifacts and its program runs;
- registry dependencies are reported fresh in the real-source build;
- the published build messages do not retain the vendor store path.

The Crucible policy gates under `tests/crucible/` keep narrow test selection,
private target directories, and deterministic harness arguments. They share one
vendored dependency set, `tests/crucible/_cargo-deps.nix`, so a lockfile update
changes a single fixed-output hash.
