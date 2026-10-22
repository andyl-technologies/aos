# First-party Bazel migration

RFC-0028 defines the target architecture. Implementation proceeds through
reviewable milestones; Cargo remains authoritative for consumers until their
Bazel feature, test, package, platform, and license checks pass.

All caching remains on local disk. Bazel and accache retain separate cache
roots, with no cache service. Accache remains available for non-Bazel builds.

## Implemented infrastructure

The root workspace uses Bzlmod with Bazel 9.2.0, rules_rust 0.71.2, and
rules_cc 0.2.17. Nix fetches the hashed source inventory under
`third_party/bazel/`, applies the registry patches, and removes bundled
compiled tools. Rust helpers used by the rules compile from source too.
The native Linux adapter supplies AOS Rust, GCC, binutils, libc, and GCC
runtime libraries. Other platform adapters remain to be qualified.

The shared functions in `pkgs/build-support/_bazel/` prepare workspaces,
build/check labels, and install package targets. A package exports a versioned
manifest with explicit files, destinations, modes, version, and license domain;
Nix verifies exported bytes and package identity before ordinary fixup.
Runtime dependencies remain explicit Nix package inputs. The fixture check
executes the Rust, C++, and Rust/native programs after fixup.

```sh
aos-dev --release build check build.bazel.all --no-out-link
aos-dev bazel build //tools/bazel/tests/fixture:package
nix develop --file bazel-shell.nix
```

The launcher ignores user/system/workspace rc files, checks the packaged Bazel
version, supplies an allowlisted environment, and disables downloads and remote
services. Every module has an immutable local override. An empty local registry
makes undeclared modules fail locally. A preparation derivation evaluates module
extensions offline and produces their platform/toolchain-specific lock; actual
builds treat lock changes as errors. Preparation depends on declarations and
source layout, not implementation bytes, and never invokes a resolver online.

Nix builds use private output bases and Bazel filesystem sandboxes inside the
outer network-isolated Nix sandbox. They reuse Nix's network namespace because
creating another namespace would require mounting `/sys`, absent in Nix.
Direct development requests Bazel's network isolation as well. Its shadow
workspace keeps generated locks/output links outside the checkout, with one
lock covering setup and execution per output base. Only the disk action cache
is shared across independent builds. Release mode uses a temporary output base
and requests no shared cache.

Production consumers still use Cargo. These fixtures do not establish
production feature parity, cross-platform support, editor integration, or
completion of the RFC. The full cache invalidation/concurrency matrix and
family-specific performance budgets remain required before production cutover.

## Local cache evidence

`tests/evidence/native-linux-cache.json` records the first passing native Linux
cross-derivation trial. In a fresh Nix execution, an application-only edit
restored the declared Python generator, source-built procedural macro, generated
Rust library, shared Rust/C++ libraries, and Rust/native binary from disk; the
edited Rust and C++ applications rebuilt. The edited cached and uncached
executables matched byte for byte and both returned `answer=43` (the original
returned `answer=42`). The unchanged native-link binary combines the two library
results and returns `answer=84`. Each build had an independent
output base. Event fingerprints cover declared arguments, environment, and
input content hashes; they are not advertised as Bazel's remote Action digest.

Use an empty dedicated cache to repeat the registered qualification:

```sh
AOS_DEV_CACHE_DIR=/var/tmp/aos-bazel-trial aos-dev cache init
AOS_DEV_CACHE_DIR=/var/tmp/aos-bazel-trial aos-dev \
  --no-go-cache --no-rust-target-cache --no-rust-incremental --no-accache \
  build check build.bazel.cache.verify --no-out-link
```

The cache-specific checks are exposed only when a shared Bazel cache is
selected; release `allChecks` includes the uncached infrastructure suite.
`tests/cache-proof.nix` also accepts a unique `trial` and sandbox `cacheDir`
for new measurements without substituting a completed qualification output.
`cache.invalidation.all` tests Rust/C++ implementation edits, headers, generated
input, generator environment, Rust features/flags, and a tool closure identity
change with unchanged logical compiler labels. Every case has a separate cold
namespace and baseline Nix derivation, so equivalent outputs from a different
case cannot mask a required miss. It checks affected misses, unaffected hits,
semantic fingerprints, and all three executable results. The passing native
Linux evidence is in `tests/evidence/native-linux-invalidation.json`.

`cache.concurrent` runs independent Nix builds against the same cache namespace,
requires overlapping execution intervals, and compares every exported artifact
with isolated builds. It verifies distinct mount/PID/user namespaces and output
directory inodes. Sandboxes can have identical visible UIDs/PIDs; those numbers
alone do not establish shared execution state. The passing evidence is retained
in `tests/evidence/native-linux-concurrent.json`.

Build evidence also retains launcher wall/CPU time, child peak RSS, block I/O,
UID mappings, namespaces, command, and cache selection. These are individual execution measurements;
they do not establish production performance budgets. Foreign-target, CPU,
linker/sysroot, and PGO invalidation, interrupted/corrupt-cache recovery, and
family-specific performance baselines remain required before their cutovers.

## Updating rule dependencies

Updates are explicit network operations with the AOS-built Bazel and Python.
Resolve `bazel mod graph --lockfile_mode=update --output=json` using a fresh
output base and the source-built JDK, then run:

```sh
python3 tools/bazel/metadata/module_inventory.py \
  --graph /path/to/module-graph.json --lock MODULE.bazel.lock \
  --output third_party/bazel/modules.json
```

The exporter checks registry responses against the module lock. Review source
URLs/hashes, patches, the source-only exclusion audit, and any additional rule
helper repositories in `rule-inputs.json`. Re-run the offline checks with empty
per-user caches. Ordinary launchers cannot perform this update.

## Configured source selection

Every shared build exports `inventory.json` from an aspect over its configured
targets. It records dependency labels, first-party source files, generated
inputs, feature/flag/environment declarations, and execution/target variants
that occur in the graph. External Rust targets retain their configuration
metadata without becoming first-party source paths.

After a successful analysis/build, check that inventory into the owning family
and pass its path as `sourceInventory` to `mkAosBazelWorkspace`. The function
reads that checked-in JSON during pure evaluation; it never runs Bazel or
realizes an inventory derivation. Hashes cover module/BUILD/shared policy
declarations and the exporter. Graph changes reject the stale inventory.
Implementation contents stay ordinary source inputs. Discovery roots under
owned `src`, `tests`, and `benches` trees include new files while unrelated
documentation, other worktrees, Cargo outputs, and Bazel outputs stay outside
the selected source.

`checks.build.bazel.precision-parity` compiles the native fixtures from the
generated selection and compares artifact digests with the conservative
selection. `source-selection` checks documentation exclusion, new-file
inclusion, and stale-graph rejection without evaluation-time builds. The
fixture inventory is an infrastructure contract; production families still
need their own selected configurations and parity checks.

Generated output labels are followed back to their generating rules. Generator
scripts and input data therefore remain part of the source selection even when
consumers depend on an output file rather than the rule label. The fixture uses
`aos_python_generator` with declared inputs, outputs, environment, and the AOS
Python closure. It also builds its procedural macro for the execution platform
and links a Rust binary to the native library through an explicit C ABI.

## Isolated Rust tests

`rules/test.bzl` compiles ordinary `rules_rust` libtest artifacts and runs each
selected case in a fresh process through `testing/runner.py`. Compilation and
execution use AOS tools; the runner never invokes Cargo. Test runfiles and the
declared Rust test environment are retained, and ambient environment inheritance
is rejected. Interpreter files and their Nix closure identity are declared test
inputs.

`testing/policy.json` preserves the current nextest oracle's timeout periods,
termination grace, slow-case overrides, and exclusive cases. Its update tool
rejects unsupported filter or scheduling changes. The policy check compares it
with `crates/.config/nextest.toml` during migration; ordinary test actions consume
only the JSON policy. Regenerate explicitly with:

```sh
python3 tools/bazel/metadata/test_policy.py \
  --oracle crates/.config/nextest.toml --output tools/bazel/testing/policy.json
```

The runner supports exact/substring selection, ignored tests, stable Bazel
shards, bounded concurrency, exclusive execution, cancellation, and process-group
cleanup. Zero matches fail. Failures, crashes, and timeouts remain failures;
JUnit records each invocation, and Nix retains the test log/XML as evidence.
Policy tests exercise these cases, including forced termination of a test that
ignores SIGTERM. The real Rust fixture includes two cases which fail when they
share a process, plus an ignored failure that must remain unselected by default.
Doctests, platform/resource checks, and family-specific integration inventories
remain separate migration obligations.

## Boot Rust pilot and license analysis

`checks.build.bazel.pilot.all` builds `aos-boot-identity` and `aos-recovery`
directly with Rust rules. It runs 15 identity unit cases, six UKI CLI integration
cases, 13 recovery unit cases, both doctest targets, and the ignored recovery
manifest case with AOS-built jq. A native `rustc` oracle must discover exactly
the same case names, including the ignored case. The CLI integration suite also
runs against the existing production package. Production installation scripts,
qualification, cross builds, and Cargo metadata remain unchanged until the
remaining family acceptance checks pass.

Shared compile macros declare a license domain. Package analysis follows
compiled dependency edges and rejects Apache host/GPL QEMU combinations in
either direction; protocol code can be consumed by either. Compiler plugins
are checked in their own execution scope. Compiled dependencies without a
declaration fail closed, apart from an explicit list of pinned rule support
targets. `checks.build.bazel.license-boundary` proves both prohibited link
directions fail analysis before any compilation. This supplements the existing
ABI, source-retention, and publication gates; it does not replace them.

The pinned rules' source-built doctest writer embeds AOS Bash. Ordinary test
execution never needs a host `/usr/bin/env` interpreter.

## Migration oracle

`metadata/cargo-inventory.json` records Cargo's discovered targets, declared
features, package metadata, workspace contracts, and Nix consumers for the
main workspace and standalone first-party workspaces. It is a migration
oracle, not a Bazel dependency definition. It does not claim resolved feature
parity or completed performance measurements.

Regenerate with AOS-built Python and Cargo:

```sh
python3 tools/bazel/metadata/cargo_inventory.py \
  --cargo "$(command -v cargo)" \
  --output tools/bazel/metadata/cargo-inventory.json
```

Pass `--check` to detect drift. Cargo runs with `--locked --offline --no-deps`;
the exporter does not compile code or fetch dependencies. Inventory files
must never become global inputs to every compilation action.

## Explicit Rust dependency updates

`third_party/rust/BUILD.bazel` declares crate_universe specifications without a
first-party Cargo manifest. Build the specification package normally, then run
`aos-dev bazel update-deps core` to resolve third-party dependencies explicitly.
This command uses source-built Cargo and cargo-bazel in a private temporary
Cargo home. It is the network-enabled update boundary; ordinary build and test
commands retain download denial and immutable repository overrides.

The updater retains Cargo's third-party lock, the crate_universe context,
rendered Rust rules, source URLs and SHA-256 hashes, original SPDX expressions,
and the updater/tool closure identity. Downloaded archives must agree with both
resolved locks. Declaration fingerprints reject stale specification packages;
publication replaces only previously generated files and preserves unrelated
files. Subsequent updates seed resolution from the generated third-party lock.

Nix fetches these hashed source archives and supplies the rendered repositories
to Bazel. The rules' own metadata parser dependencies are likewise pinned source
archives, using the BUILD files in the pinned rules_rust source. Compilation uses
Rust rules directly. The first-party toolchain's Cargo entry point fails if a
build script attempts a nested Cargo invocation; the explicit updater receives
the actual source-built Cargo separately.

`checks.build.bazel.dependencies.all` exercises this path with Crucible's
`crucible-determinism` library, unit tests, and doctests. Its `thiserror` dependency
also exercises procedural macros, Cargo metadata, and third-party build scripts.
This pilot does not yet replace the production Crucible package or remove its
Cargo manifest.

Configured inventories retain loaded first-party BUILD and Starlark definitions,
including module includes. Declaration discovery queries the configured aspect's
target set rather than traversing an unconfigured dependency closure. Refresh
combined package/test inventories with `metadata/merge_inventory.py`; it rejects
stale declaration and exporter fingerprints before merging them.
