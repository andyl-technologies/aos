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
compiled tools. Rust helpers used by the rules compile from source too. Nix
builds the unchanged upstream Cargo-manifest environment extractor once from
the same pinned rules archive and source dependencies. The rules receive it
as an explicit executable input, avoiding its repeated dependency compilation
in empty Bazel output bases. Its standalone, workspace-inheritance and empty
manifest fixtures match the environment supplied by upstream Cargo;
`checks.build.bazel.manifest-extractor` checks that boundary.
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

The pinned `rules_rust` doctest writer and bootstrap process wrapper use
AOS-built Bash explicitly. Actions block `/bin/sh`, including when a Nix client
mounts a compatibility shell. The generator fixture attempts to execute that
path and requires rejection before emitting its outputs. This keeps a daemon's
compatibility mount from concealing an undeclared interpreter dependency.

Production consumers retain their Cargo or direct-rustc recipes. These fixtures do not establish
production feature parity, cross-platform support, or completion of the RFC. The remaining platform/invalidation checks and
family-specific performance budgets remain required before production cutover.

## Native library imports

`mkAosBazelNativeLibraries` supplies a Nix-built repository of named `CcInfo`
providers. Each entry chooses an AOS package, header package/directory, library
file, and explicit `shared` or `static` linkage. The package's target system
must match the repository platform. Imported headers and library bytes are
declared Bazel inputs; each link also consumes a manifest of the selected
variant's realized runtime closure. These library identities remain separate
from the compiler identity. Shared imports add their immutable AOS library
directory to the consumer's runtime search path.

`checks.build.bazel.native-libraries` checks shared and static SQLite/zstd
imports through both C and Rust consumers. The programs execute an in-memory
SQL query and a zstd round trip, require SQLite FTS5/thread support, and exercise
zstd's worker configuration. The static test explicitly selects
`pkgs.zstdStaticMultithread`: upstream's ordinary static
archive disables threading even though its shared library enables it. The
default zstd derivation identity remains unchanged.

The check inspects sandboxed compiler/link actions for declared headers,
closure manifests, and the selected library byte hashes. It verifies ELF
dependencies and runtime paths, checks the license closure, and requires
analysis to reject a foreign target or an absent Nix repository override.
A compiled doctest calls the same native probe for both linkage variants. The
pinned rules receive narrow fixes for empty source roots and shared-library
flags when converting compiler inputs into doctest commands.
`tests/evidence/native-linux-native-libraries.json` retains the qualification.
This qualifies native Linux imports; family qualification separately checks
store/campaign build-script bindings.

`checks.build.bazel.static-runtime.all` qualifies the native Linux static
runtime adapter before the guest conversion. `mkAosBazelStaticLibraries`
extends explicit static SQLite/zstd imports with declared glibc archives,
the existing guest unwinder shim, and a rebased libm linker script. Consumers
opt in through `@aos_native//:static_runtime` and target-only Rust flags
`-Ctarget-feature=+crt-static` and `-Crelocation-model=static`. Execution-platform
procedural macros keep the ordinary dynamic toolchain.

The check executes C and Rust SQLite/zstd probes after package installation,
requires classic static ELF executables without an interpreter or shared
imports, and verifies the exact archive/script bytes and closure manifests in
actual sandboxed link actions. An optional `retainActionGraph` build argument
retains expanded compiler arguments; the qualification matches Rust response
file contents against the executed input hashes before checking target and
macro flags. Static glibc still embeds optional locale/timezone/loader data
paths, so the Nix closure reports its glibc reference instead of treating ELF
static linkage as proof of independence from all runtime data. This fixture
does not qualify the guest package, foreign static targets, or VM behavior.
`tests/evidence/native-linux-static-runtime.json` retains the qualification.

Entries may select `pkgConfigFiles` explicitly. Their source-built pkg-config
wrapper searches only those files, clears ambient search paths and sysroots,
and records its native execution-tool closure separately from the target
library closure. Build scripts receive the wrapper, metadata, headers, and
libraries as declared inputs. They cannot discover an undeclared host library.

## Rust package identity

Each migrated Rust package declares `aos_rust_package` in its BUILD file. The
declaration owns the package name, SemVer version, edition, license expression
and domain, authors, description, and optional project URLs. Its libraries,
binaries, procedural macros, and tests receive the same `package` value.
`aos_package` uses that declaration for the installed artifact manifest too.
Per-target overrides of package identity fail before compilation. A separately
named installed component, such as `crucible-fleet-store` from the
`crucible-store` Rust package, declares its installation identity explicitly
while preserving the source package's compiler metadata.

The wrapper supplies the compatible `CARGO_PKG_*` compiler environment directly
from the declaration, including separate version components and prerelease
identifiers. No Cargo manifest is an input to these builds. Target-specific
environment entries such as integration-test executable paths remain explicit.

`build.bazel.metadata-parity` compares the configured package environments of
the boot, determinism, protocol, and shared-memory targets against a separate
temporary Cargo manifest oracle. `build.bazel.metadata-policy` exercises eleven
rejected declarations and overrides with actual Bazel analysis. The synthetic
fixture checks package identity in its binary, unit tests, and doctest,
including a version with both prerelease and build metadata.
`tests/evidence/native-linux-package-metadata.json` records the passing combined
suite, 36 configured Rust targets across five packages, and the rejected cases.

## Local cache evidence

`tests/evidence/native-linux-cache.json` records the first passing native Linux
cross-derivation trial. In a fresh Nix execution, an application-only edit
restored the declared Python generator, source-built procedural macro, generated
Rust library, shared Rust/C++ libraries, and Rust/native binary from disk; the
edited Rust and C++ applications rebuilt. The edited cached and uncached
executables matched byte for byte and both returned `answer=43` (the original
returned `answer=42`). The unchanged native-link binary combines the two library
results and returns `answer=84`. Each build had an independent
output base. The qualification retains Bazel's actual action digests for the
cache-enabled executions. Separate event fingerprints cover declared arguments,
environment, and input content hashes for comparison with the uncached oracle,
where Bazel omits the action digest.

Use an empty dedicated cache to repeat the registered qualification:

```sh
AOS_DEV_CACHE_DIR=/var/tmp/aos-bazel-trial aos-dev cache init
AOS_DEV_CACHE_DIR=/var/tmp/aos-bazel-trial aos-dev \
  --no-go-cache --no-rust-target-cache --no-rust-incremental --no-accache \
  build check build.bazel.cache.verify --no-out-link
```

The cache-specific checks are exposed only when a shared Bazel cache is
selected; release `allChecks` includes infrastructure checks and recovery tests
using a disposable cache.
`tests/cache-proof.nix` also accepts a unique `trial` and sandbox `cacheDir`
for new measurements without substituting a completed qualification output.
`cache.invalidation.all` tests Rust/C++ implementation edits, headers, generated
input, generator environment, Rust features/flags, C++ linker flags, and an actual
compiler executable/closure change with unchanged logical compiler labels. Every case has a separate cold
namespace and baseline Nix derivation, so equivalent outputs from a different
case cannot mask a required miss. It checks affected misses, unaffected hits,
action digests, semantic fingerprints, and all three executable results. The passing native
Linux evidence is in `tests/evidence/native-linux-invalidation.json`.

The expanded thirteen-case matrix also changes a named Rust target CPU and an
actual header in a selected AOS sysroot overlay. Their programs return changed
values, and the sysroot proof requires the header in the compiler's declared
inputs. Symlinked headers retain their canonical AOS roots through explicit
`extraHeaderRoots`; those roots enter both include policy and closure identity.
Changes to proof definitions also select a new cache namespace, preventing an
older candidate result from concealing a required miss.

The PGO case trains the same instrumented fixture once and four times using
the AOS-built Rust compiler and its matching LLVM profile merger. It checks
actual library counters and requires the corresponding profile digest in each
compiler action. The changed profile must recompile the library. Consumers
reuse results only when their semantic fingerprints and action digests remain
unchanged: different weights can produce identical optimized library bytes.
`tests/evidence/native-linux-pgo-invalidation.json` retains the training records,
passing twelve-case matrix and combined suite.

The linker case replaces the selected AOS `ld` executable with an AOS Bash
wrapper. A copy of the compiler wrapper changes only its explicit binutils
selection prefix, retaining all ordinary AOS flags and the compiler binary.
The proof requires changed declared linker bytes, actual execution recorded in
Bazel events, cache misses under the changed toolchain closure, and unchanged
program behavior. `tests/evidence/native-linux-linker-invalidation.json` retains
the passing thirteen-case matrix and combined suite.

On x86_64 Linux, `cache.target` builds the same package labels first natively,
then for AArch64, then for AArch64 again in a third fresh Nix execution.
Target compilation must miss the native entries while the execution-platform
procedural macro is restored. The final build restores all selected foreign
actions with identical declared bytes. All three artifacts have the required
ELF machine and runtime results, with foreign execution through AOS QEMU.
`tests/evidence/native-linux-target-cpu-sysroot.json` retains the passing matrix,
target action digests, compiler inputs and source fingerprints.

`cache.concurrent` runs independent Nix builds against the same cache namespace,
requires overlapping execution intervals, and compares every exported artifact
with isolated builds. It verifies distinct mount/PID/user namespaces and output
directory inodes. Sandboxes can have identical visible UIDs/PIDs; those numbers
alone do not establish shared execution state. The passing evidence is retained
in `tests/evidence/native-linux-concurrent.json`.

Build evidence also retains launcher wall/CPU time, child peak RSS, block I/O,
UID mappings, namespaces, command, and cache selection. These are individual execution measurements;
they do not establish production performance budgets. Further foreign-platform qualification and
family-specific performance baselines remain required before their cutovers.

`tests/evidence/native-linux-toolchain-cache.json` records a fresh native trial
with the source-built developer tools and WASM adapter present. Cross-derivation
reuse, overlapping concurrent builds, and all nine existing invalidation cases
pass against the updated compiler closure. These are correctness experiments;
their individual timings do not replace repeated family performance baselines.

`tests/evidence/native-linux-prebuilt-manifest-extractor.json` retains the
passing combined suite, device/editor parity, upstream helper fixtures,
cross-derivation reuse, concurrent use and nine invalidation cases with the
Nix-built helper. This qualification does not establish a speedup.

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

## Repository source ownership

Each Rust package declares `source_package` using the same `RUST_PACKAGE`
identity as its compilation targets. `//crates:source_catalog` collects all
77 workspace members; `//:source_catalog` also includes the two standalone
accache packages. The catalogs declare Rust source ownership and expose those
files as runfiles for repository-wide structural tests. Nested Bazel packages
retain separate ownership.

Catalog generation uses Bazel's built-in write action and reads no Cargo
manifest. `checks.build.bazel.source-catalog.all` compares identities and exact
source coverage against the retained Cargo migration inventory and rejects any
external tool execution. Metadata declarations for packages awaiting conversion
do not claim that their compilation, tests, or installation have migrated.
The engine conversion uses this foundation to preserve repository-wide audits
while replacing manifest-based workspace discovery.

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
`aos-dev bazel update-deps <core|device|store|guest|engine|quota|session|control>` to resolve the selected
third-party dependency profile explicitly.
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

Dependency profiles preserve Cargo's distinct feature configurations. The
`core` profile remains the default for the qualified boot, shared, and protocol
families. The `device` profile adds Ciborium, Serde's `alloc` feature, and Syn's
`full` feature for the deterministic device models. Every first-party alias in
one configuration selects the same resolved profile, preserving Serde's Rust
type identity across the device and protocol libraries. The existing core
feature graph remains unchanged. Both profiles retain exact versions and
archive checksums from the temporary workspace lock. The `store` profile
resolves the storage/campaign roots separately, including SQLite, threaded zstd,
and signing dependencies; it does not widen the core or device graph.
Repository labels normalize SemVer `+` metadata as crate_universe does, while
source archives, package identities, and parity comparisons retain the exact
original versions.

```sh
aos-dev bazel test //crates/crucible/engine/crucible-device:unit \
  --//tools/bazel/rules:dependency_profile=device
aos-dev build check build.bazel.device.all --no-out-link
```

The Nix device workspace pins this setting for compilation and configured
discovery. Using a device-only dependency under the core profile fails analysis.
`tools/bazel/tests/device.nix` provides conservative inventory-refresh and
precise qualification entry points. The connected family includes determinism,
device, protocol, and shared-memory tests, doctests, examples, Clippy, formatting,
and documentation; Cargo remains its execution and feature-parity oracle.

The source updater separately reviews shared and host-only SPDX expressions.
Ciborium, `ciborium-io`, and `ciborium-ll` retain their Apache-2.0-only ownership
as `apache-host` dependencies, even though their dependencies share the same
profile. Actual analysis probes allow that closure under an Apache host root
and reject it under protocol or GPL roots. This classification does not change
the process boundary or admit Apache-only code into QEMU.

`tests/evidence/native-linux-device-profiles.json` retains the passing combined
suite, precise configured inventory, 642 cases across 33 libtest artifacts, the
item-qualified compile-only doctest, and all feature/example comparisons. It
also records 58 policy tests, fresh cross-derivation restoration, nine cache
invalidation cases, and 11 seconds of overlap between independent cache writers.
These are native Linux conversion checks. Production cutover, full-family
foreign-target workflows, and larger-family performance acceptance remain
open; the whole-workspace ABI and license gates are recorded separately.

`checks.build.bazel.dependencies.all` exercises this path with Crucible's
`crucible-determinism` library, unit tests, and doctests. Its `thiserror` dependency
also exercises procedural macros, Cargo metadata, and third-party build scripts.
This pilot does not yet replace the production Crucible package or remove its
Cargo manifest.

Configured inventories retain loaded first-party BUILD and Starlark definitions,
including module includes. Declaration discovery combines the aspect's target set with a configured
`cquery` dependency graph. This retains original alias labels and the Starlark
files their BUILD packages load, while avoiding unconfigured dependency walks
into unused toolchains. Refresh
combined package/test inventories with `metadata/merge_inventory.py`; it rejects
stale declaration and exporter fingerprints before merging them.

## Cache integrity and recovery

`checks.build.bazel.recovery` uses a disposable disk cache inside a Nix sandbox.
Every invocation gets a fresh workspace and output base. It checks warm reuse,
missing blobs, corruption of a compiler artifact and captured stdout, complete
cache eviction, and cancellation after a generator writes a partial output.
The resumed build must regenerate that action and reproduce the original
package bytes and runtime behavior. Published CAS entries are hashed after
cancellation; temporary cache writes are never treated as published results.
The test retains per-case logs and metrics and never modifies the host's shared
cache.

AOS patches Bazel 9's disk-cache client to verify both path-backed copies and
streamed CAS downloads. The unpatched client accepted an altered compiler
artifact in the recovery experiment. Verification hashes materialized bytes,
preserves filesystem copy/reflink support, and rejects digest mismatches before
successful action completion. Action-cache keys identify actions rather than
the serialized ActionResult, so CAS verification does not incorrectly treat
those keys as content hashes. A corrupt shared entry can be bypassed with
`--no-bazel-cache` while it is removed through the cache maintenance commands.

The invalidation matrix also checks C++ link-action digests and a linker-flag
change that leaves compile actions reusable. The compiler replacement case
changes a real executable and its realized Nix closure under the same logical
Bazel label, preserving program behavior.

## Crucible storage and campaign graph

`checks.build.bazel.store.all` connects `crucible-store` and
`crucible-campaign`. Its explicit configurations cover the default features,
`test-support`, `destructive-recovery-faults`, and both features together.
Each configuration selects the same family variant in both packages and
compares unit, integration, binary-test, doctest, and resolved dependency
inventories with an offline Cargo oracle. Required-feature integration targets
appear only in configurations that enable them.

The family imports AOS SQLite as a shared library and AOS threaded zstd as a
static library. Declared pkg-config tools supply their build-script metadata;
Rust FFI linkage uses `link_deps`. The test workspace selects `-Copt-level=s`
and `-Cdebuginfo=0`, matching the current Cargo test profile. Case timeouts and
exclusive scheduling continue to use the shared nextest policy. The binary's
empty libtest artifact is explicitly allowed; an unmatched filter still fails.

The dependency specification retains reviewed Cargo feature units that the
pinned crate_universe resolver otherwise merges. Target libc has no optional
features; jobserver's build dependency uses a separate `default,std` instance,
including a separate build script with constant features. Serde and serde_core
exclude `alloc`, which the generator introduces through unsupported-platform
proc macros. The updater checks exact crate versions, upstream feature sets,
and redirected dependency edges before publishing these rules. A lock or graph
change fails the update until the declaration is reviewed. Cargo parity still
compares the distinct compiled feature sets without merging them.

The check also builds Clippy, formatting, documentation, and editor parity.
The temporary Cargo editor oracle selects the compiled default targets. Cargo
metadata before and after the selection must retain every other target record;
only integration tests with disabled required features are omitted. Source code,
dependency features, and lint settings stay unchanged, and inference statistics
and diagnostics are compared exactly.

Its installed `crucible-fleet-store` runs the complete built-in store probe and
rejects an unsupported command after Nix fixup. The check compares the probe's
full output, apart from its temporary storage root, and invalid-command output
against the retained Cargo binary. Production builders remain
unchanged while platform and performance acceptance work continues.
The native linkage check hashes both selected libraries against the binary's
declared Rust action inputs and inspects the installed ELF and runtime closure:
SQLite remains a shared dependency, zstd is static, and the interpreter belongs
to the declared AOS runtime closure.

`tests/evidence/native-linux-store.json` retains the passing aggregate check,
all four test/feature inventories, runtime and native-linkage proofs, and the
cache checks. Each configuration preserves Cargo's single ignored case. Both
default editor models retain 12 unknown expressions with identical diagnostics;
this is parity evidence, not a claim of complete inference.

```sh
aos-dev build check build.bazel.store.all --no-out-link
nix-build tools/bazel/tests/store.nix -A conservative.inventory --no-out-link
```

The second command refreshes configured metadata by requesting only the
inventory aspect's output group. It does not compile or execute the targets;
qualification does both independently. Validate and publish that output's
`inventory.json` as `metadata/store-inventory.json`, then rerun the precise
qualification. The inventory includes all feature variants and developer and
package roots, so source selection remains a pure Nix evaluation input.

## Static guest qualification

`checks.build.bazel.guest.all` builds the guest library and executable, both
libtest artifacts, both integration tests, doctests, Clippy, formatting,
documentation, and editor parity. Its separate `guest` dependency profile
preserves the guest's resolved libc and SHA-2 features alongside the
campaign/store test dependencies. A version-guarded override removes the
generator's extra `once_cell/std` feature. Exact third-party feature units and
the protocol, store, campaign, and guest's first-party features are compared
with an offline Cargo release build.

The installed package includes explicit instruction-ABI build metadata from
the shared protocol source. Runtime qualification checks that metadata,
classic static ELF linkage, the selected libc/archive/closure input hashes in
an uncached sandboxed link, and six CLI cases against the Cargo binary. Static
libc's optional runtime-data reference remains visible in the Nix closure.
The ABI and fingerprint integration tests read declared repository inputs;
they do not discover a Cargo manifest or an old package-builder implementation.

```sh
aos-dev bazel --family guest build //crates/crucible/guest/crucible-guest:package
aos-dev bazel --family guest rust-project //crates/crucible/guest/crucible-guest:lib
aos-dev bazel update-deps guest
nix-build tools/bazel/tests/guest.nix -A conservative.inventory --no-out-link
```

The family option selects the guest's static target flags and Nix library
repository. Execution tools retain their ordinary dynamic configuration.
The ordinary development launcher continues to serve the host families.
The guest editor configuration keeps the guest's selected roots as workspace
members and retains protocol/store/campaign as library dependencies. Cargo
metadata verifies the same membership in its temporary oracle. The exporter
removes the pinned aspect's unconditional test cfg from library-only roots,
preserving their real features, aliases, and generated inputs.
Guest editor parity compares guest-owned diagnostic locations and types.
Cargo's analyzer still visits test bodies in local path dependencies without
their libtest dependencies, so aggregate inference counts have different
scopes. The evidence retains both sets of counts and every Cargo diagnostic
outside the guest scope. Diagnostics without source locations are retained
separately as unattributed Cargo diagnostics; any unattributed Bazel diagnostic
fails this scoped check. Other qualified families keep whole-model comparison.
The inventory refresh exports configured metadata without compilation; validate
its contracts with `metadata/merge_inventory.py` before adopting the checked-in
inventory. Library-only selections can omit dependency integration trees;
the owning family's parity check still requires its complete selected tests.

Production guest consumers continue to use their existing builder. Foreign
static targets, guest VM behavior, and performance acceptance remain separate
requirements before cutover.

`tests/evidence/native-linux-guest.json` retains the native qualification:
33 executed cases and one ignored case, exact features for 78 external crate
identities and four first-party packages, six installed CLI comparisons,
static runtime inputs and closure, and the scoped editor comparison. The
117 policy tests and direct `aos-dev` command regression check also pass.

## Engine conversion

`tools/bazel/tests/engine.nix` exposes the engine's default, `test-support`,
`test-double`, and combined feature checks. Each configuration compares exact
test cases, ignored cases, examples, doctests, and first-party and external
features with an offline Cargo oracle. Its `all` target also requests Clippy,
formatting, documentation, and editor parity. Native x86_64 Linux qualification
passes; production consumers retain their existing builders while performance
acceptance and other platform gates remain open.

`tests/evidence/native-linux-engine.json` records 1,235 executed libtest cases
for default and `test-support`, and 1,298 for `test-double` and combined features,
with one ignored case per configuration. Each matches 104 external crate
identities, eight first-party feature configurations, both examples, and the
compile-only doctest. The scoped editor comparison matches all 50 owned
diagnostics, including nine attributed synthetic diagnostics, with no analyzer
panics. Its inference totals remain distinct from Cargo's wider dependency
model. The 133 policy tests and required Rust test-target compilation also pass.

Three integration artifacts have no cases without `test-double`. Those labels
have explicit empty-test allowances; parity requires the corresponding Cargo
artifacts to exist and to list no cases. Other zero-case selections still fail.

```sh
aos-dev bazel --family engine test //crates/crucible/engine/crucible-engine:unit
aos-dev bazel --family engine rust-project //crates/crucible/engine/crucible-engine:lib
aos-dev bazel update-deps engine
nix-build tools/bazel/tests/engine.nix -A all \
  --no-out-link --max-jobs 4 --cores 4 --option substitute false
```

The family launcher selects the engine dependency profile, declared SQLite and
threaded zstd imports, and Cargo's optimized test settings, including debug
assertions and overflow checks. The `engine` profile preserves the shared-memory
protocol's reviewed permissive dependency closure while keeping other host
dependencies in their existing license domain.

Source audits receive their Rust files, fixtures, and documentation as declared
inputs. The repository-wide size audit uses `//crates:source_catalog`; the
temporary Cargo oracle receives the same generated catalog. Bazel compilation
does not consume first-party Cargo manifests. Engine-specific test source and
runtime inputs remain scoped to the tests that inspect them.

The Cargo editor oracle receives the same assertion and overflow settings as
the compiled engine. The analyzer's default optimized configuration would
otherwise hide assertion-gated test helpers. Verbose analyzer output attributes
synthetic expression diagnostics to their enclosing source file and body byte
range. The comparison preserves their types and multiplicity, and checks row
counts against the analyzer's statistics. The complete raw output, normalized
diagnostics, and analysis logs are retained under `editor/` in the qualification
output; missing source context still fails the check.

## Shared Crucible protocol graph

`checks.build.bazel.protocol.all` builds `crucible-qemu-protocol` and
`crucible-qemu-shmem`, their unit and 22 integration test binaries, both doctest
targets, and the shared-memory ABI-header example. The isolated runner executes
302 native Linux test cases. An offline Cargo oracle runs the same suites,
compares discovered test names, and checks each resolved dependency feature set
against the configured Bazel inventory. Distinct compilation variants remain
distinct sets; a union cannot hide a missing feature configuration.

The shared `core` dependency family retains the versions and features from the
existing workspace, including BLAKE3's `std,pure` configuration. Its sources keep
their original license expressions. The updater admits sources to the shared
protocol scope only when their expression appears in the specification's
reviewed list; a new expression fails the update before publication. Host and
plugin consumers within a dependency profile reuse the same canonical crate
instances without Rust type identity conflicts. A different profile retains its
own resolved feature configuration instead of widening this one.

`aos_license_check` applies the existing closure analysis to library/test roots
which do not export an installed package. Both protocol graphs include it;
a negative fixture proves protocol code cannot acquire an Apache-host
implementation dependency. The existing ABI, license, and corresponding-source
gates remain independently required.

`metadata/protocol-inventory.json` owns configured source selection. Refresh
from a conservative build when declarations change:

```sh
nix-build tools/bazel/tests/protocol.nix -A conservative.all --no-out-link
```

Copy that output's `inventory.json` to the checked-in inventory and rerun
`checks.build.bazel.protocol.all` with the precise selection. The Cargo oracle
retains its discovered binaries separately so comparison changes do not rebuild
the oracle. These checks qualify the native graph; production consumers and
foreign-target adapters still need the remaining RFC acceptance work.


## Rust developer workflows

The AOS Rust release supplies Clippy, rustfmt, rustdoc, rust-analyzer, its matching
proc-macro server, and standard-library sources. The compiler closure identity
includes these source-built tools. The launcher pins the checked-in formatter
and Clippy configuration; the workspace deny levels remain explicit
`rust_lint_config` inputs on crates that inherit them from Cargo. During
coexistence, a check compares both the configuration and lint levels with the
Cargo oracle. Negative fixtures must reject host-clock access and `unwrap`.

The boot and protocol BUILD packages expose `clippy`, `format`, and
`documentation` targets alongside their existing tests. Formatting and Clippy
also cover the declared binaries and integration roots. The small infrastructure
fixture has a runnable doctest, and its evidence check requires one passing
case rather than accepting an empty doctest suite.

```sh
aos-dev bazel build //crates/crucible/protocol/crucible-qemu-protocol:clippy
aos-dev bazel test //crates/crucible/protocol/crucible-qemu-protocol:format
aos-dev bazel build //crates/crucible/protocol/crucible-qemu-protocol:documentation
nix develop --file bazel-shell.nix
aos-dev bazel rust-project //tools/bazel/tests/fixture:rust_app
```

`rust-project` consumes the pinned rules_rust aspect's configured graph and only
current successful build-event outputs. It preserves aliases, features,
build-script environments, generated roots, and compiled procedural macros.
Library and libtest views share a root; ambiguous feature/toolchain variants
fail instead of silently merging. Generate separate projects for incompatible
configurations. The file is written atomically to the worktree root and ignored
by Git. Its paths require the development output base to remain available;
release mode rejects editor export because its output base is temporary.

The Bazel shell puts the AOS developer binaries on PATH. Point the editor at
that `rust-analyzer` and the generated `rust-project.json`, following the
[rust-analyzer project format](https://rust-analyzer.github.io/book/non_cargo_based_projects.html).
Builds and tests continue through `aos-dev`; the exporter does not install
editor configuration or enable an ambient Cargo check command. The toolchain
prepares upstream standard-library metadata offline from its installed vendored
Rust sources. Its `cargo` adapter serves those immutable records for the exact
library manifest and supported target; it executes no Cargo process. Arbitrary
manifests, compilation and changed feature requests are rejected.
`checks.build.bazel.sysroot-metadata` checks the records and rejection boundary.
First-party discovery and compilation stay in Bazel.

`checks.build.bazel.editor` type-checks the fixture's library/test view,
generated source, and real procedural macro with the source-built analyzer;
it requires zero unknown expression/pattern types and no analyzer panics.
`developer-evidence` retains the nonempty doctest and formatter results, and
`developer-policy` verifies the lint contract and its rejection cases.

`checks.build.bazel.device.editor` exports the connected device family,
including its libraries, unit tests, integration tests and ABI-header example.
It compares every first-party root and feature set with the compiled inventory,
checks procedural-macro artifacts, and runs the source-built analyzer without
a Cargo driver. The exporter preserves child-module discovery, generated
directories, and the build-script cfg/environment files actually consumed by
rustc. `graph.json` records inference counts as well as graph parity.
`device.editor-parity` compares all inference counts and normalized diagnostic
locations/types with a temporary offline Cargo editor oracle. This preserves
pre-existing analyzer limitations while rejecting missing modules or newly
unknown types. The initial incomplete smoke result remains historical evidence
in `tests/evidence/native-linux-device-editor.json`. The corrected gate analyzes
270,504 expressions and 46,719 patterns, with the same 20 unknown expressions
and zero partial types or panics in both editors.
`tests/evidence/native-linux-device-editor-parity.json` retains the exact
diagnostics, three prepared standard-library graphs, checks and fingerprints.

Passing native Linux outputs and configuration fingerprints are retained in
`tests/evidence/native-linux-developer-tools.json`.

## Linux cross toolchain qualification

`mkAosBazelCrossToolchains { targetPackages = ...; }` extends the native tool
repository with a Linux target compiler, standard library, C/C++ linker and
sysroot. It uses the target stdenv's scheduler-hosted cross tools; public target
tool packages contain target-hosted executables and cannot serve that role.
Every target action includes the realized cross compiler closure identity.
Generators and procedural macros continue to select native execution tools.

On x86_64 Linux, `checks.build.bazel.cross-linux.all` builds the fixture's Rust,
C++ and Rust/C++ binaries for `//tools/bazel/toolchains:aarch64_linux`. The check
verifies their AArch64 ELF headers, foreign standard-library inputs, native
proc-macro selection, sandbox execution and expected output under AOS-built
QEMU linux-user. A native-only tool repository must reject the same target.
The combined Bazel suite includes this check on that execution platform.
The standalone entry point is `tools/bazel/tests/cross-linux.nix`.
`tests/evidence/native-linux-aarch64-toolchain.json` retains the combined pass,
artifact/runtime checks, native fallback rejection, and fresh native cache proofs.

`checks.build.bazel.cross-device` extends the experiment to all 33 device-family
unit and integration test binaries. It requires AArch64 ELF artifacts and
foreign standard-library inputs for every first-party compile, while procedural
macros retain their native standard library. Materialized compiler response
files preserve the actual Rust target and crate-type flags in the evidence.
Case discovery and execution use the same validator as the compile-loop
benchmark, inside an AOS-built AArch64 Linux kernel under QEMU system emulation.
QEMU user mode rejects `MADV_DONTFORK`, which the two hot-fork mapping tests
require. These tests remain enabled in the guest-kernel check.

The case oracle is the qualified native inventory with one explicit platform
alternative: region allocation must reject an unpinned AArch64 developer
target, replacing the native allocation-success case. Every other case name
and ignored status must match. This preserves the published x86_64 shared-memory
allocation policy; it does not extend the supported protocol ABI to AArch64.

The workspace's `compileOnly = true` setting admits its explicit target platform
for Bazel 9's test analysis, including ordinary `build` commands. The launcher
rejects `test` and `run` in that configuration, so guest execution remains an
explicit qualification step. Compiler actions continue to require native
execution tools. The compilation output exports only the declared test binaries
and case manifest; compiler logs and expanded arguments live in a separate
evidence output and do not enter the guest's runtime closure.

`tests/evidence/native-linux-device-aarch64.json` retains the 33 exported
artifacts, all 642 discovered and executed cases, native procedural-macro
roles, kernel identity, and the combined suite pass. It also records the two
user-mode failures against the same binary hash that passes under the guest
kernel, alongside the current 13-case cache-invalidation qualification.

This qualifies the x86_64 Linux to AArch64 Linux adapter and fixture runtime.
It does not yet qualify full application families, cross editor workflows,
Darwin, or the reverse execution/target pairing. Normal workspaces still select
only their supplied toolchains; adding a platform label cannot enable a host
compiler fallback or fetch a missing compiler.

## Shared AOS libraries

`checks.build.bazel.shared.all` qualifies `aos-core`, `aos-artifact-evidence`,
and `aos-oci-types` together. Their BUILD packages own library, unit test,
integration test, doctest, Clippy, formatting, documentation, and license
closure targets. The native Linux comparison executes 69 unit/integration
cases and checks one compile-only doctest against the offline Cargo oracle.
The comparison retains exact first-party and dependency feature variants,
doctest source locations, and ignored-case status.

The shared dependency snapshot contains 36 source archives. Every version and
checksum matches the workspace lock; the explicit source updater adds `anyhow`
and `base64` without introducing downloaded tools. Package metadata parity now
covers eight first-party packages and 44 configured Rust targets. The temporary
Cargo oracle remains separate from all Bazel compilation inputs.

Refresh `metadata/shared-inventory.json` from the inventories produced by
`tools/bazel/tests/shared.nix`'s conservative test and developer targets when
declarations change, then rerun the precise qualification. Passing store paths,
case inventories, and configuration fingerprints are recorded in
`tests/evidence/native-linux-shared.json`. This qualifies native Linux
compilation and developer workflows; production builder changes still require
the RFC's platform, runtime, and performance acceptance work.

## WebAssembly toolchain qualification

The native Linux compiler repository also exposes a `wasm32-unknown-unknown`
Rust toolchain. It uses the AOS-built target standard library, its separate
metadata files, and the native `rust-lld` from the same compiler closure.
`//tools/bazel/toolchains:wasm32` selects that target; generators and procedural
macros retain Linux execution toolchains. No target C/C++ compiler is registered
for WASM. Pure Rust allocator metadata does not require one.

```sh
aos-dev bazel build //tools/bazel/tests/fixture:wasm_package \
  --platforms=//tools/bazel/toolchains:wasm32
aos-dev --release build check build.bazel.wasm.all --no-out-link
```

The qualification requires a real WASM artifact, target standard-library and
linker inputs, a native procedural macro, a declared Python generator, and
sandbox execution for all five first-party compile/generation actions. The
application and macro contain opposing compile-time platform assertions. A
negative analysis check rejects a native C++ dependency under the WASM target.
`tests/evidence/native-linux-wasm-toolchain.json` retains the passing output
and action fingerprints. This is a compiler/target separation check; Worker
runtime behavior, external WASM dependencies, and foreign-target developer
workflows remain family-specific qualification work.

## Storage/campaign compile measurements

```sh
nix-build tools/bazel/bench/check.nix \
  --no-out-link --max-jobs 4 --cores 4 --option substitute false
nix-build tools/bazel/bench/store.nix --argstr trial UNIQUE-TRIAL \
  -A measurement --no-out-link --max-jobs 4 --cores 4 --option substitute false
```

The storage/campaign workload includes all 13 default-feature libtest
executables, including the fleet-store binary libtest. After every compile
sample, discovery must match all 599 executed and one ignored qualified cases.
The ordinary test policy runner then executes each selected case in its own
process, preserving its case timeout and exclusive scheduling. Validation is
untimed; an executable-wide timeout cannot stand in for that policy.

Three repetitions rotate Cargo incremental, Cargo nonincremental with accache,
and Bazel with a private JVM and local disk cache. Each series measures cold,
warm, a campaign implementation edit, a shared store API edit, a second
worktree, and a fresh build directory. The source configuration and caches
remain private to the series. Cargo profiles come from its actual artifact
events; the ordinary workspace test profile and selected Bazel flags both use
optimization `s`, debug 0, and enabled debug assertions and overflow checks.
These four settings are matched for selected first-party test artifacts.
Dependencies, execution tools, and incremental code generation retain their
baseline settings; this does not establish identical compiler invocations.
Each Cargo sample retains verbose compiler commands, including wrappers and
code-generation arguments; warm samples can contain no compiler calls. Bazel
execution events retain its action arguments. Cold Cargo samples with missing
compiler commands fail. Matched workloads require explicit launcher flags before
starting and reject artifact-profile drift. Nix evaluation, dependency preparation, test
execution, and installation are excluded. In particular, Cargo builds its
pinned bundled zstd C source, while Bazel imports the prepared AOS threaded
zstd archive. These are compile-loop measurements, not end-to-end acceptance.

The `configuration` attribute exposes the immutable workload inputs without
running measurements. `bench/check.nix` runs 24 measurement regression tests
with AOS Python in the Nix sandbox. Feature/target-change timing and family
regression budgets remain separate qualification work.

The engine conversion exposed missing assertion/overflow flags in the earlier
optimized Bazel test configuration. `tests/evidence/native-linux-test-profile-correction.json`
retains the Cargo artifact profiles and the engine compile failure that exposed
the mismatch. Timing trials without the corrected settings and complete compiler
command records are excluded. Earlier storage case/feature and runtime checks retain
their recorded scope and do not establish equality of compiler invocations.
The corrected storage qualification passes all four feature configurations,
native and installed runtime checks, and whole-model editor parity. The same
evidence file records its immutable configuration, report hashes, and case
counts; performance acceptance remains separate.

Source selection indexes selected paths and their ancestors once instead of
scanning every inventory path for each candidate file.
`tests/evidence/native-linux-source-selection-index.json` records unchanged
source bytes for all seven inventories and unchanged configured derivation
identities for the six qualified families. Three alternating store source-path
evaluation trials measured medians of 0.283s before and 0.120s after, with
uncontrolled host load. This isolates source selection and does not resolve
the broader end-to-end evaluation gap.

## Device-family compile measurements

```sh
nix-build tools/bazel/bench/device.nix --argstr trial UNIQUE-TRIAL \
  --no-out-link --max-jobs 4 --cores 4 --option substitute false
```

The harness compiles the connected determinism/device/protocol/shmem family,
then discovers and executes all 642 qualified cases from 33 test binaries
after each sample. Validation is outside the measured interval. Each mode has
private state and local caches; a fresh Bazel output base can reuse only its
series' disk action cache. Source snapshots are immutable inputs throughout.

`tests/evidence/native-linux-device-compile-baseline.json` retains all 54
samples, commands, action counts, resource metrics and repeated distributions.
The adjacent `-provenance.json` records fingerprints and measurement limits.
Median compile-loop wall times in seconds:

| Configuration | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh build directory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo incremental | 66.093 | 0.646 | 3.325 | 3.912 | 0.384 | 64.051 |
| Cargo nonincremental + accache | 50.351 | 0.339 | 30.295 | 30.574 | 0.418 | 46.120 |
| Bazel private JVM + disk cache | 90.426 | 0.509 | 10.898 | 11.549 | 10.889 | 9.820 |

The original harness incorrectly labelled Cargo's profile as optimization 0
and debug 2. `tests/evidence/native-linux-device-profile-correction.json`
verifies the retained artifact events for all 36 Cargo samples: the workspace
test profile used optimization `s` and debug 0. Bazel fastbuild used optimization
0 and debug 0. The original timings are unchanged. Matching targets
and runtime behavior does not make those profiles equivalent. Qualification
jobs also ran concurrently on this shared host; samples retain load averages.
The recorded immutable configuration predates the editor metadata fixes.

In the first repetition, both fresh-directory scenarios restored all 159 Rust
compile actions, 18 build scripts and 49 Cargo-environment extraction actions,
with no compiler execution. Implementation/API edits compiled 5/11 Rust
actions. Accache admitted misses but recorded no hits, so these results do not
establish an accache benefit. Bazel's edit loop regresses against Cargo
incremental in this comparison. Nix evaluation, preparation,
installation and timed test execution are excluded. Matched-profile and
end-to-end measurements, improvements and numeric regression budgets remain
required before production cutover.

Select comparison modes with `--arg modes '[ "cargo-incremental-debug0"
"bazel-server" ]'`. The additional Cargo mode explicitly sets both dev/test
debug and optimization levels to 0. Each sample records those levels and
whether compiler incremental state is enabled; other driver defaults can
still differ. The repeated 36-sample comparison before the prebuilt helper
change is retained in `tests/evidence/native-linux-device-debug0-baseline.json`
with adjacent provenance. Median seconds:

| Configuration | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh build directory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo incremental, debug 0 | 27.206 | 0.372 | 4.075 | 4.615 | 0.490 | 29.924 |
| Bazel private JVM + disk cache | 100.918 | 0.490 | 13.243 | 13.877 | 11.789 | 9.923 |

Whole-workspace ABI and license-boundary gates also pass after the device
declarations; `tests/evidence/native-linux-device-workspace-gates.json` records
their output identities and source fingerprints. These correctness checks
do not resolve the performance regressions.

With the upstream manifest extractor supplied by Nix, another 36-sample run
retains all 642-case validations in
`tests/evidence/native-linux-device-prebuilt-helper-baseline.json`, with
adjacent provenance. Median seconds:

| Configuration | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh build directory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo incremental, debug 0 | 27.778 | 0.497 | 4.173 | 4.088 | 0.333 | 25.464 |
| Bazel private JVM + disk cache | 41.255 | 0.432 | 10.136 | 10.264 | 8.595 | 7.959 |

The cold Bazel run executes 92 Rust compile actions and 11 build scripts,
versus 159 and 18 before this change; all 49 environment extraction actions
remain. Both fresh-directory scenarios restore all those actions. Preparing
the source-built helper happens before this timed interval and has an upfront
Nix cost. These shared-host compile-loop measurements establish neither a
total build speedup nor an accepted edit-loop tradeoff. The edit regression
and end-to-end qualification remain open.

## Initial boot compile measurements

Run the temporary Cargo/Bazel comparison with a fresh trial identity:

```sh
nix-build tools/bazel/bench/pilot.nix --argstr trial UNIQUE-TRIAL \
  --no-out-link --max-jobs 4 --cores 4 --option substitute false
```

The harness runs the real boot-identity library and binary through four modes,
rotating their order over three repetitions. Each mode measures cold compiler
caches, a warm command, an implementation edit, a public-interface edit, a
second worktree sharing compatible caches, and a fresh build directory. Every
sample checks that the produced command accepts a valid boot identity and
rejects an invalid one. Accache gets the ordinary realized-closure manifest;
the baseline fails if it never admits a compiler action.

Initial median wall times in seconds are retained with every individual sample
and command in `tests/evidence/native-linux-boot-compile-baseline.json`:

| Mode | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh build directory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo incremental | 0.753 | 0.236 | 0.370 | 0.490 | 0.265 | 0.796 |
| Cargo nonincremental + accache | 0.996 | 0.232 | 0.447 | 0.917 | 0.248 | 0.915 |
| Cargo incremental, debug=0 | 0.706 | 0.260 | 0.437 | 0.481 | 0.231 | 0.695 |
| Bazel batch + disk cache | 8.311 | 4.311 | 5.185 | 5.452 | 5.461 | 5.854 |

Bazel restores all four Rust actions in the second-worktree and fresh-directory
cases, but startup dominates this small crate. Cargo already reuses its target
directory across worktrees in this workload. Accache records three misses and
ten bypasses per repetition, with no hits. These measurements do not support
a performance-based cutover of this family yet.

Cargo dev defaults include debug information; the extra Cargo debug=0 mode
better matches Bazel fastbuild's debug setting. Preparation, Nix evaluation,
inventory export, and installation are excluded from this compile-command
comparison. Filesystem page caches and shared-host contention are uncontrolled.
Peak RSS is the largest process value among waited descendants. Actual
cross-derivation correctness is qualified separately; larger workloads,
end-to-end measurements, and numeric acceptance budgets remain required.

The follow-up `native-linux-boot-analysis-reuse.json` records 90 fresh samples
with an optional private JVM (`batch=false` in the launcher configuration).
Both JVM modes limit the heap to two GiB and active processors to the configured
job count. The private process has a 60-second idle limit. The measurement
harness explicitly shuts down every process, including after a failed sample;
it never shares an execution tree between worktrees or derivations.

| Mode | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh build directory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cargo incremental | 0.878 | 0.265 | 0.436 | 0.507 | 0.250 | 0.827 |
| Bazel batch, bounded JVM | 8.087 | 4.000 | 4.134 | 4.733 | 4.490 | 4.677 |
| Bazel private JVM reuse | 8.338 | 0.328 | 0.615 | 1.124 | 5.235 | 5.315 |

The retained JVM improves repeated commands in one worktree; creating a new
execution base still pays startup costs. Its `/proc` CPU counters and resident
memory are recorded separately from the waited launcher/client resource usage,
since a persistent process does not appear in the latter. These remain initial
compile-loop measurements; larger-family and end-to-end budgets remain open.

Nix workspaces and `aos-dev bazel` now retain a private JVM between commands
against the same output base. Nix builders shut it down on exit, preserving a
failed build's status and rejecting a successful build if shutdown fails.
Preparing the lock and standalone analysis/recovery probes use batch execution.
`aos-dev --release bazel` also forces batch execution before removing its
temporary output directory. Development processes expire after 60 idle seconds;
`aos-dev bazel shutdown` closes one explicitly. Only the action disk cache is
shared across worktrees or derivations; each process and execution tree remains
private. This adds no cache service.

`native-linux-analysis-reuse-integration.json` retains the integration checks,
same-process evidence for each Nix phase, an 8.1-second overlap between independent
builders, and a second 90-sample measurement. It also records actual developer
build reuse and release-directory cleanup. The initial concurrent attempt was
rejected because scheduling did not overlap its participants; a fresh isolated
trial passed the unchanged verifier.

## Installed boot package measurements

`bench/measure_end_to_end.py` compares the production boot-identity recipe with
a benchmark-only Bazel candidate. Invoke it with the AOS-built Python and Nix:

```sh
"$AOS_BENCH_PYTHON" tools/bazel/bench/measure_end_to_end.py \
  --root "$PWD" --scratch /tmp/aos-boot-benchmark-source \
  --output /tmp/aos-boot-benchmark-results \
  --cache-root /var/tmp/aos-dev-cache-1000/bazel \
  --nix-tools "$AOS_BENCH_NIX_BIN" --trial UNIQUE-TRIAL
```

Both scratch and output paths must be new, and scratch must be outside the
repository. The harness freezes one repository snapshot before running any
mode, then applies the same trial-specific edits to private copies. Three
repetitions rotate the candidate order. Each
records evaluation and realisation separately, verifies valid and invalid CLI
behavior, and checks the installed runtime closure. The production recipe uses
`rustc` directly; the Cargo compile-loop baseline above is a separate workload.
The candidate preserves the production install and fixup phases and checks the
same library-unit-test scope. Neither candidate changes production selection.

`native-linux-boot-end-to-end-baseline.json` retains all 36 raw samples, exact
commands, builder/JVM resources, runtime closures, and harness hashes. Median
evaluation-plus-realisation times in seconds are:

| Mode | Cold | Warm | Implementation edit | API edit | Second worktree | Fresh derivation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Production | 2.163 | 0.832 | 2.035 | 2.221 | 1.022 | 1.702 |
| Bazel candidate | 25.846 | 12.587 | 20.903 | 21.267 | 11.908 | 20.367 |

That retained baseline used the earlier per-mode snapshots with an unchanged
checkout. The current driver freezes one source tree for all repetitions and
also records the CPU model, affinity, and available-memory snapshots. The
recorded harness hashes identify the version used for each experiment.

Warm and second-worktree samples reuse the Nix output in both modes. The Bazel
warm delay is overwhelmingly evaluation, before action-cache lookup or compiler
execution. This baseline fails the useful end-to-end improvement requirement;
it does not authorize a family cutover. Source selection and evaluation need
profiling before larger-family measurements establish acceptance budgets.

`tests/evidence/native-linux-qualification-evaluation.json` records a follow-up
that removes repeated normalization inside the command-probe adapter while
retaining validation at its public boundary. The complete evaluation suite and
malformed-input checks pass, and both boot candidates retain identical Nix
derivation identities. Three evaluation-only samples measured Bazel's median
at 14.9 seconds before and 11.1 seconds after; host load varied substantially.
This does not replace the end-to-end baseline or resolve the remaining gap.

Compiler dependencies are already prepared, filesystem page caches and host
contention are uncontrolled, and snapshot/runtime checks are outside the timed
intervals. The recorder adds overhead to both modes. Its daemon-builder CPU and
maximum process RSS include adopted JVM children; the separate JVM counters
overlap that accounting and must not be added again. Existing-output samples
contain no fresh builder resources. The installed Bazel candidate adds the
declared GCC runtime library closure; it retains no compiler or JDK paths in
its numeric measurement files.

## Linux project-quota family

The quota family owns `aos-linux-project-quota`, its unit tests and the
`project-quota-flight` example. Its separate `quota` dependency profile retains
Cargo's small libc/rustix/thiserror feature graph rather than inheriting the
engine family's broader feature union. Qualification compiles the example;
only the disposable ext4 VM flight executes it with quota authority.

```sh
aos-dev bazel update-deps quota
aos-dev bazel --family quota test //crates/shared/aos-linux-project-quota:unit
nix-build tools/bazel/tests/quota.nix -A all --no-out-link
nix-build tools/bazel/tests/quota.nix -A vm --no-out-link
nix-build tools/bazel/tests/quota.nix -A cross-linux --no-out-link
```

The native check covers test and dependency-feature parity, the example,
doctests, Clippy, formatting, documentation, editor parity and installation of
the flight package. `tests/evidence/native-linux-quota.json` records native qualification: eight
executed unit cases, the compiled flight example, exact features for ten external
crate identities, and complete editor inference (3,711 expressions and 746
patterns, with no unknown types, partial types or panics). The separate `vm`
check uses the existing ext4 enforcement
assertions with the Bazel-built executable and requires a KVM builder. Native
qualification, VM enforcement and additional platform results must be recorded
before migrating production consumers. `cross-linux` compiles the same unit
cases for AArch64 with native procedural macros and runs their binaries under
an AOS AArch64 kernel in QEMU. The shared-memory protocol retains its explicit
foreign-layout rejection case when present in a family; the quota family
requires the exact native case inventory without that unrelated adjustment.
`tests/evidence/aarch64-linux-quota.json` records all eight quota cases passing,
native procedural macros, sandboxed AArch64 compilation, and the existing
device family's 642-case regression. The associated policy suite passes 136
tests. The native ext4 VM also passes byte and inode enforcement, fail-closed
nonempty release and cleared project-ID reuse. The installed flight declares
AOS `gcc-libs` as a runtime dependency; its ELF interpreter, runtime paths and
unwinder closure are checked after ordinary fixup/reference scrubbing. The
initial guest run caught the missing unwinder dependency before enforcement;
the native evidence retains that failure and the successful corrected flight.
Privileged ext4 enforcement is currently qualified only on x86_64. Production
package builders remain on Cargo during this qualification.

## Session and control API family

The `session` family selects `crucible-session` and `crucible-control-api`
together. Its dependency profile adds the reviewed Tokio feature set to the
engine dependency closure. The temporary Cargo oracle compares each external
crate's exact version and features, every selected test artifact and case, and
both crates' doctest results.

```sh
aos-dev bazel update-deps session
aos-dev bazel --family session test //crates/crucible/control/crucible-session:unit
aos-dev bazel --family session rust-project //crates/crucible/control/crucible-session:lib_for_tests //crates/crucible/control/crucible-session:unit_binary //crates/crucible/control/crucible-control-api:lib_for_tests //crates/crucible/control/crucible-control-api:unit_binary
nix-build tools/bazel/tests/session.nix -A all --no-out-link --max-jobs 4 --cores 4
```

Each crate's `:lib` retains its production dependency graph. Test-only
`:lib_for_tests` targets enable the engine test double and support APIs that
Cargo selects through development dependencies. The session feature variants
have matching test libraries in both packages, so a control API test uses the
same session features as the selected session test. Qualification covers the
default, test-support, test-double, and combined variants separately.

`tests/evidence/session-cargo-baseline.json` records the 132-case Cargo baseline
and the configured graph matching all 111 external crate identities and feature
sets. `tests/evidence/native-linux-session.json` records all four native
configurations passing 132 cases each, zero ignored cases, both doctest targets,
and developer-tool checks. `tests/evidence/aarch64-linux-session.json` records
all 132 default-family cases passing under an AOS AArch64 Linux kernel in QEMU,
with native procedural macros and target SQLite/zstd inputs.

```sh
nix-build tools/bazel/tests/session.nix -A cross-linux --no-out-link --max-jobs 4 --cores 4
```

The editor check selects those test libraries explicitly and compares
diagnostics for the two selected packages. It retains aggregate inference
statistics from both analyzers without claiming that the wider dependency
models are identical. Both analyzers report the same single unresolved type
at `src/lifecycle/session_contract.rs:876` in the control API. The raw report
retains all 1,510 Cargo diagnostics outside these selected packages and no
unattributed diagnostics. The foreign run covers the default family; additional
feature configurations remain qualified natively only.
`tests/evidence/native-linux-session-aggregate.json` records the passing aggregate
and core evaluation checks at the session checkpoint, including the corrected
quota package description. Production consumer migration and performance
acceptance remain separate requirements.

## Control transport family

The `control` family selects `crucible-control-client` and
`crucible-control-server`. Its separate dependency profile preserves the
HTTP/2, TLS, UUID, and asynchronous transport features without widening the
qualified session-only profile. All dependency archives remain pinned source
inputs supplied by Nix; repository setup and compilation stay offline.

```sh
aos-dev bazel update-deps control
aos-dev bazel --family control test //crates/crucible/control/crucible-control-client:unit //crates/crucible/control/crucible-control-server:unit
nix-build tools/bazel/tests/control.nix -A all --no-out-link --max-jobs 4 --cores 4
```

Production `:lib` targets retain default first-party dependencies. Test-only
`:lib_for_tests` targets select the engine test features and session support
APIs that Cargo resolves for the two packages together. The client test binary
can depend on the server test library, which depends on the client library;
there is no dependency cycle between libraries. The default and server
`test-support` configurations have separate Cargo comparisons.

`tests/evidence/control-transport-cargo-baseline.json` retains the executed
107-case, nine-artifact Cargo baseline with no ignored cases and 194 external
crate identities. The foreign qualification compiles those same default-family
artifacts for AArch64 and executes them under an AOS kernel in QEMU. Its guest
enables only loopback networking with target-built iproute2; QEMU has no network
interface. Existing families leave loopback disabled and retain their derivation
identities.

```sh
nix-build tools/bazel/tests/control.nix -A cross-linux --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/aarch64-linux-control.json` records all 107 default-family cases
passing across nine artifacts in the foreign guest, with no platform case
exceptions. Both native configurations pass the same test inventory and
194-crate feature comparison. `tests/evidence/native-linux-control.json` records
the passing developer checks and editor comparison against the retained
compiled graphs. The three distinct selected-package diagnostic locations and
types match Cargo. Separate library/libtest views emit six raw occurrences;
the report retains those, Cargo's three occurrences, and both inference summaries
without claiming equal multiplicities or whole-model inference. Production
consumers remain on Cargo.

The editor exporter keeps a library and its unit-test target separate when
combining their development dependencies would create a cycle. In this family,
client tests use the server, whose library uses the client. Dependent crates
retain the ordinary library identity while separate workspace roots analyze
the unit tests and their development dependencies.

## QEMU host family

The `qemu-host` family selects the Apache-licensed `crucible-qemu-host`
package. Its source-only dependency profile adds tempfile and preserves the
Linux process, network, parameter, and time features required by its tests.
Production libraries keep their ordinary engine dependencies; test libraries,
integration targets, and examples preserve Cargo's engine test-double feature.
Default and `test-support` configurations have separate qualification oracles.

```sh
aos-dev bazel update-deps qemu-host
aos-dev bazel --family qemu-host test //crates/crucible/qemu/crucible-qemu-host:unit
nix-build tools/bazel/tests/qemu-host.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/qemu-host-cargo-baseline.json` records the pre-conversion
`crucible-qemu-host` Cargo run: 841 executed cases, four existing ignored cases,
15 artifacts, and 107 external crate identities. Compared with the engine
family, it adds tempfile and its two dependencies and expands rustix's Linux
process, network, parameter, and time features.

The baseline includes the checked-in patch text, schema registry, and five Nix
files used by source audits. These audit inputs and all compiled Rust sources
have retained hashes. This is the Apache host-side crate; its ordinary Cargo
tests do not replace the separate patched-QEMU runtime, process-boundary, or VM
gates. Bazel declares those audit files as compile or runtime inputs, without
linking QEMU implementation code. The runtime source audit locates its declared
Nix inputs independently of Cargo manifests.

`tests/evidence/qemu-host-configured-graph.json` records the passing offline
configured graph, refreshed source inventories, dependency specifications,
142 policy tests, CLI checks, and workspace Rust target compilation. Its 107
external crate feature sets exactly match the Cargo baseline, and the existing
eight dependency locks remain unchanged.

`tests/evidence/native-linux-qemu-host.json` records native execution passing
all 841 cases in both configurations, with four existing ignored cases and
15 libtest artifacts each. External features match all 107 Cargo identities.
Developer checks and production license closures pass. Editor parity preserves
the same 27 selected-package diagnostics as Cargo; it does not claim complete
inference. Production migration remains pending.

`tests/evidence/aarch64-linux-qemu-host-compilation.json` records all 15 foreign
test artifacts compiling with AArch64 ELF headers and the expected Rust flags.
The `cross-linux` check qualifies compilation. Its separate
`cross-linux.runtime-probe` remains available for platform work: the full guest
run failed 46 unit cases, including rejection by the existing x86_64-only
shared-memory ABI and an unresolved trace-inode assertion. Failure details are
retained. Foreign runtime parity is not qualified, and the probe is outside the
passing aggregate. The ABI restriction and test inventory remain intact.

## S3 adapter family

The `store-s3` family selects `crucible-store-s3` with its own source-only AWS
dependency profile. Production and development libraries keep distinct store
features; the development graph enables the existing conformance API.

```sh
aos-dev bazel update-deps store-s3
aos-dev bazel --family store-s3 test //crates/crucible/storage/crucible-store-s3:unit
nix-build tools/bazel/tests/store-s3.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/store-s3-cargo-baseline.json` records 11 executed cases across
two artifacts and 222 external crate identities. The existing live-service
conformance case remains ignored, with its original requirement for an
exclusive test bucket and credentials. Development dependencies enable the
store conformance API. This baseline makes no live-service qualification claim.

`tests/evidence/store-s3-configured-graph.json` records passing offline source
inventories, all ten dependency specifications, 147 policy tests, CLI checks,
and exact agreement with all 222 Cargo dependency feature sets. The existing
nine dependency locks remain unchanged.

`tests/evidence/native-linux-store-s3.json` records passing native execution of
all 11 cases and preservation of the one ignored case across two artifacts.
Developer and production license checks pass. The selected editor package has
zero diagnostics in both Bazel and Cargo. Production migration remains pending.

The live-conformance target explicitly permits a suite containing only ignored
cases. Its complete ignored inventory remains in parity evidence. Empty and
filtered zero-match selections still fail, and newly active cases execute
normally. Running that target without external resources does not qualify the
live S3 service contract.

`tests/evidence/aarch64-linux-store-s3.json` records the same 11 executed cases
and one ignored case in an AOS AArch64 Linux guest, across both test artifacts.
All three selected Rust compilation actions use the foreign toolchain and the
reviewed profile flags; procedural macros run on the native toolchain. The guest
has loopback networking and no external network interface or S3 service.

`tests/evidence/native-linux-store-s3-aggregate.json` records the passing frozen
aggregate through the S3 adapter and core evaluation checks. One device AArch64
VM initially reached its existing 180-second timeout; the exact derivation and
then the unchanged aggregate passed on retry. The evidence retains that history.
This checkpoint predates the daemon graph and separate S3 foreign runtime gate.

## Daemon family

The `daemon` graph declares the default, test-support, destructive recovery,
and combined feature configurations. Its library edges preserve each selected
Cargo graph, including recovery features on every indirect store reference.
Daemon development dependencies enable the engine and QEMU test APIs without
enabling the session's own development features. Host tests use the guest
protocol library without the static guest runtime.

`tests/evidence/daemon-cargo-baseline.json` records the passing default Cargo
baseline: 1,111 executed cases, 24 existing ignored cases, four test artifacts,
and 264 external crate identities. The component-contract and exact-closure
integration suites require test-support and remain in the nondefault target
sets. Production migration remains pending.

`tests/evidence/daemon-cargo-feature-baselines.json` retains the additional
passing Cargo configurations: recovery executes 1,114 cases with 24 ignored;
test-support executes 1,122 with 26 ignored; combined features execute 1,125
with 26 ignored. Test-support activates both feature-gated integration suites.
All three retain the same 264 external identities and unchanged Rust sources
and Cargo manifests; differences between source snapshots are Bazel metadata.

```sh
aos-dev bazel update-deps daemon
aos-dev bazel --family daemon test //crates/crucible/control/crucible-daemon:unit
nix-build tools/bazel/tests/daemon.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/daemon-configured-graph.json` records the passing offline graph,
all 14 refreshed source inventories, 11 dependency specifications, 147 policy
tests, and CLI checks. Its default test graph matches all 264 external and
16 first-party Cargo feature identities. The existing ten dependency locks
remain unchanged. The schema registry has an explicit daemon export, and the
three newly enabled shared crypto dependencies retain reviewed source licenses.

`tests/evidence/native-linux-daemon.json` records native execution and Cargo
parity passing in all four feature configurations, with the same case counts,
ignored inventories, example, and 264 external crate identities. Developer and
production license checks pass. Editor parity preserves Cargo's selected
diagnostics; it does not claim complete inference. The frozen source precedes
the CLI graph. Foreign daemon execution and production migration remain pending.

## Crucible CLI qualification

`tests/evidence/crucible-cli-cargo-baseline.json` retains the default Cargo
baseline: 436 executed cases, 23 existing ignored cases, eight test artifacts,
281 external identities, and 18 first-party feature identities. The S3 client
construction test needs trust roots even without making a network request;
the sandbox declares `SSL_CERT_FILE` from the AOS certificate package. Its
bundle digest and the successful Cargo reports are retained.

`tests/evidence/crucible-cli-cargo-feature-baselines.json` retains eight Cargo
configurations with unchanged CLI source and fixture inputs. Default and
recovery each execute 436 cases with 23 ignored; test-double and combined
recovery/test-double each execute 493 with 41 ignored. All preserve 281 external
and 18 first-party feature identities. The four packaged-flight combinations
compile only: their listed inventories are retained separately from execution.
Their existing VM gates must supply the kernel, patched QEMU, plugin, root image,
and deployment resources before packaged runtime qualification can pass.


The Bazel graph declares all eight feature combinations, coherent production
and test dependency closures, license checks, and developer targets. Native
qualification executes the four combinations without packaged flights. The
four packaged combinations compile every selected artifact and retain their
Cargo inventories; execution still belongs to the dedicated VM gates.

```sh
aos-dev bazel update-deps crucible-cli
aos-dev bazel --family crucible-cli test //crates/crucible/control/crucible-cli:bin_crucible
nix-build tools/bazel/tests/crucible-cli.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/native-linux-crucible-cli-default.json` records passing native
Bazel execution of all 436 default cases, with the 23 ignored cases preserved,
and full inventory and dependency-feature parity against a fresh Cargo run.
Integration subprocesses resolve compiler-declared paths through Bazel runfiles;
trust roots are declared AOS certificate inputs. A test that deliberately
replaces an executable makes only its private copy writable before mutation.
Its existing assertions remain unchanged. Production migration remains pending.

`tests/evidence/native-linux-crucible-cli.json` retains the completed native
qualification. Default and recovery each execute 436 cases with 23 ignored;
test-double and combined recovery/test-double each execute 493 with 41 ignored.
All four match fresh Cargo case and feature inventories. Developer checks,
four packaged compilation graphs, and all eight production license closures
pass. Editor comparison matches 90 selected diagnostic locations and inferred
types; both raw selected reports contain 184 occurrences. Aggregate inference
statistics differ and remain incomplete. Packaged runtime execution still
requires its dedicated VM gates.

`tests/evidence/crucible-cli-configured-graph.json` retains 578 distinct
configured reports, 1,737 declared source files, all 12 dependency specification
outputs, and passing policy and CLI checks. The required workspace Rust target
compilation passed with matching hashes for the changed Rust inputs. That gate
compiles AOS application targets; CLI compilation and execution have their own
Bazel and Cargo qualification. Existing dependency locks and resolved features
remain unchanged.

`tests/evidence/crucible-cli-metadata-evaluation.json` records passing metadata
parity for 291 compiled first-party targets and the core Nix evaluation checks.
It retains the complete metadata report for the frozen CLI checkpoint before
the format library conversion.

## AOS format library qualification

`tests/evidence/formats-cargo-feature-baselines.json` retains the connected
`aos-nar`, `aos-module-format`, and `aos-registry-format` Cargo baselines. Default
features execute 158 cases; NAR compression executes 175. Both have zero ignored
cases and one passing doctest. The graphs contain 71 and 79 external crate
identities respectively, with six first-party libraries. Compression uses the
AOS multithreaded Zstandard package.

The Bazel family declares default and compression library, unit, doctest,
license, formatting, Clippy, documentation, and editor targets. Compression
uses declared AOS Zstandard and pkg-config inputs; the default libraries remain
pure Rust. The dependency profile preserves Cargo's target and build features
with exact-version guards for libc and indexmap.

```sh
aos-dev bazel update-deps formats
aos-dev bazel --family formats test //crates/shared/aos-nar:unit_compression
nix-build tools/bazel/tests/formats.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/native-linux-formats.json` retains passing native Bazel tests
and fresh Cargo parity: 158 default cases and 175 compression cases, zero
ignored cases, and one doctest each. All 71 default and 79 compression external
crate identities and six first-party feature identities match. Developer and
license checks pass. Default editor comparison preserves eight diagnostic
locations and inferred types; complete inference is not claimed.

`tests/evidence/formats-configured-graph.json` retains 162 distinct configured
reports, 73 declared source files, all 16 refreshed family inventories, 13
dependency specifications, and passing policy and CLI checks. All 12 existing
dependency locks and their source and feature pins remain unchanged.
`tests/evidence/formats-metadata-evaluation.json` records passing metadata
parity for 297 compiled first-party targets and core Nix evaluation checks
at the frozen format checkpoint. `tests/evidence/formats-required-rust-targets.json`
records passing workspace application unit and integration target compilation,
with hashes matching all 23 changed Rust inputs at that checkpoint.
Wasm qualification, performance acceptance, and production migration remain pending.

## Release format baseline

`tests/evidence/release-format-initial-cargo-failure.json` retains the initial
Cargo failure: the canonical-encoding test rejected `production_only` anywhere
in the document although the current requirement schema and fixture support it.
The test now verifies that individual requirements retain true values and omit
false defaults, while preserving the round-trip, digest, and legacy-field checks.
`tests/evidence/release-format-cargo-baseline.json` records the successful rerun:
152 executed cases, one existing ignored Nix-inventory case, 72 external crate
identities, and six first-party libraries. Release-format now has native Bazel
qualification in the connected contract family below. Workspace Rust compilation
is recorded separately.

## Connected contract qualification

`tests/evidence/contracts-cargo-baseline.json` records the connected
`aos-release-format`, `aos-module-docs`, `aos-deployment-format`, and
`aos-storage-layout` Cargo baseline before changes to their Rust sources.
It executes 225 cases across six test artifacts, with the existing Nix-inventory
case ignored. All four doctest targets contain zero cases. The graph contains
72 external crate identities and nine first-party libraries.

The contracts family uses the shared format dependency profile, extended with
the pinned `humantime` source. All previous archive pins and 110 generated crate
declarations remain unchanged. It declares each library, unit and integration
artifact, doctest, license check, and developer target.

```sh
aos-dev bazel update-deps formats
aos-dev bazel --family contracts test //crates/aos/release/aos-release-format:qualification
nix-build tools/bazel/tests/contracts.nix -A all --no-out-link --max-jobs 4 --cores 4
```

`tests/evidence/native-linux-contracts.json` retains passing native execution,
fresh Cargo case and feature parity, developer checks, license closures, and
editor parity. All 225 executable cases and the existing ignored case match;
the four doctest targets remain empty. Editor comparison preserves the single
selected unknown-type location. An integration test's declared sibling fixture
is visible through its compiler-declared package boundary. Explicit generated
source directories remain intact, with two regression tests for source roots.

`tests/evidence/contracts-configured-graph.json` retains 152 distinct configured
reports, 140 source files, all 17 refreshed family inventories, 13 dependency
specifications, and 150 passing policy tests. All 12 other dependency locks are
unchanged. Workspace Rust compilation and broader editor regression checks
run separately. The complete-checkout Nix-inventory case,
foreign and Wasm qualification, performance acceptance, and production migration
remain separate gates.

`tests/evidence/contracts-metadata-evaluation.json` records passing metadata
parity for 307 compiled first-party targets and core Nix evaluation checks at
the frozen contracts checkpoint. The initial broader editor regression stopped
at a CLI runtime dependency: its host-profile test observed a fingerprint
divergence before the CLI editor comparison. The failure and unchanged retry
scope are retained in `tests/evidence/contracts-editor-regression-initial-failure.json`;
that initial run is not counted as passing editor qualification.
`tests/evidence/contracts-editor-regression.json` retains the successful retry
of the identical 14 derivations: 13 family comparisons and the editor fixture.
It preserves each comparison's scope and unknown types, including the guest
model's 84 unattributed Cargo diagnostics. The retry does not establish the
cause of the runtime fingerprint divergence.
`tests/evidence/contracts-required-rust-targets.json` records passing workspace
application unit and integration target compilation with hashes matching all
40 contract Rust changes. It predates the later OCI and systemd source changes.

## Native integration library baseline

`tests/evidence/native-foundation-cargo-baselines.json` retains connected Cargo
baselines for `aos-nix`, `aos-transfer`, `aos-oci`, and `aos-systemd-client`.
Default features execute 210 cases and four doctests; disabling transfer executes
111 cases and one doctest. Both retain two existing ignored broker integration
cases, and the default transfer doctests retain one ignored case. The graphs
contain 281 and 181 external crate identities respectively, and eight first-party
libraries. Native inputs are source-built AOS OpenSSL, libssh2, zlib, and Zstandard.
The Rust SSH binding compiles the libssh2 sources bundled in its pinned crate;
the AOS libssh2 package remains a declared runtime input. Its crypto and
compression inputs come from AOS OpenSSL and zlib.

`tests/evidence/native-foundation-initial-cargo-failure.json` retains the initial
OCI test failure. Two assertions expected 18 objects although their shared signed
release fixture contains 20. Those assertions and the existing 20-object assertion
now share a documented fixture count. The object inventory, upload checks, and
failure assertions remain intact. The matching Bazel qualification is retained
in `tests/evidence/native-linux-native-foundation.json`.

The Bazel definitions separate three source-only dependency profiles:
`native-foundation` for production libraries, `native-foundation-tests` for
default test targets, and `native-foundation-minimal` for tests with transfer
disabled. Production keeps D-Bus broker test features and Tokio's `test-util`
feature out of its graph. Serde, Serde Core, and Syn retain separate feature
units for target compilation and compiler plugins. Each unit also selects its
own constant build-script features.

`aos-dev bazel --family native-foundation` selects the default test graph;
`rust-project` selects all four native integration packages for editor coverage.
Explicit `aos-dev bazel update-deps` commands accept each of the three profile
names. These updates resolve source dependencies; ordinary builds use the
checked-in source inventories without running Cargo or downloading tools.

Native C probes read a declared compiler response file for AOS zlib include
and library search paths. A sandboxed probe compiles and links with ambient
search paths cleared and checks the linker trace for the declared AOS library.
This keeps `libz-sys` on the same system-library path as the Cargo baseline,
without relying on ambient include paths. Native pkg-config wrappers expose
only declared metadata directories, including explicitly named dependencies
needed by OpenSSL and libssh2 queries. Both interfaces retain their native
package identities in the imported closure.

The strict native qualification passes default and transfer-disabled case,
doctest, feature, and license comparisons against fresh Cargo builds. Default
Clippy, formatting, documentation, and selected-package editor checks also
pass. The production comparison contains 274 external and eight first-party
crate identities, without D-Bus test features or Tokio `test-util`. Editor
comparison retains the same two selected unknown-type diagnostics and no
unattributed Cargo diagnostics; complete inference is not claimed.

`tests/evidence/native-foundation-configured-graph.json` retains 957 configured
reports and 102 source files across production and both test profiles. All 18
family inventories validate, all 16 dependency specifications pass, and all
164 policy tests and the CLI checks pass. The previous 13 dependency locks,
source pins, and 2,060 generated crate build files are unchanged.
`tests/evidence/native-foundation-metadata-evaluation.json` records metadata
parity for 320 compiled targets and core Nix evaluation at its frozen checkpoint.
The configured external editor identity correction is documented separately
in `tests/evidence/editor-external-configurations.json`.

`tests/evidence/native-foundation-editor-regression.json` records the passing
regression across 13 earlier family editor comparisons and the editor fixture
with configured external crate identities. Whole-model comparisons preserve
inference statistics and diagnostic multiplicities; selected-package comparisons
preserve distinct locations and types while retaining raw diagnostic counts.
The guest comparison retains its 84 unattributed Cargo diagnostics.

`tests/evidence/native-foundation-required-rust-targets.json` records passing
workspace application unit and integration target compilation with hashes
matching all eight native integration Rust changes at its frozen checkpoint.
Dedicated D-Bus integration gates remain required. Foreign and Wasm qualification,
compiler invocation equivalence, performance acceptance, production migration,
and Cargo removal remain pending.

## Core activation providers

`aos-dev bazel --family activation-core` selects the activation controller,
configuration files, kernel tunables, BPF LSM, BPF network policy, Kubernetes,
and nftables packages. Their six installed command names remain independent
of their Cargo package names. The `module_graph_check` example remains part
of the test, developer, editor, and license selections.

Production libraries and commands use `activation-core`; tests and developer
tools use `activation-core-tests`. Explicit dependency updates accept both
names. Production keeps test-only tempfile and TOML dependencies out of the
provider closure. The test profile preserves Cargo's IndexMap features and
the separate Syn versions used by derives, without enabling unrelated serde
or full-syntax features.

The Cargo baseline is retained in
`tests/evidence/activation-core-cargo-baseline.json`: 97 executed cases, no
ignored cases, 13 library and command test artifacts, and 51 external crate
identities across ten first-party packages. Seven doctest targets contain no
cases. Tests that require configured native executables retain their existing
conditional behavior; dedicated provider and assembled-system gates remain
required before production migration.

Provider lint corrections preserve those cases and existing deadline behavior.
Test modules allow panic-on-failure helpers, matching the workspace policy for
tests. Native BPF subprocess deadlines use narrowly scoped allowances for the
host monotonic clock. Production helpers precede test modules, and equivalent
conditional checks use Rust let chains.

`tests/evidence/native-linux-activation-core.json` retains passing qualification
with the checked-in configured source inventory: 68 requested roots, 237
configured reports, and 62 source files. Fresh Cargo comparisons retain all
97 cases, the empty command and doctest targets, and the test dependency graph.
Production matches a separate graph of 37 external and ten first-party crate
identities. Clippy, formatting, documentation, license closures, and selected
editor analysis pass. Both editor models report complete inference and zero
diagnostics for this selection; their aggregate sizes differ and are retained.
Foreign and Wasm execution, compiler invocation equivalence, numeric performance
acceptance, production migration, and Cargo removal remain separate work.

`tests/evidence/activation-core-configured-graph.json` retains the two source
profiles, all 18 dependency specification checks, and validation of all 19
family inventories. The previous 16 dependency locks, source pins, features,
and 2,996 generated crate build files remain unchanged; their metadata records
the new declaration digest. The native family refresh retains all 957 reports
across its production, default, transfer-disabled, and integration selections.
The 164 policy tests and CLI checks pass with all 14 launchers exported.

`tests/evidence/activation-core-metadata-evaluation.json` retains metadata parity
for 347 compiled targets and core Nix evaluation at the core activation
checkpoint. `tests/evidence/metadata-analysis-only.json` compares its original
compilation-backed result with analysis-only inventories: both reports are
byte-identical across all 347 targets. Each of the 20 selections keeps its
original workspace source and requested roots, and executes no external actions.
The metadata oracle now requests only inventory reports and rejects a nonempty
external action log. Runtime, feature, license, developer, and editor qualification
remain independently required by the family checks and aggregate.

## Filesystem and storage activation providers

`aos-dev bazel --family activation-storage` selects `aos-activation-filesystem`,
`aos-activation-nix-store`, and `aos-activation-storage`. Their eleven command
labels retain the filesystem, Nix-store, cryptsetup, format, ZFS, provisioning,
and boot-storage provider names. Libraries, command test artifacts, developer
tools, editor roots, and production license closures are declared explicitly.

Nix-store activation uses tempfile in production, so production and tests share
one `activation-storage` dependency profile. Both match Cargo's 42 external
crate identities and eight first-party packages. Syn 2 retains its derive parser
features independently of the separate Syn 3 instance used by schema derives.

`tests/evidence/activation-storage-cargo-baseline.json` retains the unchanged
Cargo baseline. `tests/evidence/native-linux-activation-storage.json` records
passing qualification with the checked-in source inventory: 77 executed cases,
one existing ignored Nix-store case, 14 library and command test artifacts,
and three empty doctest targets. The ignored case requires `AOS_TEST_NIX_STORE`
pointing to source-built Nix. Dedicated native tool, provider, and assembled-system
gates remain required before production migration.

Clippy, formatting, documentation, license closures, and selected-package editor
comparison pass. Both editor models report zero selected diagnostics and no
unattributed diagnostics. The Bazel model reports complete inference, while the
Cargo model retains incomplete inference and 964 diagnostics outside the selected
packages. Those diagnostics and the differing aggregate statistics are preserved.

`tests/evidence/activation-storage-configured-graph.json` retains 46 requested
roots, 144 configured reports, and 79 source files, together with all 20 validated
family inventories and 19 dependency specification checks. The previous 18 locks,
source pins, features, and 3,113 generated crate build files are unchanged. All
164 policy tests and CLI checks pass with 15 exported launchers.
`tests/evidence/activation-storage-metadata-evaluation.json` records metadata
parity for 375 configured Rust targets and passing core Nix evaluation. Metadata
collection uses 21 analysis-only selections with no external actions.

Foreign and Wasm execution, compiler invocation equivalence, numeric performance
acceptance, production migration, and Cargo removal remain separate qualification.
Required workspace Rust target compilation runs independently against its frozen
source checkpoint.

## Systemd activation commands

`aos-dev bazel --family activation-systemd` selects the native resource provider
and credential encryption commands. The package has two command roots and no
library. Both commands retain default and `systemd-parser-tests` test artifacts,
with explicit developer, editor, documentation, format, and license selections.
Production and both test configurations match Cargo's 103 external crate
identities and eight first-party packages through one pinned dependency profile.

`tests/evidence/native-linux-activation-systemd.json` records 56 default cases
and 58 parser-enabled cases, with no ignored cases. Parser execution uses
AOS-built Systemd, its vendor units, and AOS Bash inside the Nix sandbox. The
Bazel-built libtest artifacts run through the shared case-isolating runner;
they are not Bazel test actions. Their test-only export preserves compiler
runtime references and synthetic store-path fixtures, and the adapter checks
installed bytes against the Bazel export digests before execution.

The configured source inventory retains 12 requested roots, 175 reports, and
79 source files. Three unselected Systemd client test sources remain owned by
its source target so Bazel can parse its package; dependency test execution is
not selected. Clippy, formatting, documentation, license closures, production
features, and editor comparison pass. Both editor models report zero selected
or unattributed diagnostics. Cargo retains incomplete inference and 944
diagnostics outside the selection; Bazel reports complete inference. Their
aggregate statistics and differing root multiplicities remain explicit.

`tests/evidence/activation-systemd-configured-graph.json` records validation of
all 21 family inventories, 20 dependency specifications, 164 policy tests,
and CLI checks with 16 exported launchers. The previous 19 locks, source pins,
features, and 3,183 generated crate build files remain unchanged. Metadata
parity covers 383 Rust targets across 23 analysis-only selections with no
external actions, and core Nix evaluation passes; its frozen outputs are in
`tests/evidence/activation-systemd-metadata-evaluation.json`.

Dedicated service and assembled-system gates, foreign and Wasm execution,
compiler invocation equivalence, numeric performance acceptance, production
migration, and Cargo removal remain required separately.

## Storage/campaign compilation measurements

`tests/evidence/store-performance-v3.json` identifies a frozen compilation trial
with 54 samples: three repetitions of six scenarios in three build modes. The
full report is retained in `tests/evidence/store-performance-v3-raw.json`,
including source identities, commands, action counts, host load, JVM resources,
and untimed validation of 599 cases per sample. Median compilation seconds were:

| Scenario | Cargo incremental | Cargo nonincremental with accache | Bazel server |
| --- | ---: | ---: | ---: |
| Cold | 107.0 | 83.8 | 68.5 |
| Warm | 0.6 | 0.3 | 5.0 |
| Implementation edit | 5.4 | 52.4 | 37.7 |
| Public API edit | 6.7 | 64.2 | 47.6 |
| Second worktree | 0.3 | 0.4 | 8.3 |
| Fresh build directory | 103.8 | 83.4 | 8.9 |

Second-worktree Cargo builds can reuse their existing target directory; fresh
build directories cannot. The first Bazel second-worktree sample took 66.7
seconds, while the other two took about eight seconds. Those samples remain
visible. Shared-host load also varies across the trial.

Four selected artifact profile settings are matched. Complete compiler
invocation, codegen-unit, and incremental equivalence are not established.
Bazel imports the AOS Zstandard archive, while Cargo builds the pinned bundled
Zstandard sources; dependency preparation is outside the measured scope.
These results expose edit and no-op regressions against Cargo incremental.
They do not establish end-to-end performance, numeric acceptance budgets,
production readiness, or permission to remove Cargo.

## Static Crucible activation adapter

`aos-dev bazel --family activation-crucible` selects the optional AOS adapter
library, its tests, and the `aos-ability-crucible` command. The export preserves
the existing Nix package and command names independently of the Rust crate name
`aos-activation-crucible`. Production keeps static linkage and runtime inputs;
the original production builder remains in place during qualification.

The `activation-crucible` dependency profile matches Cargo's 49 external crate
identities and seven first-party packages. `activation-crucible-tests` matches
115 external identities and thirteen first-party packages, adding engine test
support and AOS-built static SQLite/Zstandard. Production declares only the
static compiler runtime. Scoped guest and engine library visibility admits the
adapter without exposing other implementation targets. Protocol dependencies
retain their reviewed permissive licenses; QEMU implementation code and headers
do not enter either compiled closure.

`tests/evidence/native-linux-activation-crucible.json` retains passing strict
qualification: nine executed cases, no ignored cases, two libtest artifacts,
and one empty doctest target. The command test artifact is empty, matching Cargo.
The tests include host verdict and reproduction through generic guest markers.
Clippy, formatting, documentation, license closures, and production feature
comparison pass. The static runtime gate checks the actual sandboxed link and
archive digests, installed ELF format, five startup-error comparisons with Cargo,
and a Nix closure retaining only glibc's optional data reference.

Editor comparison reports zero selected or unattributed diagnostics. The Bazel
model has complete inference for the selected roots; Cargo retains incomplete
inference and 2,806 diagnostics outside the selection. Both models' statistics
and different aggregate sizes remain explicit. The source inventory contains
nine requested roots, 255 configured reports, and 840 declared source files,
including 835 Rust files across the adapter and its dependencies.

`tests/evidence/activation-crucible-configured-graph.json` records all 22 family
inventory validations, 22 dependency specifications, 164 policy tests, and CLI
checks with 17 launchers. The previous 20 locks and 3,324 generated crate build
files remain unchanged. Metadata parity covers 388 Rust targets across 24
analysis-only selections with no external actions, and core Nix evaluation passes.
The frozen checkpoint is in
`tests/evidence/activation-crucible-metadata-evaluation.json`.

The dedicated native `checks.crucible.phase2.abiConformance` gate also passes.
`tests/evidence/activation-crucible-abi-conformance.json` records the frozen
result, generated-header and golden-vector checks, exact-version rejection,
and guest/engine doorbell coverage. Its source filter explicitly includes the
Bazel repository marker and guest Nix qualification contract; the assertions
and ABI versions are unchanged. Required workspace application unit and
integration targets also compile at the frozen Crucible lint checkpoint;
`tests/evidence/activation-crucible-required-rust-targets.json` identifies the
single changed Rust file and its source derivation. Later CLI support changes
are checked independently.

The dedicated native `gate:license-boundary` also passes at its frozen source.
`tests/evidence/activation-crucible-license-boundary.json` records 5,566 passing
workspace tests across 267 binaries, with 75 existing skips, followed by the
dependency, feature, corresponding-source reconstruction, and offline archived
plugin checks. This checkpoint covers the earlier Crucible and CLI changes;
later application changes retain their own qualification.

Dedicated provider and assembled-system gates, foreign and Wasm
execution, compiler invocation equivalence, numeric performance acceptance,
production migration, and Cargo removal remain separate qualification.

## CLI support libraries

`aos-dev bazel --family cli-support` selects `aos-cli-ui`,
`aos-closure-analysis`, and `aos-nix-docs`. Build, test, Clippy, formatting,
documentation, license, and editor targets use the same configured family.
Transfer transport stays disabled, and each library preserves whether it
inherits the Cargo workspace lint configuration. Existing production builders
remain in place during qualification.

The pinned `cli-support` profile contains 165 source crates. Production matches
Cargo's 108 compiled external crate identities and seven first-party packages;
tests match 111 external identities and the same seven first-party packages.
Every shared compiled feature-unit set matches. The three test-only external
identities are `fastrand`, `getrandom` 0.4.2, and `tempfile`. Version-guarded
specializations remove resolver-only features from Serde, Serde Core, and Syn.
Ordinary builds resolve no registries and download no tools or binaries.

`tests/evidence/native-linux-cli-support.json` retains passing strict checks:
61 unit cases, no ignored unit cases, three libtest artifacts, and five
compile-only doctests. The documentation library has no doctest cases, matching
Cargo. Production feature, developer, license, and editor comparisons pass.
Lint corrections preserve progress defaults, byte formatting, documentation
cache freshness, the public scanner API, and existing test assertions.

Editor comparison retains one identical unknown-type diagnostic in the closure
scanner in both models, two Cargo diagnostics outside the selection, and no
unattributed diagnostics. Neither inference model is complete: Bazel reports
one unknown expression and Cargo reports three. Their aggregate statistics and
diagnostic multiplicities are not claimed equivalent. The configured inventory
contains 24 requested roots, 187 reports, and 64 declared source files, including
61 Rust files.

`tests/evidence/cli-support-configured-graph.json` records validation of all 23
family inventories and dependency specifications, 164 policy tests, the source
catalog, and CLI checks with 18 launchers. The previous 22 dependency locks and
3,521 generated crate build files remain unchanged. The frozen metadata report
covers 395 Rust targets across 25 analysis-only selections with no external
actions; core evaluation passes. Its evidence is retained in
`tests/evidence/cli-support-metadata-evaluation.json`.

`tests/evidence/cli-support-required-rust-targets.json` retains the passing
required workspace unit and integration target compilation for all nine CLI
support Rust changes. Its source is frozen before the build-service conversion;
that later work requires its own qualification.

Installed consumers, dedicated provider and assembled-system gates, foreign and
Wasm execution, complete compiler invocation equivalence, numeric performance
acceptance, production migration, and Cargo removal remain separate work.

## Build-service APIs, client and server

`aos-dev bazel --family build-services` selects `aos-build-api`,
`aos-build-client`, and `aos-build-server`, with `aos-core`, `aos-nar`, and
`aos-nix` as first-party dependencies. The pinned profile contains 263 source
crates. Test and production compilation both match Cargo's 197 external
dependency identities and six first-party packages. Twelve guarded feature
policies preserve the compiled units, including ten distinct target and
execution-platform feature sets.

The API target compiles the existing `build.rs` as an ordinary Rust binary and
runs it directly through the pinned build-script runner. Its inputs declare all
four protobuf schemas, AOS-built `protoc`, protobuf headers, and the compiler's
immutable Nix closure identity. These Bazel actions use no Cargo executable or
first-party Cargo manifests. The generated-source check requires exactly 17
files and compares their content digests against fresh Cargo and the recorded
pre-conversion production baseline.

`tests/evidence/native-linux-build-services.json` retains passing strict source
selection, unit/integration and doctest parity, production features, generated
API sources, Clippy, formatting, documentation, license closure, and editor
checks. All 20 unit/integration cases match Cargo across five libtest artifacts.
The API and client library libtests remain empty. All 24 upstream-generated
doctests remain ignored with matching names and locations; the client and
server have no doctest cases.

The editor comparison retains the same two unknown-type diagnostics at token
generation expressions in both models, with no unattributed diagnostics and
two unselected Cargo diagnostics. Inference remains incomplete in both models;
aggregate statistics and diagnostic multiplicities are not claimed equivalent.
The configured inventory contains 28 requested roots, 308 reports, and 57 source
files, including 49 Rust files and all four schemas.

`tests/evidence/build-services-configured-graph.json` records all 24 configured
family inventories and dependency specifications, 166 policy tests, the source
catalog, and CLI checks with 19 launchers. The previous 23 dependency locks and
3,686 generated crate BUILD files remain unchanged. Metadata parity covers 404
Rust targets across 26 analysis-only selections, with no external actions; core
evaluation passes. Its frozen evidence is retained in
`tests/evidence/build-services-metadata-evaluation.json`.

`tests/evidence/build-services-required-rust-targets.json` retains passing
required workspace unit and integration target compilation for the twelve
build-server Rust corrections. This source is frozen before the deployment
conversion, whose Rust changes require their own compilation checkpoint.

Dedicated service and assembled-system qualification, foreign/Wasm execution,
complete compiler invocation equivalence, numeric performance acceptance,
production migration, and Cargo removal remain separate work.

## Authenticated deployment

`aos-dev bazel --family deployment` selects `aos-deployment`, with eleven
first-party dependency libraries. The pinned profile contains 101 source crates.
Production and tests both match Cargo's 72 compiled external identities and
12 first-party packages, including every compiled feature-unit set. A guarded
IndexMap policy removes its resolver-only Serde feature.

`tests/evidence/native-linux-deployment.json` retains passing strict source
selection, unit and doctest parity, production features, Clippy, formatting,
documentation, license, and editor checks. All 35 unit cases match Cargo with
no ignored libtest cases; the library has no doctests. Five evaluator cases run
in separate subprocesses with private local-root Nix stores, preserving their
original assertions. The selected-store regression executes with source-built
AOS Nix. The immutable-document case returns when its external fixture is
absent; this checkpoint does not qualify that fixture.

The test action ran uncached in the Linux sandbox with declared AOS Nix inputs
and a retained immutable closure identity. Its Bazel source contains no
first-party Cargo manifests, and the action log contains no Cargo executable
calls. The configured inventory contains ten requested roots, 135 reports, and
183 source files, including 180 Rust files. Two inventory-only roots retain
source inputs required to load a dependency's BUILD declaration.

The editor comparison reports no selected or unattributed diagnostics and
retains 952 unselected Cargo diagnostics. Bazel has complete inference for the
selected roots; Cargo's aggregate inference remains incomplete. Their aggregate
statistics and diagnostic multiplicities are not claimed equivalent.

`tests/evidence/deployment-configured-graph.json` records all 25 configured
family inventories and dependency specifications, 167 policy tests, the source
catalog, and CLI checks with 20 launchers. The previous 24 dependency locks and
3,949 generated crate BUILD files remain unchanged. Metadata parity covers 406
Rust targets across 27 analysis-only selections, with no external actions; core
evaluation passes. Its frozen evidence is retained in
`tests/evidence/deployment-metadata-evaluation.json`.

`tests/evidence/deployment-required-rust-targets.json` retains passing required
workspace unit and integration target compilation for all five deployment Rust
changes, including isolated evaluator fixtures and scoped lint corrections.
Its source is frozen before the later Hub UI annotation.

Dedicated provider and assembled-system gates, external deployment fixtures,
foreign/Wasm execution,
complete compiler invocation equivalence, numeric performance acceptance,
production migration, and Cargo removal remain separate qualification.

## Portable Hub API and shared UI

`aos-dev bazel --family hub-portable` selects `aos-hub-api` and `aos-hub-ui`.
The pinned profile contains 67 source crates. Production and tests both match
Cargo's 44 compiled external identities and two first-party packages, with every
compiled feature-unit set preserved. Four guarded feature policies remove
resolver-only features from IndexMap and Serde and retain Prost's distinct
library and generator units.

The API target compiles and runs the existing Rust generator directly with the
canonical Hub protobuf, AOS-built `protoc`, protobuf headers, and immutable tool
closure identity. The generated-source check requires exactly four outputs:
message types, ProtoJSON codecs, the binary descriptor, and Connect paths. Their
content digests match fresh Cargo and the pre-conversion production baseline.
No first-party Cargo manifests or Cargo executable participate in these Bazel
actions. Generated-source snapshots admit binary descriptor outputs alongside
Rust sources while retaining exact inventory and path validation.

`tests/evidence/native-linux-hub-portable.json` retains passing precise source
selection, unit/integration and doctest parity, production features, generated
API output, Clippy, formatting, documentation, license closure, and editor
checks. All 52 cases match Cargo across three libtest artifacts, with no ignored
cases. Both libraries have empty doctest inventories. API integration cases read
the checked API and capability manifests and the actual console Rust sources.
UI cases compile the actual stylesheet and route source text as declared data;
their assertion-only `expect()` exception is scoped to the test module.

The configured inventory contains 19 requested roots, 114 reports, and 67
declared source files, including 59 Rust files. Browser and service source used
as test text does not introduce dependencies on their compiled applications.
The editor comparison has no selected, unselected, or unattributed diagnostics.
Both inference reports remain explicit; aggregate statistics and diagnostic
multiplicities are not claimed equivalent.

`tests/evidence/hub-portable-configured-graph.json` records all 26 configured
family inventories and dependency specifications, 168 policy tests, the source
catalog, and CLI checks for 21 launchers. The previous 25 dependency locks and
4,050 generated crate BUILD files remain unchanged. The shared declaration
formatting is a separate commit with identical Starlark syntax trees. Metadata
parity covers 412 Rust targets across 28 analysis-only selections, with no
external actions; core evaluation passes. Its frozen evidence is retained in
`tests/evidence/hub-portable-metadata-evaluation.json`.

`tests/evidence/hub-portable-required-rust-targets.json` retains passing required
workspace Rust compilation for the Hub UI test-only lint annotation. The frozen
source predates the Hub model changes. Installed Hub services, foreign/Wasm
execution, complete compiler invocation equivalence, numeric performance
acceptance, production migration, and Cargo removal remain separate work.

## Hub model family

`aos-dev bazel --family hub-model` selects `aos-hub-model`, with its native
library, unit tests, retained-control integration target, doctests, Clippy,
formatting, documentation, license checks, and editor graph. Production uses
an independently pinned 124-source dependency profile; tests use 167 sources.
Their compiled external feature inventories contain 116 and 142 packages,
respectively, with four production and five test first-party packages. The API
generator belongs to the test dependency graph. Six guarded test-profile
policies preserve Cargo's target/execution feature separation.

`tests/evidence/native-linux-hub-model.json` retains passing strict source
selection, runtime and feature parity against the independent unchanged Cargo
baselines: 172 executed cases, no ignored cases, and four passing doctests.
The merged inventory contains 11 requested roots, 351 configured reports, and
91 declared files, including 82 Rust files. Existing credential entropy,
AES-GCM nonce generation, authentication timestamps, and membership-only route
validation retain their behavior through scoped lint exceptions. Mechanical
lint fixes preserve the scanner's parsing and contract assertions; moving the
ETag helper before its test module is a separate commit.

The retained-control hard-cut case recursively scans the complete production
source universe. Its original scanner deliberately ignores symlinks, so ordinary
Bazel runfiles would omit source files. A source-built Nix package inventories
all 4,856 regular production files, and a declared Python action verifies their
sizes and hashes before copying them into a regular-file tree inside the Linux
sandbox. The actual integration case traverses that tree without skipping its
audit. Independent checks verify every selected path and byte against the
checkout and every declared copy-action input against the immutable manifest.
Path enumeration also works in read-only Nix evaluation before the filtered
source enters the store.

The external audit tree deliberately includes production Cargo manifests as
text inspected by the scanner. They do not drive Bazel compilation: the strict
compilation source contains no first-party Cargo manifests, and the recorded
Bazel actions invoke no Cargo executable. Source-built protoc generates the
test dependency's API through its declared generator graph. No host service or
remote cache is introduced.

Editor parity retains ten matching unknown type expressions in the selected
model package, no unattributed diagnostics, and seven unselected Cargo
diagnostics. Both inference reports remain incomplete; aggregate inference
statistics and diagnostic multiplicities are not claimed equivalent.

`tests/evidence/hub-model-configured-graph.json` records 27 configured family
inventories, all 28 dependency specifications, 175 policy tests, and CLI checks
for 22 launchers. All previous 26 dependency locks and 4,117 generated crate
BUILD files remain unchanged. Metadata parity covers 415 Rust targets across
29 analysis-only selections with no external actions, and core evaluation
passes; the frozen outputs are retained in
`tests/evidence/hub-model-metadata-evaluation.json`.

`tests/evidence/hub-model-required-rust-targets.json` retains passing required
workspace unit and integration target compilation for all thirteen Hub model
Rust changes, including the separate ETag helper move. Its frozen source
predates the later Hub client changes. The `test-fixtures` and Wasm variants, installed Hub services, complete compiler invocation equivalence,
numeric performance acceptance, production migration, and Cargo removal remain
separate qualification work.


## Typed Hub client

`aos-dev bazel --family hub-client` selects `aos-hub-client` and its generated
Hub API dependency. The pinned profile contains 192 source crates. Production
and tests match Cargo's 122 compiled external packages and two first-party
packages, with identical compiled feature-unit sets. Eight guarded feature
policies preserve Cargo's target and generator roles, including Bitflags'
empty target feature set and the generator's `std` feature.

`tests/evidence/native-linux-hub-client.json` retains passing strict source
selection, runtime and production feature parity against the unchanged Cargo
baselines, Clippy, formatting, documentation, license closure, and editor checks.
All ten unit cases execute with no ignored cases; the doctest inventory is
empty. The cases cover typed requests, headers, errors, references, and URL
syntax. Test-only `unwrap()` exceptions are scoped to the two fixture modules.
They do not qualify live Hub authentication or network operations.

The strict inventory contains ten requested roots, 189 configured reports, and
ten declared files, including five Rust files. The API generator runs directly
with source-built protoc; all four generated outputs match fresh Cargo and the
unchanged portable Hub API baseline. The recorded generation and test actions
run uncached in the Linux sandbox, invoke no Cargo executable, and compile from
a workspace without first-party Cargo manifests. Both editor reports have
complete inference and no selected, unselected, or unattributed diagnostics.
Aggregate statistics and diagnostic multiplicities are not claimed equivalent.

`tests/evidence/hub-client-configured-graph.json` records all 28 configured
family inventories, 29 dependency specifications, 176 policy tests, and CLI
checks for 23 launchers. The previous 28 dependency locks and 4,408 generated
crate BUILD files remain unchanged. Metadata parity covers 417 Rust targets
across 30 analysis-only selections, with no external actions; core evaluation
passes. Frozen outputs are retained in
`tests/evidence/hub-client-metadata-evaluation.json`.

`tests/evidence/hub-client-required-rust-targets.json` retains passing required
workspace unit and integration target compilation for both test-only client
lint annotations. Its frozen source predates the release preparation changes.
Live Hub services,
foreign/Wasm execution, complete compiler invocation equivalence, numeric
performance acceptance, production migration, and Cargo removal remain
separate qualification work.
