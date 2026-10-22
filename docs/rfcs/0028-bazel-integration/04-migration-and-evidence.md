# Migration, qualification, and performance evidence

## Rollout order

The rollout is Rust-first, with native code exercising the same infrastructure.
It does not wait for the new evaluator or a distributed execution service.

### 1. Inventory and baseline

Export the current crate/target inventory, resolved features by build family,
generated inputs, native libraries, supported platforms, runtime dependencies,
tests, package outputs, and Cargo-dependent repository tools. Record how each
existing `mkAosCargoPackage`, artifact consumer, and qualification check maps
to a proposed Bazel target. Include standalone first-party Cargo workspaces.

Measure the current Cargo/Nix/accache configurations before changing them:
cache-empty builds, warm builds, implementation edits, public-interface edits,
feature changes, worktree changes, and fresh Nix derivation executions. Record
which compiler and package caches are enabled. Existing Cargo artifact reuse
is a baseline capability, not free performance to discard without measurement.

### 2. Common infrastructure and local cache proof

Add the root module, pinned rules, AOS toolchain repositories, shared Nix
functions, offline dependency preparation, and launcher. Use a small Rust
library/application pair and a C++ library/application pair as fixtures.

Before migrating production consumers, prove shared disk action-cache reuse
across separate Nix derivations with private output bases, including the
invalidation tests below. Establish source inventory generation and package
manifest validation. A fast repeat build in one Bazel server is insufficient.

### 3. Rust pilot and native consumer

Migrate a small reusable Rust crate and a real binary that uses it. Include
procedural macros and an integration test; add generated code/native linking
in the next pilot so the common interface is exercised beyond pure Rust.
Keep a temporary Cargo oracle only for unmigrated consumers and comparison.
Use explicit ownership of each target during coexistence; do not change both
build definitions independently.

Add `native/nix-eval/` through the same toolchain, package, test, benchmark, and
cache functions. The evaluator's limited language support and runtime design
have separate acceptance criteria. This RFC does not require an implementation
before Rust migration can proceed.

### 4. Migrate compatible Rust families

Move AOS applications, Hub native and Worker variants, Crucible host and test
variants, guest code, and GPL-side components in separately reviewed steps.
The order follows actual dependency closure and platform readiness. For each
family, switch development commands, package builders, generators, tests,
formatting/lint/documentation, and editor metadata together once parity passes.

Keep a rollback commit/selector during the validation window. Tests involving
package identities or authenticated artifacts must compare the intended new
outputs and behavior; a changed builder can legitimately change a Nix store
path. Do not promise byte-identical Cargo and Bazel binaries. Require semantic,
ABI, runtime-closure, feature, and qualification parity, and repeatability
within the same Bazel configuration.

### 5. Remove first-party Cargo configuration

Remove `crates/Cargo.toml`, `crates/Cargo.lock`, member manifests, and first-party
Cargo build configuration after all their consumers migrate. Move retained
metadata into Bazel package declarations and generated inventories. Replace
Cargo-dependent source slicing, crate inventories, documentation generation,
feature-policy tests, lint configuration, build scripts, and CLI selectors.

Retire first-party `mkAosCargoPackage`/Cargo-artifact use and the shared Cargo
target/incremental options for migrated targets. Keep generic upstream Cargo
builders for source bootstrap and third-party packages. Update contributor
instructions, `AGENTS.md`, the development shell, and command help when the
new workflow is actually implemented, not in this design-only PR.

The completion check rejects a Cargo invocation in first-party build/test
execution logs or a first-party dependency on a Cargo workspace manifest.
Dependency-update tooling and unmodified third-party sources are explicitly
outside that check. Accache's standalone workspace migrates after its bootstrap
ordering is proven; it is not omitted from the final first-party inventory.

## Required acceptance checks

The following are proposed checks, not existing passing targets. Implementation
PRs map them to `checks` and Bazel labels and retain their evidence.

| Check | Required evidence |
| --- | --- |
| Offline bootstrap | Start from AOS toolchains and pinned sources with empty user caches; deny network during repository setup and compilation; reject host compiler/library fallback |
| Toolchain separation | Build an execution-platform generator/procedural macro and a foreign-target artifact; verify actual executables, target libraries, flags, and test execution policy |
| Source inventory | Dependency/BUILD changes invalidate or reject a stale inventory; new implementation files are included; unrelated docs, worktrees, run state, and outputs do not enter package sources |
| Package outputs | Install only current declared outputs; reject invalid destinations and missing artifacts; verify loader/rpath, runtime closure, debug outputs, and corresponding source |
| Rust parity | Compare features, generated API outputs, native ABI, unit/integration/doctest inventories, lint settings, and package behavior against the pre-migration inventory |
| Test runner | Preserve exact filtering, process isolation, timeouts, exclusive groups, failures, ignored tests, and zero-match rejection; retain external-resource checks |
| Cross-derivation cache reuse | Different Nix derivations and fresh output bases restore unchanged Rust and C++ actions from the shared local cache; no producer execution tree is available |
| Cache invalidation | Change source/header, generated input, dependency, compiler closure, linker/sysroot, feature, target, CPU setting, environment, or PGO input; require misses for affected actions and correct outputs |
| Concurrent cache use | Independent builds and worktrees share disk results safely; interruption, eviction, or missing/corrupt blobs cannot publish or restore partial artifacts |
| Uncached parity | Fresh uncached execution and cache restoration produce matching declared artifacts for the deterministic fixtures; record all cache layers and normalizations |
| License domains | Prohibited host/plugin edge fails analysis; existing ABI/license and publication gates pass for migrated consumers |
| Cargo removal | No first-party manifests/build-driver calls remain; editor, documentation, metadata, and test workflows work from Bazel targets |

### The decisive local cache experiment

1. Prepare two immutable source snapshots with the same library and dependency
   graph and a changed application implementation. Their Nix source paths and
   derivation/output identities must differ.
2. Build the first snapshot with an empty dedicated disk action cache and a
   fresh private output base. Record action digests, executed compiler actions,
   output digests, timing, and memory.
3. Build the second snapshot in a separate Nix execution with another empty
   output base, mounting only the same disk action cache. Do not substitute a
   previously completed Nix output or restore the producer's build directory.
4. Assert unchanged library/dependency compile actions hit the cache and execute
   zero compiler processes; the changed application actions miss. Verify the
   new program result and package output manifest.
5. Rebuild the second snapshot without that cache in a fresh execution. Compare
   declared fixture artifacts and behavior against the cached build.
6. Repeat for Rust, C++, a declared generated input, and compatible worktrees.
   Then vary semantic inputs to prove misses, including an execution-tool
   closure change with the same logical compiler label.

Use execution events and action digests as the hit oracle. Cached compiler
stdout may be replayed, so log text alone cannot distinguish execution from
restoration. Register the fixture early as a regression check for changes to
toolchains, source filtering, module versions, launchers, and cache policy.

## Performance evaluation

Benchmark build-system performance and runtime performance separately. For
builds, record dependency preparation, Nix evaluation, Bazel analysis/startup,
compilation, linking, restoration, tests, and installation. Capture wall/CPU
time, peak RSS, bytes read/written, executed compiler actions, cache hit rates
by mnemonic, and restored bytes. Include a small leaf crate, a large crate, a
cross-language binary, and a representative Crucible build/test family.

Compare cold compilation, a warm no-op, a private implementation edit, a shared
API edit, a feature/target change, a second worktree, and a new Nix derivation.
Run the current Cargo incremental and nonincremental/accache configurations as
separate baselines. Report Bazel JVM/server memory and startup rather than
charging only the compiler. Local action caching must show reduced compiler
execution and useful end-to-end improvement in the cross-derivation case.

Record versions, exact flags, platform/CPU, available memory, concurrency,
cache state, and repeated-run distributions. Set numeric regression budgets
from the recorded baseline before a family's cutover. Publish any accepted
tradeoff explicitly; do not invent a speedup target without measurements or
hide an edit-loop regression behind a clean-build average.

For the evaluator and other hardware-sensitive programs, compile first and
time only fresh program executions. Pin CPU placement, record NUMA/cache
topology, and control contention. Measure cycles, allocation, peak RSS,
branch/cache/TLB events where available, and workload sizes spanning cache
capacities. Unavailable hardware counters are reported as unavailable, not
zero. Compare portable and named CPU builds separately, and never reuse a
cached timing result as a new measurement. Correctness and sanitizer builds
remain separate from optimized benchmark configurations.

## Alternatives and tradeoffs

- **Keep Cargo permanently behind Bazel:** easy initial integration, but keeps
  two orchestration layers and obscures action-level dependency/cache behavior.
  It does not meet the Cargo-removal objective.
- **Keep Cargo manifests as permanent first-party metadata:** useful during
  migration, but retains a second description of features, targets, and tests.
  The final state uses Bazel plus generated external dependency locks.
- **Replace Nix with Bazel:** loses the existing bootstrap, package, system,
  closure, and release model. This proposal assigns compilation to Bazel while
  preserving those responsibilities in Nix.
- **Port every upstream package to Bazel:** unnecessary for the first-party
  graph and a much larger maintenance obligation. Existing upstream builders
  continue to produce declared AOS dependencies.
- **Share an output base or Cargo target directory across builds:** conflates
  mutable execution state with reusable action results. Private execution
  trees plus a shared content-addressed cache are the selected design.
- **Enable accache beneath every Bazel compile:** duplicates discovery and
  cache overhead by default. Reuse its contracts and diagnostics first; any
  double-cache configuration needs its own evidence.

## Future distributed execution

The intended later RBE design uses the Nix derivation sandbox as the Bazel
action execution sandbox, with [Terrane from PR #420](https://github.com/andyl-technologies/aos/pull/420)
providing mounts and synchronization of declared inputs, toolchain closures,
and outputs. Keep action/environment/platform identities explicit now so that
backend can consume them. Worker scheduling, transport, sandbox lifecycle,
Terrane mount contracts, and distributed result publication belong to a
follow-up design. They do not gate local caching or the Rust/native migration.

## References

- [Bazel platforms](https://bazel.build/concepts/platforms) defines execution
  and target roles used by the toolchain mapping.
- [Bazel C++ toolchain configuration](https://bazel.build/tutorials/ccp-toolchain-config)
  documents explicit toolchain registration.
- [rules_rust rules](https://bazelbuild.github.io/rules_rust/rust.html) and
  [Cargo compatibility rules](https://bazelbuild.github.io/rules_rust/cargo.html)
  provide the Rust compilation, test, and build-script interfaces.
- [Crate Universe](https://bazelbuild.github.io/rules_rust/crate_universe_bzlmod.html)
  documents direct package specifications and generated external repositories.
- [Bazel caching](https://bazel.build/remote/caching) distinguishes action
  results, CAS contents, and execution; [remote execution](https://bazel.build/remote/rbe)
  is a separate extension.
- [accache storage](../../../tools/accache/README.md) and its
  [backend](../../../tools/accache/src/backend.rs) document the existing local
  Bazel-format cache and compiler identity/invalidation contracts.
- [RFC-0015](../0015-hermetic-cargo-artifacts.md) is the existing artifact and
  test contract to preserve or explicitly replace during migration.

Upstream documentation describes capabilities, not the selected version's
proven behavior. Pin and qualify exact Bazel/rules versions during the first
implementation stage; this RFC reports no measured Bazel migration speedup.
