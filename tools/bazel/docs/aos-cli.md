# CLI conversion checkpoints

The CLI has separate Bazel configurations for ordinary tests, fleet fixture
features, and the shipped fifteen-program suite. Cargo remains the production
builder while qualification continues.

`tools/bazel/tests/aos-cli.nix` exposes `default`, `fleet`, and `production`.
The test configurations provide `compile`, `tests`, `cargo`, `developer-build`,
`format`, `test-parity`, `execution-profiles`, `oracle`, and `inventory`;
production provides `build`, `installed`, `runtime-smoke`,
`developer-build`, and `inventory`. These are explicit conversion checkpoints,
not yet production selectors or ordinary `aos-dev` family routes.

For example, from the repository root:

```sh
nix-build --expr '(import ./tools/bazel/tests/aos-cli.nix {}).default.tests' \
  --no-out-link --max-jobs 4 --cores 4
nix-build --expr '(import ./tools/bazel/tests/aos-cli.nix {}).fleet.tests' \
  --no-out-link --max-jobs 4 --cores 4
nix-build --expr '(import ./tools/bazel/tests/aos-cli.nix {}).production.runtime-smoke' \
  --no-out-link --max-jobs 4 --cores 4
```

The test configurations retain all 23 integration targets, the library unit
target, and their selected binary test harnesses. The fleet configuration also
retains the three optional fixture binary harnesses. Binary paths are declared
Bazel runfiles and become absolute before a test changes a child process's
working directory. Cargo's already absolute binary paths retain their behavior.

Repository-aware tests receive an audited, declared source tree. The imported
files use a suffix until materialization so nested BUILD files cannot silently
truncate a Bazel filegroup. The materializer verifies file hashes, lengths, and
executable permissions before restoring their original paths. Architecture guards consume the declared all-profile Bazel production graph
and fail if it is missing or a dependency walk reaches an unmodeled package.
The independent Cargo comparison temporarily retains its manifest oracle. Other
repository-aware integration tests still use a conservative source snapshot;
strict source qualification and Cargo removal remain separate work.

The explicit dependency updater accepts `aos-cli-tests`, `aos-cli-fleet-tests`,
and `aos-cli-production`. Their feature policies in `third_party/rust/aos-cli.bzl`
retain distinct target and execution units. Use a `name@version` policy key when
different versions of one dependency need separate policies; its version must
match the policy's `version` field. Duplicate identities fail before rewriting
the graph. Ordinary builds consume the checked-in sources and BUILD rules
without running the resolver.

Profile lifecycle and cache installation tests use real immutable AOS packages,
native deployment envelopes, private Nix databases, and signed registry
releases. Cache installation uses distinct producer and consumer stores, signed
NARs, and a pinned Nix cache key with signature enforcement enabled. Expected
download counts come from the real closure graph. The helper's envelope and
catalog entry are authenticated along with the explicitly installed tool.
The cache tests also retain their raw store-path publication checks; a later
native publication supplies the evaluator-owned metadata required for admission.
No fixture fabricates a successful Nix validity result or deployment receipt.

`default.cargo` and `fleet.cargo` run the temporary offline comparison with the
same native libraries and fixture inputs. The Cargo environment explicitly
selects the multithreaded AOS zstd archive before the ordinary zstd tool's
pkg-config directory. `default.oracle` and `fleet.oracle` run the complete comparison. A successful
compilation alone is insufficient: compare
the retained results with `tools/bazel/tests/verify_cli.py`, passing the Bazel
test output's `evidence/tests` directory, its `inventory.json`, and the Cargo
output directory. The verifier requires exact feature units, test targets,
executed case names, and empty doctest inventories. Failed or ignored Cargo
cases and Bazel case output containing skip diagnostics fail the comparison.

Each test configuration's `oracle` also requires its `execution-profiles` gate.
The gate pairs every first-party source and libtest role with captured native
compiler requests, including generator roles from Cargo's artifact records.
It compares every configured and executed procedural macro with the native
package, version, crate name, edition, and explicit cfg unit. Distinct versions
of one macro package remain separate units. Every Rust compiler action must
execute successfully in a Linux sandbox without an action-cache hit.

Target units require size optimization, zero debug information, debug-information
stripping, and enabled assertions and overflow checks. Generators and procedural macros require zero
optimization with the same debug and checking settings. The evidence preserves
absent native options and checks their profile defaults rather than inventing
explicit flags. Remaining compiler-option differences stay visible; full
compiler defaults, native C/C++ and linker settings, ABI/runtime behavior,
editor/release/foreign profiles, cache behavior, and performance require their
own qualification. `test-parity` exposes the case comparison separately;
`oracle` retains `parity.json`, `execution-profiles.json`, `strip-semantics.json`,
`profile-semantics.json`, `native-compiler-execution.json`, and
`native-toolchain-closure.json`.

The ordinary and fleet profile gates also require complete external unit
inventories, matched by package, version, crate name, Rust library kind,
feature set, and artifact-derived native target/execution role. They compare
explicit cfgs, editions, optimization, debug information, assertions, overflow
checks, and stripping. Duplicate or unmatched units fail the gate. Four exact
pinned rules_rust helper labels are retained separately as execution tools;
they implement Bazel's build system and have no Cargo application-unit
counterpart. Native requests that additionally emit C-facing crate types keep
those types visible; this comparison does not qualify those extra artifacts.

The [strip/profile qualification](../tests/evidence/cli-strip-profiles.json)
retains the complete ordinary/fleet case comparisons and the compiler unit
pairs. Its pre-fix control matches all 552 dependency units but rejects the
old target `strip=none` setting. A mandatory native compiler probe establishes
that implicit stripping matches explicit `none` byte for byte, and that
`strip=debuginfo` removes linked C debug information with Rust debug emission
disabled. All five probe programs retain their behavior and ordinary symbols.
The selected default interpretations also require a native compiler probe:
13 runtime variants exercise omitted flags, boolean aliases, scalar overrides,
and positive and negative assertion/overflow controls. Each variant compiles
through both the wrapped and unwrapped compiler with identical binary bytes.
Five isolated comparisons require identical binaries, including implicit versus
explicit native targets. The gate binds the probed unwrapped compiler's SHA-256
to every Bazel Rust execution's compiler input and rejects foreign targets.
The independent native execution check binds every profiled source request to
observed unwrapped compiler execution and requires that compiler to match the
probe's digest. These fixture comparisons do not qualify
incremental codegen or complete application/linker equivalence.
The [compiler evidence guide](compiler-evidence.md) describes this bounded
conformance check. Complete remaining compiler options, native C/linker and
ABI/runtime/editor/platform/performance qualification remain separate work.

`default.cargo-execution-inspection` and `fleet.cargo-execution-inspection`
inspect source-built `strace` logs from the offline native compilation phase.
Every requested compiler call must reach the declared unwrapped Rust compiler;
the declared GCC and linker must also execute. Tracing stops before the test
phase. A separate snapshot preserves exactly the compiler requests belonging
to compilation; later noncompiling Cargo queries remain visible in the ordinary
profile trace. Source-request fingerprints preserve duplicate requests,
arguments, working directories, and captured Cargo metadata. Changed or
unobserved requests, another compiler, or failed inspection reject the profile
gate. An undecoded `???(` task record cannot satisfy any compiler request.
CLI inspection explicitly retains these records and marks execution capture
incomplete, while the parser's strict mode continues to reject them. The
separate `default.cargo-complete-execution` and `fleet.cargo-complete-execution`
gates reject such captures. Requested-command coverage does not qualify those
gates. The concurrent `compiler-trace-conformance` probe checks this distinction
with 96 compiler queries, eight linked compilations, and strict negative
controls. The
[retained public oracle run](../tests/evidence/cli-observed-native-execution.json)
passes 543 ordinary and 551 fleet cases, with 1,261 and 1,270 uncached Linux
sandbox actions. Both concrete native captures also pass strict parsing; the
earlier incomplete captures remain negative controls, without a tracer repair
claim. Native linker response files and complete native flag parity remain
separate checks.

The [retained native test-profile run](../tests/evidence/cli-native-test-profiles.json)
passes all 543 ordinary and 551 fleet cases. It pairs 79 and 85 first-party
compiler units respectively, plus 28 procedural macros in each configuration.
All 1,269 ordinary and 1,278 fleet actions execute successfully in Linux
sandboxes without cache hits. The four repaired dependency policies preserve
native target/execution feature units without changing production BUILD files
or the source URLs, checksums, and generator identities of any of the 65 SDKs.

That retained run predates the [build-script profile repair](build-script-profiles.md)
and records libm receiving `OPT_LEVEL=0` while its library compiles at `s`.
The new focused qualification checks corrected target/execution metadata and
libm's generated `optimizations_enabled` cfg in four configurations. Complete
external compiler and native C/linker profiles still require broader parity.

The [rerun with corrected build-script metadata](../tests/evidence/cli-native-test-profiles-with-build-metadata.json)
also passes all 543 ordinary and 551 fleet cases and the selected first-party
and procedural-macro profile checks. Its external-unit diagnostic matches cfgs
and editions for all 552 paired dependency units in each configuration. Four
additional Bazel execution libraries remain unmatched. Those four units are retained as the control for the
[optional-dependency comparison](../tests/evidence/cli-optional-dependencies.json).
The new graph pairs all 552 external units in each configuration, including
features, explicit cfg, and edition. Complete external compiler and native
C/linker profiles remain separate qualification work.

Qualification scripts and retained reports are excluded from both the test
workspace's compiler snapshot and the architecture fixture's query snapshot.
Repository-aware tests still receive their separately declared inputs. A
verifier edit changes the required qualification gate without invalidating
compiler or test derivations.
The test configurations default to the checked-in precise source inventory.
Unrelated configured-inventory JSON is excluded from their compiler source
identity. The [source-selection guide](cli-source-selection.md) documents the
qualified default and the conservative regeneration route.

The architecture-consumer checkpoint passes all 543 ordinary and 551 fleet
cases under both Cargo and Bazel, including all six architecture guards.
`../tests/evidence/aos-cli-architecture.json` binds the consumer source and declared
metadata to each actual build and comparison. Each configuration matches 38 first-party
and 439 external crate feature inventories. The required application Rust
unit and integration compile gate, formatting, and both configurations' Clippy
and documentation actions also pass. Bazel used the explicit local disk action cache;
these results do not establish strict uncached qualification.

The test configurations also expose `editor`, `editor-cargo-oracle`, and
`editor-parity`. These compare the configured CLI library, integration tests,
and selected binary harnesses with Cargo's editor model. Both retain the same
connected dependency packages, native libraries, generated inputs, feature
selection, and explicit test profile settings. The retained comparison passes
for all 30 ordinary and 33 fleet roots, with 606 and 657 unique selected
source diagnostics matching Cargo respectively. Both analyzers finish without
panics; neither model achieves complete inference. Full reports retain
unselected Cargo diagnostics and each model's different aggregate statistics
and diagnostic multiplicities. These comparisons qualify the immutable
pre-lint-cleanup sources recorded in
`../tests/evidence/aos-cli-editor-parity.json`.

The exporter preserves separate library and libtest environments when a test
redirects compile-time paths to declared runfiles. Module discovery retains
the actual selected package boundary. The Cargo feature wrapper forwards
application features only to application metadata and check invocations;
standard-library queries retain their own feature selection. The Bazel editor
compiles without a shared action cache; retained execution logs record 1,184
ordinary and 1,187 fleet actions with no action-cache hits. This does not
qualify the entire family without caches: separate dependency derivations may
still use the explicitly mounted local disk cache.

Cargo test checkpoints also retain actual compiler invocations in
`compiler-arguments.jsonl`, with a restricted Cargo environment. The wrapper
preserves arguments, working directory, process output, and exit status.
Compiler-option equivalence remains a separate gate; capturing invocations
alone does not establish it.

CLI test and production workspaces now choose execution Rust flags separately
from target flags. Their generators and procedural macros use optimization 0
and debug information 0; test execution tools enable assertions and overflow
checks, while release execution tools disable both. Target settings stay in
their respective existing profiles. The focused generator check runs with:

```sh
nix-build tools/bazel/tests/aos-cli.nix -A execution-profiles --no-out-link
```

The [enrollment report](../tests/evidence/cli-execution-profile-enrollment.json)
authenticates the actual Build API, Hub API and Hub Service compiler arguments
in both configurations. All six compiler actions and six observed generator
executions use the Linux sandbox without cache hits. Retained Cargo artifact
profiles and the independent minimal Cargo probe establish the baseline scope.
The editor now explicitly forwards its size-optimization and assertion/overflow
flags to execution tools too, matching its Cargo oracle. The
[editor enrollment report](../tests/evidence/cli-editor-execution-profile-enrollment.json)
retains all three configurations: nine compiler actions and nine actual
generator executions pass without cache hits in Linux sandboxes. The independent
rust-analyzer probe records the editor's underlying Cargo behavior. Fleet
execution and editor analysis, ordinary CLI tests, generated-source parity,
and production installation still need qualification after this profile change.

The [default editor comparison](../tests/evidence/cli-editor-profile-parity.json)
passes after enrollment: all 606 distinct diagnostic locations and inferred
types match across 30 CLI roots. All 1,229 logged editor actions
execute in Linux sandboxes without cache hits. The report retains 3,579 raw
Bazel rows, 2,551 selected Cargo rows, and 2,481 unselected Cargo rows; raw
multiplicity and aggregate inference statistics remain incomparable, and both
analyses retain incomplete inference. The helper's 543 passing test cases use
the editor execution profile, so they do not qualify the ordinary test profile.
Fleet analysis remains a separate check.

The production package exports nine CLI programs, five package-manager helpers,
and the image metadata helper. Installation verifies its manifest and bytes,
then uses ordinary AOS fixup with explicit shared-library runtime dependencies.
`runtime-smoke` resolves every executable's ELF imports through the AOS loader
and executes help for the three public CLIs. Service helpers are inspected
without entering their privileged command bodies. Split package outputs,
private dispatch identities, runtime tool wrappers, and their closure policy
still require production qualification.

The opt-in `production-precise` entry point uses the checked-in configured
source inventory. Its [qualification report](../tests/evidence/cli-production-source-inventory.json)
retains passing compilation, installation, all fifteen loader checks, three CLI
help checks, and Clippy. Its 580 configured targets and 761 selected source files
match the conservative build exactly. All selected source bytes match the
checkout; documentation, retained evidence, and first-party Cargo manifests are
absent from the strict snapshot. Both builds have identical reconstructed
arguments and environments for all 547 compiler requests.

Four installed binaries match byte for byte. Eleven differ only in `.rodata`
strings containing the numeric Bazel sandbox directory used by native library
builds; their executable code sections match. Replacing those paths was used
only to diagnose the difference. The installed artifacts remain unchanged,
and that configuration's raw-byte repeatability remains unqualified.

The opt-in native source-path adapter resolves those embedded directory names.
The [full CLI repeatability check](../tests/evidence/cli-native-source-repeatability.json)
passes for all fifteen raw programs and their normally installed bytes across
two fresh Nix builds. All 2,150 retained actions run in Linux sandboxes without
cache hits; all 547 Rust compiler requests match between executions. No artifact
normalization is used. Both installations retain exactly the earlier strict
Bazel package's six runtime dependency paths, loader results, and CLI help
results. The verifier's eight synthetic control cases pass within the 320-test
policy suite; they test rejection behavior rather than compiler parity.

The [mapped-toolchain Clippy check](../tests/evidence/cli-native-source-clippy.json)
also passes all fifteen CLI targets, retaining 1,075 uncached Linux-sandbox
actions over the same 761 selected source files.

Run the reusable comparison with:

```sh
nix-build tools/bazel/tests/native-source-paths.nix -A cli-repeatability --no-out-link
```

The ordinary production helper keeps its original toolchain and conservative
source selection. Native ABI, complete package behavior, performance acceptance,
and production enrollment remain separate gates.

`../tests/evidence/aos-cli-source-graph.json` records the 57 frozen SDK exports
and 41 configured source inventory families. The previous 54 SDKs preserve all
13,060 existing lock and generated files. Runtime evidence is separate from
this metadata validation.

The default, fleet, and production Clippy checks pass after the repairs recorded
in `../tests/evidence/aos-cli-lint-repair.json`. Native CLI clock and entropy use
is explicitly scoped outside Crucible replay policy. The report also binds the
540/548 Cargo and Bazel cases, format checks, production executable smoke tests,
and required application Rust compilation to the repaired source bytes. The
earlier failing developer report remains as baseline evidence.

Full compiler argument parity, strict uncached qualification, live service and
VM checks, performance acceptance, and production migration remain separate work.

The [configured-inventory refresh](../tests/evidence/cli-feature-inventory-refresh.json)
retains 84 registered analysis outputs covering all 45 existing families,
including the boot configuration without boot tools. It checks every prior
source, target, label, and feature/platform unit before publication. The only
replaced units are the ordinary and fleet `rand` profiles dropping the unused
`small_rng` feature, qualified by the retained native CLI comparisons. The three
newly split package roles retain their prior canonical label coverage. All 65
SDKs preserve their source declarations and resolver identities; only the four
reviewed CLI package BUILD files change in each test SDK. These inventory
checks do not establish compilation or runtime parity for every family.
The refresh also passes the full native evaluation aggregate, the 339-test Bazel
policy suite, and the registered source-selection check.

Reviewed feature policies can also set `prune_optional_dependencies` to remove
normal library dependencies disabled by that exact feature unit. The updater
reads Cargo feature activation from the source manifest after authenticating
its archive against both locks. It supports renamed optional dependencies,
explicit `dep:` activation, dependency feature activation, and weak dependency
features. Required platform dependencies and build-script dependency edges
remain intact. The ordinary and fleet SDKs opt in; production policies retain
their existing graphs. Both updater source files are installed and checked
against the checkout before any dependency resolution. The retained comparison passes all 543 ordinary and
551 fleet cases, their selected first-party/procedural-macro profiles, and the
complete 552-unit external cfg/edition inventories. Native roles come from
compiler artifact dependency edges. All 1,261 ordinary and 1,270 fleet actions
execute in Linux sandboxes without cache hits. The 85 refreshed analysis
outputs preserve all prior source and feature units across the 45 families;
registered evaluation, policy, source-selection, and architecture checks pass.
Complete compiler defaults, native C/linker settings, ABI/runtime/editor/foreign
parity, caches, and numeric performance still require their own qualification.
