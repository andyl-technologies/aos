# CLI conversion checkpoints

The CLI has separate Bazel configurations for ordinary tests, fleet fixture
features, and the shipped fifteen-program suite. Cargo remains the production
builder while qualification continues.

`tools/bazel/tests/aos-cli.nix` exposes `default`, `fleet`, and `production`.
The test configurations provide `compile`, `tests`, `cargo`, `developer-build`,
`format`, `oracle`, and `inventory`; production provides `build`, `installed`, `runtime-smoke`,
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
execution, full CLI tests, generated-source and editor parity, and production
installation still need qualification after this execution-profile change.

The production package exports nine CLI programs, five package-manager helpers,
and the image metadata helper. Installation verifies its manifest and bytes,
then uses ordinary AOS fixup with explicit shared-library runtime dependencies.
`runtime-smoke` resolves every executable's ELF imports through the AOS loader
and executes help for the three public CLIs. Service helpers are inspected
without entering their privileged command bodies. Split package outputs,
private dispatch identities, runtime tool wrappers, and their closure policy
still require production qualification.

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
