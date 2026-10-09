# Crate migration validation

This record accompanies [the workspace design](crate-workspace.md),
[active inventory](crate-inventory.md), and [unmerged-PR inventory](unmerged-crates.md).
Starting master is `2ee6311aea39bef7aef6ba4b566f9f502649f3f2`. The tracking change
is [PR #715](https://github.com/andyl-technologies/aos/pull/715).

Validation uses the repository's AOS-built Rust toolchain and native tools.
Production builds use `aos-dev --release`; development checks use an explicitly
selected, user-owned cache directory. An inherited cache became root-owned and
was correctly refused by the existing ownership guard. Its permissions and
guard were not changed.

## Compatibility and ownership

Locked, offline Cargo metadata confirms 77 unique scoped packages. Every leaf
directory matches its package name, and each default library name matches the
corresponding underscore spelling. Compared with starting master:

- All 57 Cargo executable names are retained. Four relocated boot executables
  now require the default-enabled `boot-tools` feature; this feature difference
  is intentional and is recorded separately from executable-name compatibility.
- All 638 external lockfile entries retain their versions, sources, checksums,
  and dependency lists. Changes to local dependency edges are intentional.
- All five canonical protobuf sources are byte-identical.
- All 126 distinct domain-constant name/value pairs and 43 inline canonical
  identity domain literals checked by the lexical audit are unchanged.
- The frozen Crucible control vectors retain their established bytes and digest.

Architecture checks cover portable format dependencies, deployment independence
from package installation, registry-reader independence from terminal code,
authoring independence from package installation, Hub persistence independence
from its API, and the permissive QEMU process boundary. Real implementations
belong to the extracted libraries; application-backed forwarding facades are
not used as extraction boundaries.

## Rust verification

The complete native workspace test run finished 465 target summaries, with
10,755 passed tests, 14 failures, and 78 ignored tests. This is an initial
complete-source run, not a claim that every final target passes. Isolated reruns
resolved six failures: two CLI diagnostic expectations, Hub database contention,
registry staging contention, migrated engine ABI package assertions, and the
native source-size check. The size fix extracts a coherent marker helper and
retains the original size limits.

The remaining eight failures from that run reproduce on the immutable starting
master checkout: five CLI lifecycle/cache assertions, two OCI inventory counts
(20 versus 18), and the qualification `production_only` marker assertion. Their
production behavior and assertions were not weakened to obtain a green result.

Completed verification also includes:

- Native workspace compilation of all unit and integration targets.
- Workspace doctests: 29 passed and 27 ignored across 73 target summaries.
- Nine portable libraries compiled for `wasm32-unknown-unknown`; the refined
  registry-format and transfer reporting APIs also compile without default
  features on that target.
- Actual Hub Worker and console distribution builds; native Hub compilation
  with PostgreSQL and MySQL features; 272 isolated database tests passed.
- Artifact/module/documentation tests, shared-library tests, boot and release
  tests, and the complete 279-test Crucible test-support suite passed in their
  owned scopes. Overlapping feature runs are not added into a combined total.
- Seven affected CLI integration targets passed 42 tests without capability
  skips, using AOS-built Git and SSH. Test processes isolate ambient Git
  configuration because a personal global transaction hook rejects temporary
  fixture repositories; repository hooks and real commit configuration remain
  in effect.
- The final registry reader/writer rerun passed 653 tests, with four explicitly
  ignored fixtures and no silent capability skips. Uncaptured, serial execution
  exercised real SHA-256 Git repositories and the dumb-HTTP socket clone.
- Standalone default-feature daemon unit tests passed 1,106 tests, with 22
  existing native fixture tests ignored. Its fixture dependencies are explicitly
  development-only; successful workspace feature unification is not used as
  proof that an isolated crate works.
- The exact 18-crate Crucible production Clippy scope passed with
  `-D warnings`, including all targets and the existing test-double feature.
  The neutral transfer API passed its isolated strict Clippy check.
- Frozen control ABI, license boundary, architecture, source-contract,
  engineering-hygiene, and RFC consistency checks passed in their owned scopes.

Strict Clippy over the entire legacy AOS code is not green. Isolated comparisons
with starting master reproduce existing transfer, package, and presentation
lint debt. New clock reads and declaration-order failures introduced during the
extractions were corrected; blanket lint allowances were not added.

## Repository-wide builds and checks

All aggregate build, check, formatting, and CI commands were attempted locally.
Their failures are retained rather than replaced by narrower success claims.

The committed production AOS and Hub builds pass, as does the mandatory Nix
application-target compilation check:

| Target | Realized output |
|---|---|
| Production `aos` | `/nix/store/1ln1r8l1kf4nr6fid6hdxqps8mbgkssf-aos-0.1.0` |
| Production `aos-hub` | `/nix/store/l72fd75943mk7yqz4qyizvxizaa9i39x-aos-hub-0.1.0` |
| `checks.rust.aos-test-targets` | `/nix/store/ghq8vja56n40bhci9iagz49jv7fnixm1-aos-test-targets-0.1.0` |

These builds use committed checkpoint `0deee4eb88`, preceding only four Rust
import-order changes in their selected application sources.

Fourteen independently failing Nix check-group evaluations reproduce the same
errors on exact starting master. These include the absent
`aos-ability-contract-validator`, missing image-builder inputs, private store
path expectations, and existing module-option errors. No validator stub or
weaker evaluation check was introduced.

The first aggregate formatting run found 448 files; 413 were byte-identical to
starting master. Migration-modified Rust and Nix files were formatted. Unrelated
baseline formatting debt remains outside this change.

Every one of 529 independent Crucible check children was evaluated. Eight
rename/source-layout evaluation regressions were repaired. The remaining 66
initial evaluation failures also fail on exact starting master. Independently
evaluable children are being built locally; identical derivation aliases may
share one actual build result.

The broad build attempt also encountered unrelated package failures. The mdbook
production derivation is identical to starting master and retains two upstream
preprocessor test failures. Virglrenderer again passed seven tests and timed out
in one; its input derivation differs from starting master, so the timeout is not
claimed to be a proven baseline failure.

The native lifecycle gate passes in both current and starting-master production
builds: all seven checks succeed, all seven children are reaped, and no survivors
remain. An earlier development-settings run failed its parent-death check; the
cause is unproven. Native coverage and architecture-specific runtime failures
are tracked separately. Absence of `/dev/kvm` is not treated as an explanation
for every native failure.

Isolated native Cargo recipes exposed missing SQLite build and runtime
dependencies through the existing native content-addressed store. Corrections
in 200 affected recipes declare the AOS-built SQLite package explicitly and
retain test semantics,
feature selection, and timeouts. An attempted starting-master taxonomy build
stops earlier at a vendor fixed-output hash mismatch, so it does not prove the
linker failure is a baseline runtime failure.

The production build checkpoint is `033823ad53`. Later edits complete native
test-recipe dependency declarations and documentation; production Rust code and
production package recipes are unchanged. Native unit and integration test
results are associated with their source checkpoints; four final Rust
import-order corrections changed no executable statements.

## Reproduction and evidence

Use the repository's documented [Cargo shell](../../AGENTS.md) and `aos-dev`
entry point. Set `AOS_DEV_ROOT` to the checkout being tested when running from
an isolated worktree. Native doctests receive the Cargo shell's native target
rpath flags through `RUSTDOCFLAGS` inside that shell; do not export these flags
globally into WebAssembly checks or leak OpenSSL through `LD_LIBRARY_PATH`.

The local evidence bundle contains command lines, source checkpoints, output
paths, complete logs, a machine-readable validation status, and the final
compatibility audit. Unmerged-PR handoffs include the 242-symbol control export
ownership map. The PR remains a draft while unresolved repository-wide and
native qualification failures are documented.

Final packaged build paths and the independent-child completion summary will
be recorded after the current local runs finish. Passing results from earlier
source checkpoints are identified separately from final-source reruns.
