# Crate migration validation

This record accompanies [the workspace design](crate-workspace.md),
[active inventory](crate-inventory.md), and [unmerged-PR inventory](unmerged-crates.md).
Starting master is `2ee6311aea39bef7aef6ba4b566f9f502649f3f2`; the tracking change
is [PR #715](https://github.com/andyl-technologies/aos/pull/715).

Completed local validation and remaining checks are recorded below.
It does not establish a green repository-wide result. All builds use AOS-built
compilers and native tools. Production builds use `aos-dev --release`;
development checks select a user-owned cache. An inherited root-owned cache was
correctly refused by the existing ownership guard; neither its permissions nor
the guard was changed.

## Compatibility and ownership

Locked, offline Cargo metadata confirms 77 uniquely named scoped packages. Each
leaf directory matches its package name, and each default library name uses the
corresponding underscore spelling. Against starting master:

- All 57 Cargo executable names are retained. Four relocated boot executables
  require the default-enabled `boot-tools` feature; that intentional feature
  difference is recorded separately from executable-name compatibility.
- All 638 external lockfile entries retain their versions, sources, checksums,
  and dependency lists. Local dependency edges change with crate ownership.
- All five canonical protobuf sources are byte-identical.
- All 126 distinct domain-constant name/value pairs and 43 inline canonical
  identity domain literals covered by the lexical audit are unchanged.
- Frozen Crucible control vectors retain their bytes and digest. The installed
  scenario helper emits the unchanged 15,873-byte fixture.

Architecture checks cover portable formats, deployment independence from package
installation, registry-reader independence from terminal code, authoring
independence from package installation, Hub persistence independence from
service/native execution, and the permissive QEMU process boundary. The
extracted libraries contain
their implementations. Registry authoring intentionally retains native APR
parser and presentation adapters; signing and local staging APIs accept domain
inputs without a printer.

## Rust verification

The initial complete native workspace run finished 465 target summaries:
10,755 passed, 14 failed, and 78 ignored. These counts describe that invocation,
rather than a sum of subsequent overlapping suites. Isolated reruns resolved
six failures: two CLI diagnostic expectations, Hub database contention,
registry staging contention, migrated engine ABI package assertions, and the
native source-size check. The latter extracts a coherent marker helper and
retains the original size limits.

The remaining eight failures reproduce on immutable starting master: five CLI
lifecycle/cache assertions, two OCI inventory counts (20 versus 18), and the
qualification `production_only` marker assertion. Assertions and production
behavior were not weakened to obtain a passing result.

Completed verification includes:

- Native compilation of every workspace unit and integration target, plus the
  mandatory Nix application-target compilation check.
- Workspace doctests: 29 passed, 27 ignored across 73 target summaries.
- Nine portable libraries compiled for `wasm32-unknown-unknown`. Refined
  registry-format and transfer reporting APIs also compile on that target with
  default features disabled.
- Actual Hub Worker and console distribution builds, native PostgreSQL/MySQL
  feature compilation, and all 952 Hub model/database/service unit and
  integration tests. Separate doctests pass 11 examples, with one existing
  ignore. Their native rpaths are supplied through the AOS Cargo shell.
- The final registry reader/writer rerun: 653 tests passed, with four existing
  explicit ignores (two performance fixtures, one pinned stock-Git matrix, and
  one selected-output source-built evidence fixture). Uncaptured serial runs
  exercise real SHA-256 Git repositories and dumb-HTTP socket cloning without
  silent capability skips. Package-manager tests pass 612 tests with seven
  existing ignores.
- Seven affected CLI integration targets pass all 42 tests using AOS-built Git
  and SSH. Test processes isolate ambient Git configuration because a personal
  global transaction hook rejects temporary fixture repositories. Real
  repository hooks and commit configuration remain in effect.
- Default-feature daemon tests pass 1,106 tests with 22 existing fixture
  ignores. Fixture dependencies are development-only; workspace feature
  unification is not used as proof that the standalone crate works.
- Artifact/module/documentation, shared-library, boot/release, and all 279
  Crucible test-support tests pass in their owned scopes.
- Exact 18-crate production Crucible Clippy passes with `-D warnings`; its
  strict library documentation, doctests, license checks, Rust ABI unit tests, source
  contracts, and engineering/RFC checks pass. The neutral transfer API also
  passes its isolated strict Clippy check.

The optional all-features Crucible CLI run passes 501 tests, ignores 45, and
fails eight instances of four VM cases because `CRUCIBLE_KERNEL` is missing.
The local test-double/recovery suite passes 493 tests with 41 ignores. Those VM
cases require the official disposable-VM harness, including delegated cgroups
and quota mounts; supplying kernel paths alone is insufficient. Their official
gate outcomes are included in the independent-check results below. Earlier
environment failures remain recorded separately from later gate results.

Strict Clippy over legacy AOS code is not green. Isolated comparisons reproduce
existing transfer, package, and presentation lint debt on starting master.
Introduced clock reads and declaration-order failures were corrected without
blanket lint allowances.

## Production builds

| Target | Realized output |
|---|---|
| `aos` | `/nix/store/1ln1r8l1kf4nr6fid6hdxqps8mbgkssf-aos-0.1.0` |
| `aos-hub` | `/nix/store/l72fd75943mk7yqz4qyizvxizaa9i39x-aos-hub-0.1.0` |
| `checks.rust.aos-test-targets` | `/nix/store/ghq8vja56n40bhci9iagz49jv7fnixm1-aos-test-targets-0.1.0` |
| Crucible suite | `/nix/store/gf4n9jfkz3gzmxhhq46b7zn2wp7qzsyx-crucible-0.1.0` |
| Crucible controller | `/nix/store/vvl8g04l91kj7wqkv37pssqlskhbk1x8-crucible-controller-0.1.0` |
| Crucible release-manifest guard | `/nix/store/fm556phxpysrl1mn49949yphdrxvkp3x-crucible-phase7-release-manifest-0` |

AOS, Hub, and application-target builds use committed checkpoint `0deee4eb88`.
The four subsequent import-order corrections change no executable statements in
their selected application sources. The final complete production Crucible graph uses frozen checkpoint
`f917962d700fb71686dfbfce11af386b1da7ab6a` and immutable source
`anbyzabcl6j59497ky95zrdjhb8448g7-crucible-workspace-src`. This includes the
launcher runtime, generated SQLite dependencies, scaling owners, and maintenance
fixture closure corrections. Later fixture selector changes at `ea1b827cac`
are exercised by separate official gates pinned to this source and its realized
products. Subsequent documentation commits are recorded separately.

The final Crucible build passes all 5,566 retained controller tests across 267
binaries, with 75 existing skips. Guest tests pass 33 with one skip, debugger
tests pass 36, plugin tests pass 581, and license checks pass 18. Both packaged
helpers build and install. Its actual 71-path closure co-retains matching QEMU
binary `zdsnl7ib0j7am6f3mg2a7jk4fwsda4wr-qemu-crucible-11.1.1` and corresponding
source `ckzz1hcir4jfillagn518j2nwd8jahay-qemu-crucible-source-11.1.1`.
The installed launcher is executed directly without shell fallback; both
installed wrappers retain an executable AOS-built Bash interpreter. The
installed scenario artifact is byte-identical to the stored fixture.

Earlier production attempts remain in the evidence: one failed a strict source
inventory because two existing files were absent from the source filter; another
passed all controller tests but failed installation through an incorrect
scenario-example package selector. The filter now retains the exact files and
ancestors, and the selector names their actual daemon owner. The final full
release run verifies both corrections without weakening assertions.

## Independent checks and system outputs

All aggregate build, check, formatting, and CI commands were attempted. Fourteen
independently failing top-level Nix check-group evaluations reproduce the same
errors on starting master, including the absent `aos-ability-contract-validator`,
missing image-builder inputs, private store expectations, and module-option
errors. No validator stub or weaker evaluation check was introduced.

Every one of 529 independent Crucible children was evaluated at `49b750e463`.
There are 466 distinct evaluable derivations and 63 evaluation
failures, all of which also fail on exact starting master. Renamed source paths,
package selectors, and an obsolete duration-field guard were repaired; the guard
now checks the existing `ticks` field rather than `nanos`.

The original exact-restore source guard counted relocated trait and fixture
definitions as production daemon implementations. Correction `d9bb847994`
retains all global/per-file and atomic-route counts, and positively asserts
the fixture `cfg` boundaries. Negative mutation probes reject both an ungated
fixture implementation and an additional production launcher. Its actual
production rerun passes at output
`/nix/store/gpvgyc9nkczymhvbf1z6pkvlrc3rczcc-crucible-phase2-qemu-exact-restore-reachability-0`.
The earlier failed instance remains recorded in the pinned batch.

The pinned 529-child inventory is terminal: 300 roots realized successfully,
33 roots failed in their own builders, 133 roots were blocked by demonstrated
failed prerequisites, and 63 failed evaluation. Every one of the 466 distinct
evaluable derivations was accounted for: 21 previously valid exact identities,
402 main-batch requests, and 43 supplemental requests. No root is classified
from an unfinished job or a predicted dependency failure. This is the original
checkpoint's inventory; corrected official reruns and eight additional native
mode fixtures are reported separately below. Shared failed prerequisites are
not counted as additional passing or failing inventory roots.

All 62 listed image/container/system roots were attempted:

| Root group | Passed | Failed |
|---|---:|---:|
| Images | 4 | 40 |
| Containers | 9 | 0 |
| System toplevel/unsigned roots | 9 | 0 |

Passing images are raw edge, server, server-2, and server-test. The image failures
partition into eight experimental undefined/null-image evaluations, twelve
immutable UKI duplicate-copy failures, sixteen existing chrony/module
evaluations, and four ZFS rule-conflict failures (one direct root and three
dependent conversions). Experimental and chrony evaluations reproduce on
starting master. The original UKI wrapper and normalized inputs are identical;
an exact AOS-coreutils replay reproduces its second copy into a mode-444 file.
The full original image build was not run because it requires 95 missing
derivations. The original ZFS plan selects the exact same two immutable ZFS
outputs as the current plan: the default test-pool dependency and an external
kernel override. They install conflicting `60-zvol.rules` paths. Executing the
unchanged original merge fragment with those actual original-planned inputs
reproduces the strict collision failure. This proves the composition defect
predates migration; the full original ZFS image build was not run.

The original boot-install renderer and original normalized input reproduce the
same invalid `ExecStart` argument. This is a renderer replay, not a successful
baseline VM build. The package-preset VM times out before its assertions; its
serial output contains VMM messages without demonstrated guest startup. Source
identity and the exact original successful vendor staging were verified, but
the original full VM requires 113 missing derivations and was not run. This
failure is unresolved; it is not attributed to missing KVM or a vendor mismatch.

The QEMU atomic-patch guard fails in an actual starting-master build of the exact
same derivation. Its raw patch matches the signed bundle's Git diff; generating
a mail-formatted patch adds a 5,326-byte prefix, which the existing guard counts
as a mismatch. QEMU sources and the guard remain unchanged.

Native lifecycle passes all seven checks in both current and starting-master
production builds, with seven children reaped and no survivors. An earlier
development-settings parent-death failure remains unproven. Native coverage,
architecture-specific runtime, and other package failures retain their own
classification. Absence of `/dev/kvm` is not a general explanation for them.
The mdbook production derivation is identical to starting master and retains
two upstream preprocessor failures. Virglrenderer passes seven tests and times
out in one; its changed input derivation prevents a proven-baseline claim.

The S13 round-robin quantum check stops at an existing `grep` without a filename,
which reads empty builder stdin. Exact source-identical command replay fails
after preceding prerequisite marker checks pass. This is a causal replay;
the whole original S13 derivation was not built.

The hot-fork readiness gate rejects the initial QMP child-process contract:
the unchanged QEMU patch reports schema version 3, while the unchanged test
expects version 2. An isolated current production rerun reproduces the failure.
The actual original-master native gate also fails with schema version 3 and
matching values for the other ten contract fields. The original QEMU artifact
differs from the current one; both actual responses reproduce the mismatch.

Four campaign midpoint/finding VM gates reach authenticated repository creation
and fail the unchanged fixture's schema mismatch: lineage declares scenario
schema 3 while the encoder emits schema 5. A native probe through the production
repository API reproduces `lineage-execution-model-artifact-mismatch`; changing
only that value in the diagnostic probe succeeds. The fixture, encoder, and
integrity check are unchanged from starting master. The original full VM was not
run because 19 prerequisites require builds. No schema or integrity assertion
was relaxed.

The installed native Crucible suite wrapper originally referenced the builder's
scrubbed Bash path. Direct execution failed before reaching the controller.
The original recipe has the same dependency omission. Bash is now retained as
an explicit suite runtime dependency, as it already was for cross builds.
The actual corrected suite
`02c791a3ck99zdc40xql4zyvxrj68hwz-crucible-0.1.0` executes `--help` directly
through the kernel, without a shell fallback. Both installed wrapper interpreters
are executable and retained. Its full controller rerun passes all 5,566 tests
with 75 existing skips. The actual 71-path closure co-retains the matching QEMU
binary and source `4d7bbvnn1d3qkrcm9ax6gvkaih1zv48x-qemu-crucible-source-11.1.1`.
This invocation captured `0bcc3027e0` plus the then-uncommitted SQLite fixture
patch, whose stored bytes match the subsequent `a0632083fc` commit. Its result
and selected-input hashes remain separate from the final clean source checkpoint.

A later native license-boundary guard still expected cross-only Bash and
rejected the intentional launcher dependency repair. Its recipe expectation now
requires Bash unconditionally while retaining every matching QEMU/source and
native dependency. The full official corrected guard passes against immutable
`f917962d70` source and products, at output
`l3fpqnbjysy49301w76fh2n3xlbnxw53-crucible-phase1-license-boundary-0`.
All 18 license tests and packaging/source/reconstruction checks pass. Exact
scanner mutation probes reject omission of either Bash or the matching QEMU
source. The earlier frozen guard failure remains in its original invocation.

The maintenance VM exported a configured typed-choice initrd that its rootfs
closure omitted. Its original source has the same omission. The minimal repair
retains that exact configured initrd without substituting the materially
different network-choice guest or changing the campaign's assertions.
The corrected official maintenance flight passes setup and the former missing
artifact failure, then reaches its unchanged 900-second timeout without a final
Rust diagnostic. Its precise runtime cause remains unresolved. Its requested
evidence wrapper is blocked by this failed prerequisite; the closure repair is
not reported as a passing VM gate.

The migrated scaling recipe now selects actual daemon/QEMU-host library test
artifacts. The daemon's isolated child forwards its successful uncaptured
measurement output so the native gate can check the original markers. Both
selected tests and strict all-target/all-feature Clippy pass. The host test
measures 1,320 KiB of private growth under the unchanged 65,536 KiB bound.
The corrected official raw scaling VM executes both exact clone tests and
validates their original markers. Its later production full-world acceptance
fails at 76.42 seconds when the plugin rejects block event source 0 against
reserved source 30 and QEMU aborts. The independently failing atomic-world
prerequisite reports the same error. Original/current relevant plugin code and
test behavior match after namespace substitution; no original complete VM
execution is claimed. The four requested overlay roots finish with one direct
root-builder failure and three demonstrated dependency blocks. The native clone
proof remains passing, while its full-world qualification is failed.

Isolated native recipes exposed missing SQLite build/runtime dependencies.
201 native recipe files now explicitly declare AOS-built SQLite. A generated
inner workflow fixture adds a further builder declaration, for 202 native
builder declarations; feature selection, test semantics, and timeouts remain
unchanged. Representative isolated native tests
and the standalone CLI discovery recipe pass. That standalone five-test proof
does not imply its official prerequisite aggregate passes. Final independent
results identify prerequisite blocks separately from own-builder failures.

The storage-recovery VM waits for Garage without bringing its loopback
interface up. A bounded diagnostic VM using the exact failed rootfs, Garage
binary, and configuration reports loopback down and `Network is unreachable`
from the original status command. Enabling only the interface makes that same
command report a healthy node. The original runner and harness have the same
omission and select the same Garage output. This is diagnostic causal evidence,
not a passing official gate; the fixture is unchanged in this migration.

The loaded-plugin native gate executes its comparator and finds an actual
reference/hostile timer divergence. The hot-fork atomic-world gate reaches four
quantums before the GPL plugin aborts on a block-source mismatch: the host
publishes world source 0 while the plugin requires reserved source 30. That
producer/consumer contradiction is present in the original source; the original
full VM was not run. These failures
are not attributed to missing KVM. Original/current source comparisons alone
do not establish their runtime baseline status.

Late fixture correction `ea1b827cac` changes only 18 selector fields across ten
Nix files: one dynamic Cargo package selector, fourteen crate-directory leaves,
and three library target names. All 23 installed-artifact records match unique
Cargo metadata targets and the consumer's exact manifest suffix/name/kind
checks. Installed destinations, commands, counts and assertions are retained.
The corrected Rust scopes have no source-contract references to these Nix fields.
Their corrective fixtures bind immutable `f917962d70` Rust source and products,
rather than creating another production build for changed test-Nix hashes.
The corrected official store-composition gate passes, including its official
store-equivalence prerequisite, at output
`ahswqwlibnrzzyms9dl87xk9l2bz3167-crucible-phase5-campaign-store-composition-0`.
Its command executions report 113 passes and 18 existing ignores, including the
complete 70-case harness with 52 passes and 18 ignores. Repeated selected
executions are not counted as unique tests. Eight additional native mode
fixtures are still running. The full SQLite workflow and
CLI selftest reruns are also still running; their preceding standalone software
proofs are not substituted for official prerequisite or VM results.

The unchanged million-admission stress test is running separately against its
captured source and corrected installed suite. It retains its original
1,000,000-admission workload and 604,800-second timeout. An early recorded
snapshot shows 18,464 completed admissions; this is progress, not a passing result.
Commands, captured inputs, and progress snapshots remain in local evidence.
The final report and scratch bundle will be updated after the remaining runs.

Additional terminal failures expose inherited native fixture mismatches. The
block-shmem gate creates `qemu/aio.h` and copies a nonexistent `block/aio.h`;
its exact derivation is unchanged from starting master. Original-fragment
replays also reproduce the missing preemption header, omitted `VIRTIO_ID_NET`
fixture definition, and obsolete shared-memory `icount` fields against the
unchanged public `tick` header. All replays use AOS-built tools and original
inputs. QEMU's unchanged patch registers `test-crucible-vcpu-service-time`, but
the unchanged reviewed inventory omits it; actual current configuration rejects
the extra test. This is inventory/source evidence, not a full original QEMU
configure or VM execution.

The workspace-build source guard retains an expected guest-host protocol version
of 1 while the original numeric authority is 3. Replaying the exact guard against
installed artifacts passes preceding migrated ownership/path/license checks and
fails that assertion. The fingerprint-offload verifier rejects a CRLF serial
marker with exact `grep`; diagnostic-only line-ending normalization passes.
Both verifiers are byte-identical to starting master. The original plugin-unsafe
scanner, run against the immutable original Rust tree, rejects the same
`network_custody.rs` test boundary missing from its allowlist. The scanner
is unchanged except for the migrated crate path prefix; its policy is retained.
Three requested Rust test
selectors are already absent from original Rust sources: app-random draw-cap,
correlated-failure fixture, and plugin-vCPU introspection. Their original Nix
requests exist, but no original definitions do. These findings establish
inherited fixture/selector defects, without claiming an original complete Cargo
or VM execution. Guards, headers, and assertions remain unchanged.

The AArch64 fingerprint gate stops and records at 25,000,000 observed
instructions, then selects 26,000,000 in its final assertion. That contradictory
selector is identical in starting master and directly rejects the captured
complete records. The hardware-fault fixture initializes raw instruction fields
but leaves tick targets at zero; the actual installed header defines result 7
as `PAST_BOUNDARY`, matching the unchanged dispatcher rejection. The node-hang
fixture has a related zero-tick setup and aborts after its event is absent;
complete event provenance remains unresolved. No tick target or selector was
changed in this migration.

The round-robin device flight fails its completed-pause and `WAKE_PENDING`
proofs. Single-guest materialization reaches its checkpoint-promotion watchdog.
The Envoy finding flight stays Running with boot progress until its timeout;
it is distinct from the earlier Envoy child-admission `BrokenPipe`. Packaged
Choice and Lifecycle fail because held physical RUNs remain unsettled when
queued network work is released. Diskless readiness, native coverage and KASLR
failures retain unresolved deeper causes. Relevant original source comparisons
are recorded, but do not establish original complete runtime outcomes.

The initial aggregate formatting check found 448 files, 413 byte-identical to
starting master. Migration-modified Rust and Nix files pass formatting checks;
unrelated baseline formatting debt is retained.

## Reproduction and evidence

Use the documented [Cargo shell](../../AGENTS.md) and `aos-dev`. Set
`AOS_DEV_ROOT` to the checkout under test. Native doctests receive Cargo-shell
target rpath flags through `RUSTDOCFLAGS` inside that shell; do not export them
globally into WebAssembly checks or leak OpenSSL through `LD_LIBRARY_PATH`.

The planned local bundle under `~/scratch/aos-crate-monorepo-pr-715/` will contain complete
logs, exact commands, metadata, source checkpoints, outcome classifications,
and compatibility audits. Its manifest will hash every copied artifact and record
the final branch head. The prepared nine owning-PR handoffs include the pinned inspection
snapshot and 242-symbol Crucible ownership map. They distinguish committed
code, dirty local observations, and future extractions; other owners' checkouts
were not modified. Dispatch has five implemented crates. A separate discovery at
`2026-10-10 00:10:22 UTC` found no new owning PRs. The already anticipated
assessment HTTP adapter is now committed on #713 at `2c6c78b601`; its late
source inspection is recorded separately from the original pins and dirty
working-tree observation. No owning-branch build/test claim is made.

Overlapping suites and repeated derivation confirmations are not added together.
The PR remains a draft with repository-wide and native qualification failures
documented; no merge was performed.
