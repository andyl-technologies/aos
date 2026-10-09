# RFC-0025 implementation reference

This audit records the P0 reference for T-CN-01. It supplements
[current-state.md](current-state.md), whose source revision predates the master
refresh. Source inspection and derivation evaluation do not constitute native
qualification. T-CN-01 remains open until its live witnesses and representative
device, fault, restore, and campaign regressions have passed.

## Frozen source and artifact identities

The implementation parent is `0ab383efbd` (merge of `origin/master` at
`19d517148e`). These labels are fixed commits, not moving branch names.
The reference is labeled `parent+vendor-hash-fix`: an immutable parent archive
with only the central vendor hash and its two expected-hash mirrors corrected.
No runtime source, guest, or lockfile is changed. These production derivations
identify that recovered reference:

| Artifact | Derivation basename in `/nix/store` |
| --- | --- |
| Linux readiness check | `n9kp4y4vkwq4ax23j0db84g9crgv5vd2-crucible-tcg-linux-boot-performance-determinism-0.drv` |
| QEMU | `zxsvjjl3ibs4n50jxy71kw8h84pzy1s7-qemu-crucible-11.1.1.drv` |
| Plugin | `valw9yv1aarj8xjf2dc0daq1ym5lk085-crucible-qemu-plugin-0.1.0.drv` |
| Public-protocol driver | `w9r5rabi42j3yhx91dchpk834w6b1qxq-crucible-tcg-production-performance-driver-0.drv` |
| Stock kernel | `s1a5q9l4mdhg0gb39qw64wlywhjgd0qn-linux-crucible-7.2.3.drv` |
| Readiness initramfs | `yrmqvbv6dflf2c6jpi9afi5rq0f1zz1n-crucible-live-plugin-quantum-idle-initramfs-0.drv` |

The plugin and driver share source
`/nix/store/q2jcl30brk9900392rqaiz21m5qaxkyn-crucible-workspace-src`.
The plugin's frozen build script binds these public compatibility values:

```text
CRUCIBLE_QEMU_BUILD_ID=711da31bce44a1ba43912d26dab8fe9b646a08596b3d05a04fdf8d2093fb0409
CRUCIBLE_QEMU_ATOMIC_PATCH_HASH=3492f9060ed975d4a99531dbcb20db7d65d92b233752a14daa920cae0b8d8e30
CRUCIBLE_SHMEM_HEADER_HASH=1dc465a755a9d9e8195a7e3cd22ecadcc1496fff89a2e19bcf7ffb7b9c9b8dcd
```

Recovered final installed executable SHA-256 identities are:

| Executable | SHA-256 |
| --- | --- |
| `qemu-system-x86_64` | `dca9e4b69ebfc07888bdc9455b0aab7a78f378f524b914b1f9b71692dc62975f` |
| `libcrucible_qemu_plugin.so` | `0583c73dcd3e9c16139f345e47b2137328052a8151929442081d4c71f73a8ea5` |
| `crucible-production-performance` | `267f4299a60e3fa91f9190fdf7545e41aafc559af292333199d1d505d57b896e` |

These local artifacts are retained with temporary indirect GC roots named
`/tmp/rfc0025-parent-reference-gcroot-{qemu,plugin,driver}`. They are not release
publication roots.

Build paths are identities, not successful-build claims. The initial
development-worktree preflight required 19 local derivations, including QEMU,
plugin, kernel, and driver. It overlapped early edits: its source already contains
the new `crucible-node-contract` manifest member. Its lockfile matches the parent,
but the source is not the unchanged parent. That preflight
(`bd9jvp4cwcy3zwbcflsjmbb45nkbwyic-crucible-tcg-linux-boot-performance-determinism-0.drv`)
failed before VM execution because the test vendor fixed-output hash disagreed
with its downloaded dependency closure:

```text
derivation: hl461i71q065rd7v0m1mpwxk0piar1h6-crucible-test-vendor-0.1.0-staging.drv
specified: sha256-Rax7Te32Xr+wazk4vF63nEGuFDBKHxAJ+lCXkRo/bxw=
observed:  sha256-A+uv1ImPeDaOOm5TqTLWyQJwJU8cfKhKkdLOAc4+myI=
```

Do not replace this failed attempt with a historical result. Recovery uses an
immutable `git archive 0ab383efbd` tree at
`/tmp/rfc0025-parent-vendor-reference`, changing only the central vendor hash and
its two mirrored expected constants. The measured reference is labeled
`parent+vendor-hash-fix`; no runtime source, guest, or lockfile is changed.
The lockfile SHA-256 is
`55bcbf2a4b9c8746633840eca78bfb66f7f80ac4ca4db0ab35f5e045ebc34042`.
The corrected central hash file SHA-256 is
`2f0affacdee5b64b59873f67b8855239b13397c16cda6e835eef8abed31f9cf5`.
The two corrected mirrors are
`tests/crucible/phase7-crucible-package-inventory.nix` and
`tests/crucible/phase7-crucible-workspace-package.nix`; each differs from its
parent only by that literal hash substitution.

## Compatibility and dependency inventory

[reference-compatibility.tsv](reference-compatibility.tsv) records version,
schema, magic, and domain constant declarations from the parent revision,
including private constants. It excludes test/golden-vector files, long compound
expressions, and dynamically constructed domains. It is a source inventory,
not a proof that every mutable field has a serialization witness.

[reference-dependencies.tsv](reference-dependencies.tsv) records all dependency
declarations in the 19 existing Crucible manifests, including development,
build, optional, feature, and target-conditioned declarations. This is the
declared package graph, not Cargo's resolved feature graph. In particular:

- `crucible-sim` owns the pure lower-layer vocabulary and codecs.
- `crucible-device` depends on sim and shmem rather than the engine.
- `crucible-campaign` and `crucible-cas` remain below runtime orchestration.
- `crucible-qemu -> crucible` is an explicit host-adapter exception in the
  [crate-layer gate](../../../tests/crucible/phase1-crate-layer-graph.nix).
- New lower-layer contract values must not pull `crucible`, QEMU, process
  launch, or host supervision into campaign/device dependencies.

Important reference formats are scenario TOML `crucible.scenario.v9`, properties
`crucible.model.properties.v2`, production exact closure version 9, checkpoint
root envelope version 5, RPC ABI 8.0.0, control protocol 3, shmem ABI 30,
selectable pending transport 2, doorbell frame 3, and instruction doorbell ABI 4.
Renaming Rust source types does not permit changing any of these bytes/domains.

## Authority and continuation custody

| State or operation | Existing authoritative owner and source |
| --- | --- |
| Raw retirement, exact physical stop, native timer and input admission | QEMU/plugin, with typed evidence retained by `crucible-qemu` |
| Node handles and pending native requests | `QemuNodeSet`, `crucible-qemu/src/node_set.rs` |
| Shared time, event order, pending scheduler delivery, quantum/decision state | Engine scheduler and its checkpoint, `crucible/src/scheduler/` |
| Deterministic device queues, local clock, sequence and in-flight completions | `IoCore`, `crucible-device/src/subnode.rs` |
| Host block/9p continuation and independently mapped transport access | `crucible-qemu/src/supervision/host_io_runtime.rs` and device servicers |
| VMState, RAM descriptors, native capture/restore admissions | `crucible-qemu/src/node/exact_snapshot/` and realization adapters |
| Persisted closure, authenticated selected roots, artifact reachability | `crucible/src/exact_checkpoint/` and `crucible-api/src/vm_lifecycle/checkpoint_store/` |
| Campaign frontiers, choices and observations | `crucible-campaign`; realized attempt authority remains in the native lifecycle adapter |

Consumer attachments are not capture-owner IDs. Discovery descriptions and
copied receipts grant no native authority. Facades must route to these owners
without introducing duplicate mutable queues or releasing their custody.

Host threads are not represented by a single scheduler loop. Existing runtime
paths include scoped QEMU dispatch/fingerprint workers in
`node_set/concurrent.rs`, block workers with bounded command/reply queues in
`supervision/device_host_work.rs`, preemption controllers/watchdogs in
`supervision/bounded_scheduler_preemption.rs`, and cgroup/quarantine watchers in
`linux_cgroup.rs` and `linux_attempt_host.rs`. The native QEMU process has its own
thread/fork registry. Ownership changes must preserve capture, cancellation,
join, and child reconstruction responsibilities at both sides of the process
boundary; host diagnostic workers are not additional simulation nodes.

## Reproduce the reference

Run through the AOS dev shell and in-repository development entry point. This
checkout's `tools/dev/aos-dev` is not executable, so invoke it through the
source-built Bash in the dev shell without changing its mode:

```text
bash tools/dev/aos-dev list checks crucible.phase2.
bash tools/dev/aos-dev --release build check crucible.phase2.tcgLinuxBootPerformanceDeterminism --no-out-link --builders ''
```

That second command evaluates the current source. To realize the recovered
reference while the worktree changes, use its immutable derivation instead:

```text
nix-store --realise /nix/store/n9kp4y4vkwq4ax23j0db84g9crgv5vd2-crucible-tcg-linux-boot-performance-determinism-0.drv --builders '' --max-jobs 1 --cores 4
```

An additional local realization of the same QEMU derivation used 16 build cores
to overlap native compilation with the kernel build. Nix locks prevent duplicate
realizations. Build concurrency is not a runtime timing control.

The output is
`/nix/store/43v9z6gndd5i71pmlp07vqlvccb0zvky-crucible-tcg-linux-boot-performance-determinism-0`.
Its `samples.jsonl` and compact `evidence/results.json` retain timings, executable
and guest hashes, host metadata, and exact witnesses. The check removes the two
full 256 MiB RAM captures after verification. Raw temporary diagnostics are not
committed or published as release artifacts.

The authentic runner is
[tcg-linux-boot-performance.py](../../../tests/crucible/tcg-linux-boot-performance.py).
It measures spawn through the native `flight.ready` stop with one vCPU,
`pc-q35-9.2`, `qemu64,-rdrand,-rdseed`, SIM at 50 ps/instruction, RR quantum 4096,
seed `0x0010c004`, coverage/fingerprinting off and whitebox on. Register, full
RAM, serial, raw/logical coordinates, marker, grant, and native timer witnesses
must agree across repetitions. Capture is outside the measured boot interval.
The harness directly launches QEMU; it does not measure production cgroup and
filesystem isolation or the full campaign/lifecycle path.

For a candidate comparison, provide both explicit matched QEMU/plugin label
pairs to this same runner, retain the identical driver and guest artifacts, and
alternate trial order. If a source extraction affects only the daemon/session,
this direct-launch benchmark cannot establish its runtime overhead: add a
representative production campaign/device comparison. Run profiling separately.
The existing ordinary-TCG serial comparison uses 1 ns/instruction and must not
be described as the requested matched 50 ps comparison.
The matched-clock prototype was located locally at
`/tmp/qemu-tcg-speed-source/.worktrees/codex/tcg-50ps-clock`, with bounded helper
controls under `/tmp/tcg-50ps-proof`. The frozen production patch contains none
of `icount_tcg_50ps`, `icount_50ps_clock`, or `time=50ps`, and its executable help
still documents `2^N ns` ordinary icount. Prototype evidence does not qualify
this production artifact; integrating and qualifying that prerequisite remains
separate work.

## Required gates and audit delta

Before marking P1 behavior preserving, run the exact native execution/restore
set and applicable scheduler/campaign gates in
[qualification-plan.md](qualification-plan.md), including these discovered
routes:

```text
crucible.phase1.crateLayerGraph
crucible.phase1.layer0Determinism
crucible.phase1.gates.contentAddress
crucible.phase1.gates.replayOracle
crucible.phase2.qemuExactPreemptionLive
crucible.phase2.qemuExactSnapshotRestore
crucible.phase2.qemuExactRestoreReachability
crucible.phase3.schedulerRunCeiling
crucible.phase3.schedulerLookahead
crucible.phase3.schedulerExactLocalEvent
crucible.phase3.schedulerConservativePdes
crucible.phase3.schedulerEventOrder
crucible.phase3.schedulerConcurrency
crucible.phase3.schedulerIdleFastForward
crucible.phase7.gates.campaignContinuity
rust.aos-test-targets
```

ABI and license-boundary gates also apply to any public process/protocol change.
Some gates include literal source-symbol checks; update those when a source-only
rename occurs, preserving their behavioral fixtures rather than bypassing the
gate. A test double cannot replace native stop, device, fork, or restore evidence.

The separate Virtual RAM proposal's coordinated hard cutover conflicts with
the phased plan's promise of authenticated old checkpoint readers. No RAM
cutover is present in this frozen parent: the exact closure still contains
direct/delta RAM layers. P2 must choose and document the combined version policy
when that proposal lands; it must not promise legacy restore that another
accepted schema intentionally refuses. Implementation bindings cannot be
placed in identity-irrelevant checkpoint labels.

## Measured diagnostic boot reference

While the recovered production kernel compiled, a separately labeled
`parent-vendor-fix-stock-fixture` diagnostic used the recovered parent QEMU,
plugin, and driver with an already built stock AOS Linux 7.2.3 image. Its kernel
is `/nix/store/00vajx9bk9kns8w47cfi4434lfsfdg2h-linux-crucible-7.2.3/boot/vmlinuz-7.2.3`,
SHA-256 `07fbd0d8049d1f4f088c7d1d5fff331d33fd4c0ba64dc8a55f92305086c91d32`.
The readiness initramfs is the same frozen artifact listed above, SHA-256
`8f9ccb428617f5ee3921b2d15874632c016310afe2ae54de575090624dc7b334`.
This image is a separately identified workload, not a claim that the parent's
production kernel derivation had completed.

| Repetition | Launch through authenticated ready stop | Execution after setup |
| --- | --- | --- |
| 0 | 30.335449452 s | 30.292154191 s |
| 1 | 30.392271295 s | 30.351279199 s |
| Mean | 30.3638603735 s | 30.321716695 s |

Both attempts passed with identical complete runner witness tuples: raw and
logical coordinates, idle wake, registers, full declared 256 MiB physical-memory
range, serial, markers, actual grants, paused status, native timer witness, and
projection schema. All seven readiness negative controls rejected. Stable
coordinates were raw retirement `8481484328` and logical/idle tick
`732336187404`. The RAM-range SHA-256 was
`23905153e9ae4e8666b4cd2b43d21139abbfcd08ef4f466df094c03c1fe4a9ea`.
The projection manifest checks schema coverage, not every device's state value.

Runs were unprofiled on AMD EPYC 9755, 512 logical CPUs, Linux 6.18.54, with
QEMU pinned to CPU 96 and the driver to CPU 97. Both recorded governors were
`powersave`; no frequency policy was changed. Other builds were active. These
are ordinary-load observations, not a quiet-host or portable performance claim.
There is no candidate comparison yet. A paired comparison must reuse these
exact guest artifacts or separately qualify and label another workload.

Local evidence and every attempt are retained in
`/tmp/rfc0025-parent-vendor-reference-existing-stock-boot/results.json`.
This compact document records the reference; full RAM images and raw logs are
not committed or placed in release artifacts.

The diagnostic invocation uses only the source-built runner and artifacts:

```text
/nix/store/03xdp3x214a0px6gvhg4dwiq7i0fqkrm-python3-3.14.3/bin/python3 \
  /nix/store/x8nh57gyfjjgrrnjij6h9abm56rwkg5l-tcg-linux-boot-performance.py \
  --driver /nix/store/3cx66dwrpm74q8f5jgpc7aynlwdxrpi0-crucible-tcg-production-performance-driver-0/bin/crucible-production-performance \
  --qemu parent-vendor-fix-stock-fixture=/nix/store/afi45x18y6i6lmddmyhds827arl5wz6k-qemu-crucible-11.1.1/bin/qemu-system-x86_64 \
  --plugin parent-vendor-fix-stock-fixture=/nix/store/r3bq8y1k06qis4mr1gqff5arbb838r17-crucible-qemu-plugin-0.1.0/lib/libcrucible_qemu_plugin.so \
  --kernel /nix/store/00vajx9bk9kns8w47cfi4434lfsfdg2h-linux-crucible-7.2.3/boot/vmlinuz-7.2.3 \
  --initrd /nix/store/k6bshywhac1fvisskdb6ykjid4sza4cz-crucible-live-plugin-quantum-idle-initramfs-0/initrd.img \
  --output /tmp/rfc0025-parent-reference-repeat \
  --cpu 96 --host-cpu 97 --ram-mib 256 --repetitions 2 \
  --baseline-revision 0ab383efbd
```

Choose a fresh evidence output directory for each invocation; do not overwrite
retained attempts. Repeat affinity must be supported by the local allowed CPU
set and recorded if changed.

## Recovered production check result

The frozen `parent+vendor-hash-fix` production check completed with `PASS`.
Both boots had identical complete runner witness tuples and all seven readiness
negative controls rejected. The production kernel SHA-256 is
`1c6880cf64e1c034a7795b6215aafc35b2f2ed60ab698eb3467fb6bf97bd7a1a`; it differs
from the separately identified diagnostic image. Production coordinates were
raw retirement `8481939429` and logical/idle tick `732353188704`, with RAM-range
SHA-256 `e31ed580df6f7dfc9a086c7e6ff45e39929e275d4bb70092012de0605b763774`.

The check selected its sandbox's lowest allowed CPU, 0. Launch-through-ready
samples were 48.580239950 s and 37.323455303 s, mean 42.9518476265 s. The runner
recorded no visible governor for CPU 0. Host-load isolation was not established,
and the large spread is retained. These samples must not be compared directly
with the diagnostic's 30.3639 s mean: guest bytes, affinity, and load differ.
For candidate comparisons, rerun alternating pairs with identical explicitly
selected guest artifacts and affinity.

The complete compact evidence lives in the frozen check's `evidence/results.json`
and `samples.jsonl`; full RAM captures were removed only after verification by
the check. The check and its dependency closure are retained by
`/tmp/rfc0025-parent-reference-gcroot-boot`. The successful build log is
`/tmp/rfc0025-parent-vendor-reference-boot-build.log`; the first failed preflight
log remains retained separately.

## Execution status

- Initial check evaluation: passed, but source provenance audit detected the
  early contract manifest edit; the listed artifacts identify that preflight.
- Source/dependency/schema audit: recorded; mutable-state coverage still needs
  case-by-case live qualification.
- Initial production preflight: failed on the frozen test-vendor hash;
  diagnostic log retained locally at `/tmp/rfc0025-parent-boot-build.log`.
- Corrected parent archive production build and Linux boot: passed, with only
  the vendor hash prerequisite corrected and remote builders disabled; 2/2
  authentic boots and seven negative controls passed as recorded above.
- Recovered QEMU, public-protocol driver, and plugin: built; plugin package
  Nextest check passed 581 tests across 4 binaries, with zero skipped.
- Diagnostic stock-kernel boot reference: 2/2 attempts passed; exact witness
  tuples matched, with timing scope and host-load limits recorded above.
- Device, fault, restore, and campaign references: not yet executed for this
  implementation parent.
- Parent/candidate performance delta: not yet measured.
