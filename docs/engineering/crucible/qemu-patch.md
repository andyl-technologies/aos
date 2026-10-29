# The atomic QEMU patch

Crucible runs guests on a patched QEMU built from source by the `qemu-crucible`
package. The shipped integration contains **one atomic final-state patch**,
`pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch`, applied to the
pinned upstream QEMU 11.1.1 release. This page explains what the patch adds,
why each capability exists, how the patch stays inert outside simulation mode,
and how it is built, regenerated, and tested.

The patched emulator and everything compiled into it are on the GPL side of
the Crucible process boundary. The Apache-licensed host reaches it only
through the versioned control socket and shared-memory protocols; see
[../../legal/licensing.md](../../legal/licensing.md). The host side is
described in [qemu-integration.md](qemu-integration.md) and the in-QEMU Rust
plugin that calls the new APIs is described in [qemu-plugin.md](qemu-plugin.md).

## Artifact and provenance

The authoritative descriptor is
`pkgs/emulation/qemu-patches/_atomic-patch.nix`. The leading underscore keeps
package discovery from treating it as a derivation.

| Field | Meaning |
| --- | --- |
| `qemuVersion`, `qemuSourceUrl`, `qemuSourceHash` | The pinned upstream tarball (`qemu-11.1.1.tar.xz`). |
| `file`, `sha256` | The checked-in patch and its SHA-256. |
| `catalogName`, `class`, `capability` | The catalog entry `crucible-deterministic-qemu-integration`, class `F`. |
| `commit`, `tree` | The single integration commit and its tree. |
| `baseCommit`, `baseTree` | The reconstructed upstream base commit. |
| `bundle`, `bundleSha256` | `crucible-qemu-11.1.1.bundle`, a thin Git bundle whose prerequisite is the base commit. |
| `deterministicAuthorName`, `deterministicAuthorEmail`, `deterministicBaseDate`, `deterministicPatchDate` | Fixed author and dates so regeneration is byte-reproducible. |
| `additionalCapabilities` | Catalog-only capability names carried by the same patch. |

The patch is the `git format-patch` output of one DCO-signed commit whose
parent is the pinned base. The base is reconstructed deterministically from
the upstream tarball, so the repository stores only the thin bundle rather
than a second copy of the QEMU tree. The patch currently touches about 690
QEMU files; most of the volume is under `hw/`, `include/`, `tests/`,
`target/`, and `accel/`.

Maintaining one rebasable commit against one pinned release keeps the review
surface fixed: a QEMU version bump is a rebase of that commit, followed by
every microtest and inertness check again, and a new build identity. A
determinism run reproduces only against the exact QEMU build that produced
it, so that identity is part of every artifact (see
[Build identity](#build-identity)).

## Catalog

The catalog names the capabilities carried by the shipped artifact. Four
names are catalog-only: they name contract-level mechanisms that other
documents and result artifacts refer to, but they are not separate patch
files.

```text
INTEGRATION                                        class
  crucible-deterministic-qemu-integration ........ F

CATALOG-ONLY CAPABILITIES                          class
  rr-switch-quantum .............................. D
  crucible-plugin-advance-barrier ................ D
  crucible-plugin-device-wake .................... D
  crucible-net-direct-inject-api ................. F

NOT CARRIED / DEVELOPMENT ONLY                     class
  (crucible-replay-start) ........................ -
  crucible-tcg-exec-diag ......................... dev
  crucible-virtserial-socket ..................... dev
```

The catalog-only mappings are:

- `rr-switch-quantum` -> `crucible-qemu-11.1.1.patch`
- `crucible-plugin-advance-barrier` -> `crucible-qemu-11.1.1.patch`
- `crucible-plugin-device-wake` -> `crucible-qemu-11.1.1.patch`
- `crucible-net-direct-inject-api` -> `crucible-qemu-11.1.1.patch`

Class `D` marks a determinism-critical mechanism: it changes how virtual
time advances, how an instruction budget is computed, how entropy is drawn,
or when an event is delivered. A defect there can silently break
reproducibility for every run, so those mechanisms carry the tightest sim
predicates and run-twice-and-compare microtests. Class `F` marks a feature
surface (an API export or a sim-only device path) whose failure is loud.

`crucible-replay-start` is deliberately absent. Crucible's determinism comes
from eliminating entropy sources, counting instructions, and injecting inputs
at seeded instruction counts; it never uses QEMU's record/replay subsystem.

## Inertness

The load-bearing property of the patch is that simulation control is inert
unless simulation mode is active. Active means the `sim` accelerator is
selected with `-accel sim` and the Crucible plugin is loaded; mechanisms such
as warp suppression additionally require the plugin to have acquired time
control. Accelerator selection and `qemu_plugin_request_time_control` are
complementary requirements, not alternative activation paths.

The same `qemu-crucible` binary also serves ordinary TCG, so one pinned
source with gated controls replaces a separate simulation-only fork.
Inertness is achieved structurally, by one of three mechanisms:

1. **New files** compiled into a new accelerator or device that exists only
   when selected, for example `accel/tcg/tcg-accel-ops-sim.c` and
   `block/crucible-shmem.c`.
2. **A branch on a sim predicate** whose other branch is unchanged upstream
   code: the selected accelerator name being `sim`, `ICOUNT_PRECISE`, a plugin
   owning time control (`qemu_plugin_has_time_control()`), or a registered
   plugin callback being non-NULL.
3. **A new plugin API export** that does nothing until a plugin calls it.

The one exception is the picosecond timer representation. Ordinary TCG keeps
its exact fractional timer phase in versioned VMState data and restores it
correctly. The pinned Q35 sim-off corpus is byte-identical to upstream except
for one framed, versioned PIT exact-phase subsection. Timing and migration
layouts outside that corpus are not claimed to match upstream
byte-for-byte.

## Capability families

Sections below describe each family by the behavior it guarantees. Exact
interfaces are listed in [Plugin API surface](#plugin-api-surface).

### The `sim` accelerator and virtual time

- `-accel sim` is a TCG-derived accelerator with a split vCPU/main event loop
  (`accel/tcg/tcg-accel-ops-sim.c`, `tcg-accel-ops-sim-shmem.c`). Guest
  progress depends only on retired instructions and plugin-authorized
  advances, never on host thread scheduling.
- It accepts only precise `-icount shift=0,align=off,sleep=off` and refuses
  anything else before guest execution (`-accel sim requires -icount
  shift=0,align=off,sleep=off`). It also rejects icount bias. Virtual time is
  a picosecond logical clock that advances 50 ticks per retired instruction;
  QEMU's upstream nanosecond shift setting does not apply.
- While a plugin holds time control, idle wall-clock warp is suppressed,
  while the clock-notify path still wakes the main loop. The virtual clock
  advances only by retirement and by explicit plugin-authorized jumps.
- The instruction budget is computed from `QEMU_CLOCK_VIRTUAL` deadlines
  only; `QEMU_CLOCK_REALTIME` deadlines never enter the precise budget.
- Guest-visible RTC and realtime reads resolve to the virtual clock plus the
  fixed configured epoch.

See [virtual-time.md](virtual-time.md) for the tick model.

### Entropy

- With `-seed`, QEMU's guest-random path draws from a run-seed-derived
  stream, and the GLib global PRNG (used for generated IDs, UUIDs, and device
  metadata) is reseeded from the same seed, so device state is reproducible
  as well as guest memory.
- Under `-accel sim`, guest random without `-seed` is refused before host
  crypto is touched (`-accel sim requires -seed for deterministic guest
  random`). The unseeded host-entropy path is unchanged outside sim mode.
- Virtio-rng request dispatch and completion are synchronous at the request
  instruction count in sim mode, so both the entropy bytes and their delivery
  point are fixed.

### Multi-vCPU round robin, IPIs, and preemption

- `rr_switch_quantum` is an `-icount` sub-option. In sim mode the
  single-threaded round-robin loop switches vCPUs after that many retired
  instructions in ascending vCPU order, instead of QEMU's adaptive real-time
  quantum. Outside sim mode the helper returns zero and upstream behavior is
  unchanged. A quantum above the signed 32-bit range is refused.
- Inter-vCPU IPI, SIPI, and INIT delivery becomes visible to the target at a
  deterministic node instruction count on the round-robin event path
  (`include/system/crucible-sim-ipi.h`).
- `qemu_plugin_inject_preemption` forces a vCPU switch or delivers an
  interrupt at a commanded node instruction count
  (`accel/tcg/tcg-accel-ops-preemption.c`). A command outside the authorized
  `[deadline, ceiling]` window is rejected loudly, never clamped or deferred.
- `qemu_plugin_read_vcpu_regs` reads an arbitrary vCPU index, not only the
  current one, and `qemu_plugin_rr_cursor` reports the current vCPU and its
  position inside the quantum. Both are side-effect-free, so the host can
  fingerprint all N vCPUs.
- `qemu_plugin_crucible_single_threaded_rr` returns one only when vCPU
  callbacks are serialized by single-threaded round robin; the plugin
  requires it before registration.

### Queued time advance and event-driven wakes

The plugin never runs or polls QEMU's main loop recursively from a vCPU
callback.

- `qemu_plugin_advance_time_ticks(target_tick)` only enqueues one absolute
  target. Queued normal-main-loop work then advances the clock and runs
  `qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)`. Completion is delivered to the
  callback registered with `qemu_plugin_register_time_advance_cb` on a later
  main-loop pass, after timer-produced main-loop bottom halves have run
  (`crucible-plugin-advance-barrier`). The queued work stays runnable while a
  vCPU is blocked on device I/O. A second request while one is outstanding is
  rejected with `-EBUSY`.
- `qemu_plugin_register_wake_fd` registers the plugin's eventfd on the main
  `AioContext`. Its handler drains scheduler wakes, notifies pending device
  consumers, and kicks the vCPU parked on QEMU's BQL condition variable. It
  stays dispatchable from a synchronous block request's nested `aio_poll()`
  (`crucible-plugin-device-wake`).
- `qemu_plugin_crucible_wait_idle_wake` lets the exact simulated round-robin
  idle callback release the BQL around one raw non-private futex wait on the
  slot's `wake_signal` word (`plugins/crucible-idle-wait.c`). Holding the BQL
  while waiting would block the BQL-dependent producers that publish the
  wake. Every wait return forces the round-robin loop to rescan from the
  start before any guest execution, device work, receive injection,
  fingerprint capture, or time advance, because releasing the BQL invalidates
  the callback's earlier observations.

### Observation

- `qemu_plugin_clock_deadline_ps` returns the exact next
  `QEMU_CLOCK_VIRTUAL` deadline in picoseconds, `-1` when no timer is armed,
  or `-2` when the deadline cannot be represented. Upstream QEMU has no
  equivalent. The plugin requires it; an overshoot-and-correct fallback cannot
  be made bit-deterministic.
- `qemu_plugin_icount_raw` reads the bias-excluded retirement count.
- `qemu_plugin_icount_at_tb_entry` reports the entry count from inside a
  translation-block execution callback and rejects calls from any other
  context.
- `qemu_plugin_force_vcpu_exit` normalizes the first exit phase so the
  exit/run alternation cannot settle into opposite phases on different runs.
- `qemu_plugin_crucible_capture_fingerprint_material` captures guest RAM and
  the admitted read-only device and volatile projections at an exact
  boundary for the single-VM fingerprint.

### Device co-simulation

Each path is inactive unless its plugin callback is registered, in which
case the device routes through the shared-memory rings described in
[io-subnodes.md](io-subnodes.md).

- **Block.** The new `crucible-shmem` block driver (`block/crucible-shmem.c`)
  forwards virtio-blk requests to the block executor and completes them at
  virtual-time-determined points. An explicit pending sentinel separates "not
  ready" from zero-length write and flush success. Typed error results,
  discard, and transport reset are carried through the same path.
  Registration uses `qemu_plugin_register_blk_cb`,
  `qemu_plugin_register_blk_event_cb`, and `qemu_plugin_register_blk_wait_cb`.
- **9p.** With `qemu_plugin_register_9p_cb` registered, virtio-9p becomes a
  raw-message pipe to the 9p executor; with no callback the upstream internal
  server is used unchanged.
- **Network.** `qemu_plugin_register_net_tx_cb` routes every guest-sent frame
  to the plugin instead of the netdev backend. `qemu_plugin_net_inject`
  attempts one inbound frame and returns `0` on complete guest delivery, `1`
  on backpressure (ownership stays with the caller), or a negative status on
  permanent failure (`crucible-net-direct-inject-api`). A retained frame
  stays in the bounded, checkpointed shared-memory ring and never in a
  QEMU-private packet queue, and each retry re-probes the device rather than
  trusting the private queue's `receive_disabled` latch.

### Checkpoints, faults, and hot fork

- Exact checkpoint capture and restore use QMP commands
  `crucible-checkpoint-capture`, `-commit`, `-abort`, `-restore`, and
  `query-crucible-checkpoint-epoch`, with descriptor-bound RAM and device
  VMState.
- Typed fault execution lives in `plugins/crucible-fault*.c` with
  per-architecture register adapters in `target/i386/crucible-register.c`
  and `target/arm/crucible-register.c`. The fault model is described
  elsewhere in this folder.
- Retained hot fork adds QEMU-owned quiescence inventories and barriers (RCU,
  AIO, block, timers, plugin callbacks and workers, monitor) and child
  reconstruction (`block/crucible-hot-fork-source.c`,
  `include/qemu/crucible-hot-fork-*.h`). See
  [time-travel-debugging.md](time-travel-debugging.md).

### Guest-to-host doorbell

For the guest-to-host doorbell, no QEMU patch was added. The pinned upstream
plugin API already provides instruction-execution callbacks and
`qemu_plugin_read_memory_vaddr`, which together observe a reserved trap
(`out 0xe7, al` on x86_64, the inert `hint #0x4c` on AArch64) and read its
payload. Only the host-to-guest reply path needs the patch-provided
`qemu_plugin_crucible_write_memory_vaddr`, and it is reachable only in
white-box mode. See [guest-host-channel.md](guest-host-channel.md).

## Plugin API surface

The plugin resolves each export at install time and fails closed if any
required one is missing. The patch adds these exports, among others:

| Export | Purpose |
| --- | --- |
| `qemu_plugin_has_time_control` | Report whether a plugin owns virtual time |
| `qemu_plugin_advance_time_ticks` | Enqueue one absolute virtual-time target |
| `qemu_plugin_register_time_advance_cb` | Register queued-advance completion |
| `qemu_plugin_crucible_wait_idle_wake` | One BQL-releasing idle futex wait |
| `qemu_plugin_clock_deadline_ps` | Exact next virtual-timer deadline |
| `qemu_plugin_icount_raw` | Raw retirement count |
| `qemu_plugin_icount_at_tb_entry` | Entry count inside a TB execution callback |
| `qemu_plugin_force_vcpu_exit` | Force the current vCPU to exit |
| `qemu_plugin_register_wake_fd` | Main-loop wake eventfd |
| `qemu_plugin_read_vcpu_regs` | Register file of any vCPU |
| `qemu_plugin_rr_cursor` | Round-robin cursor |
| `qemu_plugin_inject_preemption` | Commanded vCPU switch or interrupt |
| `qemu_plugin_register_net_tx_cb`, `qemu_plugin_net_inject` | Network TX intercept and lossless RX |
| `qemu_plugin_register_blk_cb`, `qemu_plugin_register_9p_cb` | Block and 9p forwarding |
| `qemu_plugin_request_shutdown`, `qemu_plugin_request_vmstop` | Orderly shutdown and exact native stop |
| `qemu_plugin_crucible_write_memory_vaddr` | White-box host-to-guest reply |

`qemu_plugin_request_time_control` comes from upstream QEMU (available since
9.1). The plugin build asserts that the installed `qemu-plugin.h` declares
`qemu_plugin_read_vcpu_regs`, `qemu_plugin_rr_cursor`, and
`qemu_plugin_inject_preemption` before compiling. The plugin uses blocking
`std` I/O on QEMU's callback threads and a few dedicated worker threads; no
async runtime runs inside QEMU.

## AArch64 PMU

The supported AArch64 sim profile explicitly selects `pmu=off`; the host
launch profile rejects an AArch64 CPU model without exactly one `pmu=off`
(`LaunchProfileError::Aarch64PmuMustBeOff`). The PMU `INST_RETIRED`
overflow interrupt is driven by a nanosecond timer and cannot fire at the
exact retired-instruction tick after a fractional or idle advance. Non-sim
ARM PMU behavior is unchanged.

## Development-only diagnostics

`crucible-tcg-exec-diag` (per-execution icount tracing) and
`crucible-virtserial-socket` (raw serial socket framing for white-box
debugging) are not applied by the shipped package. Neither name appears in
the patch or in `pkgs/emulation/qemu.nix`, which
`checks.crucible.phase1.qemuDiagnosticPatchesDevOnly` enforces. Any such
capability in a developer build must be inert by default and must not change
guest-visible instruction counts when off.

The shipped patch does define fixed QEMU trace events (for example
`crucible_sim_rr_control_boundary` and the `crucible_sim_determinism_*`
family). They are enabled only through the host launch builder's fixed
`-D`/`-trace` blocks, whose exact selections are part of the hashed command
line; see [qemu-integration.md](qemu-integration.md).

## Build

`pkgs/emulation/qemu.nix` builds three relevant outputs, instantiated in
`pkgs/default.nix`:

| Package | `applyCruciblePatch` | Use |
| --- | --- | --- |
| `qemu` | no | Generic AOS QEMU, unrestricted |
| `qemu-crucible` | yes, `enablePlugins = true` | The Crucible emulator |
| `qemu-crucible-reference` | no, `enablePlugins = true` | Unpatched comparison build for inertness checks |

When `applyCruciblePatch` is set, the build applies the patch with
`patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1`, so any drift
from the pinned base fails instead of fuzzing. The build also copies the
generated shared-memory ABI header
`crates/crucible/crucible-qemu-shmem/include/crucible_shmem_abi.h` into the
tree, compile-probes its ABI version and layout, and installs it as
`include/aos/crucible/crucible_shmem_abi.h`.

`pkgs/emulation/crucible-qemu-plugin.nix` builds the Rust plugin against
`qemu-crucible` and installs it as
`lib/qemu/plugins/crucible-qemu-plugin.so`.
`pkgs/emulation/crucible-qemu-trace-plugin.nix` builds a separate C
instruction-trace plugin used by trace-fingerprint checks.

### Build identity

`qemu-crucible` writes `share/aos/crucible/qemu-build-identity.env`. Its
material covers the QEMU version and source hash, the `qemu.nix` and configure
flags hashes, the atomic patch hash, the patch branch head and base commits,
the bundle and branch material hashes, and the shared-memory ABI version
(`qemu_shmem_abi=crucible-shmem-abi-v<N>`) and header hash. The plugin build
receives the same identity through `CRUCIBLE_QEMU_BUILD_ID`,
`CRUCIBLE_QEMU_ATOMIC_PATCH_HASH`, and `CRUCIBLE_SHMEM_HEADER_HASH`.

### Corresponding source

`pkgs/emulation/qemu-crucible-source.nix` produces `qemu-crucible-source`,
the complete corresponding source for the patched binary. Release policy
publishes the `crucible` suite, which co-retains that output; `qemu-crucible`
is never published as a standalone root. See
[packaging.md](packaging.md) and
[../../legal/licensing.md](../../legal/licensing.md).

## File inventory and licenses

The patch preserves the license of every QEMU file it modifies.
`pkgs/emulation/qemu-patches/LICENSES.md` lists every file the patch creates
with its license and basis; new unmarked files inherit QEMU's
`GPL-2.0-or-later` default. A change that creates or removes a QEMU file must
update that inventory, which `checks.crucible.phase6.qemuPatchLicenseLedger`
checks. Commits touching `pkgs/emulation/qemu-patches/` need a DCO
`Signed-off-by` line.

## Regeneration and checks

`tests/crucible/_qemu-atomic-patch-repository.nix` builds a Git object
database from the upstream tarball, applies the patch, verifies that the
resulting tree equals the recorded `tree`, authenticates the signed commit
carried by the bundle, and verifies the DCO sign-off.
`checks.crucible.phase2.qemuPatchRegeneration` then reruns
`git format-patch --stdout --no-signature --no-stat --full-index --binary
<baseCommit>..<commit>` and requires the output to equal the checked-in patch
byte for byte and to match `sha256`. It also checks that the built package's
identity file names the same patch and commits.

`qemu-crucible` carries two package checks:

- `checks.integration.qemu-crucible-patch-microtests`: focused microtests,
  one per capability. A determinism mechanism's test shows that the targeted
  entropy source is eliminated in sim mode, that the unpatched reference
  build lacks the capability, and that the mechanism is a no-op outside sim
  mode. Performance-only mechanisms are tested by bit-identical cross-run
  icount comparison, not by timing.
- `checks.integration.qemu-crucible-qemu-inert`: runs the same workload
  (boot, block, 9p, RNG reads, guest output, QMP introspection, and Q35
  migration) on `qemu-crucible-reference` and on `qemu-crucible` with sim
  mode off, and requires identical guest-visible evidence. It allows only the
  PIT exact-phase subsection in migration bytes and requires the patched
  QMP command set to keep upstream's commands. The enumerated Crucible
  host-control command `crucible-complete-terminal-lifecycle` must fail closed
  without sim mode and leave a stopped VM stopped.

Narrower source checks pin individual mechanisms, for example
`checks.crucible.phase1.qemuDoorbellNoPatch` and
`checks.crucible.phase2.qemuRrQuantumIcount`. The full list is in
[testing-and-gates.md](testing-and-gates.md).
