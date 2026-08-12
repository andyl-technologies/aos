# 11 — The QEMU patch series

The carried series contains **65 patches**. This count is checked against
`pkgs/emulation/qemu-patches/_series.nix` by
`checks.crucible.referenceIntegrity`.

This file specifies the **patch series** that AOS's from-source QEMU package
([`26-packaging-aos-integration.md`](26-packaging-aos-integration.md)) carries to
make Crucible's determinism contract ([`04-determinism-contract.md`](04-determinism-contract.md))
and co-simulation transport ([`13-shmem-abi.md`](13-shmem-abi.md)) realizable.
The patches are the C-side mechanisms that the entropy-source enumeration of
[`04-determinism-contract.md`](04-determinism-contract.md) §4.6 marks as **patch**
class (E2, E3, E9, E14, E18, E19, E20), plus the plugin-API surface the in-VM
plugin ([`12-qemu-plugin.md`](12-qemu-plugin.md)) calls to own virtual time, and
the device co-simulation paths that route block / 9p / network I/O through the
shared-memory rings ([`13-shmem-abi.md`](13-shmem-abi.md)).

The series is **Crucible's own**, named `crucible-*`. It is not a fork of, nor a
verbatim copy of, any prior internal exploration or third-party patch set
([CONV-1]). Where a prior exploration proved a mechanism necessary, Crucible
re-derives it as a focused, inertness-gated, micro-tested patch with its own name.

Requirement IDs in this file use the prefix `PATCH`. Gate names referenced here
(`gate:qemu-inert`, `gate:patch-microtests`, `gate:layer0-determinism`,
`gate:layer1-injection`, `gate:abi-conformance`) are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md); the
packaging that applies, builds, and gates the series is
[`26-packaging-aos-integration.md`](26-packaging-aos-integration.md); the time
model the patches enforce is [`09-virtual-time-icount.md`](09-virtual-time-icount.md);
the plugin that consumes the new API surface is
[`12-qemu-plugin.md`](12-qemu-plugin.md); the shared-memory ABI the device paths
read is [`13-shmem-abi.md`](13-shmem-abi.md); the guest↔host channel that the
doorbell discussion (§11.7) coordinates with is
[`16-guest-host-channel.md`](16-guest-host-channel.md).

The single most important property of this entire file is **inertness**: every
mechanism here is dead code unless simulation mode is explicitly activated, so the
*same* AOS QEMU source built and shipped for production use is behaviorally
identical to upstream ([INV-7], [DET-36]). The patch series is what makes
"determinism is opt-in, production QEMU is untouched" true at the source level.

## 11.1 Governing principles

The series is held to four governing principles. Every individual patch satisfies
all four; the per-patch detail (§11.4–§11.8) states how each one does.

### 11.1.1 Inertness (the load-bearing principle)

- **[PATCH-1]** Every patch in the series MUST be **inert unless simulation mode
  is active**. "Active" means the plugin (`crucible-qemu-plugin`,
  [`12-qemu-plugin.md`](12-qemu-plugin.md)) is loaded, the `sim` TCG accelerator
  is selected via `-accel sim`, and any mechanism-specific capability such as
  time-control ownership has also been acquired. Accelerator selection and
  `qemu_plugin_request_time_control` are complementary requirements, not
  equivalent activation paths. The same
  AOS QEMU binary, built from the same patched source but launched without sim
  mode, MUST be behaviorally identical to upstream QEMU of the pinned version.
  *Gate:* `gate:qemu-inert`. *Spec:* §11.1.1; satisfies [INV-7], [DET-36].

- **[PATCH-2]** The gate for a patch's non-sim behavior MUST be a *checked*
  property, not a reviewed claim: `gate:qemu-inert` runs a corpus of
  upstream-equivalent invocations (boot, run, migrate, QMP introspection) against
  both the unpatched pinned QEMU and the AOS-patched QEMU *with sim mode off*, and
  MUST observe byte-identical guest-visible behavior (same instruction streams
  under plain `-icount`, same device enumeration, same migration streams). A patch
  that perturbs any of these out of sim mode fails the gate. *Gate:*
  `gate:qemu-inert`. *Spec:* §11.1.1; satisfies [INV-7], [DET-36].

- **[PATCH-3]** Inertness MUST be achieved structurally, by one of three
  permitted mechanisms, never by a runtime heuristic that "usually" stays off:
  (a) **new files** compiled into a new accelerator (`tcg-accel-ops-sim.c`) or new
  device (`block/crucible-shmem.c`) that is only instantiated when the sim
  accelerator / device is selected; (b) a **branch gated on a sim predicate** —
  `qemu_plugin_has_time_control()`, `use_icount == ICOUNT_PRECISE`, or a registered
  plugin callback being non-NULL — whose else-branch is verbatim upstream behavior;
  or (c) a **new plugin-API export** that does nothing unless a plugin calls it.
  A patch MUST NOT alter an upstream code path that runs in the non-sim
  configuration. *Gate:* `gate:qemu-inert`. *Spec:* §11.1.1; satisfies [INV-7].

The three mechanisms map cleanly onto the patch categories: determinism patches
(§11.4) use (b); the sim-mode accelerator and device patches (§11.5, §11.6) use
(a); the plugin-API patches (§11.5) use (c). No patch is permitted to use a
fourth, looser mechanism.

### 11.1.2 Per-patch micro-tests

- **[PATCH-4]** Every patch MUST carry a **focused micro-test** exercising exactly
  the behavior it adds — neither a broad end-to-end scenario nor a no-op smoke
  test. A determinism patch's micro-test MUST demonstrate, in isolation, that the
  entropy source it targets is eliminated when the patch is active (e.g. two runs
  agree on the affected quantity) and reintroduced when the patch is reverted
  (the test goes red), per [DET-18]. A capability patch's micro-test MUST exercise
  the new API or device path and assert its documented contract. *Gate:*
  `gate:patch-microtests`. *Spec:* §11.1.2; satisfies [DET-37], forward-ref 24.

- **[PATCH-5]** Every patch's micro-test MUST also assert the patch's **inertness**
  (it is a determinism/capability change in sim mode *and* a no-op out of sim
  mode), so that the pair "takes effect in sim mode / inert out of sim mode" of
  [DET-37] is checked by the patch's own test, not only by the aggregate
  `gate:qemu-inert`. *Gate:* `gate:patch-microtests`, `gate:qemu-inert`. *Spec:*
  §11.1.2; satisfies [DET-37], [INV-7].

### 11.1.3 Stated invariant per patch

- **[PATCH-6]** Every patch MUST state, in its commit message and in this file's
  catalog (§11.3), the single **determinism invariant or capability** it enforces,
  written as a reference to a `DET-*` / `TIME-*` / `SHM-*` / `PLUG-*` requirement.
  A patch that does not map to a stated requirement MUST NOT be in the series; the
  series exists to satisfy the contract, not to accumulate convenience changes.
  *Gate:* `gate:patch-microtests`. *Spec:* §11.1.3.

### 11.1.4 Rebasable series against a pinned QEMU

- **[PATCH-7]** The series MUST be maintained as a **rebasable, ordered series**
  (a `quilt`-style stack or a tracked branch of single-purpose commits) against a
  single **pinned upstream QEMU version** ([PATCH-30]). Each patch MUST be a
  single logical change with a stable name (`crucible-<name>.patch`); the order is
  significant where one patch depends on a file another creates (e.g. the
  sim-mode accelerator file must exist before patches that extend it). *Gate:*
  `gate:patch-microtests`, forward-ref 26. *Spec:* §11.1.4; satisfies [DET-35].

- **[PATCH-8]** CI MUST gate the series on the pinned QEMU: the series MUST
  **apply cleanly**, the patched tree MUST **build**, and **every per-patch
  micro-test MUST pass**, on the AOS QEMU version, on every change to the series
  or the pin. The regeneration pipeline (§11.9) MUST produce the committed patch
  files reproducibly so a drift between the committed series and the regenerated
  series fails CI. *Gate:* `gate:patch-microtests`, `gate:qemu-inert`,
  forward-ref 26. *Spec:* §11.1.4; satisfies [DET-35], [PKG].

## 11.2 Classification: determinism-critical vs feature

Patches fall into two risk classes. The class governs how much scrutiny a patch
gets and how its inertness is argued.

- **[PATCH-9]** Each patch MUST be classified as **determinism-critical
  (dangerous)** or **feature/capability**. A *determinism-critical* patch changes
  how virtual time advances, how the instruction budget is computed, how entropy
  is drawn, or how an event's timing is decided — a defect in it silently breaks
  [DET-1] for *every* run, possibly without an obvious failure. A *feature* patch
  adds an API export or a device/transport path that is only reached in sim mode
  and whose failure is loud (a missing symbol, a wrong I/O result caught by a
  micro-test). Determinism-critical patches MUST carry the strongest inertness
  argument (a precise sim predicate, [PATCH-3](b)) and the most adversarial
  micro-test (run-twice-and-diff under host perturbation, [DET-38]). *Gate:*
  `gate:qemu-inert`, `gate:layer0-determinism`. *Spec:* §11.2; satisfies [INV-7],
  [INV-10].

The **risky** patches for AOS's production QEMU — the ones whose inertness must be
argued most carefully because they touch shared, always-compiled files — are:

- `crucible-icount-no-realtime` (§11.4) — edits the upstream icount budget
  function; gated on `-accel sim` with `use_icount == ICOUNT_PRECISE`.
- `crucible-no-warp-with-plugin` (§11.4) — edits the upstream warp timer; gated on
  `-accel sim` with `qemu_plugin_has_time_control()`.
- `crucible-block-rtc-read` (§11.4) — edits the upstream RTC/timedate read path;
  enabled only by `-accel sim`.
- `crucible-det-getrandom` and `crucible-det-glib-prng` (§11.4) — edit QEMU's
  entropy paths; gated on a `deterministic` predicate set only under sim mode.

Every *other* patch is either a new file (the sim accelerator, the shmem device
drivers) or a pure additive plugin-API export, both of which are inert by
construction (the file is not compiled into a used object / the export is never
called) and therefore lower-risk. The five edits above are the only places a bug
could leak into production behavior, so they carry the heaviest gating.

## 11.3 The patch catalog

The catalog groups the series by category. Each row gives the patch name, its
risk class (D = determinism-critical, F = feature), the invariant/capability it
enforces, and a one-line mechanism. Per-patch detail follows in §11.4–§11.8.
Diagnostic-only patches (dev-only, **not shipped** in the AOS package) are marked
*dev*.

```text
DETERMINISM (source elimination)                       class  enforces
  crucible-sim-accel ............ sim-mode TCG event loop  D    DET-1, TIME-23, E14
  crucible-no-warp-with-plugin .. suppress idle warp        D    DET-10, TIME-21, E2
  crucible-icount-no-realtime ... drop realtime from budget D    DET-9,  TIME-22, E3
  crucible-block-rtc-read ....... seed/pin guest RTC base   D    DET-8, TIME-20, E5
  crucible-det-glib-prng ........ seed global GRand (1-line) D    DET-21, E9
  crucible-det-getrandom ........ deterministic guest-rng   D    DET-21, DET-19, E9
  crucible-net-deterministic .... icount-timed RX delivery  D    DET-11, DET-13, E18
  crucible-rr-quantum-icount .... RR switch @ node-icount    D    PATCH-44, DET-1, QEMU-43
  crucible-det-ipi .............. deterministic IPI/SIPI/INIT D    PATCH-45, DET-1, INV-7
  crucible-aarch64-det-ipi-adapter AArch64 IPI delivery adapter D  DET-4, PLUG-14, GHC-4
  crucible-det-virtio-ioeventfd . sync virtio-rng vq dispatch D    DET-1, E7
  crucible-det-rng-delivery ..... sync virtio-rng completion  D    DET-1, E7, E9
  (crucible-replay-start) ....... NOT CARRIED (see §11.4)    —    NG-6 (PATCH-43)

PLUGIN TIME CONTROL (API surface)                      class  enforces
  crucible-rr-fingerprint-helpers phase-1 fp helper ABI F    DET-29, QEMU-43
  crucible-plugin-time-advance .. queued vtime + completion D    TIME-23, TIME-27, DET-1, INV-10
  crucible-time-advance-commit-barrier  fence RR through plugin commit D  TIME-23, TIME-27, DET-1, INV-10
  crucible-time-advance-enqueue-kick  kick active vCPU into barrier D  TIME-23, TIME-27, DET-1, INV-10
  crucible-time-advance-arm-at-vcpu-boundary  arm after TCG exit D  TIME-23, TIME-27, DET-1, INV-10
  crucible-plugin-advance-barrier  order timer BH completion D    PATCH-19, DET-1, INV-10
  crucible-plugin-device-wake ... event-driven device wake   D    PATCH-20, DET-1, INV-10
  crucible-clock-deadline ....... exact next vtimer deadline D    TIME-24, TIME-25
  crucible-plugin-icount-raw .... raw icount read           F    DET-29, INV-10
  crucible-vcpu-introspect ...... per-vCPU regs + RR cursor  F    PATCH-46, DET-29, INV-10
  crucible-sim-observer ......... post-exec boundary observe F    DET-29, PLUG-35
  crucible-safe-fingerprint-boundary exact BQL-held capture  F    DET-29, PLUG-35
  crucible-process-argv-attestation raw launch argv SHA-256  F    DET-31, QEMU-34
  crucible-raw-state-export ..... GPA RAM + terminal VMstate  F    DET-29, PLUG-47
  crucible-preemption-inject .... commanded vCPU switch/IRQ  D    PATCH-47, DET-1, PLUG-50
  crucible-plugin-vcpu-exit ..... force vCPU exit            D    DET-1, INV-10
  crucible-plugin-wake-fd ....... main-loop wake-fd          F    SHM-26, INV-8
  crucible-plugin-tcg-exec-cb ... TCG-exec callback          F    coverage, INV-7
  crucible-plugin-vmstop ........ exact boundary to native pause D  DET-1, INV-10, QEMU-43

DEVICE CO-SIM (shmem transport)                        class  enforces
  crucible-blk-shmem ............ virtio-blk over shmem      F    PATCH-26, DET-16, E19, SHM-13
  crucible-blk-shmem-io-fixes ... blk I/O correctness        D    PATCH-27, DET-16, E19
  crucible-blk-write-sentinel ... write/flush 0-len sentinel D    PATCH-28, DET-16, E19
  crucible-9p-shmem ............. virtio-9p over shmem       F    PATCH-29, DET-16, E19
  crucible-dev-cb-api ........... register blk/9p callbacks  F    PATCH-30, PLUG, SHM-17
  crucible-net-tx-callback ...... intercept guest TX         F    PATCH-31, DET-18, E18, SHM-17
  crucible-net-flush-api ........ lossless RX inject + flush F    PATCH-32, DET-18, E18
  crucible-block-typed-errors ... exact block result to errno     F    STOR-RESULT, IO-8, PATCH-26
  crucible-block-discard ........ deterministic discard transport F    STOR-DISCARD, DET-16, PATCH-26
  crucible-block-transport-reset  epoch/recovery/reset transport       F    STOR-RESET, STOR-RESULT, DET-16, PATCH-26

TCG SIM CORRECTNESS / PERF                             class  enforces
  crucible-sim-loop-fix ......... single-vCPU loop fixes     D    PATCH-34, DET-1, NG-1
  crucible-sim-first-exit ....... normalize first exit phase D    PATCH-34, DET-1, INV-10
  crucible-sim-skip-second-events  drop redundant 2nd events D    PATCH-34, DET-1
  crucible-sim-poll-immediate ... wake-driven shmem poll      D    PATCH-34, DET-13, E19
  crucible-sim-batch-tcg-exec ... batch TCG exec calls        F    PATCH-35, DET-1, INV-10, PERF
  crucible-sim-idle-callbacks ... idle/resume cb wiring       D    PATCH-34, TIME-24, INV-8
  crucible-sim-shmem-dispatch ... shmem co-sim dispatch glue  F    PATCH-34, SHM-1
  crucible-sim-freeze-warp-at-observation-boundary  freeze vclock at obs boundary  D    DET-8, DET-29
  crucible-sim-gate-rr-kick ..... sim-gate stock RR kick timer D    DET-30
  crucible-blk-device-completion-advance  resume blocked I/O at delivery icount  D    DET-16, PATCH-27, PLUG-21, IO-31
  crucible-9p-sync-kick ......... sync sim-mode 9p vq dispatch D    DET-16, PATCH-29, PLUG-22, IO-32
  crucible-whitebox-guest-write . callback guest-memory reply   F    PLUG-34, PLUG-51, GHC-32, GHC-37
  crucible-translation-prefetch-helper dedicated demand TCG helper F PERF-32

SIGNAL-DRIVEN FAULT EXECUTION                          class  enforces
  crucible-fault-command-abi ... closed command/result registry F FAULT-ABI, FAULT-CAP, FAULT-ORDER
  crucible-fault-safe-boundary exact icount/quiescent commit      D FAULT-BOUNDARY, FAULT-AUTH, DET-1
  crucible-memory-boundary-mutate atomic GPA/GVA RAM mutation    F QFP-MEM-1, QFP-MEM-2, FAULT-ORDER
  crucible-memory-access-faults typed CPU/DMA memory rules       D QFP-MEMA-1, QFP-MEMA-2, FAULT-ORDER
  crucible-architecture-register-faults typed CPU registers     D QFP-REG-1, QFP-REG-2, FAULT-ORDER
  crucible-instruction-and-exception-faults exact instruction/exception effects D QFP-INSN-1, QFP-EXC-1, FAULT-ORDER
  crucible-interrupt-faults ... realized controller disposition/storms D QFP-IRQ-1, QFP-IRQ-2, FAULT-ORDER
  crucible-hardware-error-inject architecture error/ECC delivery D QFP-HWERR-1, QFP-HWERR-2, FAULT-ORDER
  crucible-vcpu-service-control rational CPU service/stall/offline D QFP-VCPU-1, QFP-VCPU-2, FAULT-ORDER
  crucible-node-lifecycle-faults crash/hang/reset/power lifecycle D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
  crucible-block-typed-errors closed guest-visible block errors F STOR-RESULT, IO-8, PATCH-26
  crucible-block-discard .... deterministic discard transport F STOR-DISCARD, DET-16, PATCH-26
  crucible-block-transport-reset transactional reset/recovery F STOR-RESET, STOR-RESULT, DET-16, PATCH-26
  crucible-plugin-vmstop ... exact plugin-boundary native pause D DET-1, INV-10, QEMU-43
  crucible-terminal-lifecycle-completion staged terminal exit D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
  crucible-authenticated-terminal-lifecycle authenticated exit D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
  crucible-immutable-process-generation launch-bound process ID D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
  crucible-core-fault-vmstate transactional bounded core state D QFP-STATE-1, QFP-STATE-2, FAULT-ORDER
  crucible-guest-clock-faults guest clocks/timer rearming/evidence D QFP-CLOCK-1, QFP-CLOCK-2, FAULT-ORDER
  crucible-accelerator-fault-device deterministic accelerator device/faults D QFP-ACCEL-1, QFP-ACCEL-2, FAULT-ORDER
  crucible-fault-vmstate aggregate fault-state identity D QFP-STATE-1, QFP-STATE-2, QFP-STATE-3

GUEST↔HOST CHANNEL (coordinate with 16)                class  enforces
  (no new patch required — see §11.7)                   —     GHC reuse

DIAGNOSTIC-ONLY (dev, NOT shipped)                     class  enforces
  crucible-tcg-exec-diag ........ per-exec icount trace      dev  divergence debug
  crucible-virtserial-socket .... raw serial socket framing  dev  white-box debug
```

The shipped patch-file inventory is the `patches` list in
`pkgs/emulation/qemu-patches/_series.nix`; each shipped patch-file row above
appears there with its `catalogName`, risk class, and `enforces` mapping. Four
catalog rows are capability subentries implemented by broader shipped patches,
not additional files:

- `crucible-rr-quantum-icount` -> `0002-crucible-rr-fingerprint-helpers.patch`
- `crucible-plugin-advance-barrier` -> `0010-crucible-plugin-time-advance.patch`
- `crucible-plugin-device-wake` -> `0013-crucible-plugin-wake-fd.patch`,
  `0019-crucible-9p-shmem.patch`, and `0024-crucible-sim-poll-immediate.patch`
- `crucible-net-flush-api` -> `0009-crucible-net-deterministic.patch`

- **[PATCH-10]** The catalog above is the **authoritative inventory** of the
  series. A patch present in the AOS QEMU package but absent from this catalog, or
  vice versa, MUST fail the packaging conformance check (26). Diagnostic-only
  patches marked *dev* MUST NOT be applied in the shipped AOS QEMU package; they
  are applied only in a developer build and MUST be inert-by-construction
  (compiled out, or behind a `diag=` plugin arg) even there. *Gate:*
  `gate:qemu-inert`, forward-ref 26. *Spec:* §11.3; satisfies [INV-7], [INV-10].

## 11.4 Determinism patches (source elimination)

These patches implement the **patch**-class eliminations of the entropy table
([`04-determinism-contract.md`](04-determinism-contract.md) §4.6). All are
determinism-critical.

### crucible-sim-accel — deterministic TCG sim-mode event loop

- **Enforces:** [DET-1], [TIME-23], [INV-8]; eliminates E14 (host thread
  scheduling of QEMU threads).
- **Mechanism:** Adds a new TCG accelerator operations file
  (`accel/tcg/tcg-accel-ops-sim.c`) selectable as `-accel sim`. It implements a
  **split event loop**: the vCPU thread owns icount accounting, main-AIO-context
  polling, and CPU execution; the main thread retains QMP / iohandler servicing.
  The single-vCPU sim loop drives `first_cpu` directly and advances virtual time
  only by retiring instructions and by plugin-authorized jumps (no wall-clock
  warp). Because it is a *new file* compiled into a *new accelerator*, none of its
  code runs unless `-accel sim` is selected.
- **Micro-test:** boot a tiny guest under `-accel sim` twice; assert identical
  per-`tcg_cpu_exec` icount-delta traces (via the plugin's icount read) across
  runs under injected host scheduling jitter; assert `-accel tcg` (non-sim) is
  unaffected.
- **Inertness:** [PATCH-3](a) — the file is only linked into a path reached when
  the `sim` accelerator is selected; with any other accelerator it is never
  entered.
- **Risk:** D. This is the foundation patch; everything else in §11.5–§11.8
  extends the file it creates, so it MUST be first in the series ([PATCH-7]).

- **[PATCH-11]** The series MUST add a deterministic sim-mode TCG accelerator
  (`-accel sim`) with a split vCPU/main event loop in which virtual time advances
  only by retired instructions and plugin-authorized jumps, never by host
  wall-clock, and in which guest progress is independent of host thread scheduling
  order (E14). The accelerator MUST be a new file inert under any other
  accelerator. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:*
  §11.4; satisfies [DET-1], [TIME-23], [INV-8], [DET-18] (E14).

### crucible-no-warp-with-plugin — suppress idle warp when the plugin owns time

- **Enforces:** [DET-10], [TIME-21]; eliminates E2 (wall-clock warp while idle).
- **Mechanism:** In the upstream warp-timer path (`icount_start_warp_timer`),
  when the selected accelerator is `sim` and a plugin holds time control
  (`qemu_plugin_has_time_control()` returns true), skip *all* clock advancement
  (both the `sleep=off` bias warp and the `sleep=on` realtime timer) but
  **preserve the `qemu_clock_notify(QEMU_CLOCK_VIRTUAL)` wakeup**, so the main
  loop still wakes when vCPUs idle and plugin timers still fire. Only the plugin
  may advance `qemu_icount_bias` thereafter.
- **Micro-test:** with sim time control held, idle the guest and assert virtual
  time does not advance until the plugin issues an explicit jump; without time
  control, and with non-sim time control, assert upstream warp still advances the
  clock (the notify path is preserved).
- **Inertness:** [PATCH-3](b) — the new branch is taken *only* under sim mode with
  plugin time control held; the else-branch is verbatim upstream warp behavior.
- **Risk:** D (edits an always-compiled upstream file).

- **[PATCH-12]** The series MUST suppress QEMU's idle wall-clock warp whenever
  sim mode is active and a plugin holds time control, while preserving the
  clock-notify wakeup path so the main loop and plugin timers still progress.
  The suppression MUST be gated on the sim and time-control predicates so
  non-sim QEMU warps exactly as upstream. *Gate:* `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §11.4; satisfies [DET-10], [TIME-21], [DET-18]
  (E2), [INV-7].

### crucible-icount-no-realtime — drop realtime deadlines from the icount budget

- **Enforces:** [DET-9], [TIME-22]; eliminates E3 (realtime deadlines in the
  icount budget).
- **Mechanism:** In `icount_get_limit`, the instruction budget is normally the
  soonest of the `QEMU_CLOCK_VIRTUAL` deadline and the `QEMU_CLOCK_REALTIME`
  deadline (the latter "helps with input processing"). In sim-mode **precise
  icount** (`-accel sim -icount shift=N`), the realtime deadline is *not* folded
  in, so the number of guest instructions executed per TB exit depends solely on
  the virtual clock and is host-speed-independent. Non-sim and non-precise
  (adaptive) icount keep the upstream behavior.
- **Micro-test:** run a fixed workload under precise mode on an artificially
  slowed host and a fast host; assert identical instructions-per-TB-exit; assert
  adaptive mode still consults the realtime deadline.
- **Inertness:** [PATCH-3](b) — the realtime deadline is dropped only under
  `-accel sim` with `use_icount == ICOUNT_PRECISE`; every other mode is
  unchanged.
- **Risk:** D (edits an always-compiled upstream file).

- **[PATCH-13]** The series MUST add a sim precise (fixed-shift) icount mode whose
  instruction budget is computed from `QEMU_CLOCK_VIRTUAL` deadlines only, never
  mixing `QEMU_CLOCK_REALTIME` deadlines into the budget; non-sim and
  non-precise modes MUST retain upstream behavior. *Gate:*
  `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.4; satisfies
  [DET-9], [TIME-22], [DET-18] (E3), [INV-7].

### crucible-block-rtc-read — pin the guest realtime-clock base

- **Enforces:** [DET-8], [TIME-20]; eliminates E5 (wall-clock / RTC reads),
  patch-side complement to the launch-time fixed epoch.
- **Mechanism:** ensures the emulated RTC and the value underlying
  `clock_gettime`/`gettimeofday` resolve to a **fixed configured epoch advanced by
  the icount-derived virtual clock**, with no path by which a guest read returns
  host wall-clock. Where an upstream device would consult `QEMU_CLOCK_HOST`, the
  sim path substitutes the icount-derived `QEMU_CLOCK_VIRTUAL` value plus the
  configured epoch (and per-node skew, §[TIME-16]). This is primarily a
  launch-config pin (E5 is `launch + patch`); the patch portion blocks the
  residual host-time read paths.
- **Micro-test:** boot two runs with the same fixed epoch; assert the guest's RTC
  reads and `clock_gettime` results are bit-identical and equal the
  icount-derived value; assert non-sim QEMU reads host time as upstream.
- **Inertness:** [PATCH-3](b) — the substitution is gated on the sim/time-control
  predicate; non-sim RTC reads host time exactly as upstream.
- **Risk:** D.

- **[PATCH-14]** The series MUST ensure every guest-visible realtime/RTC read
  resolves, in sim mode, to the icount-derived virtual clock plus the fixed
  configured epoch (optionally skewed per §[TIME-16]), with no residual path
  returning host wall-clock; non-sim reads MUST be upstream-identical. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-8], [TIME-20], [DET-18] (E5), [INV-7].

### crucible-det-glib-prng — deterministic glib PRNG

- **Enforces:** [DET-21]; eliminates E9 (glib `GRand` drawn from host entropy).
- **Mechanism:** QEMU device models and helpers draw from glib's *global*
  `GRand`, which upstream seeds from host entropy on first use. This patch is a
  **one-line change**: it wires a single `g_random_set_seed(seed)` call — seeded
  from the run seed — into Crucible's deterministic `-seed` handler, so the global
  `GRand` QEMU-internal draws consume (device MACs, IDs, internal randomness that
  lands in device state `T`) is reproducible. It is **not** a broad per-call-site
  reseed: the per-thread / unseeded-context (e.g. I/O / iohandler threads using
  seed 0) and the emulated guest-RNG / `getrandom` fallbacks are the job of the
  separate `crucible-det-getrandom` patch (below), not this one. The seeding is
  gated on the `deterministic` flag set only under sim mode.
- **Micro-test:** in sim mode, two runs produce identical sequences from the
  global `GRand` and identical device MACs/IDs; out of sim mode, `GRand` is seeded
  from host entropy as upstream (probe differs run-to-run).
- **Inertness:** [PATCH-3](b) — the `g_random_set_seed` call runs only when the
  `deterministic` predicate (sim mode) is set.
- **Risk:** D in *class* (it touches entropy), but **small in size/blast-radius**:
  a single seed call in the `-seed` handler, not edits scattered across glib-random
  call sites.

- **[PATCH-15]** The series MUST seed QEMU's glib `GRand` deterministically from
  the run seed in sim mode so QEMU-internal random draws (device MACs/IDs,
  internal randomness in `T`) are reproducible; out of sim mode the host-entropy
  seeding MUST be unchanged. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-21], [DET-18] (E9), [INV-7].

### crucible-det-getrandom — deterministic guest-random / hardware RNG

- **Enforces:** [DET-21], [DET-19]; eliminates E9 (QEMU's
  `qemu_guest_getrandom` host-entropy fallback under sim).
- **Mechanism:** preserves QEMU's `-seed` deterministic guest-random path and
  adds a sim-only fail-closed guard for unseeded `qemu_guest_getrandom`, before
  the host-crypto fallback can run. Combined with `crucible-det-glib-prng`,
  seeded sim runs draw from the run-seed-derived GLib stream; unseeded sim runs
  must provide `-seed` instead of silently using host entropy.
- **Micro-test:** seeded draws produce identical guest-random streams with zero
  host entropy calls; sim without `-seed` fails closed before host crypto; non-sim
  unseeded random remains the upstream host-crypto path.
- **Inertness:** [PATCH-3](b) — guarded by `current_accel_name() == "sim"` and
  only reached when `-seed` has not selected QEMU's deterministic path.
- **Risk:** D.

- **[PATCH-16]** The series MUST route QEMU's guest-random / hardware-RNG entropy
  through a deterministic, run-seed-derived stream in sim mode when `-seed` is
  provided, and MUST fail closed before host crypto if sim guest-random is used
  without `-seed`; out of sim mode the unseeded host-entropy path MUST be
  unchanged. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.4;
  satisfies [DET-21], [DET-19], [DET-18] (E9), [INV-7].

### crucible-net-deterministic — icount-timed network delivery

- **Enforces:** [DET-11], [DET-13]; eliminates E18 (network arrival timing)
  partially on the QEMU side (the rest is the scheduler + transport).
- **Mechanism:** adds a plugin-callable **frame-injection** entry point
  (`qemu_plugin_net_inject`) plus lossless queue/flush helpers
  (`qemu_plugin_net_send`, `qemu_plugin_net_flush`,
  `qemu_plugin_net_can_receive`) so an inbound frame is either delivered
  directly at the plugin's chosen virtual-time moment or appended to QEMU's
  incoming queue and made architecturally visible only when the plugin flushes
  at that moment. Delivery is therefore a pure function of icount, not "as it
  arrives on a socket."
- **Micro-test:** inject the same frame at the same delivery icount under skewed
  producer timing across two runs; assert the guest observes it at the identical
  icount.
- **Inertness:** [PATCH-3](c) — a new plugin-API export that does nothing unless
  the plugin calls it.
- **Risk:** D (timing-determining, though additive).

- **[PATCH-17]** The series MUST provide a plugin-callable network-frame injection
  path that makes an inbound frame visible to the guest at a plugin-chosen
  virtual-time moment (its delivery icount), so RX delivery is a pure function of
  icount and not of socket-arrival timing. *Gate:* `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.4; satisfies [DET-11], [DET-13], [DET-18] (E18),
  [INV-7].

### crucible-rr-quantum-icount — round-robin switch at a pinned node-icount

- **Enforces:** [DET-1], [QEMU-43]; makes multi-vCPU instruction interleaving a
  pure function of icount under single-threaded round-robin TCG.
- **Mechanism:** in the single-threaded round-robin TCG accelerator path, the
  vCPU-switch boundary is normally `rr_quantum` derived adaptively from a
  realtime timer (`QEMU_CLOCK_VIRTUAL_RT`), so how many instructions one vCPU
  retires before the round-robin scheduler switches to the next is
  host-speed-dependent. This patch makes the switch boundary the scenario's
  fixed `rr_switch_quantum` expressed in **node-icount**: the round-robin loop
  switches the current vCPU after exactly `rr_switch_quantum` retired
  instructions (ascending vCPU rotation), never on a realtime tick. The quantum
  is set from the launch configuration (10/[QEMU-43]) and is part of the content
  hash, so the interleaving boundary is byte-identical across runs. Single-vCPU
  (`-smp 1`) is the degenerate case where no switch ever occurs.
- **Micro-test:** boot a 2-vCPU guest under `-accel sim` (single-threaded RR)
  twice under injected host scheduling jitter; assert the vCPU-switch icounts and
  the per-vCPU icount-delta traces are bit-identical; assert that with the
  adaptive realtime quantum (patch reverted) the switch icounts diverge run to
  run; assert `thread=multi` is independently rejected at launch ([QEMU-43]).
- **Inertness:** [PATCH-3](b) — the node-icount switch boundary is taken only in
  the sim round-robin path (`use_icount == ICOUNT_PRECISE` with a plugin holding
  time control); non-sim round-robin TCG uses the upstream adaptive quantum
  verbatim.
- **Risk:** D (it determines the multi-vCPU interleaving; a defect silently
  changes `T` for every multi-vCPU run).

- **[PATCH-44]** The series MUST make the single-threaded round-robin TCG
  vCPU-switch boundary a fixed `rr_switch_quantum` expressed in node-icount in
  sim mode, with an ascending vCPU rotation, so multi-vCPU instruction
  interleaving is a pure function of icount and not of the adaptive/realtime
  `rr_quantum`; out of sim mode the round-robin quantum MUST be upstream-adaptive
  unchanged. The quantum value MUST be supplied by the launch configuration
  (10/[QEMU-43]) and is part of the content hash. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-1], [DET-23], [QEMU-43], [INV-7].

### crucible-det-ipi — deterministic inter-vCPU IPI/SIPI/INIT delivery

- **Enforces:** [DET-1]; closes a multi-vCPU interrupt-timing hole.
- **Mechanism:** under multi-vCPU, one vCPU sending an inter-processor interrupt
  (IPI), startup-IPI (SIPI), or INIT to another vCPU must make that interrupt
  architecturally visible to the target at a **deterministic node-icount**, not
  whenever the host thread happens to dispatch the cross-vCPU notification. The
  patch routes IPI/SIPI/INIT delivery through the sim round-robin loop's
  icount-anchored event path so the target observes the interrupt at the same
  node-icount on every run, synchronously with the round-robin switch boundary
  ([PATCH-44]) rather than on a wall-clock-sensitive bottom-half iteration.
- **Micro-test:** on a 2-vCPU guest, have vCPU0 send an IPI to vCPU1 at a fixed
  point twice under host jitter; assert vCPU1 observes the interrupt at the
  identical node-icount across runs; assert the delivery is gated by the icount
  path, not a realtime callback.
- **Inertness:** [PATCH-3](b) — the icount-anchored delivery branch is taken only
  in the sim round-robin path; non-sim IPI/SIPI/INIT delivery is verbatim
  upstream.
- **Risk:** D (it determines cross-vCPU interrupt timing; a defect changes `T`
  for multi-vCPU runs without an obvious failure).

- **[PATCH-45]** The series MUST make inter-vCPU IPI/SIPI/INIT delivery
  architecturally visible to the target vCPU at a deterministic node-icount in
  sim mode (anchored to the round-robin event path, synchronous with the pinned
  switch boundary [PATCH-44]), so cross-vCPU interrupt timing is a pure function
  of icount; out of sim mode delivery MUST be upstream-identical. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-1], [INV-7], references [PATCH-44].

### crucible-replay-start — deliberately NOT carried

A QEMU determinism toolkit could include scaffolding to make the upstream
**record/replay** subsystem (`-icount ...,rr=record|replay`,
`replay_configure`, the replay event stream) initialize cleanly at `preconfig`
so a run starts from a reproducible replay state. Call this hypothetical patch
`crucible-replay-start`. **Crucible does NOT carry it, by design.**

The reason is [NG-6]: Crucible's determinism model is **not** record/replay. A
run is reproducible because (a) the instruction budget per TB exit is a pure
function of the fixed-shift virtual clock (`crucible-icount-no-realtime`,
[PATCH-13]), (b) every entropy source is eliminated at its source in sim mode
(`crucible-det-glib-prng`/`crucible-det-getrandom`/`crucible-block-rtc-read`,
[PATCH-14]–[PATCH-16]), and (c) every cross-node input is injected at a
plugin-chosen icount through the deterministic transport ([PATCH-17], 13). There
is no recorded event log replayed back into QEMU; reproduction is *re-derivation*
from `(def, seed, schedule)` ([INV-1], 22 §22.8), not playback of a QEMU replay
stream. Carrying replay-start scaffolding would add a second, parallel
determinism mechanism — one that touches the always-compiled `replay/` and
`icount` init paths and would itself need an inertness argument — for zero
capability gain, and risks two determinism models disagreeing.

- **[PATCH-43]** The series MUST NOT carry record/replay-start scaffolding (no
  `crucible-replay-start`-style patch enabling QEMU's `rr=record|replay`
  subsystem): Crucible's determinism is source-elimination + icount + seeded
  injection, never QEMU record/replay ([NG-6]). If a future need for replay-stream
  interop arises it MUST be introduced as a separately-named, sim-gated,
  inertness-argued, micro-tested patch with its own catalog entry — never folded
  silently into the determinism path. *Gate:* `gate:qemu-inert`. *Spec:* §11.4;
  satisfies [NG-6], [INV-7].

## 11.5 Plugin time-control patches (the API surface)

These patches export the plugin-API surface that
[`12-qemu-plugin.md`](12-qemu-plugin.md) calls to own virtual time and to read the
exact next deadline. They are additive exports ([PATCH-3](c)) except where noted.

### crucible-plugin-time-advance — callback-safe virtual-time handoff

- **Enforces:** [TIME-23], [TIME-27]; the foundation of plugin time ownership.
- **Mechanism:** exposes `qemu_plugin_has_time_control()` and the callback-safe
  `qemu_plugin_advance_time_ns(ns)` request, paired with
  `qemu_plugin_register_time_advance_cb()` for completion delivery. The request
  entry point only claims a single outstanding slot and queues work on the
  normal main-loop AioContext. The queued bottom half, outside the originating
  plugin/vCPU callback, advances
  `QEMU_CLOCK_VIRTUAL` and dispatches due virtual timers. A two-stage main-loop
  BH barrier then invokes the registered completion callback after BHs produced
  by those timers. The QEMU-side pending barrier remains armed through that
  callback and is released only after the plugin has committed the matching
  logical-time state, so the RR thread cannot resume in the cross-owner commit
  window. The request path MUST NOT call `main_loop_wait`, `aio_poll`, or
  `aio_bh_poll`.
- **Micro-test:** acquire time control, enqueue a known target, prove the callback
  returns before clock movement, run the queued main-loop work, and prove timer BHs run
  in the normal main loop before the completion callback. Assert that the
  callback still observes the pending barrier and that the barrier is clear
  only after the callback returns. Negative controls reject missing
  ownership/callbacks, overlap, negative targets, and backwards targets with
  explicit status.
- **Inertness:** [PATCH-3](c).
- **Risk:** D (it is the mechanism every other time patch composes with).

### crucible-time-advance-commit-barrier — cross-owner commit fence

- **Enforces:** [TIME-23], [TIME-27], [DET-1], [INV-10].
- **Mechanism:** keeps QEMU's pending flag set while the registered plugin
  completion callback commits its corresponding logical-time state. The sim RR
  loop also checks that flag at TCG-batch entry and continuation boundaries and
  parks on the vCPU halt condition while it is set.
- **Micro-test:** require the plugin completion callback to observe the pending
  flag, then require the flag to clear after callback return. The live block-I/O
  gate additionally fails if raw icount advances between enqueue and completion.
- **Inertness:** all new checks are gated by a plugin-owned pending advance, and
  the RR-loop checks are additionally gated by sim mode.
- **Risk:** D.

### crucible-time-advance-enqueue-kick — prompt pending-barrier entry

- **Enforces:** [TIME-23], [TIME-27], [DET-1], [INV-10].
- **Mechanism:** kicks the active sim vCPU immediately after enqueueing the
  main-loop advance bottom half. The kick terminates an already-running TCG
  batch so the RR loop reaches the pending check rather than retiring a stale
  batch after the advance request has claimed its slot.
- **Micro-test:** the live block-I/O gate races host completion against guest
  execution in both directions and requires identical request, completion, and
  delivery coordinates across repeated synchronous and asynchronous runs.
- **Inertness:** the kick occurs only after an explicit plugin time-advance
  request successfully claims the single pending slot.
- **Risk:** D.

### crucible-time-advance-arm-at-vcpu-boundary — synchronous barrier handshake

- **Enforces:** [TIME-23], [TIME-27], [DET-1], [INV-10].
- **Mechanism:** reserves the single advance slot, then uses QEMU's synchronous
  `run_on_cpu` work queue to arm the pending predicate on the vCPU thread. A
  request from another thread therefore returns only after the current TCG
  batch has exited and the vCPU has processed the arm work; a request already
  on that vCPU executes the arm callback directly. The RR loop ignores the
  reserved state and parks only after the arm callback release-publishes the
  armed state.
- **Micro-test:** require one synchronous vCPU-boundary arm per accepted
  request, require overlap rejection while reserved or armed, and require raw
  icount to remain fixed from API return through completion.
- **Inertness:** the work-queue handshake occurs only after an explicit plugin
  request claims the time-control advance slot.
- **Risk:** D.

- **[PATCH-18]** The series MUST export a plugin time-control surface that lets
  the plugin acquire ownership and enqueue one explicit absolute virtual-time
  target across an idle gap. The callback entry point MUST be enqueue-only; the
  actual clock/timer work MUST execute from queued normal-main-loop work and
  completion MUST be handed to a later main-loop callback. The queued work MUST
  remain runnable while a vCPU is blocked on device I/O. The series MUST also export the
  `has_time_control` predicate the warp patch keys on. *Gate:*
  `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.5; satisfies
  [TIME-23], [TIME-27], [INV-8].

### crucible-plugin-advance-barrier — order timer BHs before completion

- **Enforces:** [DET-1], [INV-10]; closes a BH-delivery-drift hole.
- **Mechanism:** the queued advance worker schedules a barrier BH. Because QEMU
  captures a BH-list slice before invoking the barrier, the barrier schedules
  completion onto the next slice; timer-produced BHs already in the current
  slice run first. No callback recursively polls an AioContext. The vCPU remains
  halted until normal QEMU wake/interrupt delivery or the completion callback
  explicitly makes work runnable.
- **Micro-test:** arm a timer whose callback schedules a BH, enqueue an advance,
  and assert the timer BH becomes visible before the plugin completion callback
  and at the same icount. Assert that no nested poll API occurs.
- **Inertness:** [PATCH-3](c) — only runs inside the plugin-called advance.
- **Risk:** D.

- **[PATCH-19]** The queued time-advance path MUST order timer-produced main-loop
  bottom halves before its completion callback using normal AioContext dispatch,
  without synchronously draining or recursively entering the main loop from a
  plugin/vCPU callback. *Gate:* `gate:layer0-determinism`,
  `gate:divergence-bisect`. *Spec:* §11.5; satisfies [DET-1], [INV-10].

### crucible-plugin-device-wake — resume device work from the wake handler

- **Enforces:** [DET-1], [INV-10]; closes an I/O-completion-delivery-drift hole.
- **Mechanism:** the registered scheduler wake fd is owned by QEMU's main
  `AioContext`. It is therefore dispatched by both the outer main loop and the
  nested `aio_poll()` used while synchronous block I/O holds the calling
  thread. After draining it to `EAGAIN`, the handler notifies block and 9p
  consumers. Block request coroutines resume from a locked,
  generation-guarded `CoQueue`; a pending 9p PDU is repolled and completed
  exactly once. The wake event enum and notifier lifetime API live in the internal
  `system/crucible-plugin-wake.h` header installed by the patch. Neither path
  spins, nests the main loop, nor depends on a host-time poll timer.
- **Micro-test:** leave block and 9p requests pending, signal the scheduler wake
  fd, and assert normal-handler resumption, exact-once completion, failure/EOF
  cleanup, and no `main_loop_wait`/`aio_poll`/`aio_bh_poll` call.
- **Inertness:** [PATCH-3](c).
- **Risk:** D.

- **[PATCH-20]** The series MUST deliver scheduler/device completion through the
  normal main-`AioContext` wake-fd handler and event-driven device handoffs. It
  MUST NOT expose or use a plugin call that recursively runs or polls QEMU's
  main loop. *Gate:*
  `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §11.5; satisfies
  [DET-1], [INV-10], references [DET-18] (E19).

### crucible-clock-deadline — exact next virtual-timer deadline (REQUIRED)

- **Enforces:** [TIME-24], [TIME-25]; the clock-deadline capability.
- **Mechanism:** exports `qemu_plugin_clock_deadline_ns()` wrapping QEMU's
  internal `qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL, ...)` so the plugin
  reports the **exact** virtual time of the node's next armed guest timer deadline
  to the scheduler. Also exports `icount_adjust_bias()` helper used by the advance
  path. This is the capability that lets the scheduler jump an idle node directly
  to its next deadline (zero wasted instructions), and it is **REQUIRED**:
  Crucible MUST NOT use the inferior overshoot-and-correct fallback ([TIME-25]).
- **Micro-test:** arm a single virtual timer; idle the guest; assert
  `qemu_plugin_clock_deadline_ns()` returns exactly the timer's deadline (and a
  sentinel "no armed timer" when none is armed); assert the value derives from
  `QEMU_CLOCK_VIRTUAL`, never `QEMU_CLOCK_REALTIME`/`QEMU_CLOCK_HOST`.
- **Inertness:** [PATCH-3](c).
- **Risk:** D (a wrong deadline destroys idle-jump determinism).

- **[PATCH-21]** The series MUST export an **exact next-virtual-timer-deadline**
  query (reading `QEMU_CLOCK_VIRTUAL` only) so the scheduler can compute an exact
  local horizon and jump an idle node directly to its next deadline. The
  overshoot-and-correct fallback MUST NOT be the production mechanism; if this
  capability is unavailable the run MUST fail loudly ([TIME-25]). *Gate:*
  `gate:layer0-determinism`, `gate:scheduler-liveness`, `gate:qemu-inert`. *Spec:*
  §11.5; satisfies [TIME-24], [TIME-25], [TIME-26].

### crucible-plugin-icount-raw — raw icount read

- **Enforces:** [DET-29]; feeds the execution fingerprint.
- **Mechanism:** exports `qemu_plugin_icount_raw()` returning the raw
  instruction counter *without* the bias offset that the ns clock applies, letting
  the plugin distinguish instruction-count drift from bias drift and supplying the
  icount axis the fingerprint and divergence bisection key on.
- **Micro-test:** assert `qemu_plugin_icount_raw()` increases monotonically by the
  retired instruction count and is independent of bias adjustments.
- **Inertness:** [PATCH-3](c).
- **Risk:** F.

- **[PATCH-22]** The series MUST export a raw-icount read (bias-excluded) so the
  plugin can supply the icount axis for the execution fingerprint and divergence
  bisection. *Gate:* `gate:single-vm-fingerprint`, `gate:qemu-inert`. *Spec:*
  §11.5; satisfies [DET-29], references [INV-10].

### crucible-vcpu-introspect — per-vCPU register-file + round-robin cursor read

- **Enforces:** [DET-29]; feeds the N-vCPU execution fingerprint (10/[QEMU-34]).
- **Mechanism:** exports `qemu_plugin_read_vcpu_regs(vcpu_index, ...)` returning
  the architectural register file of an arbitrary vCPU (not only the current one)
  and `qemu_plugin_rr_cursor()` returning the round-robin scheduler cursor — which
  vCPU is current and the position within the pinned `rr_switch_quantum`
  ([PATCH-44]). Together they let the plugin and host compute a black-box
  fingerprint over **all N vCPUs** plus the interleaving state, so two runs that
  differ only in vCPU-switch phase are caught. With `-smp 1` it reduces to the
  single register file plus a trivial cursor.
- **Micro-test:** apply the patch to a 2-vCPU API fixture, read an arbitrary
  non-current vCPU register file and the cursor, and assert the read does not
  perturb `S`/`T` (the read is side-effect-free); assert short output buffers,
  register-size mismatches, invalid vCPU indexes, boundary cursors, zero
  quanta, out-of-range current-vCPU cursors, and no-current-vCPU cursors fail
  closed; assert the patched QEMU binary exports the dynamic symbols and the
  unpatched reference QEMU header does not declare them.
- **Inertness:** [PATCH-3](c) — a new plugin-API export that does nothing unless a
  plugin calls it.
- **Risk:** F (loud failure if a register read is wrong or missing).

- **[PATCH-46]** The series MUST export a per-vCPU register-file read (for an
  arbitrary vCPU index, not only the current one) and a round-robin cursor read
  (current vCPU + position within the pinned `rr_switch_quantum`) so the host can
  compute the N-vCPU execution fingerprint (10/[QEMU-34]) black-box; the reads
  MUST be side-effect-free wrt `S`/`T`. *Gate:* `gate:single-vm-fingerprint`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [DET-29], references [QEMU-34],
  [PATCH-44], [INV-10].

### crucible-sim-observer — observation-only post-execution boundary

- **Enforces:** [DET-29], [PLUG-35]; lets an independent plugin fingerprint the
  exact architectural state reached after a scheduler-controlled execution
  window.
- **Mechanism:** adds a second, observation-only callback beside the single
  scheduler-owned shmem dispatch callback. The RR loop invokes it only after
  `cpu_exec` and icount processing have completed. It finishes before the
  control plugin's release publication makes the boundary visible to the host,
  so evidence cannot race host collection. Registering the observer never
  replaces the ceiling callback and cannot authorize progress.
- **Micro-test:** compile the callback against the patched installed header,
  reject the stock-header negative control, and require the loaded-QEMU coverage
  gate to consume the callback for its post-boundary register, RAM, RR-cursor,
  memory, and device-I/O fingerprint.
- **Inertness:** [PATCH-3](c) — an additive plugin-API export that is inert until
  an auxiliary plugin registers it.
- **Risk:** F.

### crucible-safe-fingerprint-boundary — exact BQL-held capture boundary

- **Enforces:** [DET-29], [PLUG-35]; prevents a requested observation horizon
  from overshooting and keeps complete state capture inside the QEMU lock
  boundary.
- **Mechanism:** clamps the sim execution budget to the next observer ceiling,
  publishes the resulting logical icount only after execution, and invokes the
  observation callback while the BQL is held.
- **Micro-test:** require the exact budget clamp, post-execution notification,
  BQL ordering, and a live non-cadence horizon with zero observed overshoot.
- **Inertness:** [PATCH-3](c) — the observer ceiling and callback are inert until
  an observation plugin registers them.
- **Risk:** F.

### crucible-process-argv-attestation — process-entry raw argv identity

- **Enforces:** [DET-31], [QEMU-34]; lets the observation runner reject a QEMU
  process whose actual Unix argument vector differs from the prepared launch.
- **Mechanism:** hashes the original `argc` and every raw `argv[i]` byte string,
  including `argv[0]` and empty or non-UTF-8 values, before `qemu_init` parses
  options. The system-emulation plugin API exposes only the version, argument
  count, raw-byte count, and SHA-256 digest. The expected digest is never passed
  through plugin argv, avoiding a circular identity.
- **Micro-test:** compare an independently computed launcher digest with a
  loaded patched-QEMU probe, require stock-header rejection, and make the v5
  trace importer reject missing or mismatched attestation evidence.
- **Inertness:** [PATCH-3](c) — capture is read-only and the additive export has
  no guest-visible effect unless an observation plugin queries it.
- **Risk:** F.

### crucible-raw-state-export — GPA-sorted guest-RAM + terminal VMState snapshot

- **Enforces:** [DET-29], [PLUG-47]; lets an observation plugin capture the exact
  guest-visible machine state — physical RAM plus non-RAM device VMState — for the
  final fingerprint without a guest-side agent.
- **Mechanism:** exposes GPA-sorted enumeration and exact copy of guest-RAM
  regions, plus a terminal one-shot serialized non-RAM VMState snapshot
  (begin/size/copy/free) captured while the machine is paused at a requested
  boundary. The system-emulation plugin API exports only read-only accessors.
- **Micro-test:** require the GPA-sorted RAM region export, the exact RAM copy,
  and the terminal VMState snapshot lifecycle exports, with a stock negative
  control proving the exports are absent on unpatched QEMU.
- **Inertness:** [PATCH-3](c) — the exports are read-only and additive, with no
  guest-visible effect unless an observation plugin queries them.
- **Risk:** F.

### crucible-preemption-inject — commanded vCPU switch / interrupt delivery

- **Enforces:** [DET-1], [PLUG-50]; makes the vCPU-switch + interrupt timing an
  explorable, plugin-applied decision.
- **Mechanism:** exports
  `qemu_plugin_inject_preemption(at_icount, deadline_icount, ceiling_icount, kind, ...)`
  letting the time-controlling plugin force a round-robin vCPU switch or deliver
  an interrupt to a target vCPU at a **commanded node-icount**, so the scheduler's
  `Decision::Preemption` (08) can be applied deterministically. The injection is
  anchored to the same icount-driven round-robin event path as [PATCH-44]/[PATCH-45],
  so a commanded preemption lands at exactly the requested icount on every run. A
  commanded icount outside the authorized `[deadline, ceiling]` window MUST be
  rejected by the export (the plugin fails loud, [PLUG-50]); the export never
  silently clamps or defers.
- **Micro-test:** command a vCPU switch (and separately an interrupt) at a fixed
  in-window icount on a 2-vCPU guest twice under host jitter; assert the switch /
  interrupt occurs at the identical icount across runs; assert an out-of-window
  command is rejected with a distinct error rather than applied.
- **Inertness:** [PATCH-3](c) — a new plugin-API export inert unless the plugin
  calls it.
- **Risk:** D (it determines interleaving when exploration is active; a defect
  changes `T`).

- **[PATCH-47]** The series MUST export a plugin-callable preemption-injection
  path that forces a round-robin vCPU switch or delivers an interrupt at a
  commanded node-icount (anchored to the icount round-robin event path of
  [PATCH-44]/[PATCH-45]) so the scheduler's `Decision::Preemption`
  (12/[PLUG-50]) is applied deterministically; a commanded icount outside the
  authorized `[deadline, ceiling]` window MUST be rejected loudly, never clamped
  or deferred. *Gate:* `gate:layer1-injection`, `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [DET-1], [INV-7], [INV-10],
  references [PLUG-50], [PATCH-44].

### crucible-plugin-vcpu-exit — force vCPU exit (phase normalization)

- **Enforces:** [DET-1], [INV-10]; normalizes the first-exit phase.
- **Mechanism:** exports `qemu_plugin_force_vcpu_exit()` setting `cpu->exit_request`
  on the current vCPU. The plugin calls it at vCPU init so the first
  `tcg_cpu_exec` always starts with `exit_request = 1`, deterministically.
  Without it, the initial `exit_request` is wall-clock-sensitive on a
  later-spawned VM, locking two runs into opposite phases of the exit/run
  alternation — a persistent one-call offset that cascades into guest-visible
  divergence. (Complemented by `crucible-sim-first-exit`, §11.8, for the
  first-spawned VM where the CPU may not yet exist at plugin init.)
- **Micro-test:** spawn a VM under sim mode twice with skewed startup timing;
  assert the first-`tcg_cpu_exec` `exit_request` phase is identical across runs.
- **Inertness:** [PATCH-3](c).
- **Risk:** D.

- **[PATCH-23]** The series MUST export a force-vCPU-exit call the plugin uses to
  normalize the first-exit phase across runs so the exit/run alternation cannot
  lock into opposite phases on a later-spawned VM. *Gate:* `gate:layer0-determinism`,
  `gate:divergence-bisect`. *Spec:* §11.5; satisfies [DET-1], [INV-10].

### crucible-plugin-wake-fd — cross-process wake-fd into the main loop

- **Enforces:** [SHM-26], [INV-8]; integrates the cross-process wake.
- **Mechanism:** exports `qemu_plugin_crucible_single_threaded_rr()` as a live
  proof that the sim accelerator is active with MTTCG disabled, plus
  `qemu_plugin_register_wake_fd(fd)` (rejects blocking descriptors, registers a
  nonblocking eventfd or pipe on QEMU's main `AioContext`,
  accepts idempotent registration of the same descriptor but rejects replacement
  by a different descriptor while the owner is live,
  drains it through `EAGAIN`, synchronously notifies registered QEMU device
  consumers, and reports+unregisters EOF or hard errors). Registration on the
  main `AioContext` is essential: a synchronous block request can enter a
  nested `aio_poll()` while waiting, and that poll must be able to drain the
  scheduler wake and resume the block coroutine. The sim RR loop parks the
  first vCPU with `qemu_cond_wait_bql(first_cpu->halt_cond)`, whose atomic BQL
  release-and-wait lets normal QEMU event dispatch continue. After draining a
  scheduler wake, the handler kicks that vCPU. No plugin callback enters
  `main_loop_wait` or `aio_poll`; QEMU retains event-loop ownership and the
  scheduler remains the single wake authority of [INV-8].
- **Micro-test:** register a nonblocking wake fd, exercise interrupted and short
  reads through the terminal `EAGAIN`, and assert device notifiers and the vCPU
  kick happen only after the full drain. Assert spurious `EAGAIN` does not kick,
  and EOF or a hard error reports the failure, unregisters the fd, notifies
  pending devices, and requests host-error shutdown. The layer gate separately
  checks that QMP remains serviced while the vCPU is parked.
- **Inertness:** [PATCH-3](c).
- **Risk:** F (loud failure if broken).

- **[PATCH-24]** The series MUST export wake-fd registration on the main
  `AioContext`; its handler drains scheduler wakes, notifies pending device
  consumers, and kicks the vCPU parked on QEMU's BQL condition variable. It
  MUST remain dispatchable from a synchronous block request's nested
  `aio_poll()`, and MUST NOT export or call a blocking main-loop wait from
  plugin or vCPU callbacks. This integrates cross-process wakes and QEMU's own
  fd handlers without transferring event-loop ownership away from QEMU, keeping
  the scheduler the single wake authority. *Gate:* `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [SHM-26], [INV-8].

### crucible-plugin-tcg-exec-cb — TCG-exec callback (coverage)

- **Enforces:** the coverage capability (forward-ref
  [`22-advanced-features.md`](22-advanced-features.md)).
- **Mechanism:** retains `qemu_plugin_register_tcg_exec_cb()` as a
  runtime-toggleable post-`tcg_cpu_exec()` slice hook, and exports
  `qemu_plugin_icount_at_tb_entry()` for the coverage path. The latter observes
  committed icount plus the active RR vCPU's executed reservation without
  committing timer state, subtracts the current TB reservation, and rejects
  execution outside precise single-threaded sim RR. The plugin combines it with
  QEMU's stock TB translation, TB execution, and flush callbacks to obtain the
  guest PC, byte length, exact entry icount, and safe userdata-reclamation point.
- **Micro-test:** QEMU-10 source-order checks prove that the TB reservation is
  subtracted before the stock execution callback and that dynamic callbacks are
  destroyed before the exclusive flush callback. An executable C ABI/arithmetic
  model covers first, chained, refilled-budget, and next-RR-vCPU entry cases. A
  real loaded-plugin execution/fingerprint comparison remains required by the
  coverage tasks.
- **Inertness:** [PATCH-3](c) — the NULL-check is the only always-present cost and
  is in the sim accelerator (already inert outside sim mode).
- **Risk:** F.

- **[PATCH-25]** The series MUST export a TCG-exec callback fired after each
  `tcg_cpu_exec` in the sim accelerator, with zero overhead when unregistered, to
  provide the QEMU-side execution callback boundary without guest
  instrumentation. *Gate:* `gate:qemu-inert`, forward-ref 22. *Spec:* §11.5;
  satisfies coverage capability (22), [INV-7].

## 11.6 Device co-simulation patches (shmem transport)

These patches route block, 9p, and network I/O through the shared-memory rings
([`13-shmem-abi.md`](13-shmem-abi.md)) so I/O completions are first-class
deterministic events ([DET-16], E19). They are new files or new device paths
([PATCH-3](a)) plus additive registration exports ([PATCH-3](c)).

### crucible-blk-shmem — virtio-blk over the shmem SPSC queues

- **Enforces:** [DET-16], [SHM-13]; eliminates E19 (block I/O completion timing)
  on the device side.
- **Mechanism:** adds an async block driver (`block/crucible-shmem.c`) that
  forwards each block request to the coordinator via a plugin-registered callback
  (which enqueues to a shmem SPSC ring) and returns immediately; the coroutine
  parks on a locked queue, and the scheduler wake handler resumes it when the
  response lands in the inbound ring. A wake-generation check closes the
  completion-before-park race, and each handler invocation snapshots the current
  waiters so a still-pending coroutine can requeue without making wake traversal
  spin.
  Completions become visible to the guest at virtual-time-determined points
  rather than at host-timing-dependent ones.
- **Micro-test:** issue a read whose response the harness places in shmem; assert
  the guest receives the exact bytes and the completion is observed at a
  deterministic icount across two runs.
- **Inertness:** [PATCH-3](a) — a new block driver only instantiated when the
  `crucible-shmem` block backend is selected.
- **Risk:** F.

- **[PATCH-26]** The series MUST add a virtio-blk-over-shmem block driver that
  forwards requests to the coordinator through a shmem SPSC ring and delivers
  completions at virtual-time-determined points, so block I/O completion timing is
  deterministic (E19). It MUST be a new driver inert unless selected. *Gate:*
  `gate:layer1-injection`, `gate:abi-conformance`, `gate:qemu-inert`. *Spec:*
  §11.6; satisfies [DET-16], [SHM-13], [DET-18] (E19), [INV-7].

### crucible-blk-shmem-io-fixes — block I/O correctness fixes

- **Enforces:** [DET-16], E19 correctness.
- **Mechanism:** correctness fixes over `crucible-blk-shmem`: corrects the
  poll-response state machine and the sim-loop idle sleep cadence so block
  completions arrive at bounded, reproducible virtual-time offsets and ext4-on-the-
  -guest does not hang cross-run. Folds into the same new files; no upstream path
  changes.
- **Micro-test:** mount an ext4 image over the shmem block driver and run a
  read/write workload twice; assert identical completion icounts and no hang.
- **Inertness:** [PATCH-3](a).
- **Risk:** F (but determinism-adjacent: a regression reintroduces drift).

- **[PATCH-27]** The series MUST include the block-I/O correctness fixes that keep
  shmem block completions at bounded reproducible virtual-time offsets (no
  cross-run hangs, correct poll-response handling). *Gate:* `gate:layer1-injection`.
  *Spec:* §11.6; satisfies [DET-16], [DET-18] (E19).

### crucible-blk-device-completion-advance — advance blocked block I/O

- **Enforces:** [DET-16], [PATCH-27], [PLUG-21], [IO-31].
- **Mechanism:** adds a block-wait registration hook that fires after a pending
  shmem block poll and immediately before its coroutine parks. The time-owning
  plugin combines the published device-completion deadline with the next exact
  timer and scheduler ceiling, then queues the same normal-main-loop virtual-time
  advance used for an idle vCPU. Only after the advance completion callback
  commits logical time does QEMU notify wake-fd-backed device waiters and kick
  the vCPU. If the host response has not physically arrived yet, the request
  parks again at the same logical icount; host timing changes only wall-clock
  wait duration.
- **Micro-test:** require the registration export, pending-poll callback, and
  post-completion waiter notification in the reconstructed patch prefix. The
  live block-I/O gate additionally boots a real guest, services its block request
  at a future delivery icount, and requires progress to the scheduler ceiling
  with identical observations under host load and with the due response's
  physical ring write deliberately delayed in wall time.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the hook runs only for the selected
  `crucible-shmem` driver and only when a plugin registers it; otherwise the
  existing event-driven wait is unchanged.
- **Risk:** D.

### crucible-9p-sync-kick — enter 9p forwarding synchronously

- **Enforces:** [DET-16], [PATCH-29], [PLUG-22], [IO-32].
- **Mechanism:** extends the sim-mode icount ioeventfd selection rule so
  virtio-9p, like virtio-rng, handles the guest's virtqueue kick synchronously
  on the requesting vCPU thread. This pins entry into the existing
  `crucible-9p-shmem` raw-message forwarding path instead of leaving the initial
  kick queued on a host-scheduled main-loop eventfd. Completion remains modeled
  by the 9p I/O sub-node and delivered through the existing wake-fd notifier.
  The separate virtio-blk launch contract sets `ioeventfd=off` only on each
  `crucible-shmem` device, then uses the block-wait completion barrier after the
  synchronous request-observation boundary.
- **Micro-test:** reconstruct the exact QEMU prefix through patch 0039, compile
  and execute the `virtio_pci_ioeventfd_enabled` predicate before and after this
  patch, and require only sim-mode icount virtio-9p to change from asynchronous
  to synchronous. The virtio-rng, virtio-blk, plain-TCG, and sim-without-icount
  results remain unchanged. The live 9p gate additionally boots a mounting
  guest, requires nonzero request and response frames on `SLOT_9P_IO`, closes
  the scheduler ceiling by retirement or a later idle wake, and reproduces
  identical icount-domain observations under host load with a deliberately
  late physical response write.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — outside sim-mode icount the
  upstream ioeventfd predicate is unchanged; other virtio devices are unchanged.
- **Risk:** D.

### crucible-whitebox-guest-write — return synchronous doorbell replies

- **Enforces:** [PLUG-34], [PLUG-51], [GHC-32], [GHC-37].
- **Mechanism:** exports an additive plugin API that writes an exact byte range
  through the current vCPU's debug-memory translation. The white-box callback
  invokes it synchronously before the trapped guest instruction retires, so an
  application-random request can receive its typed reply without introducing an
  asynchronous input or a host-time-dependent wakeup.
- **Micro-test:** reconstruct the exact QEMU prefix through patch 0040 and prove
  the API is absent, apply patch 0041, then exercise the exported function's
  zero-length rejection, successful exact write, and failed out-of-range write.
  The live white-box gate additionally boots a real x86 guest, traps its
  application-random request, writes the authoritative deterministic reply into
  guest memory, and requires the guest to validate and acknowledge that reply.
- **Inertness:** [PATCH-3](c) — this is an additive export reached only when the
  Crucible plugin explicitly calls it from a registered white-box callback.
- **Risk:** F.

### crucible-blk-write-sentinel — explicit pending sentinel for writes/flush

- **Enforces:** [DET-16] correctness.
- **Mechanism:** the block poll callback's return value conflated "success with
  zero payload" (the normal case for writes and flushes) with "no response yet."
  Introduces an explicit `-2` *pending* sentinel distinct from `0` (success, zero
  bytes) and `-1` (error), so a completed write/flush is not mistaken for a
  not-ready poll — which would otherwise hang or mis-time the completion.
- **Micro-test:** issue a write and a flush over the shmem driver; assert the
  zero-length success completes (is not treated as pending) at a deterministic
  icount.
- **Inertness:** [PATCH-3](a).
- **Risk:** F.

- **[PATCH-28]** The series MUST use an explicit pending sentinel in the shmem
  block poll path distinct from zero-length success, so writes and flushes
  complete deterministically rather than being mistaken for not-ready polls.
  *Gate:* `gate:layer1-injection`. *Spec:* §11.6; satisfies [DET-16].

### crucible-9p-shmem — virtio-9p over the shmem queues

- **Enforces:** [DET-16], E19; the 9p file-system transport.
- **Mechanism:** makes the virtio-9p device a **dumb pipe** in sim mode: a
  plugin-registered 9p callback receives raw 9p messages from the virtqueue and
  returns raw responses (no in-QEMU 9p parsing), routing them over a shmem ring to
  a deterministic 9p I/O sub-node ([`15-io-subnodes.md`](15-io-subnodes.md)). The
  device retains at most one pending PDU and repolls it once for each drained
  scheduler-wake readiness event delivered by the main-thread notifier; queue
  processing resumes only after that PDU completes. The upstream internal 9p
  server remains the fallback when callbacks are absent. Patch
  `crucible-9p-sync-kick` additionally makes the sim-mode icount virtqueue kick
  enter this forwarding path synchronously, so host main-loop scheduling cannot
  suppress or delay publication of the initial request.
- **Micro-test:** register a callback that echoes a canned 9p response; assert the
  guest's 9p read returns the exact bytes; assert the completion icount is
  deterministic; assert the internal server is used when no callback is registered.
- **Inertness:** [PATCH-3](c) — the forward path is taken only when a 9p callback
  is registered.
- **Risk:** F.

- **[PATCH-29]** The series MUST add a virtio-9p forwarding path that, when a
  plugin 9p callback is registered, treats the device as a dumb pipe routing raw
  9p messages over a shmem ring to a deterministic 9p sub-node; with no callback
  registered the upstream internal 9p server MUST be used unchanged. *Gate:*
  `gate:layer1-injection`, `gate:qemu-inert`. *Spec:* §11.6; satisfies [DET-16],
  [DET-18] (E19), [INV-7].

### crucible-dev-cb-api — register block / 9p device callbacks

- **Enforces:** [PLUG], [SHM-17]; the registration surface.
- **Mechanism:** the plugin-API exports
  (`qemu_plugin_register_blk_cb`, `qemu_plugin_register_9p_cb`) by which the plugin
  hands the device paths their shmem-routing callbacks. Inert until called.
- **Micro-test:** register and unregister each callback; assert the device path
  switches between shmem-forwarding and upstream behavior accordingly.
- **Inertness:** [PATCH-3](c).
- **Risk:** F.

- **[PATCH-30]** The series MUST export the plugin-API registration calls for the
  block and 9p shmem-forwarding callbacks; with no callback registered each device
  MUST behave as upstream. *Gate:* `gate:qemu-inert`, `gate:abi-conformance`.
  *Spec:* §11.6; satisfies [PLUG], [SHM-17], [INV-7].

### crucible-net-tx-callback — intercept guest network TX

- **Enforces:** [DET-18], [SHM-17]; the TX side of the network transport.
- **Mechanism:** exports `qemu_plugin_register_net_tx_cb()`. When registered,
  every frame the guest sends is delivered to the callback (which routes it to the
  shmem SPSC ring `(vm -> SLOT_NET_ROUTER)`) instead of the socket backend, so
  outbound frames enter the deterministic router rather than a host socket.
- **Micro-test:** register a capturing callback; have the guest send a frame;
  assert the callback receives the exact frame and the socket backend does not.
- **Inertness:** [PATCH-3](c).
- **Risk:** F.

- **[PATCH-31]** The series MUST export a TX-intercept callback that routes every
  guest-sent frame to the plugin (for shmem-ring delivery) instead of the socket
  backend when registered; with no callback the socket backend is used as
  upstream. *Gate:* `gate:layer1-injection`, `gate:qemu-inert`. *Spec:* §11.6;
  satisfies [DET-18] (E18), [SHM-17], [INV-7].

### crucible-net-flush-api — lossless RX inject + flush

- **Enforces:** [DET-18]; the RX side correctness.
- **Mechanism:** the naive inject path (`qemu_receive_packet`) silently drops
  frames when the receiver (virtio-net) is momentarily unready — nondeterministic
  loss. The QEMU-side append/flush primitives are introduced by
  `crucible-net-deterministic`: `qemu_plugin_net_send` appends to QEMU's
  incoming queue through a callback-backed lossless append helper,
  `qemu_plugin_net_flush` drains that queue with an observable success/failure
  result, and `qemu_plugin_net_can_receive` is diagnostic. This item completes
  the end-to-end co-sim integration around those primitives: the plugin flushes
  at the start of each idle callback, then injects, so backpressure buffering
  lives in QEMU's queue and the harness inbox stays focused on virtual-time
  scheduling.
- **Micro-test:** inject a frame while the receiver is momentarily unready; assert
  it is not dropped and is delivered at the chosen icount when flushed; two runs
  agree.
- **Inertness:** [PATCH-3](c).
- **Risk:** D (it determines RX delivery timing; a regression reintroduces
  nondeterministic loss).

- **[PATCH-32]** The series MUST provide lossless RX injection (queue + flush)
  so an inbound frame is never silently dropped when the receiver is momentarily
  unready, and is delivered at the plugin's chosen virtual-time moment; backpressure
  buffering MUST stay in QEMU's queue. *Gate:* `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.6; satisfies [DET-18] (E18).

## 11.7 Guest↔host channel: no new patch required

The white-box guest↔host channel ([`16-guest-host-channel.md`](16-guest-host-channel.md))
needs a synchronous **doorbell**: a trapped instruction the guest executes to
signal the plugin. The question this file answers is whether the patch series must
add a doorbell mechanism.

- **[PATCH-33]** The guest↔host doorbell ([`16-guest-host-channel.md`](16-guest-host-channel.md))
  MUST be implemented by **reusing an existing QEMU trap surface** — a reserved
  port-I/O write or an MMIO write to a fixed address — observed via the plugin's
  existing memory-access / instrumentation callbacks, plus the plugin's
  memory-read API to fetch the payload. The series MUST NOT add a bespoke
  trapped-instruction patch unless a spike proves the existing trap + plugin-read
  path cannot deliver a *synchronous, deterministic* doorbell. Whether a patch is
  required at all is therefore **NO** by default; any patch added here is gated on
  that spike and MUST be inert and white-box-only. *Gate:* `gate:qemu-inert`,
  forward-ref 16. *Spec:* §11.7; satisfies [INV-7], coordinates with [GHC].

The rationale: a reserved port-I/O write already traps to QEMU deterministically
at a defined instruction boundary under `-icount`, and the plugin already has the
memory-access callback and memory-read API to observe it and read the payload.
Adding a new trapped-instruction patch would be a determinism-critical edit to a
hot path for no capability gain. The white-box channel is OPT-IN ([G-3], [DET-17])
and MUST NOT perturb determinism whether enabled or not, so reusing the inert
plugin-callback surface is strictly preferable to a new patch.

## 11.8 TCG sim correctness / performance patches

These patches refine the sim accelerator (§11.4's `crucible-sim-accel`) for
correctness and performance. Correctness patches that affect timing are
determinism-critical; pure performance patches must be **determinism-preserving by
construction** (fixed iteration counts, never wall-clock-gated). Diagnostic-only
patches are dev-only and **not shipped**.

### crucible-sim-loop-fix — single-vCPU sim-loop fixes (D)

- **Enforces:** [DET-1], [NG-1]. Operates on `first_cpu` directly (sim mode is
  `-smp 1`, [NG-1]) instead of the `CPU_NEXT` iteration that returns NULL on the
  second call for a single CPU and makes `exit_request` bookkeeping fragile;
  resets pending `exit_request` deterministically each loop iteration.
- **Micro-test:** run a single-vCPU guest twice; assert identical loop-iteration
  `exit_request` bookkeeping and identical icount trace.

### crucible-sim-first-exit — normalize first-exit phase (D)

- **Enforces:** [DET-1], [INV-10]. Forces `cpu->exit_request = 1` on the very
  first sim-loop iteration before `tcg_cpu_exec`, so both runs always have
  `delta = 0` on call #0 and enter the same exit/run alternation phase.
  Complements `crucible-plugin-vcpu-exit` (§11.5) for the first-spawned VM where
  `qemu_get_cpu(idx)` may return NULL too early in CPU setup.
- **Micro-test:** spawn the first VM twice with skewed startup; assert identical
  first-call phase.

### crucible-sim-skip-second-events — drop the redundant second events pass (D)

- **Enforces:** [DET-1] (and perf). Removes the redundant no-work
  `sim_process_events()` call after `sim_wait_io_event()`: the plugin's
  time-control advance already fires virtual-clock timers inline, so timers are
  dispatched before control returns to the loop; the AIO/GLib polls the second
  call would do happen on the next iteration anyway. The pass still runs when a
  CPU has queued work, stop, or unplug state, so QMP quit and process
  termination remain serviced.
- **Micro-test:** assert the per-exec timer-dispatch behavior is unchanged
  (bit-identical icount trace) with the no-work second pass removed, and that
  pending CPU lifecycle work still reaches `qemu_wait_io_event_common`.

### crucible-sim-poll-immediate — wake-driven shmem completion (D)

- **Enforces:** [DET-13], E19. A pending shmem block request parks on a `CoQueue`.
  QEMU's main-`AioContext` scheduler-wake handler snapshots and resumes the
  current waiters, which re-poll and requeue if still pending. A mutex plus
  monotonically increasing wake generation prevents a scheduler wake racing
  between poll and park from being lost. Wake-fd failure resumes all waiters
  with `-EIO`. No device, plugin, or vCPU callback enters or polls the main
  loop.
- **Micro-test:** assert a pending request parks once, a normal scheduler wake
  resumes and re-polls it, a wake immediately before park is observed through
  the generation check, and a terminal wake failure releases the waiter.

### crucible-sim-batch-tcg-exec — batch TCG exec calls (F, perf)

- **Enforces:** PERF, **determinism-preserving**. Batches up to a *fixed* N
  `tcg_cpu_exec` calls per outer-loop iteration to amortise per-iteration overhead.
  Determinism is preserved by: a fixed N (not wall-clock gated); breaking on
  `EXCP_HALTED` (so the plugin idle callback advances virtual time);
  breaking on `EXCP_DEBUG`/`EXCP_ATOMIC`; a per-iteration shmem TB-sync check
  (publish `current_ns`, spin at the `max_advance` ceiling); and
  `qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)` between iterations.
- **Micro-test:** run a workload with batching on and off; assert **bit-identical**
  icount traces (perf differs, determinism does not).
- **Risk:** F — but because it touches the hot loop, its micro-test MUST be the
  bit-exact cross-run diff, not merely a perf measurement.

### crucible-sim-idle-callbacks — idle / resume callback wiring (D)

- **Enforces:** [TIME-24], [INV-8]. Wires the vCPU idle/resume callbacks so that
  when all CPUs idle, the plugin's idle callback fires (where it reads the exact
  next deadline and advances virtual time), then control returns to the main loop
  so timer callbacks that may unhalt the CPU are processed by the deadline handler.
  This is the glue that lets a time-controlling plugin own idle advancement
  ([INV-8]) rather than the upstream warp.
- **Micro-test:** idle the guest; assert the plugin idle callback fires exactly
  once per idle transition and that an armed timer wakes the CPU at the
  deterministic deadline.

### crucible-sim-shmem-dispatch — shmem co-sim dispatch glue (F)

- **Enforces:** [SHM-1]. A small dispatch stub (`tcg-accel-ops-sim-shmem.c`)
  connecting the sim accelerator to plugin-owned shmem callbacks for per-node
  clock publish / ceiling read, so the accelerator participates in the SPSC
  handshake of [`13-shmem-abi.md`](13-shmem-abi.md) §13.6 while the plugin owns
  the actual ABI acquire/release operations.
- **Micro-test:** assert the bridge is inert until callbacks are registered, then
  publishes `current_icount`, clamps the per-run TCG budget to
  `max_advance_icount`, and parks on the scheduler wake path when no registered
  budget remains.

- **[PATCH-34]** The sim-correctness patches (`crucible-sim-loop-fix`,
  `crucible-sim-first-exit`, `crucible-sim-skip-second-events`,
  `crucible-sim-poll-immediate`, `crucible-sim-idle-callbacks`,
  `crucible-sim-shmem-dispatch`) MUST each preserve or repair instruction-level
  determinism, MUST extend only the sim accelerator files (inert outside sim mode,
  [PATCH-3](a)), and MUST carry a bit-exact cross-run micro-test. *Gate:*
  `gate:layer0-determinism`, `gate:layer1-injection`, `gate:qemu-inert`. *Spec:*
  §11.8; satisfies [DET-1], [TIME-24], [DET-13], [SHM-1], [INV-7], [INV-10].

- **[PATCH-35]** Any pure-performance patch (e.g. `crucible-sim-batch-tcg-exec`)
  MUST be **determinism-preserving by construction** — fixed iteration bounds,
  never wall-clock-gated, with the same per-iteration ceiling/timer discipline —
  and its micro-test MUST be a **bit-identical cross-run icount diff** (with
  batching on vs off), not a performance measurement. A perf patch that changes
  any guest-visible icount is a determinism defect. *Gate:* `gate:layer0-determinism`,
  `gate:single-vm-fingerprint`. *Spec:* §11.8; satisfies [DET-1], [INV-10].

- **[PATCH-36]** Diagnostic-only patches (`crucible-tcg-exec-diag` — per-exec
  icount tracing; `crucible-virtserial-socket` — raw serial socket framing for
  white-box debugging) are **dev-only and MUST NOT be applied in the shipped AOS
  QEMU package** ([PATCH-10]). In a developer build they MUST be inert by default
  (compiled out or behind an explicit `diag=` plugin arg) and MUST NOT alter
  guest-visible icount when off. *Gate:* `gate:qemu-inert`, forward-ref 24, 26.
  *Spec:* §11.8; satisfies [INV-7], [INV-10].

### crucible-sim-freeze-warp-at-observation-boundary — freeze virtual time at the capture boundary (D)

- Once the sim guest is clamped at the observer's max-advance boundary (the
  terminal target icount) it cannot retire instructions, so QEMU treats it as
  idle and `icount_start_warp_timer` advances `qemu_icount_bias` to the next
  virtual-timer deadline in multiple steps — a large warp plus a 1 ns tail warp
  to the PIT deadline. The terminal snapshot is *requested* at the boundary but
  *captured* asynchronously after the pause, so it lands after a **variable**
  number of tail warps: `qemu_icount_bias` (carried in the timer/icount VMState)
  differs by ~1 ns run-to-run and the device-state fingerprint flaked ~11-28%.
  Evidence: per-warp logs showed one ordinal doing two warps at icount=50001
  (deadline 27412699 then deadline 1) while another did one.
- The patch adds a sim-only clamp gate at the top of `icount_start_warp_timer`
  (guarded by patch 0004's sim/time-control predicate): when the sim observer is
  registered and the raw icount has reached the observer max-advance, it notifies
  the virtual clock and returns without advancing the bias. This **redefines the
  terminal capture point**: virtual time is *frozen* at the boundary. The choice
  is freeze-at-boundary, **not** drain-to-quiescence — a clamped guest's idle
  warps never terminate (they step through timer period after timer period), so
  they are artifacts of the observation clamp, not genuine waits; freeze is the
  only well-defined semantics and it captures the genuine execution-derived bias.
- Latent-leak note: the registers happened to be equal in today's runs, but a
  guest clock read could capture the stray 1 ns — this is a real determinism bug,
  not gate pedantry. Confirmed: 15/15 cache-busted runs at zero divergence versus
  the 11-28% baseline. **Depends on `crucible-safe-fingerprint-boundary` (0034)**,
  which introduces the `crucible_sim_observer_*` helpers this gate reads; note the
  cross-patch dependency for drop-one attribution. *Gate:* `gate:qemu-inert`,
  forward-ref phase-2 fingerprint gates. *Spec:* §11.8; enforces [DET-8], [DET-29].

### crucible-sim-gate-rr-kick — omit the stock round-robin kick timer in sim (D)

- The stock TCG round-robin kick timer (`rr_start_kick_timer` / `rr_kick_thread`,
  a 100 ms `TCG_KICK_PERIOD`, created only for ≥2 vCPUs) is redundant in sim mode,
  which rotates vCPUs deterministically via `rr_switch_quantum`. The patch
  sim-gates `rr_start_kick_timer` with an early return so the virtual-timer arm
  set is deterministic (evidence: with it gated, per-arm logs are byte-identical
  across ordinals). This alone did **not** fix the terminal fingerprint —
  `crucible-sim-freeze-warp-at-observation-boundary` (0037) is the root fix; this
  held cleanup is bundled with it. *Gate:* `gate:qemu-inert`. *Spec:* §11.8;
  enforces [DET-30].

### crucible-translation-prefetch-helper — off-by-default demand translation helper (F, perf)

- **Enforces:** [PERF-32], **determinism-preserving admission required**. At a
  demand translation miss, the RR vCPU remains stopped while a dedicated,
  registered TCG helper context runs `tb_gen_code`; the requesting vCPU waits
  synchronously for that exact translation result before continuing.
- **Micro-test:** reconstruct the exact QEMU prefix through patch 0045, prove
  the helper source is absent, apply patch 0046, and require the helper entry
  point. The real translation-heavy cold-boot gate then runs the packaged QEMU
  with the helper off and on, requires more than 100 completed translation
  requests, and compares fingerprints and canonical boundary logs bit-for-bit.
- **Inertness:** the experiment is off by default. Off mode does not start the
  helper thread and retains the original `mmap_lock` / `tb_gen_code` demand
  translation path.
- **Risk:** F — admission remains blocked on any divergence, and the helper
  stays disabled by default even after a green neutrality proof. *Gate:*
  `gate:perf-bench`, `gate:single-vm-fingerprint`. *Spec:* §11.8; satisfies
  [PERF-32], [INV-10].

## 11.9 The regeneration / rebase pipeline and CI gates

The series must stay applicable, buildable, and correct against the pinned QEMU,
and the committed patch files must be reproducible from the development branch.

- **[PATCH-37]** Crucible MUST provide a **regeneration pipeline** that produces
  the committed `crucible-*.patch` files from the tracked development branch (the
  ordered single-purpose commits, [PATCH-7]) against the pinned QEMU tag,
  deterministically (stable author/date/ordering so the bytes are reproducible).
  CI MUST regenerate the series and fail if the committed files differ from the
  regenerated ones (drift detection). *Gate:* `gate:patch-microtests`,
  forward-ref 26. *Spec:* §11.9; satisfies [DET-35], [PKG].

- **[PATCH-38]** CI MUST run, for the pinned QEMU version, the per-patch pipeline:
  (1) the series **applies cleanly** in order; (2) the patched tree **builds**;
  (3) **every per-patch micro-test passes** ([PATCH-4]); (4) **`gate:qemu-inert`**
  proves non-sim behavior is upstream-identical ([PATCH-2]); (5) the
  **`gate:patch-microtests`** aggregate is green. A change to the series, the
  pin, or the generated shmem header ([SHM-4]) MUST re-run all five. *Gate:*
  `gate:patch-microtests`, `gate:qemu-inert`, forward-ref 24, 26. *Spec:* §11.9;
  satisfies [DET-37], [INV-7], [PKG].

- **[PATCH-39]** A bump of the pinned QEMU version is a **re-gated event**: the
  series MUST be rebased onto the new tag, every micro-test re-run, every
  inertness check re-run, and the QEMU build identity re-pinned into the
  reproduction artifact ([DET-35], [DET-40]). A determinism run reproduces only
  against the exact QEMU build that produced it; the build identity MUST be part of
  the artifact. *Gate:* `gate:e2e-determinism`, `gate:qemu-inert`, forward-ref 26.
  *Spec:* §11.9; satisfies [DET-35], [DET-40].

## 11.10 Minimum QEMU version and plugin-API assumptions

The series depends on a baseline plugin-API surface; older QEMU lacks the
time-control primitives the whole design rests on.

- **[PATCH-40]** The series MUST target a **pinned minimum QEMU version of 10.0 or
  later**, which provides the plugin time-control API
  (`qemu_plugin_request_time_control`, `qemu_plugin_update_ns`; available since
  QEMU 9.1) plus the mature plugin instrumentation surface (vcpu idle/resume
  callbacks, memory-access callbacks, the plugin memory-read API) the design
  assumes. The exact pinned tag MUST be recorded in
  [`31-decision-register.md`](31-decision-register.md) and in
  [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md). *Gate:*
  `gate:patch-microtests`, forward-ref 26. *Spec:* §11.10; satisfies [DET-35].

- **[PATCH-41]** The exact next-virtual-timer-deadline query is **not** in
  upstream QEMU's plugin API and is supplied by `crucible-clock-deadline`
  ([PATCH-21]); the design MUST NOT assume an upstream
  `read_next_virtual_timer_deadline`-style call exists. If a future QEMU lands an
  equivalent upstream API, `crucible-clock-deadline` SHOULD be reduced to a thin
  wrapper over it (recorded in the decision register), but the **exact-deadline
  capability remains REQUIRED** ([TIME-25]); the overshoot-and-correct fallback is
  never the production mechanism. *Gate:* `gate:layer0-determinism`. *Spec:*
  §11.10; satisfies [TIME-24], [TIME-25].

- **[PATCH-42]** The series MUST assume the plugin runs `std` blocking I/O on the
  vCPU/main threads (no async runtime inside QEMU) and MUST NOT require any
  plugin-API capability beyond those listed in [PATCH-40] plus the
  Crucible-exported surface enumerated in §11.5–§11.6. A build against a QEMU
  lacking a required capability MUST fail loudly at configure/build time, never
  silently degrade to a nondeterministic fallback. *Gate:* `gate:patch-microtests`,
  `gate:qemu-inert`. *Spec:* §11.10; satisfies [DET-35], [INV-10].

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the QEMU patch series, tracked by [PLAN-3]. They
> populate the QEMU-integration slice of Phase 1 (foundation) and feed
> `gate:qemu-inert` / `gate:patch-microtests`.

- [x] **T-PATCH-1** Establish the rebasable, ordered series against the pinned
  QEMU (≥ 10.0): tracked single-purpose commits, stable `crucible-*.patch` names,
  significant ordering (sim-accel first); require each patch to state its
  determinism invariant/capability in its commit message and the §11.3 catalog,
  classified determinism-critical vs feature; forbid any record/replay-start
  scaffolding in the series. — satisfies [PATCH-6], [PATCH-7], [PATCH-9],
  [PATCH-40], [PATCH-43]; spec §11.1.3, §11.1.4, §11.4, §11.10.
  - Completed by `checks.crucible.phase2.qemuPatchSeries`: the carried stack is
    pinned to QEMU 10.0.0, uses stable `NNNN-crucible-*.patch` filenames, records
    per-patch class/invariant metadata, checks package wiring, and rejects added
    record/replay-start scaffolding.
- [x] **T-PATCH-2** Wire the per-patch CI: apply-clean + build + per-patch
  micro-test + `gate:qemu-inert` + `gate:patch-microtests` aggregate, on every
  series/pin change. — satisfies [PATCH-4], [PATCH-5], [PATCH-8], [PATCH-38];
  spec §11.1.2, §11.9.
  - Completed by `checks.crucible.phase2.gates.patchMicrotests`: the aggregate
    unpacks the pinned QEMU source, applies every carried patch with zero fuzz,
    forces the patched `qemu-crucible` build, requires the patch-series manifest
    gate, and requires every per-patch micro-test result to be keyed to that
    patched QEMU package/version. The isolated-prefix gates prove clean apply,
    warning-clean compilation, source-tree provenance, exported-symbol first
    appearance, and monotonic sim-off opt-in for every prefix. Drop-one attribution
    (`checks.crucible.phase2.gates.patchMicrotests.dropOne`) removes each carried
    patch from the series and observes the result live. It reports a concrete
    source-dependency, build-required, exported-symbol, or focused-semantic
    attribution for every patch in the current carried series. The aggregate rejects composition and
    structural fallback classifications, so a later patch cannot silently make
    an earlier patch's focused effect pass. `gate:qemu-inert` depends on this
    aggregate and supplies the completed upstream-equivalence corpus.
- [x] **T-PATCH-3** Implement `gate:qemu-inert`: run an upstream-equivalent corpus
  against unpatched-pinned vs AOS-patched-sim-off and assert byte-identical
  guest-visible behavior. — satisfies [PATCH-1], [PATCH-2], [PATCH-3]; spec
  §11.1.1, routes [INV-7], [DET-36].
  - Completed by `checks.crucible.phase2.gates.qemuInert`. The gate builds an
    unpatched reference QEMU from the same pinned 10.0.0 source and
    configuration, then runs it against patched `qemu-crucible` with no plugin,
    sim accelerator, or sim flags. Its curated upstream-equivalent corpus covers
    raw boot serial and block/9p/virtio-rng output under upstream TCG
    instruction clocks at the production shift and plain shift zero, QMP
    capability/state introspection, a migration stream, and
    snapshot save/load. These surfaces represent guest execution and device I/O,
    management compatibility, live state transfer, and durable state restore.
    The unmodified stock Linux kernel runs without Crucible-specific boot
    accommodations. Kernel printk timestamps are disabled in the guest command
    line before capture; the complete resulting serial streams are
    byte-compared. The
    marker-only projection is secondary evidence, and a negative control proves
    it could mask a guest-visible change that the raw comparison catches. QMP
    normalization sorts unordered capability collections and excludes only QMP
    transport metadata; migration is compared by full-stream digest, and
    snapshot comparison records the concluded save/load outcomes. The async
    virtio-rng timing residual is closed structurally by
    `phase2-qemu-rng-delivery-inert.nix`.
- [x] **T-PATCH-4** Implement `crucible-sim-accel`: the split vCPU/main
  deterministic TCG sim accelerator (`-accel sim`), inert under other
  accelerators, with a cross-run icount-trace micro-test. — satisfies [PATCH-11];
  spec §11.4 (E14).
  - Completed by `0001-crucible-sim-accel.patch` and
    `checks.crucible.phase1.simAccel`: `-accel sim` registers as a TCG-derived
    accelerator, rejects launch without fixed `-icount shift=N`, disables MTTCG,
    reuses TCG target CPU hooks, and runs a bounded cross-run TB execution trace
    under fixed icount. `checks.crucible.phase2.gates.patchMicrotests` carries
    the per-patch runtime check, while `checks.crucible.phase2.gates.qemuInert`
    verifies sim remains opt-in and inert under the normal patched QEMU surface.
- [x] **T-PATCH-5** Implement the warp/budget determinism patches
  `crucible-no-warp-with-plugin` and `crucible-icount-no-realtime`, each gated on
  its sim predicate with reintroduce-to-red micro-tests. — satisfies [PATCH-12],
  [PATCH-13]; spec §11.4 (E2, E3).
  - Completed by `0003-crucible-icount-no-realtime.patch`,
    `0004-crucible-no-warp-with-plugin.patch`, and their phase1 micro-tests:
    sim precise icount excludes synthetic fast/slow realtime deadlines from TB
    budgets while non-sim precise/adaptive modes retain upstream realtime
    consultation; sim time-control suppresses both sleep-off bias warp and
    sleep-on realtime timer arming while preserving virtual-clock notify, and
    non-sim time-control remains upstream. `checks.crucible.phase2.gates.patchMicrotests`
    exercises both reintroduce-to-red fixtures, and
    `checks.crucible.phase2.gates.qemuInert` verifies the normal patched QEMU
    surface remains inert.
- [x] **T-PATCH-6** Implement `crucible-block-rtc-read`: guest RTC/realtime reads
  resolve to the icount-derived virtual clock + fixed epoch in sim mode only. —
  satisfies [PATCH-14]; spec §11.4 (E5).
  - Completed by `0007-crucible-block-rtc-read.patch` and
    `checks.crucible.phase1.blockRtcRead`: sim initialization forces `rtc_clock`
    to `QEMU_CLOCK_VIRTUAL`, covering direct CMOS RTC reads as well as
    `qemu_get_timedate` and `qemu_timedate_diff`, so guest-visible realtime is
    fixed epoch plus virtual time even when launch parsing initially configured
    a host-backed RTC clock. Non-sim remains upstream host-clock behavior, with a
    stock negative control proving upstream would read host time.
- [x] **T-PATCH-7** Implement the entropy patches `crucible-det-glib-prng` and
  `crucible-det-getrandom`, with reintroduce-to-red micro-tests. — satisfies
  [PATCH-15], [PATCH-16]; spec §11.4 (E9).
  - Completed by `0005-crucible-det-glib-prng.patch`,
    `0008-crucible-det-getrandom.patch`, and the paired
    `checks.crucible.phase1.qemuDeterministicEntropy` /
    `checks.crucible.phase1.qemuDeterministicGetrandom` leaves: the global GLib
    PRNG is seeded from the run seed, guest-random thread seed handoff uses the
    deterministic stream, seeded guest `qemu_guest_getrandom` draws perform zero
    host entropy calls, sim unseeded `qemu_guest_getrandom` fails closed before
    host crypto, and non-sim unseeded guest random remains the upstream
    host-crypto path.
- [x] **T-PATCH-8** Implement `crucible-net-deterministic`: plugin-callable
  icount-timed RX delivery, with a skewed-producer cross-run micro-test. —
  satisfies [PATCH-17]; spec §11.4 (E18).
  - Completed by `0009-crucible-net-deterministic.patch` and
    `checks.crucible.phase1.qemuNetDeterministic`: QEMU exports
    `qemu_plugin_net_inject`, `qemu_plugin_net_send`,
    `qemu_plugin_net_flush`, and `qemu_plugin_net_can_receive`; direct injection
    fails closed when the NIC cannot receive; `qemu_plugin_net_send` appends to
    QEMU's incoming queue without guest-visible delivery even when the NIC is
    ready; flush fails loudly while the NIC is not ready or link-down; skewed
    producer timing observes the same guest-visible delivery icount.
- [x] **T-PATCH-9** Implement the plugin time-control surface
  `crucible-plugin-time-advance` (+ `has_time_control`) and the event-driven
  `crucible-plugin-advance-barrier` / `crucible-plugin-device-wake` handoffs with
  deterministic-propagation micro-tests. — satisfies [PATCH-18], [PATCH-19],
  [PATCH-20]; spec §11.5.
  - Implemented patch slice: `0010-crucible-plugin-time-advance.patch` exports
    `qemu_plugin_has_time_control`, enqueue-only
    `qemu_plugin_advance_time_ns`, and completion registration. The focused
    fixture proves exclusive ownership, overlap/backwards failure, queued
    main-loop work, the two-stage timer-BH ordering barrier, and absence of recursive
    main-loop/AIO polling.
  - The queued advance is now icount-correct. Under `-accel sim` the virtual
    clock is icount-derived and the qtest-only `qemu_clock_advance_virtual_time`
    never converged (its `while (clock < dest)` loop spun the vCPU thread while
    holding the BQL, so completions never ran); `0010` now advances through
    `icount_advance_virtual_time_to_ns`, which moves `qemu_icount_bias` to the
    exact target under the vm_clock seqlock. The Rust plugin's
    completion-callback-driven idle state machine ([PATCH-18]) and the
    advance-barrier handoff ([PATCH-19]) are **live-proven** by
    `checks.crucible.phase2.qemuLivePluginQuantum`: the timer-driven multiboot
    guest idle-jumps through the exact PIT deadline, completion-first, then
    wakes and re-idles below the published ceiling without self-extension — a
    40M-icount O(1) advance that is deterministic run-twice under host load.
    `checks.crucible.phase1.pluginTimeAdvance` models
    the icount clock and asserts the qtest set-based advance cannot converge
    while the bias-bump reaches the target (the regression guard for this class).
  - The `crucible-plugin-device-wake` handoff ([PATCH-20]) is live-proven by
    `checks.crucible.phase2.qemuLiveBlockIo` and
    `checks.crucible.phase2.qemuLive9pIo`: real guest requests enter the reserved
    device rings, the host publishes completions at exact future icounts, the
    plugin holds virtual time while the response is unavailable, and the
    completion wakes the normal main-loop path. Both guests progress after the
    hold clears, including a run with host CPU load and a deliberately delayed
    response. Drop-one runtime probes for patches 0017 and 0019 prove the live
    block and 9p handoffs are patch-attributed rather than supplied by a later
    patch.
- [x] **T-PATCH-10** Implement `crucible-clock-deadline` (exact next
  `QEMU_CLOCK_VIRTUAL` deadline, REQUIRED) and ban the overshoot-and-correct
  fallback; fail loudly if the capability is unavailable. — satisfies [PATCH-21],
  [PATCH-41]; spec §11.5, §11.10.
  - Completed by `0006-crucible-clock-deadline.patch` and
    `checks.crucible.phase1.clockDeadline`: QEMU exports
    `qemu_plugin_clock_deadline_ns`, reading only `QEMU_CLOCK_VIRTUAL` and
    returning an absolute virtual-clock deadline or `-1` when no timer is armed.
    The focused gate verifies the stock negative control, exercises an armed
    virtual-timer queue while the synthetic guest is idle, rejects realtime/host
    sources, proves the install path fails with only the deadline capability
    missing, forbids overshoot-and-correct, consumes the canonical
    `gate:scheduler-liveness` result, and bridges exact deadlines into scheduler
    horizons with ceil icount conversion. `gate:patch-microtests` checks the
    symbol in the built QEMU binary, `gate:layer0-determinism` consumes the
    evidence, and [PATCH-41] records that this required API is Crucible-supplied
    rather than an upstream QEMU plugin assumption.
- [x] **T-PATCH-11** Implement the plugin reads/exits/wakes
  `crucible-plugin-icount-raw`, `crucible-plugin-vcpu-exit`,
  `crucible-plugin-wake-fd`, `crucible-plugin-tcg-exec-cb`, each additive and
  zero-overhead-when-unused. — satisfies [PATCH-22], [PATCH-23], [PATCH-24],
  [PATCH-25]; spec §11.5.
  - Completed by `0011-crucible-plugin-icount-raw.patch`,
    `0012-crucible-plugin-vcpu-exit.patch`,
    `0013-crucible-plugin-wake-fd.patch`, and
    `0014-crucible-plugin-tcg-exec-cb.patch`, with
    `checks.crucible.phase1.pluginRuntimeApis` and
    `gate:patch-microtests`: QEMU now exports `qemu_plugin_icount_raw`,
    `qemu_plugin_force_vcpu_exit`, `qemu_plugin_register_wake_fd`,
    `qemu_plugin_register_tcg_exec_cb`, and the live execution-mode proof
    `qemu_plugin_crucible_single_threaded_rr`; the
    patch-level fixture validates raw icount is bias-independent and
    disabled-safe, forced vCPU exit sets the current CPU's exit request, wake-fd
    registration drains through QEMU's main `AioContext`, including synchronous
    block I/O's nested `aio_poll()`, notifies pending device consumers, and kicks
    the condition-waiting RR vCPU only after the drain; EOF and hard errors
    unregister and request host-error shutdown.
    The TCG exec callback fires after `icount_process_data()` while retaining a
    single disabled NULL-check. The full skewed-startup and QMP-service smoke
    scenarios remain layer-gate evidence rather than claims of this source-level
    fixture. The Rust plugin has typed ABI resolvers for every required export,
    requires the runtime API bundle at install, provides a
    vCPU-init callback body that invokes `qemu_plugin_force_vcpu_exit` when QEMU
    dispatches that callback, registers the wake fd with QEMU before
    `SetupAck(0)`, and calls
    `qemu_plugin_register_tcg_exec_cb` when coverage mode requests the
    exec-slice callback capability.
- [x] **T-PATCH-12** Implement the block co-sim patches `crucible-blk-shmem`,
  `crucible-blk-shmem-io-fixes`, `crucible-blk-write-sentinel` over shmem with
  deterministic-completion micro-tests. — satisfies [PATCH-26], [PATCH-27],
  [PATCH-28]; spec §11.6 (E19).
  - Completed by `0015-crucible-blk-shmem.patch`,
    `0016-crucible-blk-shmem-io-fixes.patch`, and
    `0017-crucible-blk-write-sentinel.patch`, with
    `checks.crucible.phase1.qemuBlockShmem` and `gate:patch-microtests`: QEMU now
    carries a `crucible-shmem` block driver that registers
    `qemu_plugin_register_blk_cb`, forwards read/write/flush requests through
    plugin submit/poll callbacks, yields pending coroutines through
    `aio_co_schedule(...); qemu_coroutine_yield();`, and uses `-2` as the
    explicit pending sentinel so `0` remains zero-length write/flush success. The
    focused fixture compiles the actual patched `block/crucible-shmem.c` from an
    extracted QEMU tree, proves stock QEMU lacks the block callback surface,
    exercises deterministic pending counts for read/write completions, validates
    zero-length flush success, and rejects error, overflow, and out-of-range
    completions. The ext4 guest workload remains later layer-gate evidence rather
    than a claim of this source-level patch fixture. The Rust plugin ABI now
    exposes typed block submit/poll callback signatures plus
    `resolve_qemu_register_blk_cb_symbol()` for the later live block callback
    registration work.
- [x] **T-PATCH-13** Implement the 9p co-sim path `crucible-9p-shmem` and the
  device registration surface `crucible-dev-cb-api`; upstream server used when no
  callback is registered. — satisfies [PATCH-29], [PATCH-30]; spec §11.6 (E19).
  - Completed by `0018-crucible-dev-cb-api.patch`,
    `0019-crucible-9p-shmem.patch`,
    `checks.crucible.phase1.qemuNinePShmem`, and `gate:patch-microtests`: QEMU
    now exports `qemu_plugin_register_9p_cb`, falls back to the upstream 9p
    server unless the burst-start, submit, poll, and burst-done callbacks are all
    registered, and forwards fully registered virtio-9p traffic as raw 9p
    request/response messages. The focused fixture compiles the actual patched
    `hw/9pfs/virtio-9p-device.c`, proves stock QEMU lacks the 9p callback
    surface, exercises burst start/done holding across a two-request queue
    drain, pending poll waits with sentinel `-2`, raw request/response copying,
    duplicate queue-kick deferral, exactly-once burst completion, wake-fd failure,
    callback removal, reset, and unrealize cleanup, shutdown-safe reclamation,
    no-callback notifier inertness, partial-registration fallback, and fail-closed
    oversized request/response plus request-id overflow paths that clear their PDU
    slots before freeing queue elements. A terminal wake event marks and reclaims
    the device request, while the wake-fd owner remains the single authority that
    requests host-error shutdown. This is source-level patch evidence; full guest
    9p mount and layer-1 workload evidence remains a later gate.
- [x] **T-PATCH-14** Implement the network co-sim patches
  `crucible-net-tx-callback` (TX intercept) and complete
  `crucible-net-flush-api` QEMU patch ABI/Rust resolver integration over the
  QEMU-side RX append/flush primitives, with no-loss /
  deterministic-delivery micro-tests. — satisfies [PATCH-31], [PATCH-32];
  spec §11.6 (E18).
  - Completed by `0020-crucible-net-tx-callback.patch`,
    `checks.crucible.phase1.qemuNetTxCallback`,
    `checks.crucible.phase1.qemuNetDeterministic`, and
    `gate:patch-microtests`: QEMU now exports
    `qemu_plugin_register_net_tx_cb`, preserves the upstream backend when no TX
    callback is registered, and routes flat and iov guest TX frames to the
    callback instead of the backend when registered. The focused TX fixture
    proves stock QEMU lacks the callback surface, exercises userdata delivery,
    exact flat/iov frame capture, registered-backend bypass for guest NIC
    senders, non-NIC upstream fallback, oversized iov fail-loud behavior,
    fail-loud callback rejection, and link-down fallback semantics. The RX half
    remains the `qemu_plugin_net_send`/`qemu_plugin_net_flush` lossless queue
    from `crucible-net-deterministic`; the reused RX fixture proves not-ready
    frames are retained until a deterministic flush icount, flush failure is
    loud, and skewed producer host timing does not change guest-visible
    delivery. The Rust plugin now exports typed resolvers for TX callback
    registration and the RX send/flush/can-receive patch symbols; live install
    registration remains owned by the later plugin lifecycle gates.
- [x] **T-PATCH-15** Confirm (or spike) that the guest↔host doorbell needs **no
  new patch**: reuse the existing port-I/O/MMIO trap + plugin mem-read; any patch
  added is white-box-only, inert, and spike-gated. — satisfies [PATCH-33]; spec
  §11.7, coordinates with 16.
  - Completed by `checks.crucible.phase1.qemuDoorbellNoPatch`,
    `checks.crucible.phase0.s5VirtualMemory`, the existing Phase 0 I/O-trap
    plugin evidence, `checks.crucible.phase2.qemuPatchSeries`, and
    `checks.crucible.phase2.gates.patchMicrotests`: no QEMU patch was added,
    for the doorbell path. The pinned QEMU 10.0 plugin header already exposes
    `qemu_plugin_register_vcpu_tb_trans_cb`,
    `qemu_plugin_register_vcpu_mem_cb`, `qemu_plugin_get_hwaddr`,
    `qemu_plugin_hwaddr_is_io`, `qemu_plugin_read_register`, and
    `qemu_plugin_read_memory_vaddr`. The white-box doorbell crate now labels its
    guest-to-host trap capability with those upstream plugin APIs rather than a
    bespoke `qemu_plugin_register_doorbell_trap` or
    `qemu_plugin_guest_memory_read` patch symbol. Phase 0 S5 recorded
    `qemu_plugin_read_memory_vaddr_available=true`,
    `doorbell_surface=phase0_instruction_marker_double`,
    reproducible marker icounts, matching payload bytes, and a side-effect-free
    fingerprint; Phase 0 S2 uses QEMU's existing plugin memory callbacks and
    hardware-address I/O query to observe port I/O. White-box mode still installs
    no trap when disabled, and any future host-to-guest write/reply surface
    remains outside this no-patch guest-to-host decision until a separate
    spike-gated lifecycle item adopts it.
- [x] **T-PATCH-16** Implement the sim-correctness patches
  (`crucible-sim-loop-fix`, `crucible-sim-first-exit`,
  `crucible-sim-skip-second-events`, `crucible-sim-poll-immediate`,
  `crucible-sim-idle-callbacks`, `crucible-sim-shmem-dispatch`) with bit-exact
  cross-run micro-tests. — satisfies [PATCH-34]; spec §11.8.
  - Completed by `0021-crucible-sim-loop-fix.patch`,
    `0022-crucible-sim-first-exit.patch`,
    `0023-crucible-sim-skip-second-events.patch`,
    `0024-crucible-sim-poll-immediate.patch`,
    `0025-crucible-sim-idle-callbacks.patch`,
    `0026-crucible-sim-shmem-dispatch.patch`,
    `checks.crucible.phase1.qemuSimCorrectness`, and
    `gate:patch-microtests`. The patch stack now names the sim-mode loop
    bookkeeping, first-exit normalization, lifecycle-safe redundant-event-pass
    suppression, wake-driven shmem coroutine resumption, idle/resume callback boundary,
    and shmem
    current-icount / max-advance callback bridge plus callback-registration
    guard and per-run budget clamp explicitly. The shared focused
    gate applies the full carried QEMU patch stack against the pinned QEMU
    source, verifies each named sim-correctness surface, runs a focused C
    fixture for the new loop/wake-generation/queued-time-completion/idle/shmem inertness,
    ceiling, and budget-clamp behavior, consumes
    `checks.crucible.phase1.simAccel` for the bit-identical cross-run fixed
    icount TB trace, consumes `checks.crucible.phase1.pluginTimeAdvance` for
    enqueue-only main-loop work and normal-main-loop completion evidence, and publishes one per-patch
    `gate:patch-microtests` result for each T-PATCH-16 patch.
- [x] **T-PATCH-17** Implement `crucible-sim-batch-tcg-exec` as a
  determinism-preserving perf patch (fixed N, ceiling/timer discipline) gated by a
  bit-identical batching-on-vs-off icount diff. — satisfies [PATCH-35]; spec
  §11.8.
  - Completed by `0027-crucible-sim-batch-tcg-exec.patch`,
    `checks.crucible.phase1.qemuSimBatchTcgExec`, and `gate:patch-microtests`.
    The RR loop now uses a fixed four-slot sim-only TCG batch helper while
    retaining the single-exec path outside sim mode. The helper breaks on
    `EXCP_HALTED`, `EXCP_DEBUG`, and `EXCP_ATOMIC`, refreshes virtual timers and
    icount budget between batch slots, reuses the T-PATCH-16 shmem
    max-advance clamp before each slot, and parks on the scheduler wake path at
    the ceiling. The focused C fixture compares batching-on and batching-off
    icount traces, verifies special-exit breaks, confirms timer refresh between
    slots, and exercises the shmem ceiling guard without any wall-clock input.
- [x] **T-PATCH-18** Keep the diagnostic-only patches (`crucible-tcg-exec-diag`,
  `crucible-virtserial-socket`) out of the shipped package and inert-by-default in
  dev builds. — satisfies [PATCH-10], [PATCH-36]; spec §11.3, §11.8.
  - Completed by `checks.crucible.phase1.qemuDiagnosticPatchesDevOnly`,
    `checks.crucible.phase2.qemuPatchSeries`, and `gate:patch-microtests`: no
    shipped QEMU patch was added. The gate asserts that neither
    `crucible-tcg-exec-diag` nor `crucible-virtserial-socket` appears in the
    shipped patch directory or `qemu-crucible` patch application list, records
    `qemu_crucible_dev_variant_present=false`, and treats the optional
    developer-only variant as inert by default because no diagnostic patch is
    compiled or applied unless a future explicit dev package adds one behind its
    own opt-in gate.
- [x] **T-PATCH-19** Implement the regeneration/drift pipeline (reproducible patch
  bytes from the tracked branch) and the QEMU-version-bump re-gate (rebase +
  re-test + re-pin build identity into the artifact). — satisfies [PATCH-37],
  [PATCH-39]; spec §11.9.
  - Completed by `checks.crucible.phase2.qemuPatchRegeneration` and consumed by
    `gate:patch-microtests`: the gate rebuilds the ordered patch stack from the
    checked-in `crucible/qemu-10.0.0` thin git bundle, requires the pinned QEMU
    base commit as its prerequisite, verifies the base/head commits and each
    per-patch commit/tree entry, and requires exactly one DCO `Signed-off-by`
    trailer matching the manifest's authorized human contributor on every patch
    commit. It regenerates canonical
    `--unified=3` patch bytes, including Git blob-identity `index` lines, fails
    on committed-file drift, applies the regenerated series with fuzz disabled,
    and records the QEMU source hash, patch count,
    patch-series hash, patch-branch bundle/material, and QEMU build identity. The
    reproduction-artifact-shaped fixture pins that build identity and rejects a
    deliberate changed-build negative control, making a QEMU pin or patch change
    a re-gated event.
- [x] **T-PATCH-20** Pin and document the minimum QEMU version and the plugin-API
  capability set; fail the build loudly if a required capability is missing. —
  satisfies [PATCH-40], [PATCH-42]; spec §11.10.
  - Completed by `checks.crucible.phase2.qemuPatchSeries` and consumed by
    `gate:patch-microtests`: the QEMU patch manifest pins QEMU 10.0.0 and its
    source hash, every carried patch records its capability/invariant in the
    checked series catalog, the shipped package applies the manifest-generated
    series, and the aggregate gate now consumes
    `checks.crucible.phase2.qemuPluginFailLoud` so missing required QEMU/plugin
    capabilities fail with distinct diagnostics and no wall-clock fallback.
- [x] **T-PATCH-21** Implement `crucible-rr-quantum-icount`: make the
  single-threaded round-robin vCPU-switch boundary the pinned node-icount
  `rr_switch_quantum` (ascending rotation) in sim mode, supplied by the launch
  config; cross-run bit-identical switch-icount micro-test, with the adaptive
  realtime quantum reverting to red. — satisfies [PATCH-44]; spec §11.4.
  - Completed by `checks.crucible.phase2.qemuRrQuantumIcount` and consumed by
    `gate:patch-microtests`: the QEMU patch exposes and clamps
    `rr_switch_quantum` in node-icount units only under `-accel sim`, the launch
    gate hashes the fixed quantum and ascending vCPU rotation while rejecting
    MTTCG and unpinned quantum launches, a bounded S11 multi-vCPU trace runs
    under `-accel sim` to a fixed `stop_at` horizon and diffs plugin-emitted RR
    switch-boundary and per-vCPU icount-delta event traces across a jittered
    second run, and the aggregate gate consumes adaptive and configured-non-sim
    RR switch trace negative controls as red evidence.
- [x] **T-PATCH-22** Implement `crucible-det-ipi`: deterministic inter-vCPU
  IPI/SIPI/INIT delivery at a fixed node-icount via the round-robin event path,
  with a cross-run identical-delivery-icount micro-test on a multi-vCPU guest. —
  satisfies [PATCH-45]; spec §11.4.
  - Completed by `0028-crucible-det-ipi.patch`,
    `0042-crucible-aarch64-det-ipi-adapter.patch`,
    `checks.crucible.phase2.qemuDetIpi`,
    `checks.crucible.phase2.qemuAarch64DetIpiAdapter`, and
    `gate:patch-microtests`: sim-mode
    APIC inter-vCPU FIXED/INIT/SIPI deliveries are queued only when
    `-accel sim`, precise icount, and a pinned `rr_switch_quantum` are active;
    the round-robin handoff path drains the queue before the next vCPU runs;
    the AArch64 adapter maps the same deterministic RR drain and commanded
    preemption callbacks onto the architecture's hard-interrupt path; non-sim,
    unpinned, and self-IPI paths fall through to upstream behavior; and
    the trace plugin records `det_ipi` delivery rows while the bounded
    multi-vCPU S11 fixture diffs INIT/SIPI delivery-icount traces plus an
    opt-in commanded FIXED delivery probe across jittered runs.
- [x] **T-PATCH-23** Implement `crucible-vcpu-introspect`: per-vCPU register-file
  read (arbitrary index) + round-robin cursor read for the N-vCPU fingerprint,
  side-effect-free, additive/inert until called. — satisfies [PATCH-46]; spec
  §11.5.
  - Completed by `0029-crucible-vcpu-introspect.patch`,
    `checks.crucible.phase2.qemuVcpuIntrospect`, and
    `gate:patch-microtests`: QEMU now exports the formal
    `qemu_plugin_read_vcpu_regs` and `qemu_plugin_rr_cursor` plugin APIs while
    preserving the older `qemu_plugin_crucible_*` helpers; the register export
    canonicalizes each named register descriptor/value for an arbitrary vCPU,
    reports required length on short buffers, and fails closed instead of
    truncating; the cursor export returns current vCPU, cursor position, and
    pinned quantum only when a valid in-quantum RR cursor is active; the trace
    plugin consumes the formal exports and the microtest verifies arbitrary-vCPU
    reads, side-effect-free current-CPU behavior, short-buffer and register-size
    mismatch rejection, invalid-vCPU rejection, and cursor
    boundary/zero/out-of-range/no-current negative controls.
- [x] **T-PATCH-24** Implement `crucible-preemption-inject`: plugin-callable
  commanded vCPU switch / interrupt delivery at a node-icount anchored to the
  round-robin event path, rejecting out-of-`[deadline, ceiling]` commands loudly;
  cross-run identical-application micro-test. — satisfies [PATCH-47]; spec §11.5.
  - Completed by `0030-crucible-preemption-inject.patch`,
    `checks.crucible.phase2.qemuPreemptionInject`, and
    `gate:patch-microtests`: QEMU now exports
    `qemu_plugin_inject_preemption` with stable vCPU-switch and interrupt kind
    tags, queues one sim-mode precise-icount RR command, clamps the TCG budget to
    the commanded node-icount, and applies due commands from the same RR boundary
    path. The export receives the inclusive scheduler deadline/ceiling window and
    rejects inactive mode, duplicate commands, malformed operands, invalid
    windows, before-deadline commands, past icounts, and commands beyond the
    scheduler-published shmem ceiling. The microtest applies the real patch stack to pinned QEMU source,
    proves the stock header lacks the symbol, compiles the patched header API,
    and exercises jittered cross-run vCPU-switch and interrupt application plus
    distinct out-of-window rejection.
