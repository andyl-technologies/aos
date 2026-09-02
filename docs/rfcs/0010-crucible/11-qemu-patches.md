# 11 — The QEMU patch series

The carried series contains **155 patches**. This count is checked against
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
  under plain `-icount`, same device enumeration, same migration streams). The
  patched QEMU may expose an explicitly enumerated Crucible host-control command
  when its versioned lifecycle protocol requires one, but the gate MUST prove
  that command fails closed without sim mode, leaves the VM stopped in its
  original run state, and is the complete QMP command-set delta. A patch that
  perturbs any guest-visible or upstream management behavior out of sim mode
  fails the gate. *Gate:*
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
  crucible-serialize-rr-cursor .. authoritative RR cursor VMState D  DET-1, DET-18, INV-10
  crucible-fingerprint-state-domains guest-only state domains D  DET-18, DET-19, INV-10
  crucible-stopped-state-control-progress bounded native-stop wake D  DET-1, INV-10, QEMU-43
  crucible-inactive-retention-clock-guard active-rule-before-clock D  DET-1, QFP-STATE-2, FAULT-ORDER
  crucible-deferred-result-evidence-test typed deferred evidence coverage F  QEMU-44, FAULT-EVIDENCE
  crucible-deterministic-instruction-input-state stable instruction selector identity D  DET-1, QEMU-44, FAULT-EVIDENCE
  crucible-inert-clock-restore preserve native timers for inactive restored clocks D DET-1, QFP-CLOCK-2, QFP-STATE-2

DEVICE CO-SIM (shmem transport)                        class  enforces
  crucible-blk-shmem ............ virtio-blk over shmem      F    PATCH-26, DET-16, E19, SHM-13
  crucible-blk-shmem-io-fixes ... blk I/O correctness        D    PATCH-27, DET-16, E19
  crucible-blk-write-sentinel ... write/flush 0-len sentinel D    PATCH-28, DET-16, E19
  crucible-9p-shmem ............. virtio-9p over shmem       F    PATCH-29, DET-16, E19
  crucible-9p-completion-wake-registration realize-time notifier lifetime D PATCH-20, DET-1, INV-10
  crucible-dev-cb-api ........... register blk/9p callbacks  F    PATCH-30, PLUG, SHM-17
  crucible-net-tx-callback ...... intercept guest TX         F    PATCH-31, DET-18, E18, SHM-17
  crucible-net-direct-inject-api  lossless direct RX status F    PATCH-32, DET-18, E18
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
  crucible-lifecycle-precondition atomic lifecycle VM-state precondition D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
  crucible-typed-node-result-schema fixed typed result and occurrence evidence D QFP-RESULT-1, QFP-EVENT-1, FAULT-ORDER
  crucible-device-wait-vmstop nonblocking exact control/device-completion pause D QFP-STATE-2, DET-1, INV-10
  crucible-accelerator-result-opportunity exact one-shot accelerator result arming F QFP-ACCEL-3, QFP-RESULT-1, QFP-EVENT-1, FAULT-ORDER
  crucible-authenticated-event-request-envelope restored authenticated occurrence requests F QFP-STATE-2, QFP-ACCEL-3, QFP-EVENT-1, FAULT-ORDER
  crucible-inert-clock-restore inactive clock VMState commits retain native device timers D DET-1, QFP-CLOCK-2, QFP-STATE-2

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
- `crucible-net-direct-inject-api` -> `0009-crucible-net-deterministic.patch`

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
  (`qemu_plugin_net_inject`) whose return status distinguishes complete delivery
  from transient guest backpressure and permanent failure. The plugin consumes
  a frame from the bounded shared-memory ring only after complete delivery; a
  backpressured frame remains canonical and checkpoint-visible there for retry
  at a later idle boundary. Each retry clears QEMU's otherwise persistent
  `receive_disabled` hint before re-probing the guest device: that hint normally
  belongs to QEMU's private packet queue, which this canonical path deliberately
  does not use. Delivery is therefore a pure function of icount, not "as it
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
  with identical observations under bounded scheduler preemption and with the due response's
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
  identical icount-domain observations under bounded scheduler preemption with a deliberately
  late physical response write.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — outside sim-mode icount the
  upstream ioeventfd predicate is unchanged; other virtio devices are unchanged.
- **Risk:** D.

### crucible-9p-completion-wake-registration — bind notifier lifetime to the device

- **Patch:** `0076-crucible-9p-completion-wake-registration.patch`.
- **Enforces:** [PATCH-20], [DET-1], [INV-10].
- **Mechanism:** registers the virtio-9p completion-wake notifier whenever the
  device is realized and unregisters it when the device is unrealized. Notifier
  lifetime is therefore owned by the QEMU device, not by whether plugin callback
  registration happened to precede device realization. The notifier remains
  inert until a Crucible-forwarded PDU is pending. At a drained wake it still
  checks that the complete 9p callback family is installed before polling; a
  missing callback family with pending Crucible work fails through the existing
  device-error and shutdown path. No callback is invoked merely by registering
  the notifier.
- **Ordering requirement:** plugin installation may occur before or after
  virtio-9p realization. In either order, once runtime request forwarding is
  admitted, every host response doorbell reaches `virtio_9p_crucible_wake`, the
  response is polled once, and `crucible_9p_finish_burst` releases the shared
  `device_io_active` hold before the scheduler certifies quiescence. Registration
  must not be conditional on the earlier, transient value of
  `crucible_9p_callbacks_ready()`.
- **Micro-test:** reconstruct the patch prefix through 0075 and prove the old
  realize path conditionally registers the notifier; apply 0076 and require
  unconditional add, symmetric unrealize removal, and the retained callback-
  readiness guard in the pending-wake handler. The live 9p gate is the
  integration test: a request submitted after device realization must stop at
  its request icount, consume its deterministic response from a later doorbell,
  clear `device_io_active`, and close the scheduler ceiling in both reference
  and bounded-scheduler-preemption legs.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — stock 9p processing never creates a
  Crucible pending PDU, so the registered notifier observes no work and leaves
  upstream device behavior unchanged when sim forwarding is not installed.
- **Risk:** D.

### crucible-serialize-rr-cursor — restore the exact multi-vCPU continuation

- **Patch:** `0077-crucible-serialize-rr-cursor.patch`.
- **Enforces:** [DET-1], [DET-18], [INV-10].
- **Mechanism:** maintains one authoritative record/replay cursor across normal
  round-robin handoffs and host execution ceilings, serializes that cursor with
  icount VMState, and restores the selected vCPU and intra-turn position before
  any guest instruction can execute. The VMState section has one supported
  version; there is no compatibility reader for the earlier incomplete layout.
- **Micro-test:** checkpoints a nonzero intra-turn cursor in a multi-vCPU guest,
  restores it in a fresh QEMU process, and requires the restored register, RAM,
  device, icount, and cursor fingerprint plus the subsequent replay suffix to
  match exactly. A control that changes only the serialized cursor must fail the
  production restore-admission comparison.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the state is consumed only by
  precise-icount sim execution and migration/checkpoint operations.
- **Risk:** D.

### crucible-fingerprint-state-domains — hash guest-semantic state only

- **Patch:** `0078-crucible-fingerprint-guest-state-domains.patch`.
- **Enforces:** [DET-18], [DET-19], [INV-10].
- **Mechanism:** samples live interrupt state under the BQL without mutating it,
  includes guest-delivery-relevant interrupt bits and all declared architectural
  CPU state, and excludes only target-declared transient scheduler-exit bits.
  x86 canonicalizes `CPU_INTERRUPT_POLL`; the generic target layer canonicalizes
  `CPU_INTERRUPT_EXITTB`. Every other interrupt bit remains fingerprinted.
- **Micro-test:** proves repeated capture is side-effect-free, a fresh-process
  restore produces the same fingerprint before guest execution, guest-visible
  interrupt changes alter the digest, and transient host scheduling exits do
  not. The changed-cursor negative control is recomputed through the same
  canonical black-box fingerprint and rejected by the production runtime.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the helpers are additive and run
  only when the Crucible plugin requests an exact fingerprint boundary.
- **Risk:** D.

### crucible-stopped-state-control-progress — close native-stop wake races

- **Patch:** `0079-crucible-stopped-state-control-progress.patch`.
- **Enforces:** [DET-1], [INV-10], [QEMU-43].
- **Mechanism:** after the serialized RR thread drains host work for every vCPU,
  it rechecks both stop/unplug state and queued vCPU work under the BQL before
  sleeping. It uses a one-millisecond bounded BQL-aware condition wait so a
  non-BQL producer racing with the recheck cannot strand the native VM-stop
  handshake if its condition signal arrived just before the sleep.
- **Micro-test:** requires all three progress guards in the isolated patch,
  proves pristine QEMU lacks them, and consumes the fresh-process exact-snapshot
  gate where the plugin must publish state while the VM remains paused and QEMU
  must finish the native stop/restore control handshake without executing guest
  instructions.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the loop is entered only while a
  Crucible exact-boundary VM-stop request is pending in precise-icount sim mode.
- **Risk:** D.

### crucible-inactive-retention-clock-guard — admit work before reading time

- **Patch:** `0080-crucible-inactive-retention-clock-guard.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [FAULT-ORDER].
- **Mechanism:** `node_memory_retention_boundary()` rejects an inactive memory
  fault domain before it samples QEMU virtual time. Active retention work keeps
  the existing clock, deadline, counter, mutation, and event ordering.
- **Micro-test:** checkpoints a pending node-boundary command, restores it into
  a fresh paused QEMU process with no memory fault rule, and requires the command
  to continue exactly once. Static assertions require the active-rule guard to
  precede `node_virtual_now()`, and the live memory gates remain the positive
  control for active retention timing.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — inactive domains now return before
  a clock read; active-domain behavior is unchanged.
- **Risk:** D.

### crucible-deferred-result-evidence-test — validate typed deferred results

- **Patch:** `0081-crucible-deferred-result-evidence-test.patch`.
- **Enforces:** [QEMU-44], [FAULT-EVIDENCE].
- **Mechanism:** updates the GPL-side live instruction plugin to validate the
  canonical typed node-result evidence added to deferred completions by patch
  0074. Composed commands select the payload bound to their exact command
  sequence before checking the request and evidence digests.
- **Micro-test:** runs the complete patched-QEMU instruction-fault matrix and
  retains its stock-QEMU and non-sim negative controls. The patch-local check
  requires the obsolete empty-evidence assertion to be removed by the diff.
- **Inertness:** [PATCH-3](a) — this changes test code only and adds no runtime
  path.
- **Risk:** F.

### crucible-deterministic-instruction-input-state — stabilize selector identity

- **Patch:** `0082-crucible-deterministic-instruction-input-state.patch`.
- **Enforces:** [DET-1], [QEMU-44], [FAULT-EVIDENCE].
- **Mechanism:** instruction `input_state_sha256` selectors use a versioned
  digest of canonical architecture-register state. PC, exact instruction bytes
  and/or opcode class remain independently bound by the instruction selector.
  Whole RAM and raw non-RAM VMState stay in occurrence evidence and the
  normalized host fingerprint, but are excluded from the QEMU-local selector
  because unrelated RAM and raw device bookkeeping are not canonical
  instruction inputs. A dedicated register-state digest excludes icount and
  round-robin scheduler coordinates while the existing full execution
  fingerprint remains unchanged in occurrence evidence. Both digests are
  derived from one ordered register sample when needed together. The live
  retry fixture arms its naturally faulting load only after the exact-PC rule
  is translated and QEMU confirms commit installation.
- **Micro-test:** captures selector identities in one patched-QEMU process and
  reuses them in a fresh process for single and composed x86-64 and AArch64
  result transforms; the explicit mismatch and stock-QEMU controls remain red.
  The same matrix proves committed retry after a natural guest page fault and
  exhausts all 4,096 event slots without reducing production capacity.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the digest is computed only for an
  admitted instruction rule at its exact safe boundary.
- **Risk:** D.

### crucible-inert-clock-restore — preserve native timers for inert clocks

- **Patch:** `0083-crucible-inert-clock-restore.patch`.
- **Enforces:** [DET-1], [QFP-CLOCK-2], [QFP-STATE-2].
- **Mechanism:** aggregate clock VMState restores each source before deciding
  whether its device timers need Crucible reprojection. If the restored source
  has no rule, source-state fault, accumulated transform, freeze, or
  synchronization, native QEMU device VMState is authoritative and its timers
  are left untouched. Sources with an effective Crucible transform still run
  their device rearm callback. Wander-timer rearm remains unconditional so a
  same-process rollback cannot retain a timer from state newer than the loaded
  checkpoint.
- **Micro-test:** the production two-node live-network world captures an exact
  checkpoint under an empty fault plan, shuts both QEMU processes down, restores
  both nodes into fresh processes, and must complete the first restored quantum
  and the remaining deterministic packet exchange. The existing active-clock
  gates remain the positive control that transformed sources still rearm.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — with no effective clock mutation,
  the patch removes a Crucible callback from restore and leaves upstream device
  VMState authoritative; active fault behavior is unchanged.
- **Risk:** D.

### crucible-exact-restore-network-announcement — keep restored traffic exact

- **Patch:** `0084-crucible-exact-restore-network-announcement.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [FAULT-ORDER].
- **Mechanism:** exposes whether the central VMState deserialization transaction
  is inside a Crucible exact restore. During that transaction only,
  `virtio_net_post_load_device` deletes and clears the migration announcement
  timer instead of synthesizing guest-announcement traffic. A Crucible restore
  returns to the same modeled link and peer population, so a migration-only
  announcement would be an unrecorded frame absent from uninterrupted
  execution. The ordinary QEMU migration branch retains the upstream timer
  reset, immediate scheduling, and deletion behavior byte for byte.
- **Micro-test:** the production two-node live-network world captures an exact
  checkpoint after establishing its deterministic route, terminates both QEMU
  processes, restores both nodes into fresh processes, and requires the first
  restored quantum and the remaining packet exchange to match the uninterrupted
  branch exactly. The per-patch catalog reconstructs the QEMU prefix before
  0084 as the negative control, applies 0084 with zero fuzz, and binds the live
  result to this patch entry.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the new predicate is read only
  during virtio-net post-load, and the changed branch is reachable only while
  Crucible's central exact-load transaction is active. Ordinary migration and
  non-restore execution retain upstream behavior.
- **Risk:** D.

### crucible-register-rejection-atomicity — prove rejected commands are inert

- **Patch:** `0085-crucible-register-rejection-atomicity.patch`.
- **Enforces:** [DET-1], [QFP-REG-1], [QFP-REG-2], [FAULT-EVIDENCE].
- **Mechanism:** live register observation requires exact-boundary depth and an
  exact match between `current_cpu` and the serialized RR owner. Both plugin
  callbacks and every complete internal node/instruction boundary transaction
  own the nestable exact-boundary token. Register read
  and decode revalidate every manifest row for every realized vCPU. Rejection
  transactions hash every vCPU's canonical GDB register export and compare
  counters wired to the production TLB, TB, flags, interrupt, timer, and
  control-flow side-effect paths before reporting a non-applied result. Those
  counters are admitted only inside the thread-local architecture-register
  write scope, preventing unrelated emulator activity from being attributed to
  the mutation under audit; the timer class remains zero because no supported
  register advertises that side effect.
- **Micro-test:** the full x86-64 and AArch64 register matrix proves equal,
  nonzero canonical hashes, unchanged side-effect counters, zero applied
  icount, empty evidence, no emitted event, and unchanged selected-register
  bytes for every delayed rejection. The inconsistent-identity case performs
  the same whole-machine comparison around its reentrant synchronous result.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — observation and counters do not
  mutate guest state; they are consulted only by register-fault validation and
  its live gate. The user-mode hook is inert, and non-Crucible execution does
  not read or branch on the counters.
- **Risk:** D.

### crucible-genesis-observation-boundary — sample the exact prelaunch state

- **Patch:** `0086-crucible-genesis-observation-boundary.patch`.
- **Enforces:** [DET-1], [QFP-REG-1], [QFP-STATE-2].
- **Mechanism:** extends the BQL-held observation callback to admit exactly one
  additional run state: prelaunch while raw icount is zero. The independent
  definition process uses that boundary to read every realized vCPU, RAM, and
  registered device section after machine initialization but before any guest
  instruction. Running and terminal-pause behavior is unchanged; prelaunch
  after execution and every other stopped state fail closed.
- **Micro-test:** launches a real four-vCPU QEMU process with `-S`, waits for
  exactly one complete callback-authorized definition record before QMP quit,
  and requires zero icount, all-vCPU register manifests, and complete nonzero
  RAM and device digests. Stock QEMU is the negative API control.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the new branch is reachable only
  from the additive Crucible callback at exact prelaunch genesis and performs
  observation only. Ordinary QEMU launch and plugin exit retain their existing
  paths.
- **Risk:** D.

### crucible-deterministic-rcu-quiescence — remove host-timed sim exits

- **Patch:** `0087-crucible-deterministic-rcu-quiescence.patch`.
- **Enforces:** [DET-1], [DET-29], [QEMU-43].
- **Mechanism:** the single-threaded TCG forced-RCU notifier retains its
  ordinary `rr_kick_next_cpu()` behavior except when precise Crucible sim mode
  has a nonzero pinned RR quantum. In that bounded mode it does not let a host
  RCU worker asynchronously choose a translation-block exit, because doing so
  can change the guest instruction at which a pending interrupt is observed.
  The finite remaining RR budget provides the next natural RCU quiescent state.
- **Micro-test:** runs the real four-vCPU deterministic fingerprint workload
  twice through a non-cadence terminal horizon, applies six configured 15 ms
  SIGSTOP/SIGCONT preemptions to QEMU only after the second run's first positive
  trace coordinate and under a two-second resume watchdog, and requires the
  canonical all-vCPU, RR-switch,
  deterministic-IPI, RAM, and device evidence to compare equal. The stock
  source proves the forced-kick path remains the default outside the guarded
  mode.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — accelerators other than sim,
  imprecise icount, and sim configurations without a pinned quantum execute the
  prior forced-kick statement unchanged.
- **Risk:** D.

### crucible-deterministic-host-kick-boundary — bound generic host work

- **Patch:** `0088-crucible-deterministic-host-kick-boundary.patch`.
- **Enforces:** [DET-1], [DET-29], [QEMU-43].
- **Mechanism:** QEMU's generic RR vCPU kick keeps its immediate all-vCPU
  `cpu_exit()` loop unless precise Crucible sim mode has a nonzero pinned RR
  quantum. In that mode, patch 0090 converts state-free latency hints into a
  soft all-vCPU `exit_request`: the current translation block completes at its
  deterministic endpoint and `cpu_exec` observes the request before starting
  another block. The host arrival therefore cannot asynchronously select an
  instruction endpoint, while QEMU still services the requested work promptly.
  Already-committed stop,
  unplug, halted, stopped, and
  interrupt-request states and an admitted exact terminal pause retain an
  immediate all-vCPU exit request for the shared RR execution thread, so a
  transition targeting a non-current vCPU still returns the active TCG slice.
  Native control, wakeup, terminal observation, and published interrupt
  semantics remain live without allowing a state-free host arrival to choose a
  guest coordinate.
- **Genesis progress:** `qemu_cpu_kick()` broadcasts the halt condition before
  calling the accelerator hook. Until the RR thread records that its initial
  stopped wait is complete, the hook does not treat the initialization-time
  `stopped` bit as a committed lifecycle transition. The condition broadcast
  still starts the thread, and the soft request is normalized before first
  execution. Raw observed icount, QEMU runstate, and `rr_current_cpu` are not
  used as execution proxies.
- **Micro-test:** the production four-vCPU fingerprint workload compares two
  exact-horizon executions while only the second has bounded scheduler
  preemption after its first positive trace coordinate.
  It requires equal canonical all-vCPU, RR, deterministic-IPI, RAM, and device
  evidence and bounded QMP stop/teardown. Stock QEMU supplies the immediate-kick
  negative control. The production single-vCPU fingerprint gate separately
  proves boot, exact-horizon stop, checkpoint, and replay progress with the
  pinned quantum.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — non-sim accelerators, imprecise
  icount, and configurations without a pinned quantum execute the existing
  kick loop unchanged. In bounded sim mode, only state-free generic kicks use
  the soft between-TB exit; admitted terminal observation and committed
  control, halt, unplug, stop, and interrupt state are handled immediately.
- **Risk:** D.

### crucible-exact-boundary-vcpu-introspection — observe checkpoint CPU state

- **Patch:** `0089-crucible-exact-boundary-vcpu-introspection.patch`.
- **Enforces:** [DET-1], [QFP-REG-1], [QFP-STATE-2].
- **Mechanism:** all-vCPU register reads retain live serialized-owner and
  stopped-BQL admission, and add the exact main-loop case where no vCPU is
  current, QEMU's exact-boundary scope is active, and the BQL makes every vCPU
  quiescent. `qemu_plugin_rr_cursor()` likewise reads the authoritative committed
  `TimersState` cursor at that boundary. Quantum, owner, and range checks remain
  mandatory.
- **Micro-test:** production World networking captures an exact checkpoint from
  the main-loop control callback, restores it in fresh QEMU processes, and
  requires the next complete live quantum to match. The four-vCPU horizon gate
  retains live-owner cursor coverage, while plugin-install cursor reads retain
  the unowned-context negative control.
- **Inertness:** [PATCH-3](c) — the added path is reachable only inside QEMU's
  existing exact deterministic plugin boundary while the BQL is held. Every
  ordinary QEMU or unowned plugin context executes the prior rejection rules.
- **Risk:** D.

### crucible-active-tcg-kick-boundary — preserve bounded kick liveness

- **Patch:** `0090-crucible-active-tcg-kick-boundary.patch`.
- **Enforces:** [DET-1], [DET-29], [QEMU-43].
- **Mechanism:** state-free generic kicks in precise bounded sim mode set each
  RR vCPU's atomic `exit_request` without setting `icount_decr.high`. A running
  vCPU therefore finishes the current deterministic translation block and
  exits before another block begins; an idle RR thread is already awakened by
  `qemu_cpu_kick()`'s condition broadcast. The RR thread separately publishes
  completion of its initial stopped wait so initialization state cannot be
  mistaken for a committed stop. Stateful transitions retain `cpu_exit()`.
- **Micro-test:** structural checks require the soft atomic request, forbid an
  asynchronous decrementer write, and require the initial-wait completion
  proof. Patch 0106 tightens active execution after the production four-vCPU
  adversary proved that host arrival could otherwise choose which translation
  block observed the soft request.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the soft exit applies only inside
  the existing precise sim-mode, pinned-quantum guard. Every other accelerator
  and icount configuration retains the upstream all-vCPU `cpu_exit()` path;
  committed lifecycle and interrupt transitions retain it within the guard.
- **Risk:** D.

### crucible-defer-active-slice-host-wakes — seal the active RR slice

- **Patch:** `0106-crucible-defer-active-slice-host-wakes.patch`.
- **Enforces:** [DET-1], [DET-29], [QEMU-43].
- **Mechanism:** in multi-vCPU mode, an atomic idle/active/pending handshake
  retains each state-free generic host wake across every partial TCG slice and
  consumes it only after a full pinned RR handoff, at an authorized scheduler
  ceiling, or at a guest halt/idle boundary. An idle-to-pending claimant can
  safely publish `exit_request` because the atomic claim prevents TCG from
  starting; this closes the condition broadcast-before-wait race without
  selecting a guest execution endpoint.
  Single-vCPU mode retains the soft between-block
  request because it has no alternate RR allocation to perturb and requires
  bounded main-loop service. Terminal pause publishes its
  pending state and explicitly kicks the vCPU; committed terminal, lifecycle,
  and interrupt state retains immediate `cpu_exit()`.
- **Micro-test:** the production four-vCPU fingerprint compares complete
  canonical streams with bounded scheduler preemption applied only after the
  second run's first positive trace coordinate. S1 and
  live-network gates prove startup, between-slice, terminal-pause, and device
  wake liveness. Structural checks require the single-vCPU liveness exception,
  the idle/active/pending handshake and its canonical service points, plus cleanup on
  idle, boot, and stateful paths; they forbid a multi-vCPU soft exit.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — the new admission guard is inside
  precise sim mode with a nonzero pinned RR quantum. Other accelerators and
  icount configurations retain upstream behavior.
- **Risk:** D.

### crucible-anchor-rr-cursor-genesis — establish scheduler state before execution

- **Patch:** `0107-crucible-anchor-rr-cursor-genesis.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [QEMU-43].
- **Mechanism:** after the RR thread completes QEMU's initial stopped wait and
  before it computes the first per-vCPU budget, a fresh sim guest commits vCPU
  0 at position 0 as its serialized cursor. The initializer requires raw
  icount zero and leaves any valid cursor loaded from VMState untouched. A
  valid serialized owner also overrides a mismatching loop-local suggestion
  after host control service; only quantum completion or guest halt hands the
  turn to another runnable vCPU. Inner `CPU_NEXT` transitions consult the same
  selector, and accounting fails loudly rather than resetting a mismatched
  owner. A partial turn returns directly to the outer timer/budget loop without
  publishing an idle RR state, so its next slice is freshly clamped while the
  active-slice host-wake guard remains armed.
- **Micro-test:** the exact-snapshot gate fixes aggregate capture icount and
  compares independent derivation outputs byte for byte, including the nonzero
  intra-turn cursor and capture fingerprint. Structural checks require the
  initializer, its raw-zero assertion, its placement before the RR loop's first
  budget, and serialized-owner authority throughout a partial turn.
- **Inertness:** the initializer returns immediately outside sim mode, when no
  bounded RR quantum is configured, or when VMState already supplies a valid
  cursor. Other accelerators retain upstream scheduler state.
- **Risk:** D.

### crucible-deterministic-network-kick — preserve exact network continuation

- **Patch:** `0108-crucible-deterministic-network-kick.patch`.
- **Enforces:** [DET-1], [PLUG-23], [PLUG-24], [QEMU-43].
- **Mechanism:** sim-mode virtio-net queue kicks and serialized `tx_waiting`
  resumes drain deferred transmit bottom halves synchronously and publish the
  committed raw transmit icount. An optional sim-only VMState subsection
  preserves each virtqueue notification cursor, and exact snapshot handling
  flushes translation history symmetrically on source and restore while using
  bounded cache-independent translation-block shapes without direct chaining.
- **Micro-test:** the production two-node live-network gate requires a real
  guest acknowledgement, then compares uninterrupted and fresh-process-restored
  quanta until both a packet and new fault decisions occur. The per-patch
  micro-test also requires the optional VMState fields and retains stock-mode
  negative controls.
- **Inertness:** [PATCH-3](a), [PATCH-3](c) — synchronous kicks, the VMState
  subsection, and translation-history handling are admitted only by precise
  sim mode with the Crucible time-control boundary. Ordinary QEMU networking
  and migration retain upstream behavior.
- **Risk:** D.

### crucible-control-boundary-node-faults — complete halted-node mutations

- **Patch:** `0109-crucible-control-boundary-node-faults.patch`.
- **Enforces:** [QFP-LIFE-1], [QFP-LIFE-2], [FAULT-ORDER].
- **Mechanism:** QEMU samples one raw icount for the drained control callback,
  lets the plugin dequeue and submit commands, and then dispatches any due
  node-boundary command at that same coordinate before leaving the exact
  boundary. The pending predicate is phase-qualified, so instruction and
  device mutations remain owned by their native execution seams. Terminal
  lifecycle authorization hashes zero the raw-coordinate field in CRUCLIF
  evidence before the plugin translates it to scheduler-logical space; the
  action and event header still bind the exact logical coordinate.
- **Micro-test:** the production shared-cause gate reaches the event with a
  halted real guest, requires typed lifecycle PREPARE and APPLY to complete,
  and compares uninterrupted execution with fresh-process restore. The plugin
  unit regression fills the lossless event ring and proves command pumping
  withholds the control-token release acknowledgement until the host consumes
  enough capacity and the complete private event queue is published.
- **Inertness:** the added dispatch runs only inside the existing exact drained
  control callback and only when a due node-boundary command is pending. It does
  not advance guest time, synthesize a result, or affect ordinary QEMU modes.
- **Risk:** F.

### crucible-release-halted-rr-turn — publish idle inside a partial RR turn

- **Patch:** `0110-crucible-release-halted-rr-turn.patch`.
- **Enforces:** [DET-1], [PLUG-24], [QEMU-43].
- **Mechanism:** after a vCPU executes `HLT`, the RR selector first looks for a
  different runnable vCPU. If none exists and it returns the halted cursor
  owner, the execution loop leaves the partial turn and enters the ordinary
  all-vCPU-idle path. The serialized cursor position is retained for the next
  runnable slice; it no longer causes QEMU to call `tcg_cpu_exec()` repeatedly
  on a halted CPU that cannot retire another instruction. The exact halted
  callback may capture cross-vCPU registers at an exact completed-turn handoff
  only when the committed cursor is zero at the next serialized owner and
  `current_cpu` still names the vCPU whose turn just finished; other owner
  mismatches remain rejected. The x86 `PAUSE` helper sets a transient private
  marker that the RR loop consumes and clears immediately after TCG returns;
  generic `EXCP_INTERRUPT` exits cannot masquerade as a guest yield. A marked
  multi-vCPU `PAUSE` commits the RFC-authorized early handoff at cursor zero
  immediately after instruction accounting and before plugin callbacks,
  vmstop, scheduled fault dispatch, or host preemption can return from the
  batch. Host work at that same boundary is serviced after the canonical guest
  transition. An atomic handoff fence makes a colliding BQL control callback
  relinquish its token; the RR writer commits the owner/cursor transition and
  schedules a fresh boundary before any fingerprint or checkpoint request can
  acknowledge it. Ordinary accounting remains the sole handoff when the `PAUSE`
  coincides with a completed quantum, and single-vCPU cursor behavior is
  unchanged.
- **Micro-test:** the diskless live quantum guests deliberately reach their
  final `HLT` at a nonzero RR cursor position. The one-vCPU and four-vCPU gates
  require QEMU to publish the all-halted boundary, complete the exact timer
  idle jump, and reproduce the result under bounded scheduler preemption. The
  four-vCPU gate additionally captures the exact output-only sequence
  `AAABPPPR`: every AP publishes online and contends on a lock held by the BSP.
  The BSP releases the lock, executes `PAUSE`, and immediately attempts to
  reacquire it. Reacquisition emits `F` and parks forever. A passing `P` before
  that next BSP instruction proves a waiter ran before the reacquire. A
  non-distributable QEMU variant arms an exact abort marker only after the
  guest has issued the `AAAB` prefix and immediately before the critical
  release-site `PAUSE`. It aborts only if that marked PAUSE takes the
  still-partial early-yield branch. Earlier startup/contention PAUSEs and an
  ordinary 4096-instruction completion cannot satisfy that negative control;
  the negative additionally requires the live gate's captured pre-abort UART
  bytes to equal `AAAB`.
  The remaining APs acquire in turn before `R`, so INIT/SIPI delivery alone
  cannot satisfy the evidence.
  Structural checks require the halted-owner escape before the partial-turn
  continuation.
- **Inertness:** both branches are inside precise sim mode's RR loop. The idle
  branch requires the selected cursor owner to be halted with no pending work;
  the yield branch requires the helper-authored transient marker, multiple
  vCPUs, and a still-partial owner-matched turn. The marker transition commits
  before any control callback or host-work exit and is not VMState. Every
  ordinary QEMU accelerator retains its prior behavior.
- **Risk:** D.

### crucible-accelerator-service-schema — admit typed service capacity

- **Patch:** `0111-crucible-accelerator-service-schema.patch`.
- **Enforces:** [QFP-ACCEL-SERVICE], [FAULT-ORDER].
- **Mechanism:** the accelerator service command uses a dedicated closed schema
  whose capacity field is a ratio, matching both the versioned host encoder and
  QEMU's command-specific validator. Compute and memory-rate service limits,
  enable flags, and thermal/power policy retain their existing field types.
- **Micro-test:** the production live hardware gate submits the typed
  state-machine effect through PREPARE and APPLY, then requires three exact
  job-service occurrences and guest-visible completion under the installed
  half-capacity thermal/power policy. The per-patch certificate also requires
  the dedicated mapping and consumes the exact drop-one negative control.
- **Inertness:** only accelerator service command parsing changes. Other generic
  service commands and ordinary QEMU execution retain their prior schema and
  behavior.
- **Risk:** F.

### crucible-compile-affected-clock-sources — isolate rule compilation

- **Patch:** `0112-crucible-compile-affected-clock-sources.patch`.
- **Enforces:** [QFP-CLOCK-SOURCE], [FAULT-ORDER].
- **Mechanism:** post-commit clock compilation receives the exact changed rule.
  A transform selects sources through its target predicate; a source-state rule
  selects the identities in its typed hash set. Unrelated registered sources
  are not projected or rearmed at that transaction boundary.
- **Micro-test:** the production live hardware gate commits a degraded local
  APIC timer source while unrelated clock devices are registered, then requires
  authenticated source-transition and timer-rearm occurrences without an
  unrelated projection failure.
- **Inertness:** non-clock rules and unselected clock sources perform no work;
  selected sources preserve the existing compilation and timer-rearm path.
- **Risk:** F.

### crucible-restore-accelerator-rule-indexes — restore persistent policy

- **Patch:** `0113-crucible-restore-accelerator-rule-indexes.patch`.
- **Enforces:** [QFP-ACCEL-SERVICE], [FAULT-RESTORE].
- **Mechanism:** accelerator VMState preparation rebuilds its four private rule
  indexes by retaining references from the already-authenticated staged node
  ledger. Commit atomically replaces the live indexes alongside accelerator
  counters and memory; abort releases every staged reference.
- **Micro-test:** the production live hardware gate installs a persistent
  half-capacity service rule, captures VMState, destroys QEMU and its plugin,
  restores into a fresh process, and requires exact service evidence for the
  GPU, TPU, and FPGA jobs.
- **Inertness:** no VMState bytes or public protocol fields change. Cold starts
  and accelerators with no retained rules reconstruct empty indexes.
- **Risk:** F.

### crucible-hot-fork-readiness — report QEMU-owned quiescence proofs

- **Patch:** `0114-crucible-hot-fork-readiness.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** a fixed version-1 QMP query reports the complete nine-bit
  hot-fork proof contract and the exact subset QEMU can attest at the current
  boundary. Precise icount, single-threaded sim RR, and an authenticated exact
  paused/device-flush boundary are derived from live QEMU state. AIO/BH/timer,
  RCU, block-snapshot, plugin-ring, mapping/descriptor, and child-reinit bits
  remain clear until their subsystem-owned coordinators land, so the response
  cannot optimistically advertise hot fork.
- **Micro-test:** the typed Apache client accepts the exact incomplete bitmap,
  exposes every missing proof class, and rejects an unknown schema, changed
  required set, unknown acknowledgement, or contradictory ready flag. A live
  patched-QEMU gate requires the exact incomplete report under precise
  single-threaded sim RR, proves that ordinary QMP pause cannot acknowledge the
  exact-boundary bit, and proves that stock QEMU does not expose the command.
  QAPI generation and the patched-QEMU build gate compile the matching GPL-side
  command and response structure.
- **Inertness:** the command is observational and performs no stop, resume,
  fork, timer, I/O, or guest-state operation. Outside the exact deterministic
  profile it returns fewer acknowledgements and remains not ready. Existing QMP
  commands and non-Crucible execution are unchanged.
- **Risk:** F.

### crucible-hot-fork-thread-ownership — classify unresolved subsystem workers

- **Patch:** `0115-crucible-hot-fork-thread-ownership.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** the RCU callback worker and every QEMU `IOThread` assign their
  own version-2 thread-registry disposition at the start of their subsystem
  entry point. The values remain explicitly unresolved and contribute to the
  exact unclassified count; they identify the future barrier owner without
  claiming a safe inherited-thread action, child reinitializer, or readiness
  acknowledgement. All other non-coordinator threads retain the plain
  fail-closed `unclassified` value.
- **Micro-test:** strict Rust decoding accepts all four closed disposition
  values and rejects version 1, unknown values, inconsistent counts, and
  malformed ordering. The live patched-QEMU gate requires exactly one RCU owner
  and one monitor AIO owner in the supported launch profile, stable repeated
  snapshots, two unresolved workers, and no readiness proof beyond the existing
  precise-sim/exact-boundary set. Patch regeneration, prefix build, and drop-one
  attribution bind the QAPI and thread-entry changes to this exact patch.
- **Inertness:** owner assignment mutates only the diagnostic registry
  generation before either subsystem publishes its startup-ready condition.
  It does not stop, park, resume, fork, or reinitialize a thread, change an AIO
  or RCU operation, or set a hot-fork proof bit. Non-Crucible QMP and guest
  execution are unchanged.
- **Risk:** F.

### crucible-hot-fork-rcu-inventory — expose bounded observational RCU state

- **Patch:** `0116-crucible-hot-fork-rcu-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** a fixed version-1 QMP query snapshots at most 65,536 registered
  RCU readers under the registry lock, sorts their positive thread IDs, and
  reports instantaneous read-side activity, submitted-but-incomplete callback
  count, active `drain_call_rcu()` state, and a register/unregister generation.
  Callback accounting increments before queue publication and decrements only
  after callback return, so the callback worker's dequeue and grace-period
  interval cannot appear empty.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, inconsistent counts/completeness, nonpositive, duplicate, or
  unsorted reader IDs. The live patched-QEMU gate requires stable repeated
  reports under the supported paused profile and binds every RCU reader to the
  exact thread registry. Stock QEMU must not expose the command.
- **Inertness:** the query is observational. It does not drain callbacks, wait
  for readers, hold the registry lock across another operation, coordinate
  `fork(2)`, or change readiness bit 4. Reader activity may change immediately
  after the response; only a future coordinator-held barrier may promote the
  proof.
- **Risk:** F.

### crucible-hot-fork-aio-inventory — expose bounded AioContext activity

- **Patch:** `0117-crucible-hot-fork-aio-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** every `AioContext` receives a positive process-local identity
  and enters a 65,536-entry lifecycle registry. A fixed version-1 QMP query
  reports exact home-thread assignment, active `aio_poll()` and GLib dispatch
  calls, enqueued and executing bottom halves, queued coroutines, pending
  notification state, and checked aggregate counts. Context create, destroy,
  and home-thread transitions advance a process-local generation.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, inconsistent counts/completeness, invalid or unsorted context
  identities, invalid home threads, and mismatched aggregates. The live
  patched-QEMU gate requires stable repeated reports under the supported paused
  profile and binds every assigned home thread to the exact QEMU thread
  registry. Stock QEMU must not expose the command.
- **Inertness:** the query and counters are observational. They do not drain or
  park an AIO context, enumerate registered handlers or timers, hold a barrier
  across another operation, coordinate `fork(2)`, or change readiness bit 3.
  Activity may change immediately after the response; only a future
  subsystem-owned barrier may promote the proof.
- **Risk:** F.

### crucible-hot-fork-mutex-inventory — expose bounded QEMU lock ownership

- **Patch:** `0118-crucible-hot-fork-mutex-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** every live POSIX `QemuMutex` and `QemuRecMutex` receives a
  positive process-local identity and enters a 65,536-entry lifecycle registry.
  Lock, try-lock, recursive-lock, condition-wait, and unlock transitions retain
  exact owner thread, recursion depth, acquisition waiters, condition waiters,
  and active unlock state. A fixed version-1 QMP query returns the sorted
  records, checked aggregates, sticky ownership validity, and a create/destroy
  generation. All instrumentation-state transitions and snapshots serialize on
  the registry guard, which is a raw instrumentation-private pthread mutex so
  inventorying QEMU mutexes does not recursively instrument itself.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, inconsistent owner/depth pairs, nonrecursive depth above one,
  invalid or unsorted identities, inconsistent completeness, and mismatched
  aggregates. The live patched-QEMU gate requires stable repeated reports under
  the supported paused profile and binds every positive owner to the exact QEMU
  thread registry. Stock QEMU must not expose the command.
- **Inertness:** the query and counters are observational. They do not acquire
  all locks, retain a process-fork barrier, choose a child disposition, run a
  child reinitializer, coordinate `fork(2)`, or change readiness bit 8. A lock
  may transition immediately after the response; only the future QEMU-owned
  coordinator may turn this inventory into a retained fork proof.
- **Risk:** F.

### crucible-hot-fork-timer-inventory — expose bounded live-timer state

- **Patch:** `0119-crucible-hot-fork-timer-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** every pending `QEMUTimer` and active timer callback receives a
  stable process-local timer and timer-list identity. A fixed version-1 QMP
  query returns at most 65,536 sorted unique records with exact clock, expiry,
  scale, attributes, pending state, callback state, and checked aggregates.
  Pending entries expose a registry-owned expiry copy rather than racing the
  timer-list lock. Active callbacks use stack-owned copied registry metadata,
  so a callback may legally free its enclosing timer before returning. Inert
  initialized timers are deliberately absent.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, inconsistent pending/expiry state, inert records, invalid or
  unsorted identities, invalid clocks or scales, inconsistent completeness,
  and mismatched aggregates. The live patched-QEMU gate requires stable exact
  reports under the supported paused profile. Stock QEMU must not expose the
  command.
- **Inertness:** the query and counters are observational. They do not arm,
  cancel, run, or drain a timer, retain an AIO/BH/timer barrier across another
  operation, coordinate `fork(2)`, choose a child clock disposition, or change
  readiness bit 3. Only the future QEMU-owned coordinator may turn this
  inventory into a retained fork proof.
- **Risk:** F.

### crucible-hot-fork-bottom-half-inventory — expose every allocated QEMUBH

- **Patch:** `0120-crucible-hot-fork-bottom-half-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** every allocated `QEMUBH` receives a stable process-local
  identity and a copied bounded diagnostic name. A fixed version-1 QMP query
  returns at most 65,536 sorted unique entries spanning inert, pending, active,
  canceled, one-shot, and deferred-deletion instances. Each entry binds the
  exact owning AioContext and exposes pending, scheduled, idle, deleted,
  one-shot, and callback-active state. Lifecycle and semantic state transitions
  advance a monotonic generation and bracket every lock-free state mutation
  with an in-flight transition count. A report is stable only when no transition
  is active at either copy boundary and the generation is unchanged. The
  command permits negotiated QMP OOB execution so the inventory does not create
  and observe its own one-shot in-band dispatch bottom half.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, invalid or unsorted identities, missing AioContext bindings,
  inconsistent scheduled/idle state, inconsistent completeness, and mismatched
  aggregates. The live patched-QEMU gate requires two stable exact nonempty
  reports and cross-checks every context against the exact AIO inventory. Stock
  QEMU must not expose the command.
- **Inertness:** the query and counters are observational. They do not schedule,
  cancel, delete, run, drain, or park a bottom half, retain an AIO/BH/timer
  barrier across another operation, coordinate `fork(2)`, choose a child
  disposition, or change readiness bit 3. Only the future QEMU-owned
  coordinator may turn this inventory into a retained fork proof.
- **Risk:** F.

### crucible-hot-fork-aio-handler-inventory — expose every POSIX AIO handler

- **Patch:** `0121-crucible-hot-fork-aio-handler-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** every allocated POSIX `AioHandler` receives a stable positive
  process-local identity and enters a 65,536-entry lifecycle registry. A fixed
  version-1 QMP query returns sorted unique entries with the exact owning
  AioContext and file descriptor, deferred-deletion state, installed read,
  write, poll, poll-ready, poll-begin, and poll-end callback classes, active
  callback counts, checked aggregates, and a lifecycle/callback-set generation.
  Every callback execution is bracketed in the registry. Active callback
  counts are instantaneous and deliberately do not advance the generation
  because the query executes inside its QMP descriptor's read callback. The
  command permits negotiated QMP OOB execution so inventorying does not
  introduce in-band dispatch work.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, invalid or unsorted identities, invalid descriptors, absent
  primary callback classes, inconsistent completeness, and mismatched
  aggregates. The live patched-QEMU gate requires two identical nonempty
  reports, binds every handler to the exact AioContext inventory, and binds
  every non-deleted descriptor to the exact QEMU process. Stock QEMU must not
  expose the command.
- **Inertness:** the query and counters are observational. They do not install,
  remove, run, drain, or park a handler, retain an AIO/BH/timer barrier across
  another operation, coordinate `fork(2)`, choose a child disposition, or
  change readiness bit 3. Only the future QEMU-owned coordinator may turn this
  inventory into a retained fork proof.
- **Risk:** F.

### crucible-hot-fork-block-backend-inventory — expose every block backend

- **Patch:** `0122-crucible-hot-fork-block-backend-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-5].
- **Mechanism:** every allocated `BlockBackend`, including hidden backends,
  receives a stable positive process-local identity and enters a 65,536-entry
  lifecycle registry. A fixed version-1 QMP query returns sorted unique entries
  bound to the exact AioContext identity, monitor visibility/name, graph-root
  and device attachment, requested and shared `BLK_PERM_*` masks, effective
  permission suppression, drained-section depth, request-queue policy, and
  in-flight I/O. Structural state is copied under a dedicated registry lock;
  quiesce and in-flight values are instantaneous atomics. The command permits
  negotiated QMP OOB execution and never dereferences the BQL-owned block graph.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, invalid or unsorted identities, missing AioContext bindings,
  invalid monitor names, inconsistent write classification/completeness, and
  mismatched aggregates. The live patched-QEMU gate requires two stable exact
  reports, binds every backend to the exact AIO inventory, and observes the
  configured VMState backend. Stock QEMU must not expose the command.
- **Inertness:** the query is observational. It does not traverse or mutate the
  block graph, start or drain I/O, retain immutable writable roots, hold a
  barrier across another operation, coordinate `fork(2)`, choose a child
  disposition, or change readiness bit 5. Only the future QEMU-owned
  coordinator may combine the registry with a drained block-graph snapshot and
  child reconstruction contract.
- **Risk:** F.

### crucible-hot-fork-plugin-resource-inventory — bind plugin resources to QEMU state

- **Patch:** `0123-crucible-hot-fork-plugin-resource-inventory.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the Crucible plugin seals one fixed version-1 scalar manifest
  only after setup, wake-descriptor registration, and all required callback
  registrations succeed. The manifest binds the exact plugin and process
  generations, shared-memory device/inode/length and topology, control and wake
  descriptors, required resource classes, optional feature modes, and callback
  classes. QEMU independently records callback registration, rejects mixed
  plugin identities or inconsistent masks, and exposes the sealed and observed
  values through a strict OOB QMP query. The host brackets the report around
  one exact-child `/proc` inventory and binds the descriptors and writable
  shared mappings to the sealed values.
- **Micro-test:** strict Rust decoding rejects unknown or additional fields,
  changed schema, unknown masks, inconsistent optional modes, mismatched
  callback masks, impossible descriptor/topology values, and incomplete
  reports. Plugin runtime tests require the registered manifest to match the
  exact receiver-side wake descriptor and mapped file identity. Host audit
  tests reject missing or mistyped descriptors and missing, private, read-only,
  or length-mismatched mappings. The live patched-QEMU gate requires two exact
  stable unregistered reports; stock QEMU must not expose the command.
- **Inertness:** the report is observational. It does not count executing
  callbacks, freeze a plugin ring, park or drain callbacks, retain a barrier
  across another operation,
  reconstruct child-side resources, coordinate `fork(2)`, or change readiness
  bit 6. Those proofs remain mandatory before the QEMU-owned hot-fork
  coordinator can acknowledge plugin readiness.
- **Risk:** F.

### crucible-hot-fork-plugin-callback-barrier — retain callback quiescence

- **Patch:** `0124-crucible-hot-fork-plugin-callback-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4].
- **Mechanism:** after every covered Rust callback shares one admission counter,
  the plugin registers a process-lifetime barrier operation with QEMU. A fixed
  version-1 OOB QMP command holds, queries, or releases the reversible barrier.
  Hold is accepted only at the exact paused/device-flush boundary, atomically
  rejects later callbacks, and reports already-admitted callbacks without
  blocking QMP. Release cannot reopen permanent teardown closure. QEMU binds
  the barrier to the sealed manifest's plugin identity and derives quiescence
  from exact held, teardown, and in-flight state.
- **Micro-test:** plugin tests cover admission races, reversible drain/reopen,
  and teardown precedence. Strict Rust QMP tests reject unknown fields,
  malformed unregistered state, contradictory quiescence, and wrong-action
  responses. The live patched-QEMU gate requires a stable exact unregistered
  query shape and rejects release without a registered plugin; stock QEMU must
  not expose the command.
- **Inertness:** registration and query are dormant unless the Crucible plugin
  is loaded and an authorized OOB caller invokes the command. Holding covers
  only plugin callbacks already registered in the sealed manifest. It does not
  freeze host ring writers, drain plugin workers, clone shared-memory state,
  reconstruct child resources, coordinate `fork(2)`, or change readiness bit
  6. The future QEMU-owned coordinator must compose and roll back every
  remaining owner before acknowledging plugin readiness.
- **Risk:** F.

### crucible-hot-fork-template-coordinator — own retained preparation

- **Patch:** `0125-crucible-hot-fork-template-coordinator.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** a serialized version-4 OOB QMP coordinator owns one retained
  template-preparation generation. `prepare` begins only at the authenticated
  exact paused/device-flush boundary, acquires the plugin callback, RCU, and
  bottom-half/timer source barriers, and reports `draining` while
  already-admitted work finishes. A later prepare
  reports `prepared` only when all nine readiness bits are present in that same
  retained transaction. If the acquired barrier is quiescent but any proof is
  missing, QEMU releases every acquired barrier and reports exact `blocked`
  rollback. Query is observational, abort releases retained state, standalone
  plugin hold/release cannot mutate coordinator-owned state, and a release
  failure retains ownership for retry.
- **Micro-test:** strict Rust decoding binds the action-specific outcome,
  generation, active/rollback state, exact proof and missing bitmaps, and nested
  plugin, RCU, and asynchronous-source barrier state; it rejects changed
  schemas, unknown fields,
  contradictory readiness, forged rollback, and wrong-action outcomes. The
  live patched-QEMU gate requires stable exact idle state, rejects preparation
  outside the exact boundary without acquiring state, and requires stock QEMU
  not to expose the command.
- **Inertness:** version 4 composes the plugin callback, RCU, and complete
  asynchronous-source barriers. It does not freeze host ring writers, drain
  block owners, retain mapping or descriptor dispositions, run child
  reinitializers, or call `fork(2)`. Plugin-ring bit 6 and every other
  unresolved bit remain clear, so a drained
  transaction rolls back as `blocked` and no template can become usable.
- **Risk:** F.

### crucible-hot-fork-rcu-barrier — retain RCU quiescence

- **Patch:** `0126-crucible-hot-fork-rcu-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** a process-lifetime reversible RCU barrier gates every new
  outer read-side entry and callback submission before it can
  become visible to the RCU subsystem. `hold` publishes a sticky gate and
  returns immediately; racing admissions either publish into the exact reader
  or callback counters or park until release. The retained state reports the
  complete bounded reader registry, active readers, admission transitions,
  pending callbacks, synchronous drains, owner thread, and hold generation.
  The template coordinator acquires this barrier with the plugin callback and
  bottom-half/timer source
  barrier and acknowledges readiness bit 4 only while the complete held RCU
  state is quiescent. Abort and blocked preparation release every barrier.
- **Micro-test:** strict Rust decoding rejects unknown fields, changed schemas,
  invalid owner/hold generations, reader-count overflow, contradictory drain
  state, and an RCU proof detached from a retained quiescent transaction. A
  QEMU unit test, executed by the patched package build, proves a registered
  reader cannot cross an acquired barrier until release. The live patched-QEMU
  gate requires exact stable released state, rejection of a hold outside the
  authenticated boundary, template-version-4 nesting, and absence of the
  command in stock QEMU. Patch regeneration compiles the QAPI schema and C
  barrier into the full patched emulator.
- **Inertness:** the gate is dormant until an authorized OOB caller holds it at
  the existing exact paused/device-flush boundary. It does not classify or
  reconstruct the retained RCU worker thread in a child, drain AIO or block
  owners, freeze plugin rings, close mapping/descriptor dispositions, or call
  `fork(2)`. Those missing proofs keep template preparation blocked.
- **Risk:** F.

### crucible-hot-fork-bh-timer-barrier — park bottom halves and timers

- **Patch:** `0127-crucible-hot-fork-bh-timer-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** a process-lifetime reversible barrier uses race-closed
  two-phase admission for bottom-half and timer creation, mutation, and
  callback dispatch. `hold` parks later producers and nonblocking event-loop
  dispatch while already-admitted work and its nested source mutations drain.
  Queued bottom halves and armed timers remain retained parked state. The
  exact version-1 response reports owner/generation, admission count, bounded
  inventory completeness, queued sources, active callbacks, and derived
  quiescence. The version-3 template coordinator retains this barrier with
  the plugin and RCU barriers while OOB QMP stays live. Patch 0128 extends
  this retained barrier without changing its legacy command name.
- **Micro-test:** strict Rust decoding rejects unknown fields, changed schemas,
  invalid owner/hold generations, count overflow, contradictory completeness,
  and forged quiescence. The QEMU unit test proves nested source mutation may
  finish under a hold, pending bottom halves and timers do not dispatch while
  retained, and release runs both. The live patched-QEMU gate requires exact
  stable released state, rejection of hold outside the authenticated boundary,
  template-version-4 nesting, and absence of the command in stock QEMU.
- **Inertness:** this prerequisite does not park `AioHandler` callbacks,
  coroutine admission, the complete `AioContext`, block owners, or child clock
  and context reconstruction. It cannot acknowledge AIO proof bit 3 and does
  not call `fork(2)`.
- **Risk:** F.

### crucible-hot-fork-aio-barrier — close asynchronous admission

- **Patch:** `0128-crucible-hot-fork-aio-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the process-lifetime source barrier additionally gates
  AioContext polling and GLib dispatch, AioHandler lifecycle and callback
  entry, and coroutine scheduling through the same race-closed admission
  state. Already-admitted outer work may complete nested source mutations;
  later polls, handlers, coroutines, bottom halves, and timers remain parked.
  The exact version-2 response reports bounded AioContext and AioHandler
  completeness plus active poll, dispatch, handler-callback, and queued-
  coroutine counts. The version-4 template coordinator acknowledges proof bit
  3 exactly while this complete held asynchronous-source barrier is quiescent.
- **Micro-test:** strict Rust decoding rejects changed schemas, forged aggregate
  completeness, count overflow, active work hidden behind quiescence, and an
  AIO proof bit detached from the retained quiescent barrier. The QEMU AIO unit
  test parks an event notifier and queued coroutine alongside a bottom half and
  timer, proves none dispatch under the hold, then proves release runs all four.
  Patch regeneration compiles the QAPI schema and barrier into both supported
  QEMU system targets.
- **Inertness:** the legacy `crucible-hot-fork-bh-timer-barrier` command remains
  dormant until an authorized OOB caller holds it at the exact boundary. This
  patch does not drain block owners, freeze plugin rings, choose mapping or
  descriptor disposition, run child reinitializers, or call `fork(2)`. Proof
  bits 5 through 8 remain clear, so template preparation still rolls back as
  blocked and cannot yield a usable child.
- **Risk:** F.

### crucible-hot-fork-block-drain-barrier — retain native block quiescence

- **Patch:** `0129-crucible-hot-fork-block-drain-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** a process-lifetime version-1 main-loop QMP operation holds,
  queries, or releases QEMU's native all-block drain section. Hold is accepted
  only at the exact paused/device-flush boundary, rejects replay-events and a
  non-main AioContext, immediately quiesces new external block clients, and
  retains the drain while already-issued I/O completes. The exact bounded
  response binds the owner/generation to the block-backend registry and derives
  quiescence from complete inventory, zero aggregate in-flight I/O, and every
  rooted backend remaining inside the native drain section. The command is
  deliberately in-band because native drain acquire/release requires the BQL
  and main AioContext.
- **Micro-test:** strict Rust decoding rejects changed schemas, unknown fields,
  impossible owner/generation state, count overflow, inconsistent backend
  relationships, hidden in-flight I/O, forged quiescence, and wrong-action
  responses. The QEMU block unit test holds, observes, and releases the retained
  native drain. The live patched-QEMU gate requires stable exact released state,
  rejects hold outside the authenticated boundary without retaining state, and
  requires stock QEMU not to expose the command.
- **Inertness:** the barrier is dormant until an authorized main-loop caller
  holds it at the exact boundary. It does not freeze block-graph mutation,
  create or authenticate an immutable external-snapshot root, rotate writable
  overlays, retain child root identity, reconstruct a child graph, coordinate
  `fork(2)`, or acknowledge proof bit 5. The future coordinator must acquire
  this drain before parking the AIO sources and release AIO before releasing
  the block drain.
- **Risk:** F.

### crucible-hot-fork-block-template-coordinator — order retained block quiescence

- **Patch:** `0130-crucible-hot-fork-block-template-coordinator.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-5 OOB template coordinator schedules native
  all-block drain acquisition and release on the main AioContext. It retains the
  block drain before admitting RCU, asynchronous-source, and plugin holds;
  rollback releases plugin, asynchronous-source, and RCU admission before block
  I/O admission reopens. Pending acquisition and release remain serialized
  transaction phases, and standalone mutation of any owned barrier is rejected.
  OOB query uses the mutex-protected block inventory without invoking a
  main-loop-only operation.
- **Micro-test:** the block unit test queries retained state from a second QEMU
  thread and requires the exact generation, inventory, and quiescence observed
  by the main thread. The strict Rust schema accepts only exact pending, held,
  release, and rollback shapes, binds the nested block report, and rejects any
  attempt to derive block-snapshot proof bit 5 from native drain alone. The live
  gate requires the exact version-5 idle shape and the same standalone block
  report by value.
- **Inertness:** no drain is acquired until an authorized template prepare at
  the exact paused/device-flush boundary. This patch does not create or
  authenticate an immutable external-snapshot root, rotate overlays, reconstruct
  child block graphs, or call `fork(2)`. Proof bit 5 remains clear, so the
  coordinator rolls the otherwise quiescent transaction back as blocked.
- **Risk:** F.

### crucible-hot-fork-block-graph-barrier — retain graph-writer exclusion

- **Patch:** `0131-crucible-hot-fork-block-graph-barrier.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-2 block barrier closes block-graph writer
  admission on the main AioContext before it enters QEMU's native all-block
  drain. It rejects an already-active writer, captures the exact completed
  graph-mutation generation, and parks later graph writers behind the retained
  hold. The bounded response exposes exact graph-barrier and mutation
  generations, owner, active-writer state, and waiting-writer count. The
  version-6 OOB template coordinator composes this graph barrier with native
  block drain, RCU, asynchronous-source, and plugin barriers. On rollback it
  reopens graph admission immediately before native drain cleanup in the same
  main-loop callback, so a parked outer writer cannot interleave and nested
  cleanup graph operations cannot deadlock.
- **Micro-test:** the QEMU block unit test holds the graph barrier, enters a
  real graph writer, observes that writer parked through a scheduled release
  callback, and requires the completed-mutation generation to advance only
  after the writer runs. Strict Rust decoding binds every generation and owner,
  rejects active-writer and held-generation contradictions, and bounds waiting
  writers to `u32`. The live gate requires the exact released schema-version-2
  shape and unchanged state after a rejected hold.
- **Inertness:** graph admission remains unchanged until an authorized
  main-loop block hold at the exact paused/device-flush boundary. This patch
  does not create or authenticate an immutable external-snapshot root, rotate
  or bind writable overlays, retain child root identity, reconstruct a child
  graph, call `fork(2)`, or acknowledge proof bit 5. The otherwise quiescent
  coordinator therefore still rolls back as blocked.
- **Risk:** F.

### crucible-hot-fork-block-snapshot-roots — bind immutable writable roots

- **Patch:** `0132-crucible-bind-hot-fork-block-snapshot-roots.patch`.
- **Enforces:** RFC-0016 [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** while the version-3 native block drain and graph-writer
  barriers are retained and quiescent, the version-7 template coordinator
  binds every writable rooted backend to an exact guest-allocation-empty active
  overlay whose immediate backing node is read-only. The Apache host supplies
  an already-authenticated lowercase BLAKE3 content ID; QEMU binds it to exact
  backend and node names, process-local backend identity, virtual size, backend
  generation, captured graph-mutation generation, and coordinator owner. The
  complete sorted binding is retained by value and revalidated on every query.
  An active transaction acknowledges block-snapshot proof bit 5 exactly while
  that binding remains complete.
- **Micro-test:** the native block unit test builds a real qcow2 snapshot plus
  empty active overlay, names and opens the graph edge under one writable
  backend, retains the block barrier, binds the exact root, and requires release
  to clear the binding. Strict Rust construction and decoding enforce the same
  identifier, hash, count, generation, owner, ordering, empty-overlay, and
  read-only relationships. The live gate uses a real snapshot/overlay pair and
  requires proof bit 5 only while the retained transaction reports the exact
  bound root.
- **Inertness:** ordinary QEMU block creation and execution are unchanged.
  Binding is reachable only through an authorized template prepare at the
  exact paused/device-flush boundary after native drain and graph-writer
  exclusion become quiescent. The patch neither creates snapshot bytes nor
  reconstructs child descriptors, block graphs, or branch-private overlays;
  proof bits 7 and 8 remain clear, the coordinator rolls back as blocked, and
  no process fork is authorized.

### crucible-authenticate-fault-result-payloads — bind results to payloads

- **Patch:** `0133-crucible-authenticate-fault-result-payloads.patch`.
- **Enforces:** [QFP-RESULT], [FAULT-ORDER].
- **Mechanism:** every queued fault result hashes the exact payload retained
  beside it, including prepare-time rejection evidence. The host authenticates
  that evidence before classifying an unsupported typed request as a rejection.
- **Micro-test:** the production live hardware gate submits an unsupported APIC
  read-error request, requires an authenticated typed rejection payload, and
  proves the adapter preserves transaction ownership rather than reporting a
  fatal malformed result.
- **Inertness:** successful result payloads retain their existing bytes and
  semantics; this patch only makes their already-present evidence hash cover
  the retained payload uniformly.
- **Risk:** F.

### crucible-clock-impulse-read-error-policies — retain clock policy

- **Patch:** `0134-crucible-clock-impulse-read-error-policies.patch`.
- **Enforces:** [QFP-CLOCK-TRANSFORM], [QFP-CLOCK-SOURCE], [FAULT-ORDER].
- **Mechanism:** clock VMState version 4 persists effective impulse
  monotonicity and overdue-timer policy, and x86 TSC reads raise deterministic
  `#GP` while the selected source is in read-error state. Internal clock
  projections continue from the last valid source value.
- **Micro-test:** the production live hardware matrix exercises drift and jump
  impulse policy, an x86 TSC read-error transition, recovery, and fresh-process
  restore while the VMState gate pins `CRUCCVS4` encode/decode symmetry.
- **Inertness:** clocks without an active impulse retain the existing default
  policy, and sources outside read-error state follow their prior read path.
- **Risk:** F.

### crucible-hot-fork-ring-producer-barrier — freeze shared rings

- **Patch:** `0135-crucible-freeze-hot-fork-rings.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-2 plugin barrier reports and validates the exact
  ABI-v19 shared-ring count, number of held rings, and aggregate producer
  publications admitted before the hold. Template quiescence requires every
  ring and callback barrier to be held with both in-flight counts at zero.
- **Micro-test:** strict Rust/QMP fixtures reject partial ring holds and false
  quiescence; the shared-memory suite races producer admission with the hold
  and proves one mapped operation holds and releases every ring.
- **Inertness:** the barrier is reachable only through the existing authorized
  hot-fork command. It does not park plugin workers, clone ring content, define
  child dispositions, or acknowledge proof bit 6.
- **Risk:** F.

### crucible-hot-fork-plugin-worker-manifest — seal plugin workers

- **Patch:** `0136-crucible-seal-hot-fork-plugin-workers.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-2 resource manifest adds a closed worker mask.
  The RUN control reader and sole teardown worker are mandatory; the
  fingerprint digest worker is present exactly when fingerprint resources are
  enabled. QEMU rejects missing, unknown, or feature-inconsistent workers and
  exposes the sealed set through the exact OOB resource inventory.
- **Micro-test:** Rust parser fixtures accept the mandatory worker set and
  reject missing or feature-inconsistent workers; the live unregistered QMP
  shape pins all worker fields to zero/false, and patch regeneration proves the
  C header, validator, and QAPI move together.
- **Inertness:** the manifest is observational and installed only by the
  Crucible plugin. It does not park worker operations, clone ring bytes,
  reconstruct workers in a child, or acknowledge proof bit 6.
- **Risk:** F.

### crucible-hot-fork-plugin-worker-barrier — park sealed workers

- **Patch:** `0137-crucible-park-hot-fork-plugin-workers.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-3 plugin barrier joins the sealed worker mask to
  exact parked-worker and admitted-operation state. The RUN-control, teardown,
  and optional fingerprint workers mark blocking receive boundaries as safe
  points; a returned receive parks before its operation can mutate state while
  the hold remains active.
- **Micro-test:** the worker state-machine fixtures prove idle parking,
  admitted-operation drain, release wakeup, and optional-worker mask closure;
  strict QMP fixtures reject unknown, partial, or falsely quiescent worker
  shapes.
- **Inertness:** the barrier remains reachable only through the authorized
  hot-fork command. It does not clone retained queue/ring bytes, reconstruct
  child workers, or acknowledge proof bit 6.
- **Risk:** F.

### crucible-hot-fork-ring-consumer-barrier — drain shared-ring consumers

- **Patch:** `0138-crucible-drain-hot-fork-ring-consumers.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-4 plugin barrier adds the aggregate count of ring
  consumers admitted before the hold. Quiescence requires every
  ABI-v20-or-newer ring's producer and consumer barriers to be held and both admitted-operation counts
  to reach zero, making its queued bytes and indices stable for a later clone.
- **Micro-test:** shared-memory fixtures race consumer admission with the hold,
  reject dequeue while held, and prove mapped aggregate hold/release covers
  both endpoints; strict QMP fixtures reject false consumer quiescence.
- **Inertness:** the barrier remains reachable only through the authorized
  hot-fork command. It does not clone queued bytes, bind those bytes into a
  child mapping, reconstruct workers, or acknowledge proof bit 6.
- **Risk:** F.

### crucible-hot-fork-private-ring-stage — retain authenticated private rings

- **Patch:** `0139-crucible-retain-hot-fork-private-rings.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9].
- **Mechanism:** an OOB QMP command duplicates one bounded standard-QMP
  `getfd` entry without consuming the monitor-owned copy, then authenticates
  the duplicate's exact name, device, inode, length, regular-file type, and
  `F_SEAL_SHRINK`. QEMU retains that descriptor independently until a release
  supplies the same exact basis; standard `closefd` remains a separate host
  operation.
- **Micro-test:** typed Rust fixtures pin the stage/query/release wire shapes,
  exact-basis response checks, false disposition/readiness bits, and poisoning
  on contradictory mutation responses. A real Unix-socket fixture proves the
  two ownership layers are acquired and released in the required order.
- **Inertness:** descriptor retention is reachable only through the authorized
  custom command after standard `getfd`. It does not fork, remap a child,
  release ring barriers, complete the inherited-resource disposition table, or
  acknowledge readiness bits 6 or 7.
- **Risk:** F.

### crucible-hot-fork-worker-local-state — account dequeued worker state

- **Patch:** `0140-crucible-account-hot-fork-worker-local-state.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-5].
- **Mechanism:** the version-5 plugin barrier distinguishes an idle parked
  worker from a parked worker retaining one dequeued item in thread-local
  state. Pending workers remain parked, their bits are a subset of the parked
  mask, and subsystem quiescence requires the pending mask to be empty.
- **Micro-test:** a held worker dequeues one item and remains observably pending
  until release; strict QMP fixtures reject pending workers outside the parked
  set and false quiescence while any pending bit remains set.
- **Inertness:** the accounting path is reachable only while the existing
  authorized plugin barrier is held. It does not define child disposition,
  clone local state, reconstruct workers, or acknowledge proof bit 6.
- **Risk:** F.

### crucible-hot-fork-plugin-endpoint-stage — retain branch-private plugin endpoints

- **Patch:** `0141-crucible-stage-hot-fork-plugin-endpoints.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9].
- **Mechanism:** an OOB QMP command duplicates distinct standard-QMP `getfd`
  entries for one connected-empty AF_UNIX control socket and one empty eventfd.
  QEMU authenticates the socket by Linux `SO_COOKIE`, the eventfd by
  `/proc/self/fdinfo` identity, normalizes and verifies the retained eventfd as
  nonblocking after standard QMP import, and binds both retained duplicates to
  the exact current private-ring generation.
- **Micro-test:** typed Rust fixtures pin the exact stage/query/release schema,
  generation and identity checks, poisoning on contradictory ownership
  responses, and two-descriptor acquisition/release ordering. The live QEMU
  gate transfers real socket/eventfd descriptors, rejects foreign release and
  private-ring release while endpoints remain staged, then proves both QEMU
  and monitor ownership layers close in order.
- **Inertness:** endpoint retention is reachable only through the authorized
  custom command after two standard `getfd` imports and one private-ring stage.
  It does not fork, install endpoints in a child, expose the host continuation,
  recreate plugin workers, complete inherited-descriptor disposition, or
  acknowledge readiness bits 6 through 8.
- **Risk:** F.

### crucible-hot-fork-retained-resource-stage — stage under the retained barrier

- **Patch:** `0142-crucible-retain-hot-fork-resource-staging.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9].
- **Mechanism:** the version-10 template coordinator retains a fully drained
  incomplete transaction as `draining` until explicit abort. Private-ring and
  plugin-endpoint staging is admitted during that transaction only in the
  fully held phase, at the exact paused/device-flush boundary, and while the
  retained plugin barrier is quiescent. A new transaction rejects a nonempty
  resource stage rather than adopting stale descriptors.
- **Micro-test:** strict QMP fixtures pin the version-10 retained-draining
  shape, while the patch gate verifies the held-phase, exact-boundary, and
  plugin-quiescence predicates and the absence of automatic missing-proof
  rollback.
- **Inertness:** retained staging does not fork, install resources in a child,
  complete inherited-resource disposition, or acknowledge readiness bits 6
  through 8. The caller must explicitly abort before releasing staged
  descriptors and resuming the template.
- **Risk:** F.

### crucible-hot-fork-resource-generation-binding — bind retained generations

- **Patch:** `0143-crucible-bind-hot-fork-resource-generations.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9].
- **Mechanism:** private-ring and plugin-endpoint state version 2 records the
  exact template generation that admitted each stage. The version-11 template
  report atomically exposes both mutation generations, the endpoint-to-ring
  generation edge, and whether all retained resources belong to the current
  active transaction. Endpoint staging rejects a ring retained by another or
  already-aborted transaction.
- **Micro-test:** strict QMP fixtures accept one exact active binding, retain
  its immutable origin after abort, and reject foreign template or ring
  generations. Patch regeneration pins the QAPI and C implementation.
- **Inertness:** generation binding neither installs resources in a child nor
  completes any inherited-resource disposition. Readiness bits 6 through 8
  remain clear and no fork operation exists.
- **Risk:** F.

### crucible-hot-fork-worker-disposition-binding — bind worker dispositions

- **Patch:** `0144-crucible-bind-hot-fork-worker-dispositions.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-8], [HFORK-9].
- **Mechanism:** version 3 of the plugin-endpoint stage records the exact
  quiescent plugin-barrier generation and sealed worker mask. It accepts only
  an empty worker-local state and records equal masks for workers resumed by
  the parent and workers reinitialized by a future child. Version 12 of the
  template report keeps the resource transaction bound only while that plan
  still matches the current retained plugin barrier.
- **Micro-test:** strict QMP fixtures reject missing, contradictory, stale, or
  nonempty worker plans; the node transfer path quarantines an acknowledged
  endpoint pair whose disposition differs from the barrier it observed.
- **Inertness:** the stage records but does not apply the child reinitializer,
  transfer execution, or fork. `disposition-complete` remains false, readiness
  bits 6 through 8 remain clear, and `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-source-ring-noninheritance — exclude source rings

- **Patch:** `0145-crucible-exclude-source-rings-from-fork-children.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9], [HFORK-12].
- **Mechanism:** version 6 of the plugin barrier reports a
  `mapping-dontfork` predicate. After callback, ring, and worker admission is
  held, the GPL plugin applies `MADV_DONTFORK` to the exact live setup-region
  mapping. A failed transition rolls the holds back. Release restores
  `MADV_DOFORK` before reopening the retained parent, and a failed restore
  retains every admission hold.
- **Micro-test:** the permissive mapping owner observes Linux's `dc` VMA flag
  appear and disappear across the reversible transition. Live plugin and
  strict QMP fixtures require the mapping flag while held and reject a
  contradictory quiescent report; the readiness gate pins the version-6
  unregistered shape.
- **Inertness:** no child mapping is installed and no child worker is rebuilt.
  The template remains unready, readiness bits 6 through 8 remain clear, and
  `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-child-runtime-registration — register child reconstruction

- **Patch:** `0146-crucible-register-hot-fork-child-runtime.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-12].
- **Mechanism:** QEMU and the GPL plugin share fixed version-1 child plan and
  status structures. The plan binds the exact template, private-ring,
  endpoint-pair, and plugin-barrier generations; the authenticated Linux
  `SO_COOKIE` and eventfd identities; the private setup-region device, inode,
  length, and descriptor; the replacement control and wake descriptor
  numbers; and the exact sealed worker mask. Status echoes the complete staged
  generation and endpoint identity basis after installation. The plugin
  independently authenticates both replacement kernel objects before it
  retains its validated setup layout,
  installs the private mapping only after inherited callback and worker holds
  are complete, replaces callback-held teardown routing, forgets only a fully
  parked inherited worker set, and starts replacement control, teardown, and
  optional fingerprint workers behind the same holds. QEMU retains the exact
  process-lifetime callback and validates any future invocation against the
  sealed resource manifest.
- **Micro-test:** Rust layout and live-registration tests exercise the inert
  template query and reject child-runtime registration failure. Worker tests
  reject an incomplete inherited parked set and prove that a complete set can
  be reset and reconstructed without reopening admission.
- **Inertness:** this patch registers and retains the operation but does not
  invoke it from the fork transaction, replace child endpoints, update process
  generation, release a child, or set readiness bits 6 through 8. `T-CAM-6.2`
  remains unchecked.
- **Risk:** F.

### crucible-hot-fork-child-process-generation — bind one child incarnation

- **Patch:** `0147-crucible-bind-hot-fork-child-process-generation.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9], [HFORK-11], [HFORK-12].
- **Mechanism:** version 2 of the fixed child-runtime plan carries the exact
  nonzero process generation sealed by the template manifest and the checked
  immediate successor assigned to the child. QEMU rejects zero, overflow,
  skipped, or stale parents before invoking reconstruction, advances its
  lifecycle generation, and requires every later status to retain that exact
  successor. The plugin independently validates the same pair against its
  process-local owner, advances its live device generation only during the
  one-shot held transition, and echoes both generations in status.
- **Micro-test:** Rust ABI tests freeze the version-2 layout and exercise exact,
  stale-parent, skipped-child, and overflow pairs. Patch micro-tests require the
  QEMU-side manifest comparison, lifecycle rebind, and query/release drift
  checks while the live readiness gate remains false.
- **Inertness:** the registered operation still has no QEMU fork-transaction
  caller, so no parent process is rebound and readiness bits 6 through 8 remain
  clear. `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-child-runtime-observation — expose exact child state

- **Patch:** `0148-crucible-expose-hot-fork-child-runtime-state.patch`.
- **Enforces:** [HFORK-3], [HFORK-8], [HFORK-9], [HFORK-11], [HFORK-12].
- **Mechanism:** the OOB
  `query-crucible-hot-fork-child-runtime` command exposes version 2 of QEMU's
  process-local registered child-runtime inventory. The report binds the
  callback registration to the complete plugin resource manifest and current
  process generation, then carries the exact phase, held/reconstructed flags,
  parent/child generations, staged resource generations, authenticated
  endpoint identities, and worker disposition state. Repeated identical
  observations retain one generation; registration or a status mutation
  advances it with checked overflow.
- **Micro-test:** typed Rust parser and QMP transport tests require the exact
  field set, OOB command, manifest/generation relation, phase-specific basis,
  worker masks, immediate-successor process generation, and permanently false
  readiness acknowledgement. The live gate proves stock rejection and an exact
  stable unregistered response from patched QEMU.
- **Inertness:** the query invokes only the registered operation's observational
  action. It does not fork, initialize, release, or admit a child and never
  acknowledges readiness bits 6 through 8. `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-endpoint-replacement-plan — bind descriptor slots

- **Patch:** `0149-crucible-bind-hot-fork-endpoint-replacement-slots.patch`.
- **Enforces:** [HFORK-3], [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-12].
- **Mechanism:** version 4 of the retained plugin-endpoint stage records the
  exact QEMU-owned control and wake source descriptors and binds them to the
  distinct control and wake slots from the complete sealed plugin resource
  manifest. It rejects every source/target alias, every private-ring alias,
  incomplete or drifting manifests, and retry-time plan drift under the exact
  template, private-ring, barrier, and worker basis.
- **Micro-test:** typed Rust fixtures require the exact closed field set and
  pairwise-distinct plan, node proofs retain the observational plan, patch
  micro-tests pin the manifest comparison, and the live readiness gate proves
  the version-4 standalone source observation while the template-only targets
  remain absent.
- **Inertness:** the stage records but does not apply either descriptor
  replacement, invoke the registered child reinitializer, or fork. Descriptor
  numbers grant no authority; readiness bits 6 through 8 and `T-CAM-6.2`
  remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-endpoint-replacement-primitive — replace two exact slots

- **Patch:** `0150-crucible-add-fork-child-endpoint-replacement-primitive.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-12].
- **Mechanism:** one Linux-only GPL-side helper accepts exactly two
  pairwise-distinct source/target descriptor pairs. It duplicates both prior
  targets for rollback, preserves each target's close-on-exec flag, replaces
  both file descriptions, and invokes a caller-owned verifier over the
  installed pair. A rejected verification restores both targets and leaves the
  sources retained. An incomplete rollback reports `-EUCLEAN`, which requires
  terminal child quarantine rather than use of any ambiguous descriptor.
- **Micro-test:** the QEMU package runs a focused unit binary that proves exact
  control-socket and eventfd replacement, source closure only after accepted
  verification, target-flag preservation, complete rollback after a verifier
  rejection, and no mutation for an aliased plan. Patch micro-tests pin the
  helper, rollback, poison result, and package test invocation.
- **Inertness:** the helper is internal and has no caller. It does not establish
  an immediate fork-child context, scan or close the complete inherited
  descriptor table, invoke the plugin reinitializer, or acknowledge readiness.
  Bits 6 through 8 stay clear and `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-immediate-child-identity — pin the exact fork lineage

- **Patch:** `0151-crucible-authenticate-immediate-hot-fork-children.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-11], [HFORK-12].
- **Mechanism:** a Linux-only GPL-side primitive opens an exact pidfd for the
  quiescent parent before fork. The inherited identity admits only a process
  whose direct-parent PID is that pinned, still-live process generation, and
  arms `PR_SET_PDEATHSIG(SIGKILL)` before it returns success. Parent identity
  is checked on both sides of the pidfd liveness probe, so parent exit or
  reparenting fails closed rather than authorizing a PID-shaped substitute.
- **Micro-test:** the QEMU package runs a real-fork unit path. It proves that
  the exact immediate child authenticates and applies the two-slot replacement
  while the parent's original socket and eventfd descriptions remain
  unchanged. A grandchild inheriting the same value is rejected, and invoking
  child authentication in the capture owner is rejected.
- **Inertness:** only the unit test calls `fork(2)`. Production QEMU has no
  caller, complete inherited-descriptor disposition, child QMP channel,
  reinitializer composition, or readiness acknowledgement. Bits 6 through 8
  stay clear and `T-CAM-6.2` remains unchecked.
- **Risk:** F.

### crucible-hot-fork-plugin-ring-proof — bind the frozen plugin resources

- **Patch:** `0152-crucible-acknowledge-frozen-hot-fork-plugin-rings.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-11], [HFORK-12].
- **Mechanism:** version 13 of the retained template coordinator composes
  readiness bit 6 only while the exact branch-private ring, plugin endpoints,
  quiescent plugin barrier, and complete parent/child worker-disposition plan
  all remain bound to the same active transaction. The nested resource-stage
  schema is version 3 and reports the independently checked acknowledgement;
  the outer bitmap and nested result must agree. Generation, shrink-seal,
  endpoint-to-ring, barrier, or worker-plan drift clears the proof.
- **Micro-test:** the typed Rust decoder accepts the exact version-13/version-3
  proof shape and rejects forged outer or nested acknowledgements. Patch
  micro-tests pin the QEMU proof bit, exact worker-disposition predicate, and
  transaction-bound acknowledgement assignment.
- **Inertness:** the coordinator still lacks the complete inherited-descriptor
  disposition and child reinitialization required by bits 7 and 8. It remains
  `draining`, no production `fork(2)` caller exists, and `T-CAM-6.2` remains
  unchecked.
- **Risk:** F.

### crucible-hot-fork-closed-child-descriptor-table — close inherited FDs

- **Patch:** `0153-crucible-close-inherited-child-descriptor-tables.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12].
- **Mechanism:** a Linux-only GPL-side primitive admits only the exact live
  immediate child, blocks every blockable signal, atomically replaces the two
  staged plugin endpoint slots, and applies a strictly sorted table of at most
  4,096 final descriptors. `close_range(2)` closes every gap and the complete
  suffix, so no inherited descriptor outside the table survives. The callback
  authenticates the installed endpoint identities and final table only after
  every close succeeds. Any post-authentication error is destructive and
  requires child termination or quarantine.
- **Micro-test:** the real-fork unit path retains only the replacement control
  socket, wake eventfd, and test result channel. It proves an unrelated
  inherited descriptor is closed in the child, both replacement endpoints are
  usable, and the parent's original descriptor table remains unchanged.
- **Inertness:** the helper has no production caller and therefore does not yet
  close descriptor admission around table construction. It does not classify
  mappings, reinitialize process-private state, acknowledge readiness bits 7 or
  8, or complete `T-CAM-6.2`.
- **Risk:** F.

### crucible-hot-fork-child-descriptor-admission — close child admission

- **Patch:** `0154-crucible-close-fork-child-descriptor-admission.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12].
- **Mechanism:** a Linux-only one-shot child transaction first proves
  `close_range(2)` support, authenticates the exact immediate child, blocks
  every blockable signal, and consumes the inherited parent pidfd. Since only
  the calling thread survives `fork(2)`, the caller then constructs the retain
  table with asynchronous descriptor admission closed. Closed-table application
  requires that exact active child transaction and consumes it before endpoint
  replacement begins; invalid pre-effect arguments remain retryable, while any
  later failure is destructive.
- **Micro-test:** the real-fork closed-table path constructs its table only
  after the transaction begins and proves a blockable signal is masked. A
  separate regression proves an inactive transaction cannot change any
  descriptor.
- **Inertness:** the transaction has no production fork caller, does not assign
  dispositions to mappings, does not run child reinitialization, and does not
  acknowledge readiness bits 7 or 8. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-child-mapping-disposition — reject unsafe VMAs

- **Patch:** `0155-crucible-verify-fork-child-mapping-dispositions.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** after the exact child descriptor table is applied, a one-shot
  Linux verifier streams `/proc/self/maps` without heap allocation. Private
  VMAs retain kernel COW semantics and read-only shared VMAs cannot mutate a
  sibling; every writable shared VMA must exactly match one sorted,
  nonoverlapping branch-private allowlist range, and every allowlisted range
  must appear exactly once. The scan accepts at most 65,536 records, 8 KiB per
  record, 16 MiB in aggregate, and 4,096 writable shared ranges.
- **Micro-test:** the real-fork descriptor path installs and accepts one exact
  anonymous branch-private shared VMA after table closure. A negative
  regression omits an otherwise valid writable shared VMA and requires
  fail-closed rejection.
- **Inertness:** the verifier has no production fork caller, does not run child
  reinitialization or continuation pairing, and cannot acknowledge readiness
  bits 7 or 8 by itself. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-child-shared-backing-authentication — bind exact memfds

- **Patch:**
  `0156-crucible-authenticate-fork-child-shared-mapping-backings.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** every allowed writable shared range additionally names a
  page-aligned offset and retained backing descriptor. Before scanning, QEMU
  requires a regular file large enough for the exact range and
  `F_SEAL_SHRINK`. During the bounded procfs scan it authenticates the VMA's
  offset, device, and inode against `fstat(2)` on that descriptor rather than
  trusting a range-only declaration.
- **Micro-test:** the real-fork path retains a shrink-sealed memfd through
  descriptor closure and accepts its exact shared mapping. A second regression
  maps one same-sized sealed memfd while declaring another and requires
  destructive rejection before any mapping proof is recorded.
- **Inertness:** the verifier is still internal and unwired; no production fork
  caller composes its result with child reinitialization or acknowledges
  readiness bits 7 or 8. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-child-resource-transaction — order child disposition

- **Patch:** `0157-crucible-compose-fork-child-resource-disposition.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** one immediate-child operation preflights the complete retained
  descriptor and writable-shared mapping tables before mutation, closes
  descriptor admission, applies exact endpoint replacement and descriptor
  closure, invokes one child reinitializer that must leave recreated workers
  held, and only then authenticates the resulting mapping table. Invalid tables
  preserve the active transaction; every failure after replacement begins is
  destructive and requires child termination or quarantine.
- **Micro-test:** the real-fork path uses `MADV_DONTFORK` to omit the source VMA,
  applies the exact closed descriptor table, reconstructs the replacement VMA,
  and requires all three transaction phases. A separate unretained-backing
  preflight proves that no endpoint changes and the reinitializer is not called.
- **Inertness:** the composition remains internal and unwired. It does not
  invoke the registered QEMU/plugin reinitializer from a production fork,
  complete other QEMU subsystem reconstruction, pair the host continuation,
  release guest admission, or acknowledge readiness bits 7 or 8.
  `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-source-mapping-binding — bind the retained source VMA

- **Patch:** `0158-crucible-bind-hot-fork-source-mappings.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** while the exact template transaction is retained, private-ring
  staging streams `/proc/self/maps` under the existing 65,536-record,
  8-KiB-record, and 16-MiB aggregate bounds. It requires exactly one writable
  shared VMA at offset zero whose device, inode, and page-aligned length match
  the plugin setup-region manifest. Private-ring schema version 3 retains that
  process-local source range beside the authenticated branch-private backing;
  standalone staging explicitly carries no source-range authority.
- **Micro-test:** a shrink-sealed memfd mapped once is bound to its exact
  address, length, and zero offset. A second alias and a wrong inode are both
  rejected. The QMP and Rust-client tests reject contradictory bound/unbound
  source shapes.
- **Inertness:** the source address is an observed process-local scalar, not a
  dereferenceable cross-process pointer. No production fork invokes the
  registered runtime, constructs the complete child mapping allowlist, pairs
  the host continuation, releases guest admission, or acknowledges readiness
  bits 7 or 8. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-child-runtime-source-binding — bind runtime remap geometry

- **Patch:** `0159-crucible-bind-child-runtime-source-mappings.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** fixed-layout child-runtime plan and status version 3 carry the
  authenticated template setup-region start, length, and zero file offset.
  QEMU rejects unaligned, overflowing, differently sized, or nonzero-offset
  geometry before invoking the registered callback. The GPL plugin independently
  compares that plan with its retained process-local mapping owner before the
  exact-address branch-private install and echoes the immutable basis afterward.
- **Micro-test:** Rust layout tests pin the version-3 C ABI size and offsets,
  plugin tests reject wrong address, length, and offset bases, and the typed QMP
  parser accepts only a complete installed range while rejecting skipped process
  generations and contradictory source geometry.
- **Inertness:** the registered runtime remains unwired to the destructive child
  resource transaction. No production fork caller, complete QEMU subsystem
  reinitializer, host continuation pairing, guest-admission release, or readiness
  acknowledgement for bits 7 and 8 exists. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-registered-child-runtime-composition — compose the runtime adapter

- **Patch:** `0160-crucible-compose-registered-fork-child-runtime.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU copies a valid fixed-layout version-3 child-runtime plan
  into a prepared one-shot adapter. The adapter invokes the process-global
  registered plugin runtime exactly once and accepts success only when the
  returned status echoes the exact immutable plan and proves callbacks held,
  the branch-private mapping installed, every sealed worker parked, and no
  pending local operation. The registered entry point and adapter share the
  complete process-independent plan validator; process-local resource identity
  remains reauthenticated by the registered runtime immediately before its
  mutation.
- **Micro-test:** the real-fork child resource transaction composes descriptor
  closure, the registered-runtime adapter, and exact post-remap mapping
  verification. A fake registered runtime proves the adapter rejects an
  initializing status and is nonretryable after its first attempt; the plugin's
  production callback remains covered by its separate exact-plan and remap
  tests.
- **Inertness:** no production fork caller invokes the composed adapter, and
  complete non-plugin QEMU subsystem reinitialization, host-continuation
  pairing, guest-admission release, and readiness acknowledgements for bits 7
  and 8 remain absent. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-retained-plugin-child-plan — bind the retained plan

- **Patch:** `0161-crucible-bind-retained-plugin-child-plan.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** before it commits endpoint ownership, the version-14 retained
  template coordinator derives a fixed-layout version-3 plugin child-runtime
  plan from the exact active template, branch-private ring, authenticated source
  VMA, endpoint replacement slots, kernel identities, registered process
  generation, quiescent plugin barrier, and sealed worker disposition. It copies
  that plan into QEMU's unconsumed one-shot adapter. Idempotent staging requires
  the adapter to retain the same plan; exact endpoint release clears the parent
  copy. The strict nested report carries the adjacent parent and child process
  generations and a plan-bound bit only while the complete basis still matches.
- **Micro-test:** QEMU unit coverage exact-compares the copied plan, rejects a
  changed endpoint generation, and proves reset removes the binding. Strict Rust
  QMP fixtures accept the complete version-14 report, expose the adjacent
  generation pair, and reject malformed resource-stage shapes. The live gate
  pins the expanded idle schema while the exact patch certificate checks the
  production binding symbols.
- **Inertness:** plan construction neither forks nor mutates a child descriptor
  table or mapping. Complete non-plugin QEMU subsystem reinitialization,
  host-continuation pairing, guest-admission release, and readiness
  acknowledgements for bits 7 and 8 remain absent. `T-CAM-6.2` remains
  incomplete.
- **Risk:** F.

### crucible-hot-fork-plugin-child-resource-tables — bind exact plugin tables

- **Patch:** `0162-crucible-bind-plugin-child-resource-tables.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the version-15 retained template coordinator converts the
  exact copied registered child-runtime plan and staged branch-private control
  and wake source descriptors into a nondestructive resource-table adapter.
  The adapter contains exactly two source-to-target replacements, a strictly
  sorted three-descriptor retain set for the private ring and endpoint targets,
  and one writable-shared mapping allowlist entry backed by the retained ring
  at the plan's exact source geometry. Idempotent staging exact-compares the
  complete source and plan basis; endpoint release clears both adapters.
- **Micro-test:** QEMU unit coverage checks every replacement, sorted retained
  descriptor, mapping field, mismatched source and plan rejection, tamper
  detection, reset, and source/target alias rejection. Strict Rust QMP fixtures
  require the version-5 nested field and version-15 outer report. The live gate
  and exact patch certificate pin those public facts.
- **Inertness:** the adapter neither enumerates non-plugin QEMU resources nor
  calls the destructive child transaction. Production fork invocation,
  complete QEMU subsystem reinitialization, host-continuation pairing,
  guest-admission release, and readiness acknowledgements for bits 7 and 8
  remain absent. `T-CAM-6.2` remains incomplete.
- **Risk:** F.

### crucible-hot-fork-child-resource-contribution-composition — compose exact tables

- **Patch:** `0163-crucible-compose-child-resource-contributions.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU starts one bounded child-resource plan from the exact
  plugin contribution and can merge further immutable subsystem contributions
  into canonical sorted unions. Exact duplicate descriptors and mappings are
  idempotent; unsorted inputs, replacement-source retention, differently
  described overlapping mappings, missing retained backing descriptors, and
  unions beyond either 4,096-entry ceiling fail before the existing plan is
  changed. Sealing revalidates the complete union and the retained template
  report requires that sealed plan to contain its exact plugin basis.
- **Micro-test:** QEMU unit coverage proves canonical descriptor and mapping
  order, idempotent duplicate merging, atomic rejection of malformed, aliased,
  overlapping, and unbacked contributions, immutable sealing, tamper detection,
  reset, and both exact table ceilings. The full package gate executes all 15
  child-resource unit cases, while the live and exact-patch gates pin the
  coordinator composition symbols.
- **Inertness:** the current coordinator contributes only the already-retained
  plugin fragment. Registration of QMP, block, AIO, and other supported-profile
  resources, production fork invocation, destructive child disposition,
  host-continuation pairing, guest-admission release, and readiness
  acknowledgements for bits 7 and 8 remain absent. `T-CAM-6.2` remains
  incomplete.
- **Risk:** F.

### crucible-hot-fork-sealed-child-resource-plan-application — consume one exact union

- **Patch:** `0164-crucible-consume-sealed-child-resource-plans.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU exact-compares an inherited sealed plan with the same
  unconsumed plugin reinitializer before entering the authenticated
  immediate-child transaction. Successful preflight consumes the plan before
  descriptor mutation; the destructive path uses only the plan's canonical
  replacements, retained descriptors, and writable-shared mappings. Exact
  descriptor closure, held plugin reconstruction, and mapping authentication
  mark the plan applied. Preflight rejection retains both linear owners, while
  every failure after consumption is one-shot and rejects the child.
- **Micro-test:** the real-fork resource transaction now consumes the sealed
  adapter, retains one independently contributed result descriptor, closes an
  unlisted inherited descriptor, reconstructs the private mapping, invokes the
  registered plugin runtime once, and proves the parent's plan copy remains
  unconsumed. Negative coverage rejects an open plan, a foreign reinitializer,
  and a tampered sealed table without consumption; a second child application
  is rejected.
- **Inertness:** no production caller invokes `fork(2)` or this destructive
  adapter, and the retained coordinator still supplies only the plugin and
  diagnostics contributions. Complete QMP, block, AIO, and other supported-profile resource
  registration, host-continuation pairing, guest-admission release, and
  readiness acknowledgements for bits 7 and 8 remain absent. `T-CAM-6.1`
  through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-descriptor-replacement-composition — merge branch-private endpoints

- **Patch:** `0165-crucible-compose-child-descriptor-replacements.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** each subsystem may add a strictly target-ordered replacement
  table to the existing retained-descriptor and writable-shared-mapping
  contribution. QEMU canonicalizes the plugin's initial pair, merges at most
  4,096 replacements, and requires all sources and targets to be globally
  pairwise distinct. Exact duplicates are idempotent; a reused source,
  differently described target, missing retained target, unsorted table, or
  over-limit union fails before the accumulated plan changes. The child
  transaction saves every prior target on its fixed stack, applies the sealed
  table, and restores all targets if verification rejects the installation.
- **Micro-test:** composition reaches the exact replacement and retained-table
  ceilings, rejects source/target cross-aliases and missing targets without
  mutation, and preserves the prior retained and mapping conflict cases. The
  real-fork sealed-plan path independently contributes a result-pipe
  replacement, then reports success only through the installed target while
  the source is absent from the final child table.
- **Inertness:** no production subsystem yet supplies QMP, block, AIO, or the
  remaining non-plugin replacements, and no production caller invokes the fork
  transaction. Complete supported-profile registration, host-continuation
  pairing, guest-admission release, and readiness acknowledgements for bits 7
  and 8 remain absent. `T-CAM-6.1` through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-branch-private-child-diagnostics — bind private stderr

- **Patch:** `0166-crucible-bind-branch-private-child-diagnostics.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU duplicates one standard-QMP `getfd` entry only under the
  exact active template and private-ring generation, authenticates the
  connected AF_UNIX stream by Linux `SO_COOKIE`, makes it nonblocking, and
  contributes one source-to-stderr replacement plus retained target to the
  canonical sealed child resource plan. Plugin endpoint commitment requires
  and seals this contribution. The immediate-child adapter reauthenticates the
  resulting stderr stream after applying the descriptor union. Exact cleanup
  releases plugin endpoints, the QEMU diagnostics duplicate, the monitor name,
  and the host owners in reverse order.
- **Micro-test:** the real-fork resource-plan path installs a fresh diagnostics
  socket at stderr and proves the child authenticates it while the parent keeps
  its original stderr. Composition tests require the exact diagnostics basis,
  include it in global descriptor bounds, and reject malformed or missing
  contributions. Typed host tests cover strict schema, command serialization,
  kernel identity, template binding, and release ordering.
- **Inertness:** no production fork caller or bounded diagnostics consumer uses
  the retained endpoint. QMP, block, AIO, console, filesystem, and the remaining
  supported-profile resource contributions are still absent, so readiness bits
  7 and 8 and `T-CAM-6.1` through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-branch-private-child-qmp — retain a private monitor stream

- **Patch:** `0167-crucible-retain-branch-private-child-qmp.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the host creates a fresh connected AF_UNIX socket pair for a
  future child monitor and imports only the child endpoint through standard
  QMP `getfd`. QEMU authenticates the exact Linux `SO_COOKIE`, requires the
  stream to be empty and nonblocking, rejects aliasing with diagnostics and
  plugin control resources, and adds the retained descriptor to the same
  canonical child resource plan. Plugin endpoint commitment requires private
  rings, diagnostics, and child QMP from one template generation before it
  seals that plan. Exact cleanup releases plugin endpoints, the QEMU-retained
  child-QMP duplicate, the monitor name, diagnostics, and private rings in
  reverse ownership order.
- **Micro-test:** the sealed-plan unit paths require the QMP contribution,
  include it in exact retained-descriptor bounds, and prove that it survives
  immediate-child descriptor closure without being attached to a monitor.
  Typed host tests pin the version-1 QMP schema, descriptor transfer, exact
  template and socket identity, sealed-plan binding, and release ordering.
- **Inertness:** the host retains both fresh socket endpoints, but neither QEMU
  nor the host closes the inherited monitor, resets parser state, attaches the
  private endpoint, or performs the child handshake. Block, AIO, console,
  filesystem, and remaining supported-profile contributions are also absent.
  Production fork invocation, host-continuation pairing, guest admission,
  readiness bits 7 and 8, and `T-CAM-6.1` through `T-CAM-6.3` remain
  incomplete.
- **Risk:** F.

### crucible-hot-fork-child-qmp-reinitializer-contract — bind child monitor reconstruction

- **Patch:** `0168-crucible-bind-child-qmp-reinitializer.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU prepares a one-shot adapter bound to the exact retained
  child-QMP descriptor, Linux socket identity, template generation, and
  child-QMP mutation generation. A future runtime result is accepted only when
  it reports complete inherited-monitor disposal, dispatcher and endpoint
  reconstruction, parser and capability reset, greeting emission, held input,
  exactly one replacement monitor, and no queued or partially buffered
  requests. The adapter becomes terminal before invoking that runtime and
  rejects contradictory success reports.
- **Micro-test:** strict unit paths prove exact basis matching, complete-status
  admission, terminal behavior after both success and failure, and rejection of
  incomplete or contradictory results. Typed host and live-readiness tests pin
  child-QMP schema version 2, template version 18, resource-stage version 8,
  and the prepared-but-unconsumed state.
- **Inertness:** this patch defines and retains only the fail-closed adapter.
  It does not implement inherited monitor teardown, rebuild the dispatcher,
  attach the private endpoint, perform the private-stream handshake, invoke
  `fork(2)`, or acknowledge readiness bit 7 or 8. Remaining supported-profile
  resources, host-continuation pairing, guest admission, and `T-CAM-6.1`
  through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-qmp-reinitializer-composition — consume the monitor adapter

- **Patch:** `0169-crucible-compose-child-qmp-reinitializer.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the sealed branch-private QMP contribution now carries its
  exact template and child-QMP generations in addition to the descriptor and
  Linux socket identity. The immediate-child transaction requires both the
  plugin and QMP reinitializers to match that complete sealed basis before it
  begins descriptor mutation, then invokes them as one linear child subsystem
  reconstruction step. Either runtime failure leaves the one-shot transaction
  consumed and fail-closed.
- **Micro-test:** the real-fork resource-plan path proves that both adapters run
  exactly once and complete before shared mappings are admitted. Preflight
  tests substitute a same-endpoint QMP adapter from another mutation generation
  and prove rejection occurs before the plan or child transaction is consumed.
- **Inertness:** the QMP runtime remains an injected test contract; this patch
  does not dispose inherited monitors, construct the replacement dispatcher,
  attach the private endpoint, perform its generation handshake, invoke a
  production fork, or acknowledge readiness bit 7 or 8. Remaining
  supported-profile resources, host-continuation pairing, guest admission, and
  `T-CAM-6.1` through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-qmp-disposition-report — expose accepted completion

- **Patch:** `0170-crucible-report-complete-child-qmp-disposition.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the child-QMP report now derives `disposition-complete` from
  the exact accepted one-shot runtime status rather than hard-coding false. The
  public predicate requires the prepared, attempted, and initialized adapter
  plus the retained descriptor, socket identity, template generation, QMP
  generation, complete flags, one monitor, and empty queued/parser state.
- **Micro-test:** exact, contradictory, runtime-failure, and reset cases prove
  that only the complete accepted status becomes observable. The real-fork
  composition additionally requires the accepted predicate before the child
  can report success.
- **Inertness:** the accepted status still comes from an injected test runtime.
  This patch does not dispose inherited monitors, construct the replacement
  dispatcher, attach the private endpoint, perform its generation handshake,
  invoke a production fork, or acknowledge readiness bit 7 or 8. Remaining
  supported-profile resources, host-continuation pairing, guest admission, and
  `T-CAM-6.1` through `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-qmp-query-basis — preserve post-apply identity

- **Patch:** `0171-crucible-preserve-child-qmp-query-basis.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU separates immutable reinitializer-basis matching from
  one-shot availability. A successful attempt therefore remains bound to the
  exact retained descriptor, Linux socket identity, template generation, and
  child-QMP generation, while `prepared-for` still rejects reuse. The sealed
  resource plan likewise reports the exact QMP contribution after successful
  application but not during a partial or failed application. The version-2
  child-QMP query uses those persistent predicates, so its accepted disposition
  remains independently authenticatable over the future private monitor.
- **Micro-test:** unit coverage proves a completed adapter remains basis-bound
  but not reusable, and the real-fork resource transaction proves the applied
  plan retains the exact QMP contribution. Reset, foreign, failed, and
  contradictory cases retain their fail-closed behavior.
- **Inertness:** the concrete monitor runtime and production fork owner remain
  absent. The host can validate this query only after a future child attaches
  and releases its private monitor; this patch does not perform that attachment,
  release guest admission, or acknowledge readiness bit 7 or 8. Remaining
  supported-profile resources and `T-CAM-6.1` through `T-CAM-6.3` remain
  incomplete.
- **Risk:** F.

### crucible-hot-fork-monitor-inventory — bound monitor and parser state

- **Patch:** `0172-crucible-inventory-qmp-monitor-state.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** QEMU owns a version-1 OOB inventory of at most 256 monitors.
  It reports the monitor lifecycle generation, QMP/HMP and I/O-thread counts,
  suspended and negotiating monitors, OOB capability state, queued requests,
  partial-parser bytes, partial parsers, and parser snapshots that raced input.
  A recursive per-monitor parser lock lets the querying OOB monitor inspect its
  own reset parser. The global inventory never blocks on another parser while
  holding the monitor-list lock; a failed try-lock makes the report incomplete.
- **Micro-test:** the live Phase 6 gate rejects stock QEMU, requires two
  identical reports, and pins the supported parent profile to one stable
  OOB-enabled I/O-thread QMP monitor with no HMP monitor, suspension,
  negotiation, queued request, partial parser, or unstable record. Strict Rust
  decoding rechecks every count relationship and the 256-monitor bound.
- **Inertness:** this operation is observational. It neither disposes inherited
  monitors nor constructs a child dispatcher, attaches the private endpoint,
  releases guest input, invokes a fork, or acknowledges readiness bit 7 or 8.
  The concrete child monitor runtime and `T-CAM-6.1` through `T-CAM-6.3` remain
  incomplete.
- **Risk:** F.

### crucible-hot-fork-child-qmp-profile-binding — bind admitted monitor generation

- **Patch:** `0173-crucible-bind-supported-child-qmp-profile.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** child-QMP staging rechecks the complete supported monitor
  profile under the retained-template lock, rejects every partial, unstable, or
  multi-monitor topology, and binds the positive monitor lifecycle generation
  into child-QMP contract version 3, resource-stage contract version 9, and
  template transaction version 19. The sealed resource plan, one-shot child
  runtime status, and private host handshake must all preserve that exact
  generation.
- **Micro-test:** the live Phase 6 report pins the three new schema versions.
  Structural checks require the supported-profile predicate and the exact
  generation comparisons at staging, sealed-plan validation, and child status
  authentication. QEMU's child-resource unit test rejects a mismatched monitor
  generation.
- **Inertness:** the change authenticates one already-supported parent profile
  and its lifecycle generation. It does not reconstruct the child monitor,
  invoke a fork, release guest input, or acknowledge readiness bit 7 or 8.
  Destructive monitor reconstruction and `T-CAM-6.1` through `T-CAM-6.3`
  remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-monitor-ownership-basis — retain exact monitor owners

- **Patch:** `0174-crucible-bind-child-monitor-ownership-basis.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** child-QMP staging captures the exact admitted `MonitorQMP`,
  monitor `IOThread`, dispatcher coroutine, and positive monitor lifecycle
  generation as one QEMU-private ownership basis. QEMU revalidates the full
  supported profile and exact retained objects immediately before committing
  the endpoint, repeats that check for an idempotent restage, and clears the
  basis on release. Child-QMP contract version 4 exposes only the boolean
  `monitor-basis-bound`; native pointers never cross QAPI or shared memory.
  Resource-stage contract version 10 and template transaction version 20 bind
  the stricter contribution.
- **Micro-test:** the live Phase 6 report pins all three schema versions and the
  initially absent ownership basis. Structural checks require the private basis
  type and its prepare, current-profile comparison, and reset operations.
- **Inertness:** the retained basis is future child-reconstruction authority,
  not reconstruction itself. This patch does not dispose the inherited
  monitor, build a child dispatcher, attach the endpoint, invoke a fork,
  release guest input, or acknowledge readiness bit 7 or 8. Destructive
  monitor reconstruction and `T-CAM-6.1` through `T-CAM-6.3` remain
  incomplete.
- **Risk:** F.

### crucible-hot-fork-child-monitor-chardev-disposition — bind the inherited endpoint owner

- **Patch:** `0175-crucible-bind-child-monitor-chardev-disposition.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the private child ownership basis now also retains the exact
  inherited `Chardev`. Staging requires that it remain the admitted monitor's
  connected frontend, support GMainContext dispatch, and expose both backend
  disconnect and add-client operations. Exact restage repeats that comparison.
  Child-QMP contract version 5 exposes only
  `monitor-disposition-bound`; resource-stage contract version 11 and template
  transaction version 21 bind the stricter contribution.
- **Micro-test:** the live Phase 6 report pins all three schema versions and the
  initially absent disposition proof. Structural checks require exact frontend
  ownership, both backend operations, and the private disposition predicate.
- **Inertness:** this patch proves that the retained inherited endpoint has the
  operations needed by a future child transition. It does not call those
  operations, dispose the inherited monitor, create a child dispatcher, attach
  the private endpoint, invoke a fork, release guest input, or acknowledge
  readiness bit 7 or 8. Destructive reconstruction and `T-CAM-6.1` through
  `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-hot-fork-child-monitor-socket-resources — bind the supported socket backend

- **Patch:** `0176-crucible-bind-child-monitor-socket-resources.patch`.
- **Enforces:** [HFORK-4], [HFORK-8], [HFORK-9], [HFORK-10], [HFORK-11],
  [HFORK-12], [HFORK-21], [HFORK-22].
- **Mechanism:** the private child ownership basis now also retains the exact
  connected Unix-socket frontend, address, channel, socket, listener, read and
  HUP sources, `GMainContext`, and a positive monotonic connection generation.
  Staging rejects non-Unix and non-listening endpoints, TLS, telnet, TN3270,
  WebSocket, reconnect and connect-task state, queued descriptor transfers,
  replay mode, and non-GMainContext dispatch. Commit and exact restage repeat
  the complete comparison under the chardev write lock. A disconnect or
  reconnect changes the generation and invalidates the retained basis.
  Child-QMP contract version 6 exposes only
  `monitor-socket-resources-bound`; resource-stage contract version 12 and
  template transaction version 22 bind the stricter contribution.
- **Micro-test:** the live Phase 6 report pins all three schema versions and the
  initially absent socket-resource proof. The QEMU Unix socket-server unit
  tests require an exact basis, reject a substituted frontend and generation,
  invalidate it on disconnect and reconnect, and reject the TCP profile.
- **Inertness:** this patch retains the exact resources that a future child
  transition must consume. It does not disconnect the inherited socket, remove
  sources, destroy the inherited monitor, build a child dispatcher, attach the
  private endpoint, invoke a fork, release guest input, or acknowledge
  readiness bit 7 or 8. Destructive reconstruction and `T-CAM-6.1` through
  `T-CAM-6.3` remain incomplete.
- **Risk:** F.

### crucible-canonical-rr-genesis-cursor — expose the unique genesis coordinate

- **Patch:** `0091-crucible-canonical-rr-genesis-cursor.patch`.
- **Enforces:** [DET-1], [QFP-REG-1], [QFP-STATE-2].
- **Mechanism:** at the exact deterministic raw-zero boundary before QEMU's
  first runnable selection, `qemu_plugin_rr_cursor()` maps the intentionally
  unowned serialized cursor to its unique next scheduler coordinate: vCPU 0,
  position 0. The read does not mutate `TimersState`. An invalid owner at any
  later coordinate or outside the exact boundary remains rejected.
- **Micro-test:** the production live-world lifecycle captures canonical
  genesis state in a fresh QEMU process, executes the selected lossy-network
  branch, and requires its decisions to match the branch found before a durable
  checkpoint and exact next-quantum restore. Structural checks pin the raw-zero
  and position-zero conjunction and retain the non-genesis negative control.
- **Inertness:** [PATCH-3](c) — the new success case requires the existing
  exact-boundary scope, invalid serialized owner, raw icount zero, and cursor
  position zero simultaneously. Every post-genesis and ordinary unowned read
  follows the prior fail-closed path.
- **Risk:** D.

### crucible-canonical-terminal-rr-cursor — project terminal live observations

- **Patch:** `0092-crucible-canonical-terminal-rr-cursor.patch`.
- **Enforces:** [DET-1], [DET-29], [QFP-STATE-2].
- **Mechanism:** when the current serialized owner observes the transient live
  position equal to `rr_switch_quantum`, `qemu_plugin_rr_cursor()` reports the
  scheduler's next vCPU at position zero. This is the coordinate RR accounting
  commits when the translation block returns; the projection does not mutate
  scheduler state or admit any other out-of-range cursor.
- **Micro-test:** the full production instruction and exception mutation matrix
  exercises fingerprint capture at instruction completion, while structural
  checks pin terminal equality, next-vCPU selection, and position-zero output.
- **Inertness:** [PATCH-3](c) — the projection requires sim's pinned quantum,
  a live current owner, and exact terminal equality. Exact-boundary, genesis,
  non-sim, and invalid-owner behavior remains unchanged.
- **Risk:** D.

### crucible-canonical-register-cursor — commit after-instruction coordinates

- **Patch:** `0093-crucible-canonical-register-cursor.patch`.
- **Enforces:** [DET-1], [DET-29], [QFP-STATE-2].
- **Mechanism:** register mutations advance the callback-local retired prefix
  by the current instruction for after-instruction evidence. An exact terminal
  is projected onto the next RR owner at position zero, matching the serialized
  coordinate that scheduler accounting commits.
- **Micro-test:** the full live register mutation matrix exercises before and
  after phases, and its terminal case rejects the legacy position-equal-quantum
  encoding in favor of the canonical position-zero handoff.
- **Inertness:** [PATCH-3](c) — only register evidence in the existing
  after-instruction mutation phase receives the semantic advancement; before
  phase and non-register behavior is unchanged.
- **Risk:** D.

### crucible-retention-virtual-time-origin — keep retention in one clock domain

- **Patch:** `0094-crucible-retention-virtual-time-origin.patch`.
- **Enforces:** [DET-1], [TIME-23], [E14].
- **Mechanism:** memory-retention installation records its initial exposure from
  QEMU's authoritative virtual nanosecond clock. It no longer interprets the
  raw instruction coordinate on a boundary result as virtual time before adding
  the configured nanosecond interval.
- **Micro-test:** the live memory-access matrix installs a one-nanosecond
  retention rule under precise icount and requires decay exactly one virtual
  nanosecond and one raw instruction after installation. Clock-biased immediate
  decay at the installation coordinate fails the test.
- **Inertness:** [PATCH-3](c) — only the initial deadline of an explicitly
  installed retention fault changes. Other memory rules and inactive fault
  execution remain unchanged.
- **Risk:** D.

### crucible-raw-pte-update-identity — separate transient PTEs from A/D writes

- **Patch:** `0095-crucible-raw-pte-update-identity.patch`.
- **Enforces:** [QFP-MEMA-1], [QFP-MEMA-2], [FAULT-ORDER].
- **Mechanism:** the x86 page-table walker retains the raw low word loaded from
  backing RAM before applying a transient corrected-poison transform.
  Translation and protection checks consume the corrected PTE, while accessed
  and dirty updates compare and update the raw backing word. Corrected fault
  bits therefore remain transient and cannot force an endless cmpxchg retry.
- **Micro-test:** the production x86 memory-access matrix applies corrected
  poison to a live page-table entry whose accessed bit must be updated. The
  guest must finish the translation, observe the intended mapping, publish one
  corrected event, and terminate before the hard timeout.
- **Inertness:** [PATCH-3](c) — without an active page-table-walk correction,
  the retained raw word equals the translated word and the upstream cmpxchg is
  unchanged.
- **Risk:** D.

### crucible-physical-page-table-region-fixture — target descriptor storage

- **Patch:** `0096-crucible-physical-page-table-region-fixture.patch`.
- **Enforces:** [QFP-MEMA-1], [QFP-MEMA-2], [FAULT-EVIDENCE].
- **Mechanism:** the live TCG plugin fixture declares persistent page-table
  descriptor regions as physical targets. A walk transaction identifies the
  initiating guest virtual address separately from the descriptor GPA, so a
  descriptor region indexed as a GVA cannot match the physical walk access.
  Ordinary guest-memory region scenarios remain virtual targets.
- **Micro-test:** the x86_64 and AArch64 live memory matrices install a failed
  region over a page-table descriptor and require one error event plus the
  architecture's guest-visible fault result.
- **Inertness:** [PATCH-3](c) — only the test plugin's target-address-space bit
  changes; production QEMU code and inactive execution are untouched.
- **Risk:** F.

### crucible-canonical-memory-retry-identity — survive TB retranslation

- **Patch:** `0097-crucible-canonicalize-memory-retry-identity.patch`.
- **Enforces:** [DET-1], [QFP-MEMA-1], [QFP-STATE-2].
- **Mechanism:** memory retry keys identify instruction-backed accesses by
  architectural PC, address, length, actor, access class, and page-walk
  identity without hashing or comparing the TB-local instruction ordinal.
  Fault delivery may retranslate the same instruction at a different local
  ordinal. The retained serialized field is canonicalized to zero so
  checkpoints do not encode translation-block shape.
- **Micro-test:** the live page-table retry case first applies a one-shot
  access error, then requires the retried architectural access to carry retry
  ordinal one and apply the observer transform exactly once.
- **Inertness:** [PATCH-3](c) — the key is consulted only while active memory
  fault rules track a poisoned access retry.
- **Risk:** D.

### crucible-inactive-nested-tsc-guard — preserve SVM icount parity

- **Patch:** `0098-crucible-inactive-nested-tsc-guard.patch`.
- **Enforces:** [DET-1], [QFP-CLOCK-2], [PATCH-3].
- **Mechanism:** SVM entry and exit test whether the x86 TSC fault source is
  active before evaluating `cpu_get_tsc()` arguments for the discontinuity
  hook. The inactive path performs only the upstream TSC-offset assignment.
  This prevents an otherwise irrelevant virtual-clock read from accounting the
  virtualization instruction before QEMU's exception restore bookkeeping.
- **Micro-test:** the live nested stage-1 and stage-2 page-table cases execute
  VMRUN and VMEXIT with no active clock rule and must complete without a
  negative icount delta.
- **Inertness:** [PATCH-3](c) — the inactive branch is exactly the upstream
  offset update; active TSC faults retain discontinuity rebasing.
- **Risk:** D.

### crucible-valid-aarch64-abort-fixture — reach exception delivery

- **Patch:** `0099-crucible-valid-aarch64-abort-fixture.patch`.
- **Enforces:** [QFP-MEMA-1], [FAULT-EVIDENCE], [PATCH-3].
- **Mechanism:** the live AArch64 memory poison scenario supplies the
  architecture validator with data-abort vector `3` and a same-EL syndrome
  carrying the required exception class and instruction-length bit. The old
  vector `4` identifies a breakpoint, and a zero syndrome is uncategorized, so
  that pair cannot prepare a data-abort command.
- **Micro-test:** the focused AArch64 poison-exception case must prepare and
  commit canonical evidence, deliver the abort through the guest vector, and
  publish `0xe1` exactly once.
- **Inertness:** [PATCH-3](c) — this is a GPL-side test fixture and changes no
  production execution path.
- **Risk:** F.

### crucible-aarch64-memory-exception-vectors — admit architectural aborts

- **Patch:** `0100-crucible-aarch64-memory-exception-vectors.patch`.
- **Enforces:** [QFP-MEMA-1], [FAULT-EVIDENCE], [PATCH-3].
- **Mechanism:** the production memory-rule admission check requires AArch64
  instruction-abort vector `2` for fetch-only rules and data-abort vector `3`
  for non-fetch rules. The old shifted pair, vectors `3` and `4`, contradicted
  QEMU's architectural enum and rejected every valid memory exception before
  the architecture validator ran.
- **Micro-test:** the focused poison-exception and one-shot retry cases must
  prepare and commit canonical evidence, then complete through the guest's data
  abort vector; the full invalid-rule matrix must retain atomic rejection.
- **Inertness:** [PATCH-3](c) — the check changes only explicit commanded-fault
  admission; with no matching command, it is unreachable.
- **Risk:** D.

### crucible-canonical-snapshot-rr-resume — preserve source continuation

- **Patch:** `0101-crucible-canonicalize-snapshot-rr-resume.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [QEMU-43].
- **Mechanism:** after a successful deterministic snapshot, QEMU arms the
  existing one-shot serialized-owner selection. Source execution therefore
  resumes from the same RR owner and intra-turn position that a fresh process
  selects after loading the snapshot.
- **Micro-test:** exact snapshot source continuation and two fresh-process
  restores must converge at the same canonical RR coordinate and guest-state
  fingerprint, including a nonzero intra-turn cursor.
- **Inertness:** [PATCH-3](c) — the hook changes only successful sim-mode
  snapshots with a valid serialized RR cursor.
- **Risk:** D.

### crucible-bql-exact-register-capture — observe snapshot boundaries

- **Patch:** `0102-crucible-bql-exact-register-capture.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [QEMU-43].
- **Mechanism:** a BQL-held exact callback may read quiescent vCPU registers
  while post-snapshot RR owner reselection is pending. Idle-time advance
  completions explicitly enter the exact-boundary scope; concurrent and
  non-exact running contexts remain rejected.
- **Micro-test:** exact snapshot source continuation and two fresh-process
  restores must capture identical register state, while negative admission
  cases remain fail-closed.
- **Inertness:** [PATCH-3](c) — the widened admission requires both an explicit
  exact callback and BQL ownership in deterministic single-threaded RR mode.
- **Risk:** D.

### crucible-isolate-checkpoint-control-wake — preserve frozen device state

- **Patch:** `0103-crucible-isolate-checkpoint-control-wake.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [PATCH-20].
- **Mechanism:** once exact VM stop is pending, the shared eventfd wake hands
  the BQL to QEMU's main loop without incrementing the block wake generation or
  resuming a parked request coroutine. Response and reset notifications keep
  their normal production progress semantics.
- **Micro-test:** the pending-block exact snapshot scenario must reach native
  stopped state and restore durably without admitting a completion beyond the
  published pause coordinate.
- **Inertness:** [PATCH-3](c) — request suppression is limited to a drained
  wake after the exact native-stop handoff has already been queued.
- **Risk:** D.

### crucible-preserve-checkpoint-block-durability — retain volatile state

- **Patch:** `0104-crucible-preserve-checkpoint-block-durability.patch`.
- **Enforces:** [DET-1], [QFP-STATE-2], [QFP-BLOCK-3].
- **Mechanism:** while an exact Crucible VM stop is pending, the shared-memory
  block backend treats QEMU's synthetic stop-time flush as complete without
  submitting a request. The paired Apache checkpoint remains authoritative for
  volatile cache, controller, media, and fault continuations.
- **Micro-test:** the pending-durability exact snapshot must stop, save, and
  restore twice without a post-quiescence flush request or a change to its
  canonical storage continuation; ordinary guest flush gates remain green.
- **Inertness:** [PATCH-3](c) — suppression requires the exact Crucible VM-stop
  state; guest flushes and ordinary QEMU stops retain the production transport.
- **Risk:** D.

### crucible-selector-control-plane-fixtures — isolate selector admission

- **Patch:** `0105-crucible-selector-control-plane-fixtures.patch`.
- **Enforces:** [FAULT-ORDER], [PATCH-3], [QFP-INST-3].
- **Mechanism:** live instruction-fault overlap and exclusivity modes install
  selectors whose occurrence cannot be reached during the fixture. This keeps
  control-plane admission independent of the guest instruction used for the
  preparation rendezvous.
- **Micro-test:** x86 and AArch64 live QEMU runs must reject overlapping and
  non-exclusive selectors without emitting an instruction-fault event first.
- **Inertness:** [PATCH-3](c) — only the QEMU test plugin changes; production
  selector admission, matching, mutation, and wire behavior are unchanged.
- **Risk:** F.

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

### crucible-net-direct-inject-api — canonical, lossless RX injection

- **Enforces:** [DET-18]; the RX side correctness.
- **Mechanism:** the naive inject path (`qemu_receive_packet`) silently drops
  frames when the receiver (virtio-net) is momentarily unready - nondeterministic
  loss. `qemu_plugin_net_inject` instead reports complete delivery, transient
  backpressure, or permanent failure. The plugin advances the shared-memory read
  index only for the completely delivered prefix. Backpressure buffering remains
  in the bounded, checkpointed shared-memory ring; QEMU-private packet queues are
  deliberately not used because they are neither canonical nor part of the
  durable checkpoint protocol.
- **Micro-test:** inject a frame while the receiver is momentarily unready; assert
  it is not dropped, remains in the canonical ring, QEMU's `receive_disabled`
  latch cannot suppress the later canonical probe, and the frame is delivered
  on a deterministic retry; two runs agree.
- **Inertness:** [PATCH-3](c).
- **Risk:** D (it determines RX delivery timing; a regression reintroduces
  nondeterministic loss).

- **[PATCH-32]** The series MUST provide lossless direct RX injection with
  distinct complete, backpressure, and permanent-failure results so an inbound
  frame is never silently dropped when the receiver is momentarily unready and
  is delivered at the plugin's chosen virtual-time moment. Backpressure
  retention MUST remain in the bounded, checkpointed shared-memory ring, never
  a QEMU-private packet queue. A canonical retry MUST re-probe the guest device
  independently of QEMU's private-queue `receive_disabled` latch. *Gate:*
  `gate:layer1-injection`,
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
    instruction clocks at the production shift and plain shift zero, upstream
    QMP capability/state introspection plus the exact fail-closed terminal
    lifecycle control extension, a migration stream, and
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
    `qemu_plugin_net_inject`; direct injection returns success only for complete
    guest delivery, reports transient backpressure without taking ownership, and
    fails loudly for missing or link-down NICs and malformed frames. The plugin
    retains backpressured frames in the bounded canonical ring, and skewed
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
    40M-icount O(1) advance that is deterministic run-twice under bounded scheduler preemption.
    `checks.crucible.phase1.pluginTimeAdvance` models
    the icount clock and asserts the qtest set-based advance cannot converge
    while the bias-bump reaches the target (the regression guard for this class).
  - The `crucible-plugin-device-wake` handoff ([PATCH-20]) is live-proven by
    `checks.crucible.phase2.qemuLiveBlockIo` and
    `checks.crucible.phase2.qemuLive9pIo`: real guest requests enter the reserved
    device rings, the host publishes completions at exact future icounts, the
    plugin holds virtual time while the response is unavailable, and the
    completion wakes the normal main-loop path. Both guests progress after the
    hold clears, including a run with bounded scheduler preemption and a deliberately delayed
    response. Drop-one runtime probes for patches 0017 and 0019 prove the live
    block and 9p handoffs are patch-attributed rather than supplied by a later
    patch. Patch `0076-crucible-9p-completion-wake-registration.patch` closes the
    device/plugin initialization-order case by binding notifier registration to
    virtio-9p realization; the same live gate proves a plugin installed after
    device realization still consumes the response doorbell and releases the
    device-I/O hold.
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
  `crucible-net-direct-inject-api` QEMU patch ABI/Rust resolver integration over
  the direct-injection result contract, with no-loss /
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
    uses `qemu_plugin_net_inject` from `crucible-net-deterministic`; the reused RX
    fixture proves not-ready frames remain caller-owned until a deterministic
    retry, permanent failure is loud, and skewed producer host timing does not
    change guest-visible delivery. The Rust plugin exports typed resolvers for TX
    callback registration and direct RX injection; live install registration
    remains owned by the later plugin lifecycle gates.
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
    multi-vCPU S11 fixture diffs the exact causal INIT, SIPI, and reverse-path
    commanded FIXED triple across scheduler-preempted runs. A bounded live
    firmware fixture enables the same probe under ordinary TCG, proves guest
    instruction retirement, and requires zero deterministic-delivery rows,
    executing the non-sim fallback control.
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
