# 11 — The atomic QEMU integration patch

The shipped integration contains **one atomic final-state patch**. This
count is checked against
the QEMU integration manifest by
`checks.crucible.referenceIntegrity`.

The carried patch is
`crucible-qemu-11.1.1.patch`, cataloged as
`crucible-deterministic-qemu-integration`. It is generated from the single
DCO-signed commit recorded by the QEMU integration manifest and applies directly to the pinned
QEMU 11.1.1 base. The sections below catalog the cohesive mechanisms contained
in that final-state patch; they do not define independently applicable
compatibility stages.

This file specifies the **atomic integration patch** that AOS's from-source QEMU package
([`26-packaging-aos-integration.md`](26-packaging-aos-integration.md)) carries to
make Crucible's determinism contract ([`04-determinism-contract.md`](04-determinism-contract.md))
and co-simulation transport ([`13-shmem-abi.md`](13-shmem-abi.md)) realizable.
The patch contains the C-side mechanisms that the entropy-source enumeration of
[`04-determinism-contract.md`](04-determinism-contract.md) §4.6 marks as **patch**
class (E2, E3, E9, E14, E18, E19, E20), plus the plugin-API surface the in-VM
plugin ([`12-qemu-plugin.md`](12-qemu-plugin.md)) calls to own virtual time, and
the device co-simulation paths that route block / 9p / network I/O through the
shared-memory rings ([`13-shmem-abi.md`](13-shmem-abi.md)).

The integration is **Crucible's own**. It is not a fork of, nor a
verbatim copy of, any prior internal exploration or third-party patch set
([CONV-1]). Where a prior exploration proved a mechanism necessary, Crucible
re-derives it as a focused, inertness-gated capability in the atomic patch.

Requirement IDs in this file use the prefix `PATCH`. Gate names referenced here
(`gate:qemu-inert`, `gate:patch-microtests`, `gate:layer0-determinism`,
`gate:layer1-injection`, `gate:abi-conformance`) are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md); the
packaging that applies, builds, and gates the atomic patch is
[`26-packaging-aos-integration.md`](26-packaging-aos-integration.md); the time
model the patch enforces is [`09-virtual-time-icount.md`](09-virtual-time-icount.md);
the plugin that consumes the new API surface is
[`12-qemu-plugin.md`](12-qemu-plugin.md); the shared-memory ABI the device paths
read is [`13-shmem-abi.md`](13-shmem-abi.md); the guest↔host channel that the
doorbell discussion (§11.7) coordinates with is
[`16-guest-host-channel.md`](16-guest-host-channel.md).

The single most important property of this entire file is **inertness**: every
mechanism here is dead code unless simulation mode is explicitly activated, so the
*same* AOS QEMU source built and shipped for production use is behaviorally
identical to upstream ([INV-7], [DET-36]). The atomic patch is what makes
"determinism is opt-in, production QEMU is untouched" true at the source level.

## 11.1 Governing principles

The atomic patch is held to four governing principles. Sections 11.4 through
11.8 state how each capability task satisfies them.

### 11.1.1 Inertness (the load-bearing principle)

- **[PATCH-1]** The atomic patch MUST be **inert unless simulation mode
  is active**. "Active" means the plugin (`crucible-qemu-plugin`,
  [`12-qemu-plugin.md`](12-qemu-plugin.md)) is loaded, the `sim` TCG accelerator
  is selected via `-accel sim`, and any mechanism-specific capability such as
  time-control ownership has also been acquired. Accelerator selection and
  `qemu_plugin_request_time_control` are complementary requirements, not
  equivalent activation paths. The same
  AOS QEMU binary, built from the same patched source but launched without sim
  mode, MUST be behaviorally identical to upstream QEMU of the pinned version.
  *Gate:* `gate:qemu-inert`. *Spec:* §11.1.1; satisfies [INV-7], [DET-36].

- **[PATCH-2]** The gate for the atomic patch's non-sim behavior MUST be a *checked*
  property, not a reviewed claim: `gate:qemu-inert` runs a corpus of
  upstream-equivalent invocations (boot, run, migrate, QMP introspection) against
  both the unpatched pinned QEMU and the AOS-patched QEMU *with sim mode off*, and
  MUST observe byte-identical guest-visible behavior (same instruction streams
  under plain `-icount`, same device enumeration, same migration streams). The
  patched QEMU may expose an explicitly enumerated Crucible host-control command
  when its versioned lifecycle protocol requires one, but the gate MUST prove
  that command fails closed without sim mode, leaves the VM stopped in its
  original run state, and is the complete QMP command-set delta. An integration change that
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
  The atomic patch MUST NOT alter an upstream code path that runs in the non-sim
  configuration. *Gate:* `gate:qemu-inert`. *Spec:* §11.1.1; satisfies [INV-7].

The three mechanisms map cleanly onto the capability categories: determinism
mechanisms (§11.4) use (b); the sim-mode accelerator and devices (§11.5, §11.6)
use (a); the plugin API (§11.5) uses (c). The atomic patch may not use a fourth,
looser mechanism.

### 11.1.2 Component micro-tests

- **[PATCH-4]** Every capability task MUST have a **focused micro-test** exercising exactly
  the behavior it adds — neither a broad end-to-end scenario nor a no-op smoke
  test. A determinism capability's micro-test MUST demonstrate, in isolation, that the
  entropy source it targets is eliminated by the atomic patch (e.g. two runs
  agree on the affected quantity), while the pristine-QEMU negative lacks the
  capability and makes the same focused assertion fail, per [DET-18]. A capability micro-test MUST exercise
  the new API or device path and assert its documented contract. *Gate:*
  `gate:patch-microtests`. *Spec:* §11.1.2; satisfies [DET-37], forward-ref 24.

- **[PATCH-5]** The component suite MUST also assert the atomic patch's **inertness**
  (it is a determinism/capability change in sim mode *and* a no-op out of sim
  mode), so that the pair "takes effect in sim mode / inert out of sim mode" of
  [DET-37] is checked by the patch's own test, not only by the aggregate
  `gate:qemu-inert`. *Gate:* `gate:patch-microtests`, `gate:qemu-inert`. *Spec:*
  §11.1.2; satisfies [DET-37], [INV-7].

### 11.1.3 Stated invariants

- **[PATCH-6]** The atomic commit and this file's catalog (§11.3) MUST state every
  **determinism invariant and capability** the integration enforces,
  written as a reference to a `DET-*` / `TIME-*` / `SHM-*` / `PLUG-*` requirement.
  A capability that does not map to a stated requirement MUST NOT be in the atomic
  integration; the patch exists to satisfy this contract.
  *Gate:* `gate:patch-microtests`. *Spec:* §11.1.3.

### 11.1.4 Rebasable atomic patch against a pinned QEMU

- **[PATCH-7]** The integration MUST be maintained as one **rebasable final-state
  commit** against a single **pinned upstream QEMU version** ([PATCH-30]). The
  generated patch has the stable name
  `crucible-qemu-11.1.1.patch`; its commit, tree, and
  prerequisite base are recorded in the QEMU integration manifest and in the retained Git
  bundle. *Gate:* `gate:patch-microtests`, forward-ref 26. *Spec:* §11.1.4;
  satisfies [DET-35].

- **[PATCH-8]** CI MUST gate the integration on the pinned QEMU: the patch MUST
  **apply cleanly**, the patched tree MUST **build**, and **every component
  micro-test MUST pass**, on the AOS QEMU version, on every change to the patch
  or the pin. The regeneration pipeline (§11.9) MUST produce the committed patch reproducibly so drift between the committed patch and regenerated output
  fails CI. *Gate:* `gate:patch-microtests`, `gate:qemu-inert`,
  forward-ref 26. *Spec:* §11.1.4; satisfies [DET-35], [PKG].

## 11.2 Classification: determinism-critical vs feature

Capability tasks fall into two risk classes. The class governs their scrutiny
and how their inertness is argued.

- **[PATCH-9]** Each capability task MUST be classified as **determinism-critical
  (dangerous)** or **feature/capability**. A *determinism-critical* slice changes
  how virtual time advances, how the instruction budget is computed, how entropy
  is drawn, or how an event's timing is decided — a defect in it silently breaks
  [DET-1] for *every* run, possibly without an obvious failure. A *feature* slice
  adds an API export or a device/transport path that is only reached in sim mode
  and whose failure is loud (a missing symbol, a wrong I/O result caught by a
  micro-test). Determinism-critical slices MUST carry the strongest inertness
  argument (a precise sim predicate, [PATCH-3](b)) and the most adversarial
  micro-test (run-twice-and-diff under host perturbation, [DET-38]). *Gate:*
  `gate:qemu-inert`, `gate:layer0-determinism`. *Spec:* §11.2; satisfies [INV-7],
  [INV-10].

The **risky** mechanisms in AOS's patched QEMU — the ones whose inertness must be
argued most carefully because they touch shared, always-compiled files — are:

- `crucible-icount-no-realtime` (§11.4) — edits the upstream icount budget
  function; gated on `-accel sim` with `use_icount == ICOUNT_PRECISE`.
- `crucible-no-warp-with-plugin` (§11.4) — edits the upstream warp timer; gated on
  `-accel sim` with `qemu_plugin_has_time_control()`.
- `crucible-block-rtc-read` (§11.4) — edits the upstream RTC/timedate read path;
  enabled only by `-accel sim`.
- `crucible-det-getrandom` and `crucible-det-glib-prng` (§11.4) — edit QEMU's
  entropy paths; gated on a `deterministic` predicate set only under sim mode.

Every *other* capability is either a new file (the sim accelerator, the shmem device
drivers) or a pure additive plugin-API export, both of which are inert by
construction (the file is not compiled into a used object / the export is never
called) and therefore lower-risk. These shared-file edits are the places a bug
could leak into production behavior, so they carry the heaviest gating.

## 11.3 The patch catalog

The shipped catalog has one final-state patch. Its class is F because the
commit is an additive integration boundary; the determinism-critical slices
within it remain subject to the D-class requirements and gates below. Four
operation names stay as catalog-only capabilities because other RFC sections
and result artifacts refer to those stable contract names. They are not
additional patch files.

```text
INTEGRATION                                             class  enforces
  crucible-deterministic-qemu-integration ............ F  DET-1 DET-35 HFORK-4 HFORK-22 CPERF-5 PATCH-39 QEMU-43 PKG-9

CATALOG-ONLY CAPABILITIES                               class  enforces
  rr-switch-quantum .................................. D  PATCH-44 DET-1 QEMU-43
  crucible-plugin-advance-barrier .................... D  PATCH-19 DET-1 INV-10
  crucible-plugin-device-wake ........................ D  PATCH-20 DET-1 INV-10
  crucible-net-direct-inject-api ..................... F  PATCH-32 DET-18 E18

NOT CARRIED / DEVELOPMENT ONLY                         class  enforces
  (crucible-replay-start) ............................ -  NG-6 PATCH-43
  crucible-tcg-exec-diag ............................. dev  divergence debug
  crucible-virtserial-socket ......................... dev  white-box debug
```

The catalog-only mappings are:

- `rr-switch-quantum` -> `crucible-qemu-11.1.1.patch`
- `crucible-plugin-advance-barrier` -> `crucible-qemu-11.1.1.patch`
- `crucible-plugin-device-wake` -> `crucible-qemu-11.1.1.patch`
- `crucible-net-direct-inject-api` -> `crucible-qemu-11.1.1.patch`

The capability families inside the atomic patch are deterministic TCG and
virtual time; the versioned plugin ABI; block, 9p, and network co-simulation;
exact checkpoint capture and restore; typed fault execution; device projection
manifests; and retained hot-fork worker quiescence. Sections 11.4 through 11.8
specify their normative behavior without presenting them as independently
applicable changes.

- **[PATCH-10]** The catalog above is the **authoritative inventory** of the atomic patch and
  its capability labels. A different shipped patch or an unmapped capability
  MUST fail the packaging conformance check (26). Diagnostic-only capabilities
  marked *dev* MUST NOT be applied in the shipped AOS QEMU package; they are
  available only in a developer build and MUST be inert-by-construction
  (compiled out, or behind a `diag=` plugin arg) even there. *Gate:*
  `gate:qemu-inert`, forward-ref 26. *Spec:* §11.3; satisfies [INV-7], [INV-10].

## 11.4 Determinism and scheduling requirements

The atomic patch implements these requirements as one reviewed final-state
change. The catalog above records each mechanism and risk class; the checks
named below exercise the individual capability tasks.

### Mechanism index inside the atomic patch

Each line below names one independently gated mechanism inside the atomic
patch. These are review and evidence labels, not patch files or compatibility
stages. The short description states the reason the mechanism exists.

- crucible-sim-accel ............ sim-mode TCG event loop  D    DET-1, TIME-23, E14
- crucible-no-warp-with-plugin .. suppress idle warp        D    DET-10, TIME-21, E2
- crucible-icount-no-realtime ... drop realtime from budget D    DET-9,  TIME-22, E3
- crucible-block-rtc-read ....... seed/pin guest RTC base   D    DET-8, TIME-20, E5
- crucible-det-glib-prng ........ seed global GRand (1-line) D    DET-21, E9
- crucible-det-getrandom ........ deterministic guest-rng   D    DET-21, DET-19, E9
- crucible-net-deterministic .... icount-timed RX delivery  D    DET-11, DET-13, E18
- rr_switch_quantum .... RR switch @ retired instructions    D    PATCH-44, DET-1, QEMU-43
- crucible-det-ipi .............. deterministic IPI/SIPI/INIT D    PATCH-45, DET-1, INV-7
- crucible-aarch64-det-ipi-adapter AArch64 IPI delivery adapter D  DET-4, PLUG-14, GHC-4
- crucible-det-virtio-ioeventfd . sync virtio-rng vq dispatch D    DET-1, E7
- crucible-det-rng-delivery ..... sync virtio-rng completion  D    DET-1, E7, E9
- crucible-rr-fingerprint-helpers phase-1 fp helper ABI F    DET-29, QEMU-43
- crucible-plugin-time-advance .. queued vtime + completion D    TIME-23, TIME-27, DET-1, INV-10
- crucible-time-advance-commit-barrier  fence RR through plugin commit D  TIME-23, TIME-27, DET-1, INV-10
- crucible-time-advance-enqueue-kick  kick active vCPU into barrier D  TIME-23, TIME-27, DET-1, INV-10
- crucible-time-advance-arm-at-vcpu-boundary  arm after TCG exit D  TIME-23, TIME-27, DET-1, INV-10
- crucible-plugin-advance-barrier  order timer BH completion D    PATCH-19, DET-1, INV-10
- crucible-plugin-device-wake ... event-driven device wake   D    PATCH-20, DET-1, INV-10
- crucible-clock-deadline ....... exact next vtimer deadline D    TIME-24, TIME-25
- crucible-plugin-icount-raw .... raw icount read           F    DET-29, INV-10
- crucible-vcpu-introspect ...... per-vCPU regs + RR cursor  F    PATCH-46, DET-29, INV-10
- crucible-sim-observer ......... post-exec boundary observe F    DET-29, PLUG-35
- crucible-safe-fingerprint-boundary exact BQL-held capture  F    DET-29, PLUG-35
- crucible-process-argv-attestation raw launch argv SHA-256  F    DET-31, QEMU-34
- crucible-exact-checkpoint-export .. descriptor-bound RAM + device VMState  F    DET-29, PLUG-47
- crucible-preemption-inject .... commanded vCPU switch/IRQ  D    PATCH-47, DET-1, PLUG-50
- crucible-plugin-vcpu-exit ..... force vCPU exit            D    DET-1, INV-10
- crucible-plugin-wake-fd ....... main-loop wake-fd          F    SHM-26, INV-8
- crucible-plugin-tcg-exec-cb ... TCG-exec callback          F    coverage, INV-7
- crucible-plugin-vmstop ........ exact boundary to native pause D  DET-1, INV-10, QEMU-43
- crucible-stopped-state-control-progress bounded native-stop wake D  DET-1, INV-10, QEMU-43, QFP-STATE-2
- crucible-inactive-retention-clock-guard active-rule-before-clock D  DET-1, QFP-STATE-2, FAULT-ORDER
- crucible-deferred-result-evidence-test typed deferred evidence coverage F  QEMU-44, FAULT-EVIDENCE
- crucible-deterministic-instruction-input-state stable instruction selector identity D  DET-1, QEMU-44, FAULT-EVIDENCE
- crucible-inert-clock-restore preserve native timers for inactive restored clocks D DET-1, QFP-CLOCK-2, QFP-STATE-2
- crucible-blk-shmem ............ virtio-blk over shmem      F    PATCH-26, DET-16, E19, SHM-13
- crucible-blk-shmem-io-fixes ... blk I/O correctness        D    PATCH-27, DET-16, E19
- crucible-blk-write-sentinel ... write/flush 0-len sentinel D    PATCH-28, DET-16, E19
- crucible-9p-shmem ............. virtio-9p over shmem       F    PATCH-29, DET-16, E19
- crucible-9p-completion-wake-registration realize-time notifier lifetime D PATCH-20, DET-1, INV-10
- crucible-dev-cb-api ........... register blk/9p callbacks  F    PATCH-30, PLUG, SHM-17
- crucible-net-tx-callback ...... intercept guest TX         F    PATCH-31, DET-18, E18, SHM-17
- crucible-net-direct-inject-api  lossless direct RX status F    PATCH-32, DET-18, E18
- crucible-block-typed-errors ... exact block result to errno     F    STOR-RESULT, IO-8, PATCH-26
- crucible-block-discard ........ deterministic discard transport F    STOR-DISCARD, DET-16, PATCH-26
- crucible-block-transport-reset  epoch/recovery/reset transport       F    STOR-RESET, STOR-RESULT, DET-16, PATCH-26
- crucible-sim-loop-fix ......... single-vCPU loop fixes     D    PATCH-34, DET-1, NG-1
- crucible-sim-first-exit ....... normalize first exit phase D    PATCH-34, DET-1, INV-10
- crucible-sim-skip-second-events  drop redundant 2nd events D    PATCH-34, DET-1
- crucible-sim-poll-immediate ... wake-driven shmem poll      D    PATCH-34, DET-13, E19
- crucible-sim-batch-tcg-exec ... batch TCG exec calls        F    PATCH-35, DET-1, INV-10, PERF
- crucible-sim-idle-callbacks ... idle/resume cb wiring       D    PATCH-34, TIME-24, INV-8
- crucible-sim-shmem-dispatch ... shmem co-sim dispatch glue  F    PATCH-34, SHM-1
- crucible-sim-freeze-warp-at-observation-boundary  freeze vclock at obs boundary  D    DET-8, DET-29
- crucible-sim-gate-rr-kick ..... sim-gate stock RR kick timer D    DET-30
- crucible-blk-device-completion-advance  resume blocked I/O at delivery icount  D    DET-16, PATCH-27, PLUG-21, IO-31
- crucible-9p-sync-kick ......... sync sim-mode 9p vq dispatch D    DET-16, PATCH-29, PLUG-22, IO-32
- crucible-whitebox-guest-write . callback guest-memory reply   F    PLUG-34, PLUG-51, GHC-32, GHC-37
- crucible-fault-command-abi ... closed command/result registry F FAULT-ABI, FAULT-CAP, FAULT-ORDER
- crucible-fault-safe-boundary exact icount/quiescent commit      D FAULT-BOUNDARY, FAULT-AUTH, DET-1
- crucible-memory-boundary-mutate atomic GPA/GVA RAM mutation    F QFP-MEM-1, QFP-MEM-2, FAULT-ORDER
- crucible-memory-access-faults typed CPU/DMA memory rules       D QFP-MEMA-1, QFP-MEMA-2, FAULT-ORDER
- crucible-architecture-register-faults typed CPU registers     D QFP-REG-1, QFP-REG-2, FAULT-ORDER
- crucible-instruction-and-exception-faults exact instruction/exception effects D QFP-INSN-1, QFP-EXC-1, FAULT-ORDER
- crucible-interrupt-faults ... realized controller disposition/storms D QFP-IRQ-1, QFP-IRQ-2, FAULT-ORDER
- crucible-hardware-error-inject architecture error/ECC delivery D QFP-HWERR-1, QFP-HWERR-2, FAULT-ORDER
- crucible-vcpu-service-control rational CPU service/stall/offline D QFP-VCPU-1, QFP-VCPU-2, FAULT-ORDER
- crucible-node-lifecycle-faults crash/hang/reset/power lifecycle D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-terminal-lifecycle-completion staged terminal exit D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-authenticated-terminal-lifecycle authenticated exit D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-immutable-process-generation launch-bound process ID D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-core-fault-vmstate transactional bounded core state D QFP-STATE-1, QFP-STATE-2, FAULT-ORDER
- crucible-guest-clock-faults guest clocks/timer rearming/evidence D QFP-CLOCK-1, QFP-CLOCK-2, FAULT-ORDER
- crucible-accelerator-fault-device deterministic accelerator device/faults D QFP-ACCEL-1, QFP-ACCEL-2, FAULT-ORDER
- crucible-fault-vmstate aggregate fault-state identity D QFP-STATE-1, QFP-STATE-2, QFP-STATE-3
- crucible-lifecycle-precondition atomic lifecycle VM-state precondition D QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-typed-node-result-schema fixed typed result and occurrence evidence D QFP-RESULT-1, QFP-EVENT-1, FAULT-ORDER
- crucible-device-wait-vmstop nonblocking exact control/device-completion pause F QFP-STATE-2, DET-1, INV-10
- crucible-accelerator-result-opportunity exact one-shot accelerator result arming F QFP-ACCEL-3, QFP-RESULT-1, QFP-EVENT-1, FAULT-ORDER
- crucible-authenticated-event-request-envelope restored authenticated occurrence requests F QFP-STATE-2, QFP-ACCEL-3, QFP-EVENT-1, FAULT-ORDER
- crucible-hot-fork-readiness .... report QEMU-owned quiescence proofs  F    HFORK-3, HFORK-4
- crucible-hot-fork-thread-ownership .. classify unresolved subsystem workers  F    HFORK-3, HFORK-4
- crucible-hot-fork-rcu-inventory .. expose bounded observational RCU state  F    HFORK-3, HFORK-4
- crucible-hot-fork-aio-inventory .. expose bounded AioContext activity  F    HFORK-3, HFORK-4
- crucible-hot-fork-mutex-inventory .. expose bounded QEMU lock ownership  F    HFORK-3, HFORK-4
- crucible-hot-fork-timer-inventory .. expose bounded live-timer state  F    HFORK-3, HFORK-4
- crucible-hot-fork-bottom-half-inventory .. expose every allocated QEMUBH  F    HFORK-3, HFORK-4
- crucible-hot-fork-aio-handler-inventory .. expose every POSIX AIO handler  F    HFORK-3, HFORK-4
- crucible-hot-fork-block-backend-inventory .. expose every block backend  F    HFORK-3, HFORK-5
- crucible-hot-fork-plugin-resource-inventory .. bind plugin resources to QEMU state  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-plugin-callback-barrier .. retain callback quiescence  F    HFORK-3, HFORK-4
- crucible-hot-fork-template-coordinator .. own retained preparation  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-rcu-barrier .. retain RCU quiescence  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-async-worker-barrier .. park asynchronous workers  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-aio-barrier .. close asynchronous admission  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-block-drain-barrier .. retain native block quiescence  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-block-template-coordinator .. order retained block quiescence  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-block-graph-barrier .. retain graph-writer exclusion  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-block-snapshot-roots .. bind immutable writable roots  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-ring-producer-barrier .. freeze shared rings  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-plugin-worker-manifest .. seal plugin workers  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-plugin-worker-barrier .. park sealed workers  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-ring-consumer-barrier .. drain shared-ring consumers  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-private-ring-stage .. retain authenticated private rings  F    HFORK-3, HFORK-8, HFORK-9
- crucible-hot-fork-worker-local-state .. account dequeued worker state  F    HFORK-3, HFORK-4, HFORK-5
- crucible-hot-fork-plugin-endpoint-stage .. retain branch-private plugin endpoints  F    HFORK-3, HFORK-8, HFORK-9
- crucible-hot-fork-retained-resource-stage .. stage under the retained barrier  F    HFORK-3, HFORK-8, HFORK-9
- crucible-hot-fork-resource-generation-binding .. bind retained generations  F    HFORK-3, HFORK-8, HFORK-9
- crucible-hot-fork-worker-disposition-binding .. bind worker dispositions  F    HFORK-3, HFORK-4, HFORK-8, HFORK-9
- crucible-hot-fork-source-ring-noninheritance .. exclude source rings  F    HFORK-3, HFORK-8, HFORK-9, HFORK-12
- crucible-hot-fork-child-runtime-registration .. register child reconstruction  F    HFORK-3, HFORK-4, HFORK-8, HFORK-9, HFORK-12
- crucible-hot-fork-child-process-generation .. bind one child incarnation  F    HFORK-3, HFORK-8, HFORK-9, HFORK-11, HFORK-12
- crucible-hot-fork-child-runtime-observation .. expose exact child state  F    HFORK-3, HFORK-8, HFORK-9, HFORK-11, HFORK-12
- crucible-hot-fork-endpoint-replacement-plan .. bind descriptor slots  F    HFORK-3, HFORK-4, HFORK-8, HFORK-9, HFORK-12
- crucible-hot-fork-child-endpoint-replacement-primitive .. replace two exact slots  F    HFORK-4, HFORK-8, HFORK-9, HFORK-12
- crucible-hot-fork-immediate-child-identity .. pin the exact fork lineage  F    HFORK-4, HFORK-8, HFORK-9, HFORK-11, HFORK-12
- crucible-hot-fork-plugin-ring-proof .. bind the frozen plugin resources  F    HFORK-4, HFORK-8, HFORK-9, HFORK-11, HFORK-12
- crucible-hot-fork-closed-child-descriptor-table .. close inherited FDs  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12
- crucible-hot-fork-child-descriptor-admission .. close child admission  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12
- crucible-hot-fork-child-mapping-disposition .. reject unsafe VMAs  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-shared-backing-authentication ..   F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-resource-transaction .. order child disposition  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-source-mapping-binding .. bind the retained source VMA  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-runtime-source-binding .. bind runtime remap geometry  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-registered-child-runtime-composition .. compose the runtime adapter  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-retained-plugin-child-plan .. bind the retained plan  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-plugin-child-resource-tables .. bind exact plugin tables  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-resource-contribution-composition .. compose exact tables  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-sealed-child-resource-plan-application .. consume one exact union  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-descriptor-replacement-composition .. merge branch-private endpoints  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-branch-private-child-diagnostics .. bind private stderr  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-branch-private-child-qmp .. retain a private monitor stream  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-reinitializer-contract .. bind child monitor reconstruction  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-reinitializer-composition .. consume the monitor adapter  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-disposition-report .. expose accepted completion  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-query-basis .. preserve post-apply identity  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-monitor-inventory .. bound monitor and parser state  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-profile-binding .. bind admitted monitor generation  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-monitor-ownership-basis .. retain exact monitor owners  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-monitor-chardev-disposition .. bind the inherited endpoint owner  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-monitor-socket-resources .. bind the supported socket backend  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-held-child-monitor-socket .. replace the inherited child stream while held  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-held-child-qmp-protocol .. reset inherited protocol state while held  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-held-child-qmp-dispatcher .. replace the inherited dispatcher while held  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-held-child-monitor-iothread .. replace the inherited monitor worker while held  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-qmp-activation .. greet before releasing replacement input  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-concrete-child-qmp-runtime .. bind monitor reconstruction before fork  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-child-thread-registry .. reconstruct the immediate child registry  F    HFORK-4, HFORK-22
- crucible-hot-fork-rcu-runtime-transaction .. compose RCU and registry fork ownership  F    HFORK-4, HFORK-22
- crucible-hot-fork-rcu-thread-disposition .. bind the RCU worker disposition  F    HFORK-4, HFORK-22
- crucible-hot-fork-monitor-thread-disposition .. bind the monitor IOThread disposition  F    HFORK-4, HFORK-8, HFORK-9, HFORK-22
- crucible-hot-fork-rcu-worker-ordering .. defer child RCU worker startup  F    HFORK-4, HFORK-22
- crucible-hot-fork-retained-rcu-barrier .. retain template RCU exclusion  F    HFORK-4, HFORK-22
- crucible-hot-fork-retained-async-barrier .. retain template async exclusion  F    HFORK-4, HFORK-22
- crucible-hot-fork-async-runtime-transaction .. release child async exclusion before QMP  F    HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-main-loop-coordinator .. execute fork on the QEMU main loop  F    HFORK-3, HFORK-4, HFORK-22
- crucible-hot-fork-private-qmp-transaction .. fork retained templates through private QMP  F    HFORK-3, HFORK-4, HFORK-8, HFORK-9, HFORK-10, HFORK-11, HFORK-12, HFORK-21, HFORK-22
- crucible-hot-fork-parent-reap-status .. retain exact child wait status  F    HFORK-3, HFORK-4, HFORK-11, HFORK-22
- crucible-hot-fork-child-process-contract .. contain children from birth  F    HFORK-3, HFORK-4, HFORK-11, HFORK-22
- crucible-hot-fork-child-console .. replace the fork-child console endpoint  F    HFORK-3, HFORK-4, HFORK-8, HFORK-11, HFORK-22
- crucible-hot-fork-read-only-block-source .. retain native immutable sources  F    HFORK-4, HFORK-8, HFORK-22
- crucible-hot-fork-native-worker-retirement .. rebuild native child I/O  F    HFORK-4, HFORK-8, HFORK-22
- crucible-hot-fork-native-source-ownership .. retain VMState and file identities  F    HFORK-4, HFORK-8, HFORK-22
- crucible-hot-fork-complete-native-source-set .. own the native source closure  F    HFORK-4, HFORK-8, HFORK-22
- crucible-hot-fork-template-native-sources .. freeze and restore retained sources  F    HFORK-4, HFORK-8, HFORK-22
- crucible-hot-fork-child-native-files .. adopt child-private native files  F    HFORK-9, HFORK-22
- crucible-hot-fork-child-files .. bind child-private files to the fork transaction  F    HFORK-9, HFORK-22
- crucible-out-of-band-descriptor-transfer .. allow out-of-band descriptor transfer  F    HFORK-9, HFORK-22
- crucible-plugin-child-plan-blockers .. report plugin child plan blockers  F    HFORK-4, HFORK-22
- crucible-child-plan-mapping-extents .. validate child plan mapping extents  F    HFORK-4, HFORK-22
- crucible-fork-preparation-blockers .. report fork preparation blockers  F    HFORK-4, HFORK-22
- crucible-monitor-basis-verified-before-fork .. verify child monitor basis before fork  F    HFORK-4, HFORK-22
- crucible-carried-fork-mutexes .. carry coordinator-owned and parked mutexes  F    HFORK-4, HFORK-22
- crucible-rr-vcpu-thread-restart .. restart the round-robin vCPU thread in the child  F    HFORK-4, HFORK-22
- crucible-cgroup-procs-child-placement .. place the fork child through cgroup.procs  F    HFORK-4, HFORK-22
- crucible-fork-parent-registry-release-order .. release the registry before the fork parent locks  F    HFORK-4, HFORK-22
- crucible-child-placement-before-fork-return .. complete child placement before the fork returns  F    HFORK-4, HFORK-22
- crucible-child-step-exit-status .. identify the failed child step in the exit status  F    HFORK-4, HFORK-22
- crucible-child-resource-plan-substep-status .. identify the failed resource plan sub-step  F    HFORK-4, HFORK-22
- crucible-child-iothread-start-bound .. bound the child monitor iothread start  F    HFORK-4, HFORK-22
- crucible-child-failure-result-report .. report the failing child result on its diagnostics stream  F    HFORK-4, HFORK-22
- crucible-plugin-child-worker-settle .. wait for the plugin child workers to park  F    HFORK-4, HFORK-22
- crucible-qmp-child-stage-report .. name the failing child QMP reconstruction stage  F    HFORK-4, HFORK-22
- crucible-child-monitor-fd-names .. drop inherited monitor descriptor names in the child  F    HFORK-4, HFORK-22
- crucible-child-monitor-iothread-context .. rebuild the monitor iothread GLib context in the child  F    HFORK-4, HFORK-22
- crucible-child-dispatcher-idle .. run the rebuilt dispatcher to its idle wait in the child  F    HFORK-4, HFORK-22
- crucible-console-child-stage-report .. name the failing console child stage  F    HFORK-4, HFORK-22
- crucible-console-child-default-context .. admit the default main context for the console child  F    HFORK-4, HFORK-22
- crucible-active-plugin-child-workers .. admit idle parked workers in an active plugin child  F    HFORK-4, HFORK-22
- crucible-child-file-install-report .. report a failed child-file install on the diagnostics  F    HFORK-4, HFORK-22
- crucible-unsettled-source-descriptor-report .. name the node and check behind an unsettled source  F    HFORK-4, HFORK-22
- crucible-child-file-plan-descriptors-retained .. retain the child-file plan descriptors instead of closing  F    HFORK-4, HFORK-22
- crucible-child-current-monitor-bindings .. drop the inherited current-monitor bindings in the child  F    HFORK-4, HFORK-22
- crucible-forkable-template-ram .. make guest RAM forkable while a template is retained  F    HFORK-4, HFORK-22
- crucible-stage-release-under-retained-template .. admit child stage release while a template is retained  F    HFORK-4, HFORK-22
- crucible-restarted-vcpu-thread-current-cpu .. name the current CPU on the restarted vCPU thread  F    HFORK-4, HFORK-22
- crucible-serialized-vmstop-resume-callback .. serialize guest reply handoff on the RR thread  F    PATCH-34, TIME-24, INV-8
- crucible-deferred-single-vcpu-state-free-host-kicks .. defer single-vCPU host wakes to RR boundaries  D    DET-1, DET-29, QEMU-43
- crucible-sim-rr-idle-wake-rescan .. release the BQL for one wait and rescan  D    DET-1, DET-13, QEMU-43
- crucible-hot-fork-external-mutex-registry .. retain mutex identity outside caller storage  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-api-port .. port the integration to QEMU 11 interfaces  F    PATCH-39, DET-35, PKG-9
- crucible-versioned-retained-child-status .. version and isolate retained child status records  F    HFORK-4, HFORK-22
- crucible-replay-snapshot-before-startup-resume .. load replay before CPU resume  D    DET-1, DET-35, PATCH-39
- crucible-qemu-11-atomic128-hooks .. retain 128-bit atomic observation  D    DET-1, DET-35, PATCH-39
- crucible-qemu-11-qapi-docs .. emit QAPI docs with the QEMU 11 generator  F    PATCH-39, PKG-9
- crucible-qemu-11-mutex-registry-declarations .. retain file-scope registry state  F    HFORK-4, PATCH-39
- crucible-qemu-11-memory-barrier-interface .. include the global barrier API  F    HFORK-4, PATCH-39
- crucible-qemu-11-character-frontend-type .. use the QEMU 11 frontend type  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-qed-table-layout .. document QED table allocation layout  F    PATCH-39, PKG-9
- crucible-qemu-11-child-monitor-chardev .. align child monitors with QEMU 11 chardevs  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-child-qmp-qom-identity .. validate child QMP identity through QOM  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-listener-descriptor-apis .. use QEMU 11 listener and FD APIs  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-plugin-inventory-callbacks .. attach inventory to QEMU 11 callbacks  D    DET-1, HFORK-4, PATCH-39
- crucible-qemu-11-fault-node-diagnostics .. retain warning-clean fault state  F    PATCH-39, PKG-9
- crucible-qemu-11-character-frontend-tests .. exercise the QEMU 11 frontend fixtures  F    HFORK-4, PATCH-39
- crucible-qemu-11-channel-blocking-result .. preserve channel result polarity  F    HFORK-4, HFORK-22, PATCH-39
- crucible-qemu-11-arm-translation-result .. preserve successful ARM translations  D    DET-1, DET-35, PATCH-39
- crucible-qemu-11-arm-fault-translation-result .. preserve successful ARM fault translations  D    DET-1, DET-35, PATCH-39
- crucible-qemu-replay-icount-lock .. retain the replay lock across icount limit calculation  D    DET-1, PATCH-39, QEMU-43
- crucible-hot-fork-graph-writer-admission .. release completed block graph writers  F    HFORK-4, HFORK-22, PATCH-39
- crucible-exact-checkpoint-ram-deltas .. capture and restore exact RAM deltas  F    CPERF-5, T-CAM-5.3
- crucible-serialized-rr-cursor .. restore the exact multi-vCPU continuation  D    DET-29, QEMU-34, QEMU-43, QFP-STATE-2
- crucible-fingerprint-guest-state-domains .. hash guest-semantic state only  D    DET-29, QEMU-34, QFP-STATE-2
- crucible-exact-restore-network-announcement .. keep restored traffic exact  D    DET-1, QFP-STATE-2, FAULT-ORDER
- crucible-genesis-observation-boundary .. sample the exact prelaunch state  D    DET-1, QFP-REG-1, QFP-STATE-2
- crucible-deterministic-rcu-quiescence .. remove host-timed sim exits  D    DET-1, DET-29, QEMU-43
- crucible-deterministic-host-kick-boundary .. bound generic host work  D    DET-1, DET-29, QEMU-43
- crucible-exact-boundary-vcpu-introspection .. observe checkpoint CPU state  D    DET-1, QFP-REG-1, QFP-STATE-2
- crucible-active-tcg-kick-boundary .. preserve bounded kick liveness  D    DET-1, DET-29, QEMU-43
- crucible-canonical-rr-genesis-cursor .. expose the unique genesis coordinate  D    DET-1, QFP-REG-1, QFP-STATE-2
- crucible-canonical-terminal-rr-cursor .. project terminal live observations  D    DET-1, DET-29, QFP-STATE-2
- crucible-canonical-register-cursor .. commit after-instruction coordinates  D    DET-1, DET-29, QFP-STATE-2
- crucible-retention-virtual-time-origin .. keep retention in one clock domain  D    DET-1, TIME-23, E14
- crucible-canonical-snapshot-rr-resume .. preserve source continuation  D    DET-1, QFP-STATE-2, QEMU-43
- crucible-isolate-checkpoint-control-wake .. preserve frozen device state  D    DET-1, QFP-STATE-2, PATCH-20
- crucible-preserve-checkpoint-block-durability .. retain volatile state  D    DET-1, QFP-STATE-2, QFP-BLOCK-3
- crucible-anchor-rr-cursor-genesis .. establish scheduler state before execution  D    DET-1, QFP-STATE-2, QEMU-43
- crucible-control-boundary-node-faults .. complete halted-node mutations  F    QFP-LIFE-1, QFP-LIFE-2, FAULT-ORDER
- crucible-release-halted-rr-turn .. publish idle inside a partial RR turn  D    DET-1, PLUG-24, QEMU-43
- crucible-restore-accelerator-rule-indexes .. restore persistent policy  F    QFP-ACCEL-SERVICE, FAULT-RESTORE
- crucible-virtio-net-exact-restore-reset .. reset after announcement suppression  D    QFP-REG-1, QFP-STATE-2
- crucible-source-mapping-page-extents .. round source mapping extents to pages  F    HFORK-4, HFORK-22
- crucible-register-rejection-atomicity .. prove rejected commands are inert  D    DET-1, QFP-REG-1, QFP-REG-2, FAULT-EVIDENCE
- crucible-valid-aarch64-abort-fixture .. reach exception delivery  F    QFP-MEMA-1, FAULT-EVIDENCE, PATCH-3
- crucible-bql-exact-register-capture .. observe snapshot boundaries  D    DET-1, QFP-STATE-2, QEMU-43
- crucible-selector-control-plane-fixtures .. isolate selector admission  F    FAULT-ORDER, PATCH-3, QFP-INST-3
- crucible-raw-pte-update-identity .. separate transient PTEs from A/D writes  D    QFP-MEMA-1, QFP-MEMA-2, FAULT-ORDER
- crucible-physical-page-table-region-fixture .. target descriptor storage  F    QFP-MEMA-1, QFP-MEMA-2, FAULT-EVIDENCE
- crucible-canonical-memory-retry-identity .. survive TB retranslation  D    DET-1, QFP-MEMA-1, QFP-STATE-2
- crucible-inactive-nested-tsc-guard .. preserve SVM icount parity  D    DET-1, QFP-CLOCK-2, PATCH-3
- crucible-aarch64-memory-exception-vectors .. admit architectural aborts  D    QFP-MEMA-1, FAULT-EVIDENCE, PATCH-3
- crucible-defer-active-slice-host-wakes .. seal the active RR slice  D    DET-1, QFP-KICK-3, QEMU-43
- crucible-deterministic-network-kick .. preserve exact network continuation  D    DET-1, PLUG-23, PLUG-24, QEMU-43
- crucible-accelerator-service-schema .. admit typed service capacity  F    QFP-ACCEL-SERVICE, FAULT-ORDER
- crucible-compile-affected-clock-sources .. isolate rule compilation  F    QFP-CLOCK-SOURCE, FAULT-ORDER
- crucible-authenticate-fault-result-payloads .. bind results to payloads  F    QFP-RESULT, FAULT-ORDER
- crucible-clock-impulse-read-error-policies .. retain clock policy  F    QFP-CLOCK-TRANSFORM, QFP-CLOCK-SOURCE, FAULT-ORDER
- crucible-nonblocking-cancellation-eventfd .. restore nonblocking cancellation eventfd  F    HFORK-4, HFORK-22
- crucible-runtime-transaction-blockers .. report runtime transaction blockers  F    HFORK-4, HFORK-22
- crucible-mapping-backing-partial-page .. admit shared mappings into a backing partial page  F    HFORK-4, HFORK-22
- crucible-tcg-exec-diag ........ per-exec icount trace      dev  divergence debug
- crucible-virtserial-socket .... raw serial socket framing  dev  white-box debug

- **[PATCH-11]** The atomic patch MUST add a deterministic sim-mode TCG accelerator
  (`-accel sim`) with a split vCPU/main event loop in which virtual time advances
  only by retired instructions and plugin-authorized jumps, never by host
  wall-clock, and in which guest progress is independent of host thread scheduling
  order (E14). The accelerator MUST be a new file inert under any other
  accelerator. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:*
  §11.4; satisfies [DET-1], [TIME-23], [INV-8], [DET-18] (E14).

- **[PATCH-12]** The atomic patch MUST suppress QEMU's idle wall-clock warp whenever
  sim mode is active and a plugin holds time control, while preserving the
  clock-notify wakeup path so the main loop and plugin timers still progress.
  The suppression MUST be gated on the sim and time-control predicates so
  non-sim QEMU warps exactly as upstream. *Gate:* `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §11.4; satisfies [DET-10], [TIME-21], [DET-18]
  (E2), [INV-7].

- **[PATCH-13]** The atomic patch MUST add a sim exact-tick icount mode whose
  instruction budget is computed from `QEMU_CLOCK_VIRTUAL` deadlines only, never
  mixing `QEMU_CLOCK_REALTIME` deadlines into the budget; non-sim and
  non-precise modes MUST retain upstream behavior. *Gate:*
  `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.4; satisfies
  [DET-9], [TIME-22], [DET-18] (E3), [INV-7].

- **[PATCH-14]** The atomic patch MUST ensure every guest-visible realtime/RTC read
  resolves, in sim mode, to the icount-derived virtual clock plus the fixed
  configured epoch (optionally skewed per §[TIME-16]), with no residual path
  returning host wall-clock; non-sim reads MUST be upstream-identical. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-8], [TIME-20], [DET-18] (E5), [INV-7].

- **[PATCH-15]** The atomic patch MUST seed QEMU's glib `GRand` deterministically from
  the run seed in sim mode so QEMU-internal random draws (device MACs/IDs,
  internal randomness in `T`) are reproducible; out of sim mode the host-entropy
  seeding MUST be unchanged. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-21], [DET-18] (E9), [INV-7].

- **[PATCH-16]** The atomic patch MUST route QEMU's guest-random / hardware-RNG entropy
  through a deterministic, run-seed-derived stream in sim mode when `-seed` is
  provided, and MUST fail closed before host crypto if sim guest-random is used
  without `-seed`; out of sim mode the unseeded host-entropy path MUST be
  unchanged. *Gate:* `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.4;
  satisfies [DET-21], [DET-19], [DET-18] (E9), [INV-7].

- **[PATCH-17]** The atomic patch MUST provide a plugin-callable network-frame injection
  path that makes an inbound frame visible to the guest at a plugin-chosen
  virtual-time moment (its delivery icount), so RX delivery is a pure function of
  icount and not of socket-arrival timing. *Gate:* `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.4; satisfies [DET-11], [DET-13], [DET-18] (E18),
  [INV-7].

- **[PATCH-43]** The atomic patch MUST NOT carry record/replay-start scaffolding (no
  `crucible-replay-start`-style patch enabling QEMU's `rr=record|replay`
  subsystem): Crucible's determinism is source-elimination + icount + seeded
  injection, never QEMU record/replay ([NG-6]). If a future need for replay-stream
  interop arises it MUST be introduced as a separately-named, sim-gated,
  inertness-argued, micro-tested patch with its own catalog entry — never folded
  silently into the determinism path. *Gate:* `gate:qemu-inert`. *Spec:* §11.4;
  satisfies [NG-6], [INV-7].

- **[PATCH-44]** The atomic patch MUST make the single-threaded round-robin TCG
  vCPU-switch boundary a fixed `rr_switch_quantum` expressed in retired instructions in
  sim mode, with an ascending vCPU rotation, so multi-vCPU instruction
  interleaving is a pure function of icount and not of the adaptive/realtime
  `rr_quantum`; out of sim mode the round-robin quantum MUST be upstream-adaptive
  unchanged. The quantum value MUST be supplied by the launch configuration
  (10/[QEMU-43]) and is part of the content hash. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-1], [DET-23], [QEMU-43], [INV-7].

- **[PATCH-45]** The atomic patch MUST make inter-vCPU IPI/SIPI/INIT delivery
  architecturally visible to the target vCPU at a deterministic node-icount in
  sim mode (anchored to the round-robin event path, synchronous with the pinned
  switch boundary [PATCH-44]), so cross-vCPU interrupt timing is a pure function
  of icount; out of sim mode delivery MUST be upstream-identical. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`, `gate:qemu-inert`.
  *Spec:* §11.4; satisfies [DET-1], [INV-7], references [PATCH-44].


## 11.5 Plugin control and observation requirements

The current exported surface includes `qemu_plugin_icount_raw`,
`qemu_plugin_icount_at_tb_entry`, `qemu_plugin_force_vcpu_exit`,
`qemu_plugin_register_wake_fd`, `qemu_plugin_read_vcpu_regs`,
`qemu_plugin_rr_cursor`, `qemu_plugin_inject_preemption`,
`qemu_plugin_advance_time_ticks`, and `qemu_plugin_register_time_advance_cb`.
Queued time advancement runs `qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)` before
publishing completion; the plugin-facing operation is
`qemu_plugin_advance_time_ticks(target_tick)`. These names are part of the pinned ABI and
are checked in the generated header and the built dynamic symbol table.

The sim accelerator accepts only precise `-icount shift=0,align=off,sleep=off`.
It rejects any other icount configuration before guest execution; the fixed
1 ps tick scale does not inherit QEMU's upstream nanosecond shift setting.

The supported AArch64 sim profile explicitly selects `pmu=off`. QEMU rejects a
PMU-enabled ARM CPU during sim realization, before guest execution, because its
`INST_RETIRED` overflow IRQ uses a nanosecond timer and cannot fire at the exact
retired-instruction tick after a fractional or idle advance. Non-sim ARM PMU
behavior is unchanged. This restriction remains until the overflow IRQ uses
an exact instruction boundary.

- **[PATCH-18]** The atomic patch MUST export a plugin time-control surface that lets
  the plugin acquire ownership and enqueue one explicit absolute virtual-time
  target across an idle gap. The callback entry point MUST be enqueue-only; the
  actual clock/timer work MUST execute from queued normal-main-loop work and
  completion MUST be handed to a later main-loop callback. The queued work MUST
  remain runnable while a vCPU is blocked on device I/O. The atomic patch MUST also export the
  `has_time_control` predicate for plugin ownership checks. *Gate:*
  `gate:layer0-determinism`, `gate:qemu-inert`. *Spec:* §11.5; satisfies
  [TIME-23], [TIME-27], [INV-8].

- **[PATCH-19]** The queued time-advance path MUST order timer-produced main-loop
  bottom halves before its completion callback using normal AioContext dispatch,
  without synchronously draining or recursively entering the main loop from a
  plugin/vCPU callback. *Gate:* `gate:layer0-determinism`,
  `gate:divergence-bisect`. *Spec:* §11.5; satisfies [DET-1], [INV-10].

- **[PATCH-20]** The atomic patch MUST deliver scheduler/device completion through the
  normal main-`AioContext` wake-fd handler and event-driven device handoffs. It
  MUST NOT expose or use a plugin call that recursively runs or polls QEMU's
  main loop. *Gate:*
  `gate:layer1-injection`, `gate:divergence-bisect`. *Spec:* §11.5; satisfies
  [DET-1], [INV-10], references [DET-18] (E19).

- **[PATCH-21]** The atomic patch MUST export an **exact next-virtual-timer-deadline**
  query (reading `QEMU_CLOCK_VIRTUAL` only) so the scheduler can compute an exact
  local horizon and jump an idle node directly to its next deadline. The
  overshoot-and-correct fallback MUST NOT be the production mechanism; if this
  capability is unavailable the run MUST fail loudly ([TIME-25]). *Gate:*
  `gate:layer0-determinism`, `gate:scheduler-liveness`, `gate:qemu-inert`. *Spec:*
  §11.5; satisfies [TIME-24], [TIME-25], [TIME-26].

- **[PATCH-22]** The atomic patch MUST export a raw-icount read (bias-excluded) so the
  plugin can supply the icount axis for the execution fingerprint and divergence
  bisection. *Gate:* `gate:single-vm-fingerprint`, `gate:qemu-inert`. *Spec:*
  §11.5; satisfies [DET-29], references [INV-10].

- **[PATCH-23]** The atomic patch MUST export a force-vCPU-exit call the plugin uses to
  normalize the first-exit phase across runs so the exit/run alternation cannot
  lock into opposite phases on a later-spawned VM. *Gate:* `gate:layer0-determinism`,
  `gate:divergence-bisect`. *Spec:* §11.5; satisfies [DET-1], [INV-10].

- **[PATCH-24]** The atomic patch MUST export wake-fd registration on the main
  `AioContext`; its handler drains scheduler wakes, notifies pending device
  consumers, and kicks the vCPU parked on QEMU's BQL condition variable. It
  MUST remain dispatchable from a synchronous block request's nested
  `aio_poll()`, and MUST NOT export or call a blocking main-loop wait from
  plugin or vCPU callbacks. This integrates cross-process wakes and QEMU's own
  fd handlers without transferring event-loop ownership away from QEMU, keeping
  the scheduler the single wake authority. *Gate:* `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [SHM-26], [INV-8].

- **[PATCH-25]** The atomic patch MUST export `qemu_plugin_icount_at_tb_entry` so the
  plugin's standard translation-block execution callback can observe the exact
  entry icount without guest instrumentation. The export MUST reject calls
  outside that callback context. *Gate:* `gate:qemu-inert`, forward-ref 22.
  *Spec:* §11.5; satisfies coverage capability (22), [INV-7].

- **[PATCH-46]** The atomic patch MUST export a per-vCPU register-file read (for an
  arbitrary vCPU index, not only the current one) and a round-robin cursor read
  (current vCPU + position within the pinned `rr_switch_quantum`) so the host can
  compute the N-vCPU execution fingerprint (10/[QEMU-34]) black-box; the reads
  MUST be side-effect-free wrt `S`/`T`. *Gate:* `gate:single-vm-fingerprint`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [DET-29], references [QEMU-34],
  [PATCH-44], [INV-10].

- **[PATCH-47]** The atomic patch MUST export a plugin-callable preemption-injection
  path that forces a round-robin vCPU switch or delivers an interrupt at a
  commanded node-icount (anchored to the icount round-robin event path of
  [PATCH-44]/[PATCH-45]) so the scheduler's `Decision::Preemption`
  (12/[PLUG-50]) is applied deterministically; a commanded icount outside the
  authorized `[deadline, ceiling]` window MUST be rejected loudly, never clamped
  or deferred. *Gate:* `gate:layer1-injection`, `gate:layer0-determinism`,
  `gate:qemu-inert`. *Spec:* §11.5; satisfies [DET-1], [INV-7], [INV-10],
  references [PLUG-50], [PATCH-44].


## 11.6 Device co-simulation requirements

- **[PATCH-26]** The atomic patch MUST add a virtio-blk-over-shmem block driver that
  forwards requests to the coordinator through a shmem SPSC ring and delivers
  completions at virtual-time-determined points, so block I/O completion timing is
  deterministic (E19). It MUST be a new driver inert unless selected. *Gate:*
  `gate:layer1-injection`, `gate:abi-conformance`, `gate:qemu-inert`. *Spec:*
  §11.6; satisfies [DET-16], [SHM-13], [DET-18] (E19), [INV-7].

- **[PATCH-27]** The atomic patch MUST include the block-I/O correctness fixes that keep
  shmem block completions at bounded reproducible virtual-time offsets (no
  cross-run hangs, correct poll-response handling). *Gate:* `gate:layer1-injection`.
  *Spec:* §11.6; satisfies [DET-16], [DET-18] (E19).

- **[PATCH-28]** The atomic patch MUST use an explicit pending sentinel in the shmem
  block poll path distinct from zero-length success, so writes and flushes
  complete deterministically rather than being mistaken for not-ready polls.
  *Gate:* `gate:layer1-injection`. *Spec:* §11.6; satisfies [DET-16].

- **[PATCH-29]** The atomic patch MUST add a virtio-9p forwarding path that, when a
  plugin 9p callback is registered, treats the device as a dumb pipe routing raw
  9p messages over a shmem ring to a deterministic 9p sub-node; with no callback
  registered the upstream internal 9p server MUST be used unchanged. *Gate:*
  `gate:layer1-injection`, `gate:qemu-inert`. *Spec:* §11.6; satisfies [DET-16],
  [DET-18] (E19), [INV-7].

- **[PATCH-30]** The atomic patch MUST export the plugin-API registration calls for the
  block and 9p shmem-forwarding callbacks; with no callback registered each device
  MUST behave as upstream. *Gate:* `gate:qemu-inert`, `gate:abi-conformance`.
  *Spec:* §11.6; satisfies [PLUG], [SHM-17], [INV-7].

- **[PATCH-31]** The atomic patch MUST export a TX-intercept callback that routes every
  guest-sent frame to the plugin (for shmem-ring delivery) instead of the socket
  backend when registered; with no callback the socket backend is used as
  upstream. *Gate:* `gate:layer1-injection`, `gate:qemu-inert`. *Spec:* §11.6;
  satisfies [DET-18] (E18), [SHM-17], [INV-7].

- **[PATCH-32]** The atomic patch MUST provide lossless direct RX injection with
  distinct complete, backpressure, and permanent-failure results so an inbound
  frame is never silently dropped when the receiver is momentarily unready and
  is delivered at the plugin's chosen virtual-time moment. Backpressure
  retention MUST remain in the bounded, checkpointed shared-memory ring, never
  a QEMU-private packet queue. A canonical retry MUST re-probe the guest device
  independently of QEMU's private-queue `receive_disabled` latch. *Gate:*
  `gate:layer1-injection`,
  `gate:qemu-inert`. *Spec:* §11.6; satisfies [DET-18] (E18).


## 11.7 Guest-host channel decision

For guest-to-host doorbells, no QEMU patch was added. The pinned upstream API
already provides `qemu_plugin_read_memory_vaddr` alongside translation and
memory callbacks; the host-to-guest selectable reply is a separate, explicitly
gated capability in the atomic integration patch.

- **[PATCH-33]** The guest↔host doorbell ([`16-guest-host-channel.md`](16-guest-host-channel.md))
  MUST be implemented by **reusing an existing QEMU trap surface** — a reserved
  port-I/O write or an MMIO write to a fixed address — observed via the plugin's
  existing memory-access / instrumentation callbacks, plus the plugin's
  memory-read API to fetch the payload. The atomic patch MUST NOT add a bespoke
  trapped-instruction patch unless a spike proves the existing trap + plugin-read
  path cannot deliver a *synchronous, deterministic* doorbell. Whether a patch is
  required at all is therefore **NO** by default; any patch added here is gated on
  that spike and MUST be inert and white-box-only. *Gate:* `gate:qemu-inert`,
  forward-ref 16. *Spec:* §11.7; satisfies [INV-7], coordinates with [GHC].


## 11.8 Simulator correctness and diagnostics

- **[PATCH-34]** The sim-correctness mechanisms (`crucible-sim-loop-fix`,
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

- **[PATCH-36]** Diagnostic-only capabilities (`crucible-tcg-exec-diag` — per-exec
  icount tracing; `crucible-virtserial-socket` — raw serial socket framing for
  white-box debugging) are **dev-only and MUST NOT be applied in the shipped AOS
  QEMU package** ([PATCH-10]). In a developer build they MUST be inert by default
  (compiled out or behind an explicit `diag=` plugin arg) and MUST NOT alter
  guest-visible icount when off. *Gate:* `gate:qemu-inert`, forward-ref 24, 26.
  *Spec:* §11.8; satisfies [INV-7], [INV-10].


## 11.9 Regeneration and rebase policy

- **[PATCH-37]** Crucible MUST provide a **regeneration pipeline** that produces
  the committed atomic patch from the DCO-signed integration commit ([PATCH-7]) against the pinned QEMU tag,
  deterministically (stable author/date/ordering so the bytes are reproducible).
  CI MUST regenerate the atomic patch and fail if the committed file differs from
  the regenerated output (drift detection). *Gate:* `gate:patch-microtests`,
  forward-ref 26. *Spec:* §11.9; satisfies [DET-35], [PKG].

- **[PATCH-38]** CI MUST run, for the pinned QEMU version, the atomic integration pipeline:
  (1) the patch **applies cleanly**; (2) the patched tree **builds**;
  (3) **every component micro-test passes** ([PATCH-4]); (4) **`gate:qemu-inert`**
  proves non-sim behavior is upstream-identical ([PATCH-2]); (5) the
  **`gate:patch-microtests`** aggregate is green. A change to the patch, the
  pin, or the generated shmem header ([SHM-4]) MUST re-run all five. *Gate:*
  `gate:patch-microtests`, `gate:qemu-inert`, forward-ref 24, 26. *Spec:* §11.9;
  satisfies [DET-37], [INV-7], [PKG].

- **[PATCH-39]** A bump of the pinned QEMU version is a **re-gated event**: the
  atomic patch MUST be rebased onto the new tag, every component microtest re-run, every
  inertness check re-run, and the QEMU build identity re-pinned into the
  reproduction artifact ([DET-35], [DET-40]). A determinism run reproduces only
  against the exact QEMU build that produced it; the build identity MUST be part of
  the artifact. *Gate:* `gate:e2e-determinism`, `gate:qemu-inert`, forward-ref 26.
  *Spec:* §11.9; satisfies [DET-35], [DET-40].


## 11.10 Pinned QEMU and plugin API assumptions

- **[PATCH-40]** The atomic patch MUST target the **pinned QEMU 11.1.1 baseline**,
  which provides the plugin time-control API
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

- **[PATCH-42]** The atomic patch MUST assume the plugin runs `std` blocking I/O on the
  vCPU/main threads (no async runtime inside QEMU) and MUST NOT require any
  plugin-API capability beyond those listed in [PATCH-40] plus the
  Crucible-exported surface enumerated in §11.5–§11.6. A build against a QEMU
  lacking a required capability MUST fail loudly at configure/build time, never
  silently degrade to a nondeterministic fallback. *Gate:* `gate:patch-microtests`,
  `gate:qemu-inert`. *Spec:* §11.10; satisfies [DET-35], [INV-10].

## 11.11 Verification and provenance

The checked-in patch is generated with `git format-patch` from one DCO-signed
commit whose parent is the pinned QEMU 11.1.1 base. The QEMU integration manifest records the
base and head commits, trees, patch hash, bundle hash, author, and sign-off.
The retained thin bundle names the exact prerequisite base and carries the
named final head. The pinned upstream source deterministically reconstructs
that base before the bundle is verified and fetched, avoiding a duplicate copy
of the complete upstream tree in the repository.

CI applies the patch with fuzz disabled, rebuilds QEMU, compares the resulting
tree to the recorded head tree, and runs the component micro-tests. The
pristine-QEMU negative requires the current capability discriminator set to be
absent. The inertness checks compare patched
sim-off behavior with the unpatched pinned build; live sim checks cover the
plugin protocol, exact checkpoint, device transports, fault execution, and
hot-fork worker barriers.

The patch preserves the license of every modified QEMU file. New files use the
license recorded in `pkgs/emulation/qemu-patches/LICENSES.md`. The distributed
binary and its matching complete source are retained together as required by
[`37-licensing-process-boundary.md`](37-licensing-process-boundary.md).

## Implementation checklist

These completed tasks describe the current atomic patch. Detailed evidence is
owned by the named checks and their result metadata, rather than duplicated in
a historical component-by-component completion log here.

- [x] **T-PATCH-1** Establish the rebasable atomic patch against pinned QEMU
  11.1.1: one DCO-signed integration commit and one generated patch; require the
  commit and §11.3 catalog to state every determinism invariant and capability,
  classified determinism-critical vs feature; forbid any record/replay-start
  scaffolding in the atomic patch. — satisfies [PATCH-6], [PATCH-7], [PATCH-9],
  [PATCH-40], [PATCH-43]; spec §11.1.3, §11.1.4, §11.4, §11.10.

- [x] **T-PATCH-2** Wire the atomic integration CI: apply-clean + build + component
  microtests + `gate:qemu-inert` + `gate:patch-microtests`, on any atomic-patch
  or pin change. — satisfies [PATCH-4], [PATCH-5], [PATCH-8], [PATCH-38];
  spec §11.1.2, §11.9.

- [x] **T-PATCH-3** Implement `gate:qemu-inert`: run an upstream-equivalent corpus
  against unpatched-pinned vs AOS-patched-sim-off and assert byte-identical
  guest-visible behavior. — satisfies [PATCH-1], [PATCH-2], [PATCH-3]; spec
  §11.1.1, routes [INV-7], [DET-36].

- [x] **T-PATCH-4** Implement `crucible-sim-accel`: the split vCPU/main
  deterministic TCG sim accelerator (`-accel sim`), inert under other
  accelerators, with a cross-run icount-trace micro-test. — satisfies [PATCH-11];
  spec §11.4 (E14).

- [x] **T-PATCH-5** Implement the warp/budget determinism mechanisms
  `crucible-no-warp-with-plugin` and `crucible-icount-no-realtime`, each gated on
  its sim predicate with reintroduce-to-red micro-tests. — satisfies [PATCH-12],
  [PATCH-13]; spec §11.4 (E2, E3).

- [x] **T-PATCH-6** Implement `crucible-block-rtc-read`: guest RTC/realtime reads
  resolve to the icount-derived virtual clock + fixed epoch in sim mode only. —
  satisfies [PATCH-14]; spec §11.4 (E5).

- [x] **T-PATCH-7** Implement the entropy mechanisms `crucible-det-glib-prng` and
  `crucible-det-getrandom`, with reintroduce-to-red micro-tests. — satisfies
  [PATCH-15], [PATCH-16]; spec §11.4 (E9).

- [x] **T-PATCH-8** Implement `crucible-net-deterministic`: plugin-callable
  icount-timed RX delivery, with a skewed-producer cross-run micro-test. —
  satisfies [PATCH-17]; spec §11.4 (E18).

- [x] **T-PATCH-9** Implement the plugin time-control surface
  `crucible-plugin-time-advance` (+ `has_time_control`) and the event-driven
  `crucible-plugin-advance-barrier` / `crucible-plugin-device-wake` handoffs with
  deterministic-propagation micro-tests. — satisfies [PATCH-18], [PATCH-19],
  [PATCH-20]; spec §11.5.

- [x] **T-PATCH-10** Implement `crucible-clock-deadline` (exact next
  `QEMU_CLOCK_VIRTUAL` deadline, REQUIRED) and ban the overshoot-and-correct
  fallback; fail loudly if the capability is unavailable. — satisfies [PATCH-21],
  [PATCH-41]; spec §11.5, §11.10.

- [x] **T-PATCH-11** Implement the plugin reads/exits/wakes
  `crucible-plugin-icount-raw`, `crucible-plugin-vcpu-exit`,
  `crucible-plugin-wake-fd`, `crucible-plugin-tcg-exec-cb`, each additive and
  zero-overhead-when-unused. — satisfies [PATCH-22], [PATCH-23], [PATCH-24],
  [PATCH-25]; spec §11.5.

- [x] **T-PATCH-12** Implement the block co-sim mechanisms `crucible-blk-shmem`,
  `crucible-blk-shmem-io-fixes`, `crucible-blk-write-sentinel` over shmem with
  deterministic-completion micro-tests. — satisfies [PATCH-26], [PATCH-27],
  [PATCH-28]; spec §11.6 (E19).

- [x] **T-PATCH-13** Implement the 9p co-sim path `crucible-9p-shmem` and the
  device registration surface `crucible-dev-cb-api`; upstream server used when no
  callback is registered. — satisfies [PATCH-29], [PATCH-30]; spec §11.6 (E19).

- [x] **T-PATCH-14** Implement the network co-sim mechanisms
  `crucible-net-tx-callback` (TX intercept) and complete
  `crucible-net-direct-inject-api` QEMU patch ABI/Rust resolver integration over
  the direct-injection result contract, with no-loss /
  deterministic-delivery micro-tests. — satisfies [PATCH-31], [PATCH-32];
  spec §11.6 (E18).

- [x] **T-PATCH-15** Confirm (or spike) that the guest↔host doorbell needs **no
  new patch**: reuse the existing port-I/O/MMIO trap + plugin mem-read; any patch
  added is white-box-only, inert, and spike-gated. — satisfies [PATCH-33]; spec
  §11.7, coordinates with 16.

- [x] **T-PATCH-16** Implement the sim-correctness mechanisms
  (`crucible-sim-loop-fix`, `crucible-sim-first-exit`,
  `crucible-sim-skip-second-events`, `crucible-sim-poll-immediate`,
  `crucible-sim-idle-callbacks`, `crucible-sim-shmem-dispatch`) with bit-exact
  cross-run micro-tests. — satisfies [PATCH-34]; spec §11.8.

- [x] **T-PATCH-17** Implement `crucible-sim-batch-tcg-exec` as a
  determinism-preserving perf patch (fixed N, ceiling/timer discipline) gated by a
  bit-identical batching-on-vs-off icount diff. — satisfies [PATCH-35]; spec
  §11.8.

- [x] **T-PATCH-18** Keep the diagnostic-only capabilities (`crucible-tcg-exec-diag`,
  `crucible-virtserial-socket`) out of the shipped package and inert-by-default in
  dev builds. — satisfies [PATCH-10], [PATCH-36]; spec §11.3, §11.8.

- [x] **T-PATCH-19** Implement the regeneration/drift pipeline (reproducible
  atomic-patch bytes from the DCO-signed integration commit) and the
  QEMU-version-bump re-gate (source-pin update +
  re-test + re-pin build identity into the artifact). — satisfies [PATCH-37],
  [PATCH-39]; spec §11.9.

- [x] **T-PATCH-20** Pin and document the minimum QEMU version and the plugin-API
  capability set; fail the build loudly if a required capability is missing. —
  satisfies [PATCH-40], [PATCH-42]; spec §11.10.

- [x] **T-PATCH-21** Implement `rr_switch_quantum`: make the
  single-threaded round-robin vCPU-switch boundary the pinned node-icount
  `rr_switch_quantum` (ascending rotation) in sim mode, supplied by the launch
  config; cross-run bit-identical switch-icount micro-test, with the adaptive
  realtime quantum reverting to red. — satisfies [PATCH-44]; spec §11.4.

- [x] **T-PATCH-22** Implement `crucible-det-ipi`: deterministic inter-vCPU
  IPI/SIPI/INIT delivery at a fixed node-icount via the round-robin event path,
  with a cross-run identical-delivery-icount micro-test on a multi-vCPU guest. —
  satisfies [PATCH-45]; spec §11.4.

- [x] **T-PATCH-23** Implement `crucible-vcpu-introspect`: per-vCPU register-file
  read (arbitrary index) + round-robin cursor read for the N-vCPU fingerprint,
  side-effect-free, additive/inert until called. — satisfies [PATCH-46]; spec
  §11.5.

- [x] **T-PATCH-24** Implement `crucible-preemption-inject`: plugin-callable
  commanded vCPU switch / interrupt delivery at a node-icount anchored to the
  round-robin event path, rejecting out-of-`[deadline, ceiling]` commands loudly;
  cross-run identical-application micro-test. — satisfies [PATCH-47]; spec §11.5.
