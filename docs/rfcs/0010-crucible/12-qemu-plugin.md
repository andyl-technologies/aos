# 12 — The in-VM QEMU plugin

This file specifies the **in-VM QEMU plugin** (`crucible-qemu-plugin`): the
`cdylib` loaded into each guest's QEMU process via the `-plugin` flag. The plugin
is the in-process half of the time-control loop — it owns the guest's virtual
clock, observes the guest going idle and resuming, intercepts the guest's device
I/O, and injects cross-node inputs at their exact delivery instruction count. It
is the component that physically *enforces* Contract A's clock clause
([`04-determinism-contract.md`](04-determinism-contract.md) §4.3, [DET-8]–[DET-10])
and the consumer side of Contract B's injection contract (§4.4, [DET-11]–[DET-14])
inside the QEMU address space, using the shared-memory ABI of
[`13-shmem-abi.md`](13-shmem-abi.md) as its sole hot-path channel and the control
protocol of [`14-protocol.md`](14-protocol.md) for one-time setup.

Requirement IDs in this file use the prefix `PLUG`. Gate names referenced here
are defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md);
the canonical gates this file is bound by are `gate:single-vm-fingerprint`,
`gate:layer1-injection`, `gate:qemu-inert`, `gate:abi-conformance`, and
`gate:layer0-determinism`. The plugin's counterparts are the QEMU patch series
that exposes the capabilities it calls ([`11-qemu-patches.md`](11-qemu-patches.md)),
the host executor that launches it and runs the scheduler
([`08-scheduling.md`](08-scheduling.md), [`10-qemu-integration.md`](10-qemu-integration.md)),
the shared-memory ABI it reads and writes ([`13-shmem-abi.md`](13-shmem-abi.md)),
the control protocol it speaks at setup ([`14-protocol.md`](14-protocol.md)), the
I/O sub-node model whose requests it submits ([`15-io-subnodes.md`](15-io-subnodes.md)),
the guest↔host channel it optionally traps ([`16-guest-host-channel.md`](16-guest-host-channel.md)),
and the coverage feed it optionally emits ([`22-advanced-features.md`](22-advanced-features.md)).
The virtual-time units it operates in are fixed by
[`09-virtual-time-icount.md`](09-virtual-time-icount.md).

The code blocks in this file are illustrative sketches per
[`00-conventions.md`](00-conventions.md): they show the intended types,
signatures, and call order so the spec is concrete, but the authoritative
statement is always the prose requirement. A sketch that disagrees with a
requirement is a defect in the sketch.

The plugin is GPL-side code because it is dynamically loaded into QEMU and calls
QEMU interfaces. It may depend on the dual-licensed `crucible-protocol` and
`crucible-shmem` boundary crates under a GPL-compatible choice, but MUST NOT
depend on Apache-only host crates. The process and dependency rules are
normative in [`37-licensing-process-boundary.md`](37-licensing-process-boundary.md).

## 12.1 Role and the single-threaded execution context

The plugin is the *only* piece of Crucible code that runs inside the QEMU
process. It owns three responsibilities that cannot be performed from outside the
process: holding QEMU's virtual-clock control, observing translation-block and
vCPU lifecycle callbacks, and intercepting the device data paths (network TX/RX,
block, 9p). Everything else — the scheduler, the temporal graph, assertions —
lives in the host executor and reaches the plugin only through the shared-memory
region and, once at setup, the control socket.

### 12.1.1 What the plugin owns

- **[PLUG-1]** The plugin MUST own virtual-time control for the lifetime of a
  sim run: it acquires QEMU's time-control capability at registration
  ([`11-qemu-patches.md`](11-qemu-patches.md)), and from that point QEMU MUST NOT
  advance the virtual clock by wall-clock warp ([`09-virtual-time-icount.md`](09-virtual-time-icount.md)
  [TIME-21], [DET-10], source E2). All virtual-time advancement during idle is an
  explicit, scheduler-authorized jump performed by the plugin (§12.3). *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §12.1, §12.3;
  routes [DET-10], [INV-8].

- **[PLUG-2]** The plugin MUST own the device and channel callbacks for its node:
  the network TX interception and RX injection (§12.5), the block and 9p
  submit/poll callbacks (§12.6), and — when white-box mode is enabled — the
  guest↔host doorbell trap (§12.7). No host component may inject a frame, complete
  an I/O, or stamp a marker into the guest's address space except through these
  plugin-owned paths. *Gate:* `gate:layer1-injection`. *Spec:* §12.1, §12.5,
  §12.6, §12.7; routes [INV-3], [INV-8].

### 12.1.2 Single-threaded round-robin ⇒ uncontended state

Every simulation VM runs under the single-threaded TCG-derived sim accelerator
(`-accel sim,thread=single`) with N ≥ 1 vCPUs (10/[QEMU-5]). QEMU drives all N vCPUs serially on **one host
thread**, so it serializes every vCPU callback — registration, translation-block
hooks, idle, resume, and the device callbacks that fire on the vCPU thread —
across all vCPUs onto exactly that one thread. This is the structural fact that
makes the plugin's state cheap and correct: the uncontended-state property is
**preserved by round-robin** even with N > 1, because there is never a second
host thread running a vCPU callback concurrently. Multi-threaded TCG
(`thread=multi`, MTTCG) would break that property and is rejected.

- **[PLUG-3]** The plugin MUST be designed for the single-threaded round-robin
  TCG execution model with N ≥ 1 vCPUs: QEMU serializes *all* vCPU-thread
  callbacks (across all N vCPUs) onto one host thread, so the plugin's own state
  is *uncontended* — a property the round-robin accelerator **preserves** for
  any N. The plugin MUST reject (fail loudly at registration) multi-threaded TCG
  (`thread=multi` / MTTCG), but MUST NOT reject `-smp N` per se: N > 1 under
  single-threaded round-robin is supported and does not introduce concurrency on
  the plugin's state. Any synchronization primitive the plugin holds for its own
  state exists only to satisfy the language's thread-safety rules for
  process-global state, never to arbitrate genuine contention. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §12.1.2;
  routes [DET-23], references [NG-1], [QEMU-5].

- **[PLUG-4]** Where two callback families can re-enter each other on the single
  vCPU thread (e.g. the idle handler advances virtual time, which fires a guest
  timer, which causes the guest to transmit a frame, which invokes the TX
  callback), the plugin MUST structure its state so the re-entrant callback does
  not require a lock the outer callback already holds. The plugin MUST NOT
  deadlock against itself on the single thread; re-entrant device callbacks MUST
  read their required pointers from registration-time-initialized, never-mutated
  state rather than from a lock shared with the idle handler. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §12.1.2, §12.5; routes [INV-8].

The re-entrancy in [PLUG-4] is real and load-bearing: advancing the clock to a
timer deadline fires that timer synchronously, and a guest whose timer handler
sends a packet will invoke the TX path *inside* the idle handler. The plugin
therefore partitions its state into (a) a handshake/clock core touched only by
the lifecycle callbacks and (b) device-callback pointers fixed once at
registration and read without locking by the re-entrant paths.

## 12.2 Plugin arguments and registration

The plugin receives all of its wiring through the QEMU `-plugin` argument string
and the inherited control socket; it derives everything else from the
shared-memory region it maps during setup. The launch side that constructs the
argument string is [`10-qemu-integration.md`](10-qemu-integration.md); the
descriptor handover is [`14-protocol.md`](14-protocol.md) §3.4.

### 12.2.1 The argument set

- **[PLUG-5]** The plugin MUST accept the following arguments on its `-plugin`
  argument string, in `key=value` form, and MUST fail registration loudly if any
  required one is missing or unparseable:
  - **`simfd=N`** — the file descriptor of the host↔plugin control socket
    ([`14-protocol.md`](14-protocol.md) §2), inherited from the host executor.
    *Required.*
  - **`slot=N`** — the plugin's zero-based node slot index into the shared-memory
    per-node array ([`13-shmem-abi.md`](13-shmem-abi.md) §13.3.2). *Required;*
    cross-checked against the `slot_index` the host sends in `HelloAck`
    ([PLUG-19]).
  - **`shmemfd=N`** — *(optional)* a pre-inherited shared-memory descriptor; when
    absent, the plugin obtains the shmem fd and the wake fd from the `Setup`
    frame's `SCM_RIGHTS` ancillary data ([`14-protocol.md`](14-protocol.md) §3.4),
    which is the canonical path.
  - **`wakefd=N`** — *(optional as a command-line source)* a pre-inherited wake
    `eventfd`; canonically delivered with the shmem fd in the `Setup` frame's
    ancillary data. The production wake eventfd itself remains required.
  - **`whitebox=on|off`** — *(optional, default `off`)* enables the guest↔host
    doorbell trap (§12.7).
  - **`coverage=on|off`** — *(optional, default `off`)* enables the basic-block
    coverage hook (§12.8).

  The slot index is the *sole* key the plugin uses to locate its own cells in the
  region; it MUST NOT infer its identity from any other source. *Gate:*
  `gate:abi-conformance`. *Spec:* §12.2.1, forward-ref
  [`14-protocol.md`](14-protocol.md) §3, [`13-shmem-abi.md`](13-shmem-abi.md)
  §13.3.2; routes [G-8].

- **[PLUG-6]** Argument parsing MUST be total and fail-closed: an unrecognized
  key, a malformed value, a missing required key, or a `slot` outside
  `0..node_count` MUST cause registration to fail with a clear diagnostic, and
  the host MUST observe the failure (a non-zero `SetupAck` or a closed socket)
  and refuse to schedule the node ([`14-protocol.md`](14-protocol.md) §5.4,
  [PROTO-21]). The plugin MUST NOT proceed with a partially-configured state.
  *Gate:* `gate:abi-conformance`, `gate:control-responsive`. *Spec:* §12.2.1,
  forward-ref [`14-protocol.md`](14-protocol.md) §5.4; routes [INV-10].

### 12.2.2 Registration order

The order of operations at registration is normative because it is what
guarantees no warp or realtime advance can occur before the plugin is in charge
([`09-virtual-time-icount.md`](09-virtual-time-icount.md) [TIME-23]).

- **[PLUG-7]** Registration MUST proceed in this fixed order, and a failure at
  any step MUST abort registration (no later step runs): (1) parse arguments
  ([PLUG-5]); (2) wrap the control fd and perform the handshake
  (`Hello`/`HelloAck`, §12.9, [`14-protocol.md`](14-protocol.md) §3.5–§3.6);
  (3) **acquire virtual-time control immediately** so the no-warp patch is active
  from the first instruction ([PLUG-1], [TIME-23]); (4) receive `Setup`, map the
  shared-memory region and validate its ABI marker, arm the wake fd, register the
  device callbacks (§12.5, §12.6) and (if enabled) the white-box and coverage
  hooks; (5) reply `SetupAck(status)`; (6) wait on the initial-ceiling / boot
  barrier (§12.9.3) before the guest retires its first architecturally-visible
  instruction. *Gate:* `gate:abi-conformance`, `gate:layer0-determinism`. *Spec:*
  §12.2.2, §12.9; routes [INV-7], [INV-8], [DET-10].

- **[PLUG-8]** Time control MUST be acquired (step 3 of [PLUG-7]) *before* the
  guest retires its first architecturally-visible instruction. If QEMU reports
  that another plugin already holds time control, registration MUST fail loudly;
  Crucible runs exactly one time-controlling plugin per VM. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §12.2.2;
  routes [DET-10], [INV-8], [TIME-23].

```rust
// Illustrative sketch (CONV-1): registration order. The authoritative
// statement is [PLUG-7]; this only shows the call sequence.
fn register(args: &PluginArgs) -> Result<PluginState, RegisterError> {
    let cfg = PluginArgs::parse(&args.raw)?;            // [PLUG-5], [PLUG-6]
    let mut control = ControlSocket::from_fd(cfg.sim_fd)?;
    let ack = control.handshake(ABI_VERSION, PROTO_VERSION)?; // §12.9.1
    let time_ctl = TimeControl::request()?;             // [PLUG-8] — before any insn
    let setup = control.recv_setup()?;                  // shmem fd + wake fd (SCM_RIGHTS)
    let region = ShmemRegion::map(setup.shmem_fd, setup.region_len)?; // validate ABI
    region.validate_header(ABI_VERSION, ack.slot_index, ack.node_count)?; // [PLUG-19]
    let wake = WakeFd::arm(setup.wake_fd)?;
    let registered_wake = wake.register_with_qemu()?; // required main-loop nudge
    register_net_callbacks(cfg.slot, &region);          // §12.5  (never-mutated ptrs)
    register_blk_callbacks(cfg.slot, &region);          // §12.6
    register_9p_callbacks(cfg.slot, &region);           // §12.6
    if cfg.whitebox { register_doorbell_trap(cfg.slot, &region); } // §12.7
    if cfg.coverage { register_coverage_hook(&region); }           // §12.8
    control.send_setup_ack(0)?;                         // [PLUG-7] step 5
    region.wait_boot_barrier(cfg.slot)?;                // shared futex; before first insn
    Ok(PluginState { time_ctl, region, slot: cfg.slot, registered_wake })
}
```

## 12.3 Time control: the hot loop without wall-clock

The plugin's central duty is to advance the guest's virtual clock *only* as the
scheduler authorizes, and never by host real time. This section specifies the
idle/advance hot loop — the place where [DET-10], [TIME-21]–[TIME-25], and the
exact-deadline discipline of [`09-virtual-time-icount.md`](09-virtual-time-icount.md)
§9.8 are physically realized.

### 12.3.1 Acquiring and holding the clock

- **[PLUG-9]** Once time control is acquired ([PLUG-8]), the plugin MUST be the
  single authority that advances virtual time for its node, and that advancement
  MUST be a pure function of (a) the guest retiring instructions up to the
  scheduler-published ceiling and (b) explicit idle jumps the plugin performs to a
  scheduler-authorized virtual time. The plugin MUST NOT read host wall-clock or
  host monotonic time on any path that influences virtual time, frame delivery, or
  I/O completion. *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`.
  *Spec:* §12.3.1; routes [DET-10], [INV-4], [TIME-32].

### 12.3.2 The idle (HLT/WFI) callback

When a vCPU executes `HLT` (x86) or `WFI` (aarch64) with no runnable work, QEMU
fires the vCPU-idle callback for that vCPU. Under `-smp N` the **node** is idle
only when **all N vCPUs are halted**: a node with one vCPU halted while another
is still runnable is *not* node-idle, and the plugin MUST keep running the
round-robin rather than treating the node as idle. The node-idle transition is
the synchronization point: the plugin computes how far it is allowed to jump,
performs that jump, and injects any inputs that come due in the jumped-over
window.

- **[PLUG-10]** On the node going idle (the transition at which **all N vCPUs are
  halted**, tracked per [PLUG-52]) the plugin MUST:
  1. read its current icount and publish it (with the derived `current_ns`) into
     its node slot ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-10], [SHM-24]),
     bumping the publish-generation counter;
  2. query the **exact** next armed guest timer deadline via the clock-deadline
     introspection capability (§12.3.4, [TIME-24]) — taken as the **minimum over
     all N vCPUs** of each vCPU's next armed deadline; a node with no armed timer
     on any vCPU reports "no deadline";
  3. compute its desired wake icount as the earliest of: the minimum-over-vCPUs
     next timer deadline (step 2), the `delivery_icount` of the head entry of any
     inbound frame ring (peeked, not consumed, §12.4.2), and the
     scheduler-published `max_advance_icount` ceiling;
  4. publish `idle_wake_icount` and set its status to idle
     ([`13-shmem-abi.md`](13-shmem-abi.md) §13.7);
  5. block on the canonical `wake_signal` futex until the scheduler raises the
     ceiling to or past the wake icount (§12.3.3) — *not* a busy spin; the
     required registered eventfd separately nudges QEMU's main loop;
  6. once released, enqueue an advance to the authorized wake icount (firing
     due timers and draining bottom-halves as a side effect, §12.3.5); if QEMU
     reports `-EBUSY` because the preceding advance still owns its barrier, the
     plugin MUST re-arm the all-halted edge and recompute after QEMU's
     completion kick rather than accepting the pre-input idle publication;
  7. inject every inbound frame whose `delivery_icount <= current_icount` in the
     deterministic total order (§12.4.2);
  8. republish `current_icount`/`current_ns`, set status running, and return.

  *Gate:* `gate:layer0-determinism`, `gate:single-vm-fingerprint`,
  `gate:layer1-injection`. *Spec:* §12.3.2; routes [DET-10], [DET-11], [INV-4],
  [SCHED-28].

- **[PLUG-11]** The plugin MUST NOT advance the guest's virtual clock past the
  scheduler-published `max_advance_icount` ceiling without a fresh authorization,
  and MUST NOT self-extend the ceiling from any locally-computed value
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-24], [TIME-29]). The wake icount of
  [PLUG-10] is *clamped at* the ceiling: if the desired wake is beyond the
  ceiling, the plugin blocks (step 5) rather than overshooting. *Gate:*
  `gate:layer0-determinism`, `gate:layer1-injection`. *Spec:* §12.3.2; routes
  [DET-12], [INV-8], [TIME-27].

- **[PLUG-52]** The plugin MUST track per-vCPU halt state for all N vCPUs and
  MUST treat the node as idle **only when every vCPU is halted**; one vCPU halted
  while another is runnable is NOT node-idle and MUST NOT trigger the idle
  publish/park/jump of [PLUG-10]. When the node is idle, `idle_wake_icount` MUST
  be the **minimum over all vCPUs** of each vCPU's next armed timer deadline
  (clamped at the ceiling per [PLUG-11]); a vCPU un-halting (interrupt, IPI, or
  the commanded preemption of [PLUG-50]) MUST clear the node-idle state. The
  plugin MUST maintain the per-vCPU halted count from the vCPU idle/resume
  callbacks so the all-halted predicate is exact, never inferred from a single
  vCPU. *Gate:* `gate:layer0-determinism`, `gate:scheduler-liveness`. *Spec:*
  §12.3.2, §12.4.1; routes [DET-10], [INV-8], references [QEMU-5], [PLUG-50].

The idle handler is the entire reason warp must be suppressed: under stock QEMU
the idle path would advance the clock by *host* elapsed time. With the plugin
holding time control and the no-warp patch active, the clock advances by exactly
the jump the plugin computes from the scheduler's ceiling and the guest's own
armed deadlines — both pure virtual-time quantities.

### 12.3.3 Blocking on the scheduler, not the wall clock

- **[PLUG-12]** When the plugin's desired wake icount exceeds the published
  ceiling, the plugin MUST park on the **cross-process futex on the slot's
  `wake_signal`** word ([`13-shmem-abi.md`](13-shmem-abi.md) §13.7), using the
  race-free publish-precondition / read-counter / wait idiom so there is no
  lost-wake window. The `wake_signal` futex is the canonical, source-of-truth wake
  primitive. The inherited wake **eventfd** ([`14-protocol.md`](14-protocol.md)
  §3.4) is a REQUIRED auxiliary main-loop nudge in the production integration:
  the plugin MUST arm and register it with QEMU before `SetupAck(0)`, and the host
  MUST write it at least once per quantum. QEMU consumes the eventfd counter to
  re-enter callbacks that re-read shared state. Eventfd is layered *on top of*
  the futex and MUST NOT replace `wake_signal` or carry timing state. The plugin
  MUST NOT busy-spin re-reading the ceiling and
  MUST NOT sleep for a wall-clock interval as a substitute for the wake. *Gate:*
  `gate:layer1-injection`, `gate:scheduler-liveness`. *Spec:* §12.3.3,
  forward-ref [`13-shmem-abi.md`](13-shmem-abi.md) §13.7; routes [INV-8],
  [G-9].

- **[PLUG-13]** The wake wait MUST have no hard-coded wall-clock timeout on the
  determinism path: the plugin parks until the scheduler raises the ceiling or
  sets the global shutdown flag. (A liveness watchdog, if any, belongs to the
  host executor and the scheduler-liveness gate, not to a per-node timeout that
  would make wake behavior wall-clock-dependent.) On observing the global
  `shutdown_requested` flag the parked plugin MUST wake, set its status to done,
  and proceed to teardown (§12.9.4). *Gate:* `gate:scheduler-liveness`,
  `gate:control-responsive`. *Spec:* §12.3.3; routes [INV-8], [INV-10].

Blocking the single vCPU thread is correct and intended: with `-smp 1` the vCPU
thread has no guest work to do at HLT, and QEMU's main loop continues on its own
thread. Parking on the `wake_signal` futex is the mechanism that lets the host
scheduler unblock the plugin without polling: the host raises the ceiling, bumps
`wake_signal`, and issues the non-private futex wake in release order. In the
production steady state the host MUST also write the eventfd at least once per
quantum, and the plugin MUST have registered it with QEMU before readiness, so
QEMU's main loop re-enters callbacks. The shared futex and state remain
authoritative, and the woken plugin observes a consistent
`(ceiling, pending-inputs)` snapshot ([SCHED-36]).

### 12.3.4 Exact next-deadline introspection

- **[PLUG-14]** On going idle the plugin MUST obtain the *exact* virtual time of
  the guest's next armed timer deadline from `QEMU_CLOCK_VIRTUAL` via the
  clock-deadline introspection capability of the patch series
  ([`11-qemu-patches.md`](11-qemu-patches.md),
  [`09-virtual-time-icount.md`](09-virtual-time-icount.md) §9.8), convert it to an
  icount via the fixed shift's `ceil` map ([TIME-4]), and report it to the
  scheduler as the node's exact local event. The deadline MUST be derived from the
  icount-driven virtual clock, never from `QEMU_CLOCK_REALTIME` or
  `QEMU_CLOCK_HOST`. *Gate:* `gate:layer0-determinism`,
  `gate:scheduler-liveness`. *Spec:* §12.3.4, forward-ref
  [`11-qemu-patches.md`](11-qemu-patches.md); routes [TIME-24], [TIME-26],
  [INV-4].

- **[PLUG-15]** The plugin MUST NOT use an overshoot-and-correct fallback for
  idle advancement (advance by a guess, observe whether a timer fired, back off).
  Such a fallback cannot be made bit-deterministic ([TIME-25]). If the
  exact-deadline capability is unavailable in the running QEMU build, the plugin
  MUST fail loudly at registration rather than degrade to guessing. *Gate:*
  `gate:layer0-determinism`, `gate:divergence-bisect`. *Spec:* §12.3.4; routes
  [TIME-25], [INV-10].

### 12.3.5 Advancing and draining

- **[PLUG-16]** When the plugin performs an idle jump it MUST enqueue exactly one
  authorized virtual-time target and return from the vCPU/plugin callback without
  mutating plugin clock or injection state. QEMU MUST advance the virtual clock
  and dispatch due timers from queued normal-main-loop work, then deliver
  completion through a later main-loop pass only after timer-produced bottom
  halves. This work MUST remain runnable while the requesting vCPU is blocked
  on deterministic device I/O. The plugin MUST
  validate that exact completion before advancing its clock, consuming inbound
  rings, injecting frames, or republishing the node as running. No next quantum
  may start while completion is pending. This two-stage barrier makes the wake
  state bit-for-bit independent of host timing without recursive main-loop
  polling. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer0-determinism`. *Spec:* §12.3.5; routes [DET-1], [INV-4],
  [SCHED-28].

The queued-completion barrier is what makes idle fast-forward exact: a
60-second idle gap collapses to one virtual-time jump ([G-9],
[`25-performance-targets.md`](25-performance-targets.md)) and every timer that was
due in that gap fires at its exact icount, in the same order, on every run.

### 12.3.6 Round-robin sub-division and commanded preemption

Within a single *running* quantum (between idle transitions) the node's N vCPUs
are interleaved by the single-threaded round-robin TCG accelerator. The plugin
drives that interleaving deterministically and applies the scheduler's
exploration decision about *when* a vCPU switch / interrupt happens.

- **[PLUG-50]** Within a RUN (the span between node-idle transitions) the
  plugin MUST drive the deterministic round-robin sub-division of the N vCPUs:
  each vCPU retires exactly the fixed, content-addressed `rr_switch_quantum`
  (in node-icount, 10/[QEMU-43], 11/[PATCH-44]) before the round-robin switches
  to the next vCPU in a **fixed ascending rotation**, never an adaptive or
  realtime quantum. The plugin MUST apply any `Decision::Preemption` the
  scheduler (08) hands it by forcing the vCPU switch / delivering the interrupt
  at the **commanded node-icount** via the preemption-injection capability of the
  patch series (11/[PATCH-47]). If a commanded preemption falls outside the
  authorized window `[deadline, ceiling]`, the plugin MUST fail loudly and
  localize it ([INV-10]) rather than clamp, defer, or apply it at a different
  icount. The interleaving, and any applied preemption, MUST be a pure function
  of icount and the decision — identical across runs given the same decision.
  *Gate:* `gate:layer0-determinism`, `gate:layer1-injection`,
  `gate:single-vm-fingerprint`. *Spec:* §12.3.6; routes [DET-1], [INV-3],
  [INV-8], [INV-10], references [QEMU-43], [PATCH-44], [PATCH-47].

A node with `-smp 1` is the degenerate case of [PLUG-50]: there is one vCPU,
the rotation never switches, and a `Decision::Preemption` reduces to a commanded
interrupt delivery at a node-icount. With N > 1 the same machinery makes the
vCPU-switch interleaving an explorable, replayable property of the schedule.

## 12.4 Idle/resume handling and holding HZ ticks during device I/O

### 12.4.1 Idle/resume lifecycle

- **[PLUG-17]** The plugin MUST treat the vCPU-idle and vCPU-resume callbacks as
  the boundary of a quantum's worth of guest progress for its node: idle is where
  the plugin publishes its clock, parks, jumps, and injects (§12.3.2); resume is
  where the plugin records that the guest has re-entered execution (republishing
  `current_icount`/`current_ns` and setting status running). Resume MUST NOT block
  and MUST NOT advance virtual time — the guest is about to execute real
  instructions. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §12.4.1; routes
  [INV-4], [INV-8].

### 12.4.2 Polling and injecting inbound frames

- **[PLUG-18]** When deciding the idle wake icount and again after an idle jump,
  the plugin MUST consult its inbound frame rings via the non-consuming
  `peek_delivery_icount` ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-21]) to learn
  when its next inbound input becomes visible, and MUST make a frame
  architecturally visible to the guest *iff*
  `frame.delivery_icount <= current_icount` ([SHM-33], [DET-11], [DET-13]). The
  moment a frame's bytes became present in the ring is irrelevant; only the
  comparison of the in-band delivery icount against the guest's current icount
  governs visibility. *Gate:* `gate:layer1-injection`. *Spec:* §12.4.2,
  forward-ref [`13-shmem-abi.md`](13-shmem-abi.md) §13.9; routes [DET-11],
  [DET-13], [INV-3].

- **[PLUG-19]** When multiple inbound frames are simultaneously deliverable
  (each with `delivery_icount <= current_icount`), the plugin MUST inject them in
  the deterministic total order `(delivery_icount, src_node, seq)` of [INV-3] /
  [SHM-34], identical across runs and independent of which producer's store landed
  first or which ring the plugin polled first. The plugin MUST NOT deliver frames
  in ring-arrival order. *Gate:* `gate:layer1-injection`. *Spec:* §12.4.2; routes
  [INV-3], [DET-14].

- **[PLUG-20]** If the plugin observes an inbound frame whose `delivery_icount`
  the guest's `current_icount` has already passed, it MUST fail loudly unless
  that frame is the canonical ring head and its ABI-versioned consumer state
  proves a prior real-QEMU backpressure result. A retained head authorizes its
  same-ring FIFO successors while it blocks them; no other late frame or
  retained marker is valid. Because guest progress is what can release device
  backpressure, a retained head and its blocked FIFO MUST NOT constrain the
  next guest wake to the head's already-attempted delivery icount. The plugin
  MUST report the frame's
  `(delivery_icount, src_node, seq)` and current icount on rejection. It MUST
  set retained state only after QEMU returns backpressure, preserve that state
  through checkpoint/restore, and dequeue the frame only after complete guest
  acceptance. *Gate:* `gate:layer1-injection`,
  `gate:divergence-bisect`. *Spec:* §12.4.2; routes [DET-12], [INV-10].

### 12.4.3 Holding HZ ticks across in-flight device I/O

A device-I/O round trip (a block read, a 9p request) is submitted at one icount
and answered later. If the guest's HZ timer ticks were allowed to advance virtual
time freely between submit and completion, the icount at which the completion
became visible would depend on how many idle jumps happened to occur in that
window — a host-timing artifact. The plugin therefore suppresses *spurious* HZ-tick
advancement of virtual time across an I/O burst so the completion lands at the
scheduler-computed icount. This does **not** freeze virtual time (which
[`15-io-subnodes.md`](15-io-subnodes.md) forbids): the requester still advances to
the scheduler-computed completion via the exact-local-event fast-forward (§8.4,
[`15-io-subnodes.md`](15-io-subnodes.md) [IO-2]/[IO-10]); only the host-timing-
dependent extra HZ ticks between submit and completion are held back.

- **[PLUG-21]** While any device-I/O request the plugin has submitted for its node
  is in flight, the plugin MUST suppress spurious HZ-tick advancement of virtual
  time between submit and the computed completion: the idle handler MUST NOT let
  background guest HZ ticks advance the clock past what the scheduler authorizes
  for the burst for as long as the per-node `device_io_active` flag is set or the
  plugin's pending-I/O counter is non-zero ([`13-shmem-abi.md`](13-shmem-abi.md)
  [SHM-9] `device_io_active`). The completion does NOT become visible at the submit
  instant: it becomes visible at the scheduler-computed
  `delivery_icount = submit_icount + modeled_latency`, to which the requester is
  fast-forwarded via the exact-local-event mechanism (§8.4,
  [`15-io-subnodes.md`](15-io-subnodes.md) [IO-2]/[IO-10]). Holding the HZ ticks
  makes that delivery icount independent of wall-clock variation in how long the
  executor takes to serve the request, so timer ticks cannot slip mid-burst.
  *Gate:* `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §12.4.3,
  forward-ref [`15-io-subnodes.md`](15-io-subnodes.md); routes [DET-19],
  [INV-4].

- **[PLUG-22]** The plugin MUST set `device_io_active` (and/or increment its
  pending-I/O counter) on the I/O *submit* path and clear it (decrement) on the
  matching *completion* path, pairing submit and completion one-to-one regardless
  of completion status, so the HZ-tick hold ([PLUG-21]) is released exactly when
  the last in-flight request for the burst has been answered. A burst-done signal
  from the device
  (for multi-request bursts, §12.6) MUST clear the flag for the whole burst.
  *Gate:* `gate:single-vm-fingerprint`. *Spec:* §12.4.3, §12.6; routes [DET-19],
  [INV-4].

Holding the HZ ticks is not a stall: the completion still arrives (the executor
serves the request and writes the response into the inbound ring), the requester
is fast-forwarded to the computed `delivery_icount`, and the device's completion
mechanism un-halts the guest, after which the next idle callback advances normally.
What this removes is only the *wall-clock-dependent number of HZ ticks* that would
otherwise slip between submit and the computed completion; virtual time is never
frozen at the submit instant.

## 12.5 Network frame emit and inject

The plugin is the bridge between the guest's emulated NIC and the shared-memory
transport. Outbound: it intercepts every frame the guest transmits and writes it
to its outbound ring with an emit-icount stamp. Inbound: it injects frames from
its inbound ring at their delivery icount (§12.4.2). The host network router
([`13-shmem-abi.md`](13-shmem-abi.md) §13.5, [SHM-17]) sits between the two and
applies the link model.

### 12.5.1 TX interception (guest → outbound ring)

- **[PLUG-23]** The plugin MUST register a network-TX interception callback
  ([`11-qemu-patches.md`](11-qemu-patches.md)) that captures every frame the guest
  emits and writes it into the node's outbound ring toward the reserved network
  router slot — the ring `(slot -> SLOT_NET_ROUTER)`
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-17]). Each enqueued `FrameEntry` MUST
  carry the **emit icount** (the guest's current icount at the moment of
  transmission) in `delivery_icount`, the node's own slot as `src_node`, a
  per-`(producer, consumer)` monotonic `seq`, and the payload; the host router
  re-stamps the effective `delivery_icount` by adding the modeled link latency and
  applying the fault table ([`08-scheduling.md`](08-scheduling.md) [SCHED-29],
  [`17-fault-injection.md`](17-fault-injection.md)). *Gate:*
  `gate:layer1-injection`. *Spec:* §12.5.1, forward-ref
  [`13-shmem-abi.md`](13-shmem-abi.md), [`08-scheduling.md`](08-scheduling.md);
  routes [INV-3], [DET-11].

- **[PLUG-24]** The TX callback MUST be safe to invoke re-entrantly from inside
  the idle handler (a frame emitted by a timer handler fired during an idle jump,
  [PLUG-4]): it MUST locate its outbound ring and slot from
  registration-time-fixed, never-mutated state, MUST NOT acquire a lock the idle
  handler holds, and MUST be deterministic in what it enqueues (the same guest
  frame at the same icount yields the same entry on every run). *Gate:*
  `gate:single-vm-fingerprint`, `gate:layer1-injection`. *Spec:* §12.5.1; routes
  [INV-8], [DET-1].

- **[PLUG-25]** A frame whose length exceeds `MAX_FRAME_DATA`
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-13]) MUST be rejected at enqueue and
  surfaced as a loud error, never silently truncated. An outbound ring that is
  full MUST be a loud error (a full ring under the conservative scheduling
  discipline indicates a scheduling defect, not a normal backpressure condition),
  never a silent drop. *Gate:* `gate:abi-conformance`, `gate:layer1-injection`.
  *Spec:* §12.5.1; routes [INV-10].

### 12.5.2 RX injection (inbound ring → guest)

- **[PLUG-26]** The plugin MUST inject inbound frames into the guest's NIC via the
  RX-injection capability of the patch series
  ([`11-qemu-patches.md`](11-qemu-patches.md)), using a canonical retry path so
  a frame is never silently dropped when the guest's RX queue is momentarily not
  ready. QEMU reports backpressure without taking ownership; the plugin leaves
  the frame in the bounded shared-memory ring until complete guest acceptance.
  QEMU-private packet queues MUST NOT own a retained frame because they are not
  part of the canonical exact-checkpoint transport state. Each later plugin
  retry invokes a fresh guest-device probe; QEMU MUST NOT let the
  `receive_disabled` hint associated with its unused private queue suppress that
  canonical retry.
  Injection MUST occur from the idle callback context (where QEMU's big lock is
  held) and MUST be gated by the delivery-icount rule of [PLUG-18]. *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §12.5.2; routes
  [DET-11], [DET-13], [INV-4].

- **[PLUG-27]** Inbound injection MUST be performed *after* the plugin has
  advanced virtual time to the wake icount (§12.3.2 step 6), so that a frame whose
  `delivery_icount` falls in the jumped-over window becomes visible at the
  deterministic wake icount rather than at whatever HLT moment the guest happened
  to reach. The plugin MUST NOT inject a frame at a virtual time earlier than its
  `delivery_icount`. *Gate:* `gate:layer1-injection`. *Spec:* §12.5.2; routes
  [DET-11], [INV-3].

```rust
// Illustrative sketch (CONV-1): the inbound-injection loop after an idle jump.
// Authoritative statements are [PLUG-18..20], [PLUG-26..27].
fn inject_due_frames(state: &PluginState, now: Icount) -> Result<(), Divergence> {
    // Frames across all inbound rings, merged into (delivery_icount, src, seq) order.
    for frame in state.region.due_inbound_frames(state.slot, now) { // [PLUG-19] order
        if frame.delivery_icount < now_floor_of_passed(state) {
            return Err(Divergence::passed_delivery(frame));         // [PLUG-20] fail loud
        }
        if net_inject_direct(&frame.data[..frame.len as usize])? == RETAINED {
            break;                                                  // [PLUG-26] canonical retry
        }
        state.region.consume(frame.handle);                         // accepted prefix only
    }
    Ok(())
}
```

## 12.6 Block and 9p device callbacks

Block and 9p I/O are modeled as first-class I/O sub-nodes with deterministic
completion icounts ([`15-io-subnodes.md`](15-io-subnodes.md)). The plugin is the
in-VM endpoint: it turns the guest's device requests into ring submissions and
turns ring responses back into device completions, freezing virtual time across
the round trip (§12.4.3).

- **[PLUG-28]** The plugin MUST register block-device submit/poll callbacks
  ([`11-qemu-patches.md`](11-qemu-patches.md)) that: on **submit**, encode the
  request (operation, offset, length, write payload) into a `FrameEntry`, enqueue
  it into the node's outbound block ring `(slot -> SLOT_BLK_IO)`
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-17]) stamped with the submit icount,
  mark device I/O active ([PLUG-21]), and return immediately; on **poll**, check
  the inbound block ring `(SLOT_BLK_IO -> slot)`, validate the response's
  `delivery_icount <= current_icount` before exposing it, deliver the response to
  the guest, and clear/decrement the device-I/O state ([PLUG-22]). *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §12.6,
  forward-ref [`15-io-subnodes.md`](15-io-subnodes.md); routes [DET-19],
  [INV-4].

- **[PLUG-29]** The plugin MUST register 9p submit/poll callbacks with the same
  shape against the reserved 9p slots `(slot -> SLOT_9P_IO)` and
  `(SLOT_9P_IO -> slot)`, plus a **burst-done** callback that clears the
  device-I/O-active flag once every request from a single device invocation has
  completed (a 9p operation may fan out to several requests; the freeze must hold
  for the whole burst, not just one round trip, [PLUG-22]). *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §12.6,
  forward-ref [`15-io-subnodes.md`](15-io-subnodes.md); routes [DET-19],
  [INV-4].

- **[PLUG-30]** A response delivered to the guest MUST be gated by its
  `delivery_icount`: the plugin MUST NOT expose an I/O completion before its
  delivery icount has been reached in virtual time (the poll callback returns
  "not ready" until the gate passes). Because the submit holds back spurious HZ
  ticks ([PLUG-21]) and the executor stamps the completion's delivery icount at or
  after the submit icount, the gate is anchored to a deterministic
  instruction-derived virtual time, never to wall-clock. *Gate:* `gate:layer1-injection`. *Spec:*
  §12.6; routes [DET-19], [DET-13].

- **[PLUG-31]** The block and 9p callbacks MUST use the same re-entrancy-safe
  state discipline as the TX callback ([PLUG-4], [PLUG-24]): they read their ring
  and slot pointers from registration-time-fixed state, never from a lock the idle
  handler holds, and pair every submit with exactly one completion so the pending
  counter cannot drift. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §12.6;
  routes [INV-8], [INV-4].

## 12.7 Guest↔host doorbell (white-box, optional)

Black-box operation is the default and is sufficient for the whole determinism
contract ([G-3], [DET-17]). The white-box doorbell is an *optional* enhancement
that lets a cooperating guest stamp fine-grained markers with the exact icount at
which they occur. It is specified in full in
[`16-guest-host-channel.md`](16-guest-host-channel.md); this section states only
the plugin's part.

- **[PLUG-32]** When and only when white-box mode is enabled ([PLUG-5]
  `whitebox=on`), the plugin MUST trap the reserved doorbell instruction or
  port-I/O write that the guest agent uses to signal the host
  ([`16-guest-host-channel.md`](16-guest-host-channel.md)), read the guest's
  payload through the plugin memory-read API (the plugin MUST read guest memory
  through the QEMU plugin API, never assume a host mapping of guest RAM), and
  record the resulting marker stamped with the exact current icount. The marker is
  delivered to the host (via a dedicated ring or the event-log path,
  [`16-guest-host-channel.md`](16-guest-host-channel.md),
  [`19-observability-event-log.md`](19-observability-event-log.md)). *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`. *Spec:* §12.7,
  forward-ref [`16-guest-host-channel.md`](16-guest-host-channel.md); routes
  [G-3], [DET-17].

- **[PLUG-33]** When white-box mode is **off** (the default), the plugin MUST NOT
  install the doorbell trap and the reserved instruction/port MUST behave exactly
  as it would under unmodified QEMU, so a guest that happens to touch it is
  unaffected. Black-box operation MUST be fully functional with the doorbell
  absent: every determinism guarantee and the execution fingerprint MUST be
  computable with zero guest cooperation. *Gate:* `gate:any-guest`,
  `gate:single-vm-fingerprint`. *Spec:* §12.7; routes [G-2], [G-3], [DET-17].

- **[PLUG-34]** Any *input* the white-box channel delivers to the guest (a marker
  acknowledgment, a control write) MUST itself obey the injection contract of
  §4.4 — carry a delivery icount and become visible at exactly that icount
  ([DET-17]) — so that enabling white-box cannot perturb determinism. A white-box
  marker is an observation stamped with an icount, not a side channel that can
  reorder the instruction stream. *Gate:* `gate:single-vm-fingerprint`,
  `gate:layer1-injection`. *Spec:* §12.7; routes [DET-17], [INV-3].

- **[PLUG-51]** **App-controlled randomness (white-box, optional).** When and
  only when a node opts in (a white-box mode, [PLUG-5] `whitebox=on`), the plugin
  MUST serve a `random_request` doorbell: when the guest agent rings it
  (§12.7, [`16-guest-host-channel.md`](16-guest-host-channel.md)), the plugin
  draws the requested value from the **seeded decision source** (the same
  deterministic stream the scheduler decisions derive from, never host entropy)
  and writes the value back to the guest at the **trap icount** under the
  injection contract of §4.4 (host→guest reply carrying a delivery icount and
  becoming visible at exactly that icount, [DET-17], [PLUG-34]). The served value
  MUST be recorded as a `Decision::AppRandom` (08) so it is part of the schedule
  and replayable. Serving a request MUST be side-effect-free with respect to the
  architectural trajectory `T` **except** for the requested value delivered at
  the trap icount — it MUST NOT perturb virtual time, frame/I-O delivery, or the
  instruction stream otherwise. The engine MUST function correctly with **zero**
  such requests: app-controlled randomness is purely additive, and a node that
  never rings the doorbell behaves exactly as a black-box node. *Gate:*
  `gate:layer1-injection`, `gate:single-vm-fingerprint`, `gate:any-guest`.
  *Spec:* §12.7; routes [DET-17], [INV-3], references [PLUG-34], [G-3].

## 12.8 Coverage hook (optional, negligible when off)

For coverage-guided fuzzing ([`22-advanced-features.md`](22-advanced-features.md))
the plugin can emit guest basic-block coverage harvested from the TCG-exec path,
with no guest instrumentation. It is off by default and MUST cost nothing when
off.

- **[PLUG-35]** When coverage is enabled ([PLUG-5] `coverage=on`), the plugin MUST
  register a TCG translation/execution callback that records, per executed basic
  block, a coverage signal (e.g. the block's guest program counter folded into a
  fixed-size coverage map) suitable for feeding the fuzzer
  ([`22-advanced-features.md`](22-advanced-features.md)). Coverage harvesting MUST
  be black-box (no guest cooperation) and MUST NOT alter the instruction stream
  `S` or the architectural trajectory `T`: enabling coverage MUST NOT change a
  fingerprint. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §12.8, forward-ref
  [`22-advanced-features.md`](22-advanced-features.md); routes [DET-1], [G-6].

  The production implementation folds each translated block into a fixed map
  slot at translation time and uses QEMU's per-vCPU scoreboard condition to
  invoke the exact-icount callback only while that slot is unseen. The callback
  marks the slot before publishing the novelty, so repeated execution remains
  entirely on QEMU's conditional hot path.

- **[PLUG-36]** When coverage is **disabled** (the default), the plugin MUST NOT
  register the TCG-exec coverage callback at all, so the hot translation/execution
  path carries no per-block overhead. Coverage MUST be a registration-time opt-in,
  never a runtime branch evaluated on every block. *Gate:*
  `gate:single-vm-fingerprint`. *Spec:* §12.8; routes [G-9].

- **[PLUG-37]** Coverage data is an **observational** output
  ([`19-observability-event-log.md`](19-observability-event-log.md)): it MUST be
  excluded from the determinism comparison (two equivalent runs may legitimately
  produce identical coverage, but coverage is consumed by the fuzzer, not by the
  fingerprint), and recording it MUST NOT influence scheduling, virtual time, or
  injection. *Gate:* `gate:single-vm-fingerprint`. *Spec:* §12.8; routes
  [DET-1].

## 12.9 Handshake, setup, boot barrier, and teardown

The control protocol ([`14-protocol.md`](14-protocol.md)) is the plugin's
one-time setup channel; after `SetupAck` it is silent until shutdown. This
section states the plugin's obligations on that channel and at the boot barrier.

### 12.9.1 Handshake

- **[PLUG-38]** The plugin MUST perform the version handshake before mapping or
  reading any byte of the shared-memory region: it sends `Hello(proto_version,
  abi_version)` carrying the shmem ABI version it was compiled against, blocks for
  `HelloAck`, and verifies the negotiated `proto_version`, the exact `abi_version`
  match, and `slot_index < node_count`
  ([`14-protocol.md`](14-protocol.md) [PROTO-10], [PROTO-11], [PROTO-16]). A
  mismatch MUST abort setup loudly. *Gate:* `gate:abi-conformance`. *Spec:*
  §12.9.1, forward-ref [`14-protocol.md`](14-protocol.md) §3.5, §3.6, §4; routes
  [G-8].

- **[PLUG-39]** The plugin MUST cross-check the `slot_index` it received as a
  launch argument ([PLUG-5] `slot=N`) against the `slot_index` the host sends in
  `HelloAck`; a disagreement is a configuration error and MUST abort setup. The
  authoritative slot is the handshake's, and it MUST equal the launch argument.
  *Gate:* `gate:abi-conformance`. *Spec:* §12.9.1; routes [G-8], [INV-10].

### 12.9.2 Setup and ABI validation

- **[PLUG-40]** On `Setup` the plugin MUST receive exactly two descriptors via
  `SCM_RIGHTS` in fixed order — the shmem fd then the wake fd
  ([`14-protocol.md`](14-protocol.md) [PROTO-8]) — `mmap` the shmem fd for exactly
  the `region_len` the host sent, validate the region header's magic, ABI version,
  and that its `node_count` and the plugin's `slot_index` are consistent
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-30]), and only then arm the wake fd
  and register callbacks. Receiving any other fd count, a short region, or a
  failed header validation MUST be a setup failure ([PROTO-21]). *Gate:*
  `gate:abi-conformance`. *Spec:* §12.9.2, forward-ref
  [`14-protocol.md`](14-protocol.md) §3.7, [`13-shmem-abi.md`](13-shmem-abi.md)
  §13.8; routes [G-8], [INV-10].

- **[PLUG-41]** The plugin MUST reply `SetupAck(status)` with `status == 0` only
  after the region is mapped, the ABI validated, the wake fd armed, and all
  callbacks registered; a non-zero status MUST carry a failure code and the plugin
  MUST NOT begin participating in scheduling (reading its clock cell, polling its
  rings, advancing time) ([`14-protocol.md`](14-protocol.md) [PROTO-13],
  [PROTO-19]). *Gate:* `gate:abi-conformance`, `gate:control-responsive`. *Spec:*
  §12.9.2; routes [G-8].

### 12.9.3 The boot barrier (initial ceiling)

- **[PLUG-42]** After `SetupAck` and before the guest retires its first
  architecturally-visible instruction, the plugin MUST wait for the scheduler to
  publish the initial `max_advance_icount` ceiling (the boot rendezvous target)
  for its slot ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-11]). The slot's
  ceiling initializes to 0 so the plugin cannot advance before this barrier
  releases; the plugin MUST block on the boot barrier (parking on the `wake_signal`
  futex as the sole barrier wait primitive, never the eventfd or a fixed
  wall-clock sleep used as the gate) until the scheduler raises the ceiling. The
  separately registered eventfd remains required for QEMU main-loop integration.
  *Gate:* `gate:layer1-injection`, `gate:layer0-determinism`.
  *Spec:* §12.9.3, forward-ref [`13-shmem-abi.md`](13-shmem-abi.md) §13.6; routes
  [DET-12], [INV-8].

The boot barrier is what prevents the most insidious early divergence: without
it, the guest would begin executing at QEMU's default icount budget and blow past
the boot rendezvous by a host-timing-dependent number of instructions before the
first idle. The barrier makes "the first run" already deterministic from
instruction zero ([DET-3], no golden first run).

### 12.9.4 Teardown

- **[PLUG-43]** The plugin MUST observe the global `shutdown_requested` flag and
  the control-channel `Quit` message as the two shutdown triggers
  ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-29],
  [`14-protocol.md`](14-protocol.md) [PROTO-14]): on either, a parked plugin MUST
  wake, set its node status to done, stop touching shmem, and initiate orderly
  QEMU shutdown so the host's shutdown escalation
  ([`14-protocol.md`](14-protocol.md) §5.3) completes without leaking the QEMU
  child. The plugin MUST NOT continue advancing time or injecting after observing
  a shutdown trigger. *Gate:* `gate:control-responsive`. *Spec:* §12.9.4; routes
  [INV-8].

## 12.10 Determinism, the FFI safety boundary, and fail-loud

The plugin is the one crate in Crucible that is *intrinsically* unsafe: it is a
`cdylib` calling into QEMU's C ABI, mapping raw shared memory, and registering C
function pointers. The determinism guarantees and the engineering standards of
[`28-engineering-standards.md`](28-engineering-standards.md) bind it especially
tightly here.

### 12.10.1 Determinism

- **[PLUG-44]** No plugin code path may read host wall-clock, host monotonic
  time, host thread-scheduling order, or any host entropy source on a path that
  influences virtual time, frame/I-O delivery, the instruction stream, or the
  architectural trajectory. The only nondeterminism the plugin participates in is
  the scheduler's authorized ceilings and the in-band delivery icounts it reads
  from shmem; both are pure virtual-time quantities. *Gate:*
  `gate:layer0-determinism`, `gate:single-vm-fingerprint`. *Spec:* §12.10.1;
  routes [INV-4], [INV-9], [TIME-32].

- **[PLUG-45]** Because the plugin runs single-threaded on the vCPU thread
  ([PLUG-3]), every atomic it performs on the shared-memory region is uncontended
  from its side; the atomic *ordering* (acquire/release) it uses MUST still match
  the ABI's ordering rules ([`13-shmem-abi.md`](13-shmem-abi.md) [SHM-20],
  [SHM-24]) because the *other* side (the host scheduler/router) is a separate
  process. The plugin MUST use acquire loads where the ABI requires them
  (reading the ceiling, reading a ring's `write_idx`) and release stores where the
  ABI requires them (publishing `current_icount`, freeing a consumed slot). *Gate:*
  `gate:abi-conformance`, `gate:layer1-injection`. *Spec:* §12.10.1; routes
  [SHM-20], [INV-3].

### 12.10.2 The FFI safety boundary

- **[PLUG-46]** Every `unsafe` block in the plugin MUST be minimal and carry a
  `// SAFETY:` comment justifying the invariant that makes it sound
  ([`28-engineering-standards.md`](28-engineering-standards.md)), specifically:
  the single-vCPU-thread serialization that makes process-global state
  uncontended; the lifetime of the mmap'd region (mapped at setup, valid for the
  process lifetime); the validity of the control/shmem/wake descriptors handed in
  at setup; and the contract that C callbacks registered with QEMU are invoked
  only on the vCPU thread. The plugin MUST NOT use `unsafe` to paper over a
  genuine data race; the soundness argument MUST be the single-threaded model plus
  the cross-process atomic ordering of [PLUG-45]. *Gate:* `gate:harness-lint`.
  *Spec:* §12.10.2, forward-ref [`28-engineering-standards.md`](28-engineering-standards.md);
  routes [INV-9].

- **[PLUG-47]** Guest memory MUST be read only through the QEMU plugin memory API
  (§12.7), never by dereferencing a presumed host pointer into guest RAM; the
  plugin MUST treat guest physical addresses as opaque handles into the API. Frame
  and request payloads copied between the guest and the shmem rings MUST be
  bounds-checked against `MAX_FRAME_DATA` and the request's declared length, never
  trusting a guest- or ring-supplied length without validation. *Gate:*
  `gate:abi-conformance`, `gate:single-vm-fingerprint`. *Spec:* §12.10.2; routes
  [INV-10].

### 12.10.3 Fail-loud on IPC and capability failure

- **[PLUG-48]** Any failure of the determinism-critical machinery MUST fail loud,
  never silent: a broken control socket, a failed handshake, an absent required
  capability (time control, exact-deadline introspection, RX injection), an ABI
  mismatch, a full outbound ring, or an already-passed delivery icount ([PLUG-20])
  MUST stop the run for that node with a distinct, diagnosable failure rather than
  degrading to a best-effort or wall-clock-dependent fallback. A determinism
  violation the plugin can detect locally MUST be reported so the divergence
  bisector can localize it ([INV-10], [DET-39]); the plugin MUST NOT smooth it
  over. *Gate:* `gate:divergence-bisect`, `gate:control-responsive`. *Spec:*
  §12.10.3; routes [INV-10], [DET-39].

### 12.10.4 Inertness when sim mode is off

- **[PLUG-49]** When sim mode is off the plugin is not loaded at all: no `-plugin`
  argument is passed, no control socket is created, no shared-memory region is
  mapped, and none of the patch-series capabilities the plugin calls take effect
  ([`14-protocol.md`](14-protocol.md) [PROTO-24], [INV-7]). The plugin's existence
  MUST have zero effect on a QEMU process launched without it; AOS's production
  QEMU built from the same source MUST be behaviorally identical to upstream when
  the plugin is absent. *Gate:* `gate:qemu-inert`. *Spec:* §12.10.4, forward-ref
  [`11-qemu-patches.md`](11-qemu-patches.md); routes [INV-7], [DET-36].

## 12.11 Summary

```text
plugin = the in-VM cdylib (-plugin), single vCPU thread ⇒ state uncontended (PLUG-1..4)
  args: simfd, slot, shmemfd/wakefd (SCM_RIGHTS), whitebox?, coverage?       (PLUG-5..6)
  register order: parse → handshake → TAKE TIME CONTROL → map shmem/validate
                  → register callbacks → SetupAck → wait boot barrier        (PLUG-7..8)
  time control: own the clock; no warp, no realtime, no wall-clock           (PLUG-9)
    idle (HLT/WFI): publish icount → exact next deadline → wake = min(timer,
                    inbound delivery, ceiling) → PARK on canonical wake_signal
                    futex (no spin); registered eventfd nudges QEMU main loop
                    → jump (drain timers/BHs) → inject due frames in order    (PLUG-10..16)
    hold HZ ticks across in-flight device I/O (device_io_active)              (PLUG-21..22)
  net: TX → outbound ring (emit icount); RX inject iff delivery<=now, in
       (delivery_icount, src, seq) order; passed-delivery ⇒ fail loud         (PLUG-23..27)
  block/9p: submit→ring(freeze time); poll→validate delivery_icount→deliver   (PLUG-28..31)
  doorbell (white-box, opt): trap reserved insn/port, read guest mem via API,
       stamp marker @ exact icount; black-box works without it                (PLUG-32..34)
  coverage (opt): TCG-exec basic-block map; zero cost when off; observational  (PLUG-35..37)
  handshake/setup/boot-barrier/teardown over the control socket               (PLUG-38..43)
  determinism + FFI: no host time; cross-process atomic ordering; minimal
       unsafe with // SAFETY:; guest mem via API only; fail loud; inert off   (PLUG-44..49)
```

If the plugin holds the clock, advances only by scheduler-authorized jumps to
exact deadlines, injects every input at its in-band delivery icount in the fixed
total order, and freezes virtual time across device I/O, then — given Contract A's
entropy elimination ([`04-determinism-contract.md`](04-determinism-contract.md)
§4.6) and Contract B's scheduler ([`08-scheduling.md`](08-scheduling.md)) — the
guest's instruction stream `S` and architectural trajectory `T` are a pure
function of `(image, cmdline, seed, injected inputs)`. The plugin is the
component that makes that purity true *inside* the QEMU process.

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is the QEMU plugin, tracked by [PLAN-3]. They
> populate Phase 1 (the determinism / harness / transport foundation), sequenced
> after the shmem ABI ([`13-shmem-abi.md`](13-shmem-abi.md)) and control protocol
> ([`14-protocol.md`](14-protocol.md)) primitives the plugin depends on.

- [x] **T-PLUG-1** Scaffold the `crucible-qemu-plugin` `cdylib`: the QEMU
  `qemu_plugin_version` and `qemu_plugin_install` exports, inert callback entry
  points, QEMU API/vCPU-count validation from `qemu_info_t`, the
  single-threaded round-robin TCG precondition, and the partition of state into a
  lifecycle core and never-mutated device-callback pointers (re-entrancy-safe);
  make the plugin the sole owner of the node's device and channel callbacks (net
  TX/RX, block/9p submit/poll, white-box doorbell trap) so no host component
  injects/completes/stamps except through these paths. —
  satisfies [PLUG-2], [PLUG-3], [PLUG-4]; spec §12.1, §12.5, §12.6, §12.7.
  Completed by `checks.crucible.phase2.qemuPluginAbiScaffold` and the live
  callback gates. The packaged `cdylib` exports only the pinned QEMU install and
  version ABI, validates the live QEMU API, vCPU topology, and single-threaded
  RR execution proof before registration, and keeps lifecycle state separate
  from its registration-time-fixed callback table. The installed production
  plugin is the sole callback owner in the live network, block, 9p, and
  white-box gates; each host servicer communicates only through the plugin-owned
  shared-memory rings and never injects, completes, or stamps guest events
  directly.
- [x] **T-PLUG-2** Implement plugin-argument parsing (`simfd`, `slot`,
  `shmemfd`/`wakefd`, `whitebox`, `coverage`) as a total, fail-closed parser that
  aborts registration on any malformed or missing required key. — satisfies
  [PLUG-5], [PLUG-6]; spec §12.2.1.
- [x] **T-PLUG-3** Implement the fixed registration order — parse → handshake →
  acquire time control before the first instruction → map+validate shmem → arm
  wake fd → register callbacks → `SetupAck` → wait boot barrier — failing
  loudly at each step. — satisfies [PLUG-7], [PLUG-8]; spec §12.2.2.
  Completed by `checks.crucible.phase2.qemuPluginRegistrationOrder`, which
  exhaustively checks the canonical sequencer and its terminal failure states,
  then consumes `checks.crucible.phase2.qemuLivePluginInstall`. The live gate
  loads the production Rust plugin and reaches ready `SetupAck`, enforces the
  boot barrier before guest execution, runs silently, consumes `Quit`, and exits
  orderly; those states are reachable only through the fixed install sequence.
- [x] **T-PLUG-4** Implement clock ownership and the no-host-time invariant: the
  plugin advances virtual time only by guest instructions up to the ceiling and by
  authorized idle jumps; ban host wall-clock/monotonic reads on the time path. —
  satisfies [PLUG-1], [PLUG-9], [PLUG-44]; spec §12.3.1, §12.10.1.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantum`, which loads no
  observation plugin so the Rust plugin is the sole `sim_shmem` time authority:
  across the boot quanta the guest advances by exactly its guest-instruction icount
  up to each host-published scheduler ceiling and stops there, and the whole boot
  fingerprint is byte-identical on a second run taken under bounded scheduler preemption — only
  possible if virtual time is owned by the plugin and never sampled from a host
  clock. When the guest idles, the plugin advances virtual time by the authorized
  idle jump to the exact next timer deadline and the guest wakes and runs on: the
  gate records a `terminal_icount` 40 million instructions past the idle-onset
  icount, confirming the plugin — not the host — drove the idle advance. The
  time-control, idle-loop, and deadline source
  paths are held free of wall-clock/monotonic/entropy APIs by the sibling
  `qemuPluginTimeControl` gate.
- [x] **T-PLUG-5** Implement the idle (HLT/WFI) callback hot loop: publish
  icount, compute the next local wake from exact timer and inbound delivery
  signals against the scheduler ceiling, park on the canonical `wake_signal`
  futex (no busy spin, no wall-clock timeout) while the required registered
  eventfd separately nudges QEMU's main loop, jump on scheduler release, mark
  done on shutdown wake, inject due frames in deterministic order, and
  republish running/resume status. —
  satisfies [PLUG-10], [PLUG-11], [PLUG-12], [PLUG-13], [PLUG-17]; spec §12.3.2,
  §12.3.3, §12.4.1.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantum`, which observes the
  plugin run the idle hot loop live: at guest HLT idle onset it publishes icount,
  computes the next local wake from the exact `QEMU_CLOCK_VIRTUAL` timer deadline,
  and parks on the canonical `wake_signal` futex with no wall-clock timeout; the
  registered eventfd separately drives QEMU main-loop re-entry. On scheduler
  release it enqueues the authorized advance and, per the deferred-completion discipline,
  waits for the queued-advance completion before mutating architectural state
  rather than advancing eagerly — and with that completion now landing (T-PLUG-7)
  it commits the jump, moving the idle guest to the exact deadline and republishing
  running. Deterministic in-order inbound-frame injection is T-PLUG-8.
- [x] **T-PLUG-6** Implement exact next-deadline introspection (read the next
  `QEMU_CLOCK_VIRTUAL` deadline via the required plugin export, `ceil`-convert to
  icount) and ban the overshoot-and-correct fallback; fail loudly during callback
  registration if the capability is missing. —
  satisfies [PLUG-14], [PLUG-15]; spec §12.3.4.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantum`, which records the
  plugin read the exact next `QEMU_CLOCK_VIRTUAL` deadline through the required
  export and `ceil`-convert it to icount live: at idle onset the gate emits
  `idle_next_deadline_icount` equal to the introspected timer deadline with no
  overshoot-and-correct, and the same value appears on both runs.
- [x] **T-PLUG-7** Implement idle-jump advancement through the required
  queued-advance (`qemu_plugin_advance_time_ns`) and normal-main-loop completion
  (`qemu_plugin_register_time_advance_cb`) exports: keep plugin state
  unchanged while pending, order timer bottom halves before completion, then
  validate the exact target before clock/ring/RX commit so the wake-point
  architectural state is bit-identical regardless of host timing. — satisfies
  [PLUG-16]; spec §12.3.5.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantum`: the diskless
  multiboot guest arms a periodic PIT timer,
  parks in HLT, and the plugin advances virtual time by an authorized 40M-icount
  O(1) jump through the exact `QEMU_CLOCK_VIRTUAL` timer deadline. The guest
  wakes, runs, and re-idles below the published scheduler ceiling without
  self-extending past it. The terminal architectural state is byte-identical on
  a second run taken under bounded scheduler preemption, proving the queued advance commits the
  same wake-point state regardless of host timing. The advance rides QEMU patch
  0010's `icount_advance_virtual_time_to_ns`
  primitive (replacing the qtest-only helper that spun under icount) with the
  reset-vs-advance completion drain in patch 0025, plus the plugin max-advance
  budget computed as `ceiling - logical_offset`.
- [x] **T-PLUG-8** Implement inbound-frame polling/injection: peek delivery
  icount, deliver iff `delivery_icount <= current_icount`, order injections by
  `(delivery_icount, src_node, seq)`, and fail loudly on an already-passed
  delivery icount. — satisfies [PLUG-18], [PLUG-19], [PLUG-20]; spec §12.4.2.
  Completed by `checks.crucible.phase2.qemuLiveNetworkIo`: a real Linux guest
  emits a probe through virtio-net, the router reply enters the reserved inbound
  ring at exactly +100,000,000 icount, and the plugin injects it before the
  guest emits its acknowledgement. The exact router latency, frame bytes,
  ordering, and sequences are identical under bounded scheduler preemption; the gate records
  raw probe and guest-ACK offsets separately as whole-guest diagnostics.
- [x] **T-PLUG-9** Implement virtual-time freeze across in-flight device I/O via
  `device_io_active`/pending-counter, paired one-to-one with submit/completion and
  cleared on burst-done. — satisfies [PLUG-21], [PLUG-22]; spec §12.4.3.
  Completed by `checks.crucible.phase2.qemuLiveBlockIo` and
  `checks.crucible.phase2.qemuLive9pIo`. Both gates delay a due response in host
  wall time while the production plugin holds virtual time at the published
  completion horizon, then require the device hold to clear and the real guest
  to progress. The block path pairs each request token with one completion; the
  9p path holds the counter across the whole request burst and clears it only at
  burst-done. Both repeat under bounded scheduler preemption with identical modeled traffic.
- [x] **T-PLUG-10** Implement the network TX interception callback: enqueue guest
  frames into the outbound router ring with an emit-icount stamp, re-entrancy-safe,
  rejecting oversize frames and full rings loudly. — satisfies [PLUG-23],
  [PLUG-24], [PLUG-25]; spec §12.5.1.
  Completed by `checks.crucible.phase2.qemuLiveNetworkIo`, which observes the
  loaded QEMU callback forward the guest's exact Ethernet probe to
  `SLOT_NET_ROUTER` with its emission icount and sequence. The packaged plugin's
  unit gate covers re-entry, oversize, and full-ring fail-loud behavior.
- [x] **T-PLUG-11** Implement RX injection via the canonical retry path from
  the idle context, after the idle jump, gated by the delivery-icount rule. —
  satisfies [PLUG-26], [PLUG-27]; spec §12.5.2.
  Completed by `checks.crucible.phase2.qemuLiveNetworkIo`: the router's
  delivery-stamped reply remains in the inbound ring across backpressure, then
  transfers through QEMU's direct injection path only after complete guest
  acceptance; the real guest proves receipt by emitting the exact ACK.
- [x] **T-PLUG-12** Implement the block submit/poll callbacks against the
  reserved block slots, freezing time on submit and validating the response's
  delivery icount before delivery. — satisfies [PLUG-28], [PLUG-30], [PLUG-31];
  spec §12.6.
  Completed by `checks.crucible.phase2.qemuLiveBlockIo`. A real Linux guest
  submits both discovery traffic and an explicit sector write through
  `SLOT_BLK_IO`; the host servicer publishes the exact future completion
  horizon, the production plugin advances to it, validates and delivers the
  response, releases the device hold, and lets the guest progress. A second run
  combines bounded QEMU scheduler preemption with a 100 ms delayed response publication while
  preserving the same request/completion observations. The drop-one gate proves
  patch 0017 is load-bearing: without its zero-byte completion fix, request-token
  ordering fails before the guest can progress.
- [x] **T-PLUG-13** Implement the 9p submit/poll/burst-done callbacks against the
  reserved 9p slots, holding the freeze for the whole burst. — satisfies
  [PLUG-29], [PLUG-30], [PLUG-31]; spec §12.6.
  Completed by `checks.crucible.phase2.qemuLive9pIo`, with
  `checks.crucible.phase2.qemu9pSyncKick` proving exact QEMU dispatch
  attribution. A real Linux guest forwards `Tversion` through `SLOT_9P_IO`,
  receives the modeled response at an 821-icount latency, releases the
  burst-wide device hold, and closes the scheduler ceiling either by retiring
  to it or by publishing an idle wake strictly beyond it. The scheduler-preemption leg
  delays response publication by 100 ms while preserving the modeled latency.
- [x] **T-PLUG-14** Implement the optional white-box doorbell trap: trap the
  reserved instruction/port, read guest memory via the plugin API, stamp the
  marker with the exact icount; ensure off-mode installs nothing and black-box is
  fully functional; route white-box inputs through the injection contract. —
  satisfies [PLUG-32], [PLUG-33], [PLUG-34]; spec §12.7.
  The x86_64 guest-to-host live slice is exercised by
  `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`: the packaged production
  Rust plugin preflights the stock QEMU translation, instruction-execution,
  register-read, and virtual-memory-read APIs; recognizes only the frozen
  `out 0xe7,al` encoding and reserved `0x00e7` port; reads `rax`/`rcx` at the
  callback's exact raw icount; and decodes the guest's golden coverage marker
  through the bounded callback core. The loaded-QEMU run records the live marker
  before reaching its exact scheduler ceiling and exits through the normal
  plugin lifecycle. The same real-backend gate now runs the production plugin
  with white-box mode both off and on: off mode emits no white-box callback
  record, and production fingerprint sampling produces the same execution
  fingerprint in both modes. The enabled run also validates the exact stopped,
  plugin-free machine's I/O map before registration and rejects a real
  `isa-debugcon` collision at port `0x00e7`. The gate also routes observations
  into the host event log and proves the live host-to-guest app-random reply
  path. The same gate now builds and boots the AOS `qemu-system-aarch64`
  target with a raw `virt` guest, recognizes only the frozen
  `hint #0x4c` encoding, reads `x0`/`x1`, decodes the same golden marker,
  enforces the exact scheduler ceiling, and tears down normally. Both
  architecture adapters therefore exercise the production callback path. The
  adapter observes QEMU's non-mutating icount from the translation block's
  entry callback, caches it per vCPU with the translated block length, and has
  the later instruction callback validate that metadata before adding the
  instruction index. It never invokes either the TB-entry helper outside its
  documented callback context or the committing raw-icount reader while the
  translation block is executing.
- [x] **T-PLUG-15** Implement the optional coverage hook: a registration-time
  opt-in TCG-exec basic-block map with zero cost when off and no effect on `S`/`T`
  or fingerprints; emit coverage as observational output. — satisfies [PLUG-35],
  [PLUG-36], [PLUG-37]; spec §12.8.
  Completed by `checks.crucible.phase6.basicBlockCoverage`. The production
  plugin registers QEMU's stock TB translation, execution, and
  flush callbacks only when coverage is enabled. It derives guest PC and block
  length at translation, observes exact TB-entry icount without committing timer
  state, bounds pending observations, and reclaims callback userdata after QEMU
  destroys generated callbacks during an exclusive TB flush. Rust callback-model
  tests, an executable C ABI/arithmetic model, and QEMU-10 source-order checks
  cover those contracts. ABI v2 now release-publishes each novel map entry into
  a dedicated per-VM SPSC ring whose capacity equals the fixed coverage-map
  cardinality. The host acquire-drains that ring only at completed quantum
  boundaries, validates sequence, icount, map index, and novelty, and admits the
  resulting observations through the generic backend boundary into the
  scheduler's unified event log before session publication, including a final
  drain returned through shutdown before the actor publishes its stopped state.
  No QEMU-local coverage vector is retained as a second record. The loaded-QEMU
  gate runs the production hook off and on against an uninstrumented standalone
  multiboot guest at the same exact icount. Coverage-on publishes live guest
  blocks, while the execution fingerprint, canonical causal log, and an
  independent instruction/register/RR-cursor/writable-RAM/device-I/O trajectory
  are identical. Coverage-off installs no TB callback. Both the busy-boundary
  shared-shutdown path and control-channel `Quit` path drain admitted callbacks
  and exit cleanly.
- [x] **T-PLUG-16** Implement the handshake and slot cross-check
  (`Hello`/`HelloAck`, exact ABI match, `slot_index < node_count`, launch-arg
  agreement). — satisfies [PLUG-38], [PLUG-39]; spec §12.9.1.
  Completed by `checks.crucible.phase2.qemuLivePluginInstall`, which boots real
  qemu-crucible with only the Rust control plugin loaded and observes the plugin
  negotiate `Hello`/`HelloAck` at the exact control-protocol and ABI versions,
  accept VM slot 0 bounded by the launch node count, and become schedulable.
- [x] **T-PLUG-17** Implement setup completion: receive the two `SCM_RIGHTS` fds,
  `mmap` and validate the region header/ABI, arm the wake fd, and reply
  `SetupAck`; refuse to participate on non-zero status. — satisfies [PLUG-40],
  [PLUG-41]; spec §12.9.2.
  Completed by `checks.crucible.phase2.qemuLivePluginInstall`, which observes the
  plugin receive the two `SCM_RIGHTS` descriptors, map and validate the shared-
  memory region header, arm the wake fd, and reply `SetupAck` with the ready
  status so the host can schedule the node.
- [x] **T-PLUG-18** Implement the boot barrier: block on the initial-ceiling
  publish before the first instruction using the shared `wake_signal` futex
  (never the eventfd or a wall-clock sleep as the barrier wait); the eventfd is
  registered before readiness for QEMU main-loop integration. — satisfies
  [PLUG-42]; spec §12.9.3.
  Completed by `checks.crucible.phase2.qemuLivePluginInstall`, which loads no
  observation plugin, so the Rust plugin is the sole `sim_shmem` dispatch time
  authority: the guest advances from cold boot to exactly the first host-
  published scheduler ceiling, which is only possible if the plugin blocked on
  the boot barrier's shared `wake_signal` futex before the first instruction;
  the separately registered eventfd remains the required main-loop nudge.
- [x] **T-PLUG-19** Implement teardown on `shutdown_requested` / `Quit`: wake,
  mark done, stop touching shmem, initiate orderly QEMU shutdown so no child
  leaks. — satisfies [PLUG-43]; spec §12.9.4.
  Completed by `checks.crucible.phase2.qemuLivePluginInstall`, which sends control
  `Quit` after the run, observes the plugin publish teardown `Done` and stop
  touching shared memory, and reaps the QEMU child with a natural zero exit and no
  leaked process.
- [x] **T-PLUG-20** Enforce the cross-process atomic-ordering rules on every shmem
  access (acquire loads / release stores matching the ABI) despite the
  single-threaded plugin side, and document that relaxed is only used for
  self-owned counters outside shmem. — satisfies [PLUG-45]; spec §12.10.1.
- [x] **T-PLUG-21** Audit and minimize every `unsafe` block with a `// SAFETY:`
  comment (single-vCPU serialization, mmap lifetime, descriptor validity,
  vCPU-thread callback contract); read guest memory only via the plugin API; bounds-
  check all payload copies. — satisfies [PLUG-46], [PLUG-47]; spec §12.10.2.
  Completed by `checks.crucible.phase2.qemuPluginUnsafeBoundary`, which confines
  production unsafe operations to the audited QEMU ABI, setup/mapping,
  coverage, fingerprint, runtime, and device callback adapters; requires a
  nearby `SAFETY:` justification for every unsafe block and a `# Safety`
  contract for every unsafe function; and rejects raw guest-address pointer
  access. Focused tests prove descriptor and mapping lifetimes, callback
  serialization, QEMU-API-only guest memory access, and bounds checks before
  network, block, 9p, and white-box payload copies.
- [x] **T-PLUG-22** Implement fail-loud handling for every determinism-critical
  failure (broken IPC, missing capability, ABI mismatch, full ring, passed
  delivery icount) with a distinct diagnosable error that the divergence bisector
  can localize; never a wall-clock-dependent fallback. — satisfies [PLUG-48];
  spec §12.10.3.
  Completed by `checks.crucible.phase2.qemuPluginFailLoud`. Its exhaustive
  negative-control matrix covers broken IPC, missing capabilities, ABI/model
  mismatch, full rings, and passed delivery icounts with distinct diagnostics
  and no wall-clock fallback. The gate also consumes the production-plugin
  network, block, and 9p live-I/O runs, proving the same guarded callback paths
  are installed and exercised in QEMU rather than existing only as unit models.
- [x] **T-PLUG-23** Add the plugin half of `gate:qemu-inert`: prove that with sim
  mode off the plugin is not loaded and has zero effect on QEMU behavior. This
  contributes plugin-half evidence for [PLUG-49]; the full real-QEMU corpus is
  completed by T-HARN-21/T-PATCH-3. — satisfies [PLUG-49]; spec §12.10.4.
- [x] **T-PLUG-24** Implement the deterministic round-robin sub-division within a
  RUN (fixed `rr_switch_quantum`, fixed ascending vCPU rotation), per-vCPU halt
  tracking, and the all-vCPUs-halted node-idle predicate with
  `idle_wake_icount = min` over vCPUs of the next armed deadline. — satisfies
  [PLUG-3], [PLUG-10], [PLUG-50], [PLUG-52]; spec §12.1.2, §12.3.2,
  §12.3.6.
  Completed by `checks.crucible.phase2.qemuLivePluginQuantumSmp`, together with
  `checks.crucible.phase2.qemuLivePluginFingerprintSmp`,
  `checks.crucible.phase3.schedulerRrSubdivision`, and
  `checks.crucible.phase3.schedulerAllVcpusIdle`. The
  deterministic RR sub-division (fixed `rr_switch_quantum`, fixed ascending
  rotation) and the all-vCPUs-halted predicate are *executed by QEMU*: patch 0002
  pins the node-icount `rr_switch_quantum`, while patch 0025 synchronizes every
  QEMU vCPU's halted state into the production plugin. The plugin uses
  `VcpuHaltTracker` to run the idle hot loop exactly once when the final vCPU
  halts and suppresses resume until a queued idle advance completes. The same
  mechanisms are also modeled in `round_robin.rs` (`RoundRobinRunState`
  fixed-quantum ascending rotation, `VcpuHaltTracker` per-vCPU halt tracking,
  `compute_all_halted_idle_wake_plan` with `idle_wake = min` via
  `aggregate_multi_vcpu_deadline`) — unit-proven and covered by
  `checks.crucible.phase3.schedulerRrSubdivision` /
  `schedulerAllVcpusIdle`. The RR sub-division behavior is live at `-smp N`:
  `checks.crucible.phase2.qemuLivePluginFingerprintSmp` samples the authoritative
  RR cursor deterministically over two runs at `-smp 4`. The dedicated SMP
  quantum gate boots a hermetic multiboot guest with the same production plugin
  at `-smp 4`. The guest starts APIC IDs 1-3 with directed INIT-SIPI-SIPI,
  then runs a lock-handoff AP/BSP rendezvous whose exact `AAABPPPR` console
  record requires a waiting AP to acquire the BSP-released lock between the
  BSP's `PAUSE` and its immediately following reacquire instruction. A failed
  early handoff emits `F` and parks forever, so eventual rotation at the
  ordinary RR quantum cannot false-green the proof. The remaining APs acquire
  in turn before the guest parks all four vCPUs in HLT and arms a periodic PIT
  deadline on the BSP.
  Patched QEMU reports each halted vCPU; the fourth transition fires the all-idle
  hot loop, whose minimum live timer deadline is the BSP's PIT deadline because
  the parked APs have none. The gate performs the authorized idle jump, observes
  the BSP wake and re-halt, then uses the production host-I/O runtime to request,
  wake, and await the exact all-halted fingerprint control boundary. Production
  `QemuNode::execution_fingerprint` owns the same bounded refresh whenever its
  first sample is absent or stale; it does not poll for a callback that an
  all-halted executor will never publish. Because fault-result polling uses the
  same control wake, the callback pumps every same-coordinate fault command
  before clearing and synchronously recapturing the requested fingerprint; the
  acknowledgement therefore orders a post-mutation hash, never a stale
  pre-mutation sample with the same icount. The live hardware gate proves this
  with a one-byte conventional-RAM mutation whose writable-RAM component makes
  the pre/post hashes differ without guest progress; its separate clock fault
  remains authenticated by the typed clock evidence.
  The scenario repeats under bounded scheduler preemption with an identical
  idle observation, execution fingerprint, and host-observable schedule.
- [x] **T-PLUG-25** Implement application of `Decision::Preemption`: force the
  vCPU switch / deliver the interrupt at the commanded node-icount via the
  preemption-injection capability (11/[PATCH-47]), failing loud and localizing an
  out-of-`[deadline, ceiling]` command rather than clamping or deferring. —
  satisfies [PLUG-50]; spec §12.3.6.
  Completed by `checks.crucible.phase2.qemuLivePluginPreemption`, with the
  callback-core contract retained in
  `checks.crucible.phase2.qemuPluginPreemption`. The ABI-v5 shared-memory
  scheduler mailbox carries vCPU-switch and interrupt commands into the loaded
  production Rust plugin. The plugin applies each command through
  `qemu_plugin_inject_preemption` at its exact commanded node-icount and
  acknowledges the mailbox sequence only after patched QEMU accepts it. The
  live `-smp 2` gate reaches exact ceilings after both a forced vCPU switch and
  a commanded interrupt, repeats byte-identically under bounded scheduler preemption, and
  cross-checks the host-observable schedule against `SimDouble`. Patch and
  plugin negative controls reject commands outside the authorized window
  `[deadline, ceiling]` rather than clamp, defer, or apply it at a different
  node-icount.
- [x] **T-PLUG-26** Implement per-vCPU register-file + round-robin cursor reads
  (via 11/[PATCH-46]) feeding the N-vCPU fingerprint (10/[QEMU-34]),
  side-effect-free wrt `S`/`T`. — satisfies [PLUG-52]; spec §12.3.2.
  Completed live by `checks.crucible.phase2.qemuLivePluginFingerprintSmp` at the
  frozen `-smp 4` pin (corroborated at `-smp 2`). The plugin's
  `PluginVcpuIntrospector::read_nvcpu_fingerprint_inputs` reads exactly the `0..N`
  vCPU register files and the round-robin cursor (`current_vcpu` + position within
  the pinned `rr_switch_quantum`) via the patched-QEMU `qemu_plugin_read_vcpu_regs`
  and `qemu_plugin_read_rr_cursor` exports (11/[PATCH-46]), and
  `PluginFingerprintSampling::sample` feeds them into the N-vCPU fingerprint
  sample. The reads are side-effect-free with respect to `S`/`T`: the whole
  fingerprint stream (per-vCPU register digests + RR cursor + guest-RAM +
  device-state) is byte-identical across two runs (the second under bounded scheduler preemption) and
  under a restart probe, so sampling perturbs neither guest state nor the
  execution trace. The N-vCPU fingerprint mints under the new
  `crucible.qemu.rust-plugin-fingerprint.v2` domain.
- [x] **T-PLUG-27** Implement the optional app-controlled randomness doorbell:
  serve a `random_request` by drawing from the seeded decision source and
  replying at the trap icount under the injection contract, record a
  `Decision::AppRandom`, keep it side-effect-free except the requested value, and
  ensure the engine functions with zero requests. — satisfies [PLUG-51]; spec
  §12.7.
  Completed by `checks.crucible.phase2.qemuLiveWhiteboxDoorbell`. The
  production plugin accepts the seeded app-random launch tuple only with
  white-box enabled, bounds the scenario draw count, traps the kind-5 request,
  derives the requested per-node/tag stream value synchronously, and writes the
  little-endian reply through
  `qemu_plugin_crucible_write_memory_vaddr`. It then emits a typed causal shmem
  record that the host scheduler independently reconstructs with
  `DecisionRecorder`; any value drift fails the run before schedule admission.
  The real guest validates the reply and emits `random-reply`, while the
  zero-request off/on runs preserve the same execution fingerprint.
