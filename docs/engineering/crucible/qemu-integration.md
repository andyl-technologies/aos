# QEMU integration (host side)

This page documents the host half of Crucible's QEMU layer: the
`crates/crucible/crucible-qemu-host` crate that builds a deterministic QEMU
command line, spawns and supervises the child process, completes the plugin
setup handoff, speaks QMP, and exposes the child to the scheduler as one
synchronous node. The in-QEMU half is described in
[qemu-plugin.md](qemu-plugin.md), and the source changes carried by the
patched QEMU are described in [qemu-patch.md](qemu-patch.md).

`crucible-qemu-host` is Apache-licensed host code. It launches QEMU as a
separate process and never links QEMU, includes its headers, or exposes QEMU
callback entry points. Every Crucible-specific exchange with the child crosses
one of the public process protocols: the control socket
([control-protocol.md](control-protocol.md)) and the shared-memory ABI
([shmem-abi.md](shmem-abi.md)). The license policy behind that split is in
[../../legal/licensing.md](../../legal/licensing.md).

## Why QEMU TCG and not KVM

Crucible's contract is that a guest's instruction stream and architectural
trajectory are a pure function of its inputs. Under hardware virtualization the
guest runs natively on the host core: timestamp counters, `RDRAND`, the CPU
feature set, and interrupt arrival relative to retired instructions all depend
on the host. There is no host-side seam that makes that interior
bit-identical.

QEMU's Tiny Code Generator (TCG) interprets the guest in software. In the
patched `sim` accelerator it counts exact retirements and advances a
picosecond logical clock by a fixed 50 ticks per retired instruction
(`SIM_TICKS_PER_INSTRUCTION` in `crucible-engine`, `TICKS_PER_INSTRUCTION` in
`crucible-qemu-shmem`). TSC reads derive from that clock, interrupts are taken
at translation-block boundaries, floating point is soft-float, and the CPU
model is whatever `-cpu` names. "Advance the guest to virtual time T" therefore
has a precise, host-independent meaning. See
[virtual-time.md](virtual-time.md) for the tick model and
[determinism.md](determinism.md) for the entropy sources the launch profile
eliminates.

## Module map

| Module | Owns |
| --- | --- |
| `launch` | `LaunchProfileCandidate`, `DeterministicLaunchProfile`, `QemuLaunchCommandBuilder`, `QemuVmLaunchConfig`, plugin argument construction, and the pre-spawn argv validator |
| `spawn` | Linux child creation with fixed inherited descriptors, the attempt process contract, and run-directory pinning |
| `host_setup` | Region initialization, the `Hello`/`Setup`/`SetupAck` handoff, and fault-capability manifest admission |
| `qmp` | `QmpClient`, the typed minimal QMP client |
| `node` | `QemuNode`, `QemuNodeChild`, and `QemuNodeChannels` |
| `quantum`, `mapped_quantum` | The per-quantum shared-memory hot path |
| `async_driver` | `run_bounded_qemu_node_step` and `QemuAsyncDriverPolicy` |
| `crash_detection` | `QemuNodeRunStatus` and `QemuCrashCause` |
| `shutdown` | The escalation ladder and `shutdown_qemu_child` |
| `inertness` | `assert_qemu_control_plane_inert` |
| `realization` | The `instantiate` branch coordinator (exact restore, replay, baked genesis) |

The realization branches, exact checkpoints, and hot fork are covered in
[execution-model.md](execution-model.md) and
[time-travel-debugging.md](time-travel-debugging.md). The GPL-side
`crucible-qemu-debug-gateway` binary that keeps GDB sessions stable across
QEMU replacement is also described there.

## The three channel planes

A `QemuNode` owns exactly one QEMU child and three logical channel roles,
returned by `QemuNodeChannels::roles`:

```text
                    host process (crucible-qemu-host)
  +------------------------------------------------------------+
  | QemuNode                                                   |
  |   QemuNodeChild (sole wait/reap authority)                 |
  |   PluginIpcControl --- AF_UNIX stream, fd 3 in the child   |
  |   ShmemHotPath ------- memfd mapping + futex word + eventfd|
  |   QmpMachineControl -- QMP Unix socket                     |
  +----------|---------------------|-------------------|-------+
             | setup / Quit        | every quantum     | lifecycle only
  +----------v---------------------v-------------------v-------+
  | qemu-system-* (patched) + crucible-qemu-plugin.so          |
  +------------------------------------------------------------+
```

| Plane | Carries | Never carries |
| --- | --- | --- |
| Plugin IPC control | Version handshake, the one-time descriptor handover, `SetupAck`, `Quit` | Any per-quantum timing or frame payload |
| Shared memory | Current icount and status, the scheduler's `max_advance_icount` ceiling, `idle_wake_icount`, the `wake_signal` futex word, SPSC frame and device rings | Socket round trips |
| QMP | Capability negotiation, run-state queries, exact checkpoint capture and restore, hot-fork staging, `quit` | Per-quantum progress |

The shared-memory plane uses more than one kernel object: the mapped memfd,
the non-private futex on the slot's `wake_signal` word, and the plugin wake
eventfd. The host performs one unconditional futex wake on every ceiling
publication and writes the eventfd at least once per quantum so QEMU's main
loop re-reads shared state; retries and serviced device I/O may add further
writes. Neither wake object carries timing data. The control channel is silent
between `SetupAck` and `Quit`.

## Launch profile

`LaunchProfileCandidate` holds the requested determinism knobs.
`LaunchProfileCandidate::try_into_deterministic` validates it into a
`DeterministicLaunchProfile`; `DeterministicLaunchProfile::conservative_default`
validates the checked-in defaults.

| Field | Default | Validation |
| --- | --- | --- |
| `cpu_model` | `qemu64,-rdrand,-rdseed` | `host` is rejected. An x86 model has `rdrand`/`rdseed` enabled rejected and is canonicalized with `-rdrand,-rdseed`. An AArch64 model (`cortex-*`, `neoverse-*`, `a64fx`) must carry exactly one `pmu=off`. |
| `accelerator` | `sim,thread=single` | Must equal `sim,thread=single`. |
| `machine_type` | `pc-q35-9.2` | Fixed text. |
| `memory_mib` | `512` | Nonzero. |
| `smp_vcpus` | `1` | `>= 1`. |
| `rr_switch_quantum` | `4096` | Nonzero and at most `i32::MAX`. |
| `rtc_clock` | `vm` | Must be `vm`. |
| `kernel_cmdline` | `console=ttyS0 reboot=k panic=1 quiet` | Fixed text. Crucible adds no `nokaslr`/`norandmaps` and requires none. |
| `scenario_seed`, `run_seed` | `0x0010_c001` | Must be equal; the setters keep them paired. |
| `machine_reset` | `Deterministic` | Required. |
| `disk_image_mode` / `guest_backing_state` | `CopyOnWriteOverlay` / `ByteIdenticalGenesis` | Either that pair or `NoBlockDevice` for both. A writable backing image or host-mutable genesis is rejected. |
| `guest_core_content` | `HostSideOnly` | Required: the guest carries nothing load-bearing for determinism. |
| `input_policy` | `NoInteractiveInput` | Required. |

The guest is never modified to obtain determinism. KASLR and ASLR stay
enabled: boot entropy is reproducible because every source is seeded
host-side. `GuestEntropySeed::from_scenario_seed` derives a 32-byte seed with
a SplitMix64 expansion, delivered through `fw_cfg` as `opt/crucible/seed`.

`DeterministicLaunchProfile::canonical_qemu_args` produces the pinned prefix
of every command line:

```text
-nodefaults -no-user-config -display none -monitor none -serial none
-parallel none
-machine <machine_type> -m <memory_mib>M
-accel sim,thread=single
-cpu <canonical cpu_model>
-smp <smp_vcpus>
-icount shift=0,sleep=off,align=off,rr_switch_quantum=<rr_switch_quantum>
-rtc base=2026-01-01T00:00:00,clock=vm
-seed <run_seed>
-fw_cfg name=opt/crucible/seed,file=crucible-guest-entropy-seed.bin
-object rng-builtin,id=crucible-rng0
-device virtio-rng-pci,rng=crucible-rng0,bus=<pci bus>,addr=<rng addr>
-append <kernel_cmdline>
```

`-seed` drives QEMU's deterministic guest-random path, its GLib global PRNG,
and `rng-builtin`; the patched QEMU refuses `-accel sim` guest random without
`-seed` (see [qemu-patch.md](qemu-patch.md)).

`DeterministicLaunchProfile::scenario_hash_material` emits a versioned
`crucible.launch.v3` block that enters the scenario content hash. Besides the
field values it records the fixed contract the profile depends on, for
example `accelerator_family=tcg-derived-sim`,
`stock_tcg_crucible_runtime=forbidden`, `sim_ticks_per_instruction=50`,
`rr_switch_quantum_units=retired-instructions`,
`rr_vcpu_rotation=ascending-vcpu-id`,
`time_control_owner=crucible-qemu-plugin`,
`idle_warp_under_time_control=suppressed`, and
`icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL`. A flag that can affect the
guest trajectory but is absent from that material is a defect.

## Building a launch command

`QemuLaunchCommandBuilder::new(profile, vm, executable, plugin, requirement)`
assembles one node's command; `DeterministicLaunchProfile::qemu_launch_command`
is the convenience wrapper. `QemuLaunchCommandBuilder::build` performs these
steps, failing with `QemuLaunchCommandError` at the first violation:

1. Require the QEMU executable, plugin, kernel or firmware, root image, and
   optional initrd to be AOS store paths (`QemuLaunchArtifact` pairs each path
   with its content hash).
2. Validate the VM and plugin configuration, including that white-box
   options, app-random, and campaign marker parking are only present with
   `whitebox=on`.
3. Bind the fault-capability requirement: the target's node hash must equal
   `qemu_fault_target_hash(node_id)` and the plugin's `fault_node_hash`
   (`FaultCapabilityNodeMismatch`), the executable suffix
   (`qemu-system-x86_64` or `qemu-system-aarch64`) must match the target
   architecture (`FaultCapabilityArchitectureMismatch`), and the realized CPU
   type must match (`FaultCapabilityCpuModelMismatch`). Production launches
   also require a world-bound requirement with an exact register manifest.
4. Compute static resource requirements (`QemuLaunchResourceRequirements`)
   from memory, vCPU count, and disk shape.
5. Emit the canonical profile arguments, then the VM arguments, optional
   console and debugger endpoints, `-plugin`, optional `-S -qmp <endpoint>`,
   optional `-gdb`, and optional diagnostic traces.
6. Re-run `validate_pre_spawn_qemu_launch_args` over the final argv.
7. Encode the plugin setup plan and record its BLAKE3 digest.

`QemuVmLaunchConfig::qemu_args` contributes the VM-specific devices: a
`vmstate` qcow2 blockdev used by exact checkpoints, `-kernel`/`-initrd` or
`-bios`, and the copy-on-write root disk:

```text
-drive id=crucible-root0,node-name=crucible-root-overlay,file=<overlay>,
       backing.driver=<raw|qcow2>,backing.file.driver=file,
       backing.file.filename=<store path>,if=none,format=qcow2,
       cache=none,aio=threads,discard=unmap
-device virtio-blk-pci,drive=crucible-root0,id=crucible-root-device0,...
```

The read-only backing image is never mutated, so two runs from the same
genesis start from byte-identical backing state. Optional
`CrucibleShmemBlockDevice` (`driver=crucible-shmem`),
`CrucibleShmem9pDevice` (`virtio-9p-pci` over a `synth` fsdev),
`CrucibleShmemNetworkDevice` (`virtio-net-pci` on a hub port), and
`CrucibleAcceleratorDevice` route device I/O through the shared-memory
sub-nodes described in [io-subnodes.md](io-subnodes.md).
`QemuVmLaunchConfig::launch_hash_material` begins with
`crucible.qemu-vm-launch.v1` and records each artifact hash and device
identity.

`QemuLaunchCommand::command_line_hash_material` emits
`crucible.qemu-launch-command.v3`: the executable, the fault-capability and
ready-marker manifest digests, the plugin setup-plan digest, and every argv
element in order. `scenario_hash_material_for_launch_command` concatenates
the profile, VM, and command-line material, so two builds of the same
scenario launch byte-identical command lines.

### The plugin argument

`QemuLaunchPluginConfig` renders the `-plugin` value. The descriptor numbers
are fixed constants (`QEMU_PLUGIN_CONTROL_FD`, `QEMU_PLUGIN_SHMEM_FD`,
`QEMU_PLUGIN_WAKE_FD`), so the argument is `simfd=3`, `shmemfd=4`,
`wakefd=5` on every launch:

```text
-plugin <store>/lib/qemu/plugins/crucible-qemu-plugin.so,simfd=3,slot=<n>,
  fault_node_hash=<64 hex>,process_generation=<n>,network_tx_next_seq=<n>,
  storage_completed_history_epochs=<n>,storage_completed_history_gaps=<n>,
  shmemfd=4,wakefd=5,whitebox=<on|off>,coverage=<on|off>
  [,campaign_marker_parking=on][,whitebox_setup=<attestation>]
  [,app_random_seed=...,app_random_cap=...,app_random_node=...]
  [,fingerprint=on]
```

The plugin path may not contain a comma, `process_generation` must be
nonzero, and the storage history limits may not exceed the compiled
`FaultResourceLimits` maxima. The plugin's parser is described in
[qemu-plugin.md](qemu-plugin.md#arguments).

### Optional endpoints and diagnostics

- **Console capture** (`with_console_capture`) replaces `-serial none` with an
  output-only `crucible-console` chardev on `crucible-console.sock`.
- **Debugger activation endpoint** (`with_debug_guest_activation_endpoint`)
  adds a virtio-serial port named `org.aos.crucible.debug` on
  `crucible-debug-activation.sock`. No host writes the activation token until
  a non-canonical debugger fork commits, so canonical execution cannot
  activate the guest agent. The endpoint is recorded in VM hash material.
- **Diagnostic traces** (`with_rr_control_boundary_trace`,
  `with_runtime_determinism_trace`, `with_runtime_liveness_trace`) add a fixed
  `-D <file> -trace <selection>` block. Selections and file names are
  constants, so callers cannot inject trace patterns or host paths, and the
  argv hash records them. The pre-spawn validator accepts only these exact
  blocks and refuses the runtime-determinism trace above 64 vCPUs.

## Pre-spawn validation

`validate_pre_spawn_qemu_launch_args` checks the final argv before spawning
any child and returns a `QemuPreSpawnLaunchValidation` with the accelerator,
quantum, vCPU count, and CPU model. It is a loud, early error, never a silent
fall-through to a nondeterministic run. It rejects:

- `-enable-kvm`, or an accelerator of `kvm`, `hvf`, or `whpx`
  (`KvmOrHardwareAcceleration`);
- any accelerator other than `sim`, including stock `tcg`
  (`NonSimAccelerator`), and a `-machine accel=` other than `sim`;
- `thread=multi` (`MultiThreadTcg`) or a missing `thread=single`;
- a missing `-icount`, a missing, `auto`, or nonzero `shift`, and `sleep` or
  `align` not set to `off`;
- a missing, zero, unparsable, or oversized `rr_switch_quantum`
  (`RrSwitchQuantumUnpinned`, `RrSwitchQuantumZero`, and related variants);
- a zero or malformed `-smp`;
- `-cpu host` and enabled `rdrand`/`rdseed`;
- host entropy (`/dev/random`, `/dev/urandom`, `rng-random`, `rng-egd`),
  `-realtime`, and `-usbdevice`;
- any network backend other than `none` or a hostless `hubport` (a hub port
  with a `netdev=` bridge is rejected), and host character backends other
  than the internal output-only chardevs;
- an RTC that is not `clock=vm` with an explicit fixed `base` (`utc`,
  `localtime`, or an omitted base is host time).

Stock `-accel tcg` is not a Crucible runtime option because it leaves the
sim-gated round-robin, IPI, shared-memory dispatch, and preemption paths
inert.

### Multi-vCPU launch

A node may have `smp_vcpus >= 1`. All vCPUs run under the single-threaded,
TCG-derived `sim` accelerator (`-accel sim,thread=single`), so QEMU serializes
them on one host thread and the interleaving is a pure function of retired
instructions. Multi-threaded TCG is rejected because separate host threads
interleave guest memory operations with no deterministic ordering.

The round-robin switch boundary is the `rr_switch_quantum` value in
`-icount`, measured in retired instructions with an ascending vCPU rotation.
It never falls back to QEMU's adaptive real-time quantum; the pre-spawn
validator refuses an unpinned value. The shipped default of 4096 is the
smallest swept quantum that met the throughput floor while preserving race
discrimination; per-branch overrides remain content-addressed. Both
`smp_vcpus=N` and `rr_switch_quantum` enter the scenario material. The node
clock stays a single aggregate icount; per-vCPU state is plugin-internal and
enters the execution fingerprint, which reads all N vCPUs' register files
plus the round-robin cursor (see [qemu-plugin.md](qemu-plugin.md)). Reading
only QEMU's first CPU would leave the interleaving unchecked.

## Spawn and descriptor passing

The Linux-only spawn path
(`spawn_prepared_qemu_child_with_fds_in_directory_guarded` in
`crates/crucible/crucible-qemu-host/src/spawn.rs`) consumes a validated
`QemuLaunchCommand`, a prepared run directory, and a
`QemuChildProcessContract`. It first checks the command's resource baseline
against the contract's sealed vCPU, resident-memory, and writable-byte
ceilings, then creates the per-node descriptors before `exec`:

| Host copy | Child copy | Kind |
| --- | --- | --- |
| control socket end | fd 3 | `socketpair(AF_UNIX, SOCK_STREAM \| SOCK_CLOEXEC)` |
| shared-memory memfd | fd 4 | `memfd_create("crucible-qemu-shmem", MFD_CLOEXEC \| MFD_ALLOW_SEALING)`, sized with `ftruncate`, sealed with `F_SEAL_SHRINK` |
| wake eventfd | fd 5 | `eventfd(0, EFD_CLOEXEC)` |

The host keeps its own memfd and eventfd and passes duplicates to the child.
Child-side copies are first relocated with `F_DUPFD_CLOEXEC` above every fixed
target slot, so `dup2` never overwrites a source. The vmstate container and
root-overlay descriptors occupy the slots immediately after fd 5.

The command clears the inherited environment (`env_clear`), connects stdin
and stdout to `/dev/null`, and inherits stderr. Its `pre_exec` closure calls
only async-signal-safe syscalls, in this order:

1. Join the attempt cgroup through the pinned `cgroup.procs` descriptor and
   check the cancellation eventfd.
2. Enter the pinned run directory.
3. Drop to the contract's non-root credentials with `no_new_privs`.
4. Set `PR_SET_PDEATHSIG=SIGKILL`, then compare `getppid()` with the parent
   PID captured before `fork`; a mismatch aborts with `ECHILD` because the
   parent may already have exited.
5. `dup2` the control, shmem, and wake descriptors to fd 3/4/5 and close the
   relocated sources.
6. Install the pinned image descriptors.

The child is wrapped in `QemuNodeChild`, which holds a private
`std::process::Child` handle and is the only owner allowed to signal, wait
on, or reap it. Its `Drop` sends `SIGKILL` and polls for up to five
seconds (`DROP_REAP_DEADLINE`); it records `reaped` only when it observed the
exit. Together with the parent-death signal this covers clean drops, panics,
and a host killed with `SIGKILL`. A prior failure mode in which orphaned
emulators reparented to PID 1 and spun until they saturated the build host is
the reason both mechanisms exist. `quarantine_orphaned_qemu_process` kills a
surviving QEMU only when its complete `/proc` identity matches the recorded
generation, so a reused PID is never signaled.

## Setup handoff

`complete_qemu_host_plugin_setup` (and its `_with_plugin_setup_plan`
variant) consumes the spawn descriptors and:

1. Initializes the memfd with the typed region image for the configured
   `RegionConfig` and checks the memfd length against the computed layout.
2. Accepts the plugin's `Hello` for the node's slot and replies `HelloAck`
   with `CONTROL_PROTOCOL_VERSION` and the shared-memory `ABI_VERSION`.
3. Sends `Setup` with three `SCM_RIGHTS` descriptors in fixed order: the
   shared-memory memfd, the wake eventfd, and a sealed memfd holding the
   current-version plugin setup plan.
4. Accepts `SetupAck(0)` and moves the control lifecycle into the
   shared-memory run phase.
5. Queries and admits the fault-capability and target manifests through the
   shared-memory fault command ring.

No guest instruction executes during setup: the plugin's boot barrier holds
the guest until the scheduler publishes the first ceiling. Message layouts
and states are in [control-protocol.md](control-protocol.md).

## QMP client

`QmpClient<S>` is a typed client, not a general QMP binding. It requires a
timeout-capable stream: `S` must implement `QmpTimeoutStream`, which
installs per-operation read and write timeouts and, on Unix, can attach one
descriptor with `SCM_RIGHTS` for `getfd`. `QmpClient::connect` reads the
`{"QMP": ...}` greeting, then sends `qmp_capabilities` with the `oob`
capability enabled. While awaiting a
command's `return` or `error`, the client skips asynchronous `event` objects.

Bounds come from `QmpIoTimeoutPolicy`:

| Limit | Default |
| --- | --- |
| `QMP_GREETING_TIMEOUT` | 5 s |
| `QMP_COMMAND_TIMEOUT` | 5 s per command write and response read |
| `QMP_MAX_LINE_BYTES` | 1 MiB |
| `QMP_MAX_ASYNC_EVENTS_PER_COMMAND` | 1024 |

Zero timeouts are rejected. A command whose boundary becomes ambiguous (for
example a timeout after a partial write) poisons the stream: the client
shuts the socket down and every later call returns
`QmpError::ConnectionPoisoned`.

The command set is a closed internal `QmpCommand` enum. Public constants name
each command, for example `QMP_CAPABILITIES_COMMAND`,
`QMP_QUERY_STATUS_COMMAND`, `QMP_STOP_COMMAND`, `QMP_CONT_COMMAND`,
`QMP_GETFD_COMMAND`, `QMP_CLOSEFD_COMMAND`, `QMP_QUIT_COMMAND_NAME`, and the
`QMP_HOT_FORK_*` family. Exact checkpoints use the patched
`crucible-checkpoint-capture`, `crucible-checkpoint-commit`,
`crucible-checkpoint-abort`, `crucible-checkpoint-restore`, and
`query-crucible-checkpoint-epoch` commands, and guarded launches adopt their
pinned block roots with `x-crucible-adopt-launch-fdsets`. Responses parse
into typed results; an unexpected shape is a `QmpError`, never a silent
misparse. There is no public execute-arbitrary-JSON path.

When QMP is configured, the launch adds `-S`, so QEMU starts stopped and the
host decides when the machine runs. Debugger activation does not use QMP:
QEMU connects its activation-only chardev during launch and Crucible writes
the fixed `QMP_DEBUG_GUEST_ACTIVATION_TOKEN` only after an explicit
non-canonical fork.

## The node wrapper

`QemuNode` (`crates/crucible/crucible-qemu-host/src/node.rs`) implements the
engine's `Backend` and `SimulationBackend` traits. It holds the
`QemuNodeChild`, a `QemuNodeChannels` bundle, a `QemuShutdownPolicy`, a
`QemuAsyncDriverPolicy`, a `QemuCrashDetector`, and a boxed
`QemuHostIoRuntime`. Scheduler-facing operations (current icount, advance to
a ceiling, deliver and emit frames, idle state, fingerprint samples, shutdown)
route through the shared-memory plane; exact checkpoint capture and restore
route through QMP; shutdown runs the escalation ladder against the owned
child.

`QemuNode::advance_to_ceiling` always goes through
`run_bounded_qemu_node_step`, so the scheduler-facing path cannot bypass the
bounded wait. One quantum is a fixed sequence of `QemuQuantumOperation`s, all
on the shared-memory plane:

```text
ReadNodeReport            plugin-published icount/status/idle wake
ComputeSchedulerCeiling   horizon -> authorized ceiling
StoreSchedulerCeiling     release-store max_advance_icount
FutexWake                 bump wake_signal + non-private futex wake
                          (the eventfd is also written)
ObservePluginReport       plugin report at the authorized boundary
ReadCompletionReport      completion from the same slot
EnqueueInboundFrame / ObserveInboundConsumption / DequeueOutboundFrame
```

There is no per-quantum QMP or plugin-IPC traffic.
`PluginIpcControlFrame` and `QmpCommand` operations exist only so the checks
`assert_qemu_quantum_hot_path_is_shmem_only` and
`assert_async_driver_quantum_hot_path_is_shmem_only` can reject them.

`QemuQuantumShmemHotPath` enforces the injection contract at the QEMU level.
It authorizes a ceiling exactly at the next inbound `delivery_icount` and
never past it, previews inbound ring entries before committing them, rejects
a frame behind the passed-delivery floor without consuming the ring, and
reports due frames in `(delivery_icount, src_node, seq)` order.
`deliver_frame` assigns monotonic router-source sequence numbers and fails
loudly if that space is exhausted. Emitted frames keep the guest's
`emit_icount` stamp for the router. Each quantum report carries device-I/O
freeze observations from the slot's `device_io_active` flag, so freeze
transitions are part of the report and the fingerprint boundary. The slot
fields, ring layout, and ordering rules are in [shmem-abi.md](shmem-abi.md).

## The bounded async driver

The scheduler wants a synchronous step; QEMU lifecycle I/O (handshakes, QMP
commands, process events, waiting for the plugin to publish completion) runs
on host real time. `run_bounded_qemu_node_step` bridges the two:

1. Validate the policy.
2. Start exactly one shared-memory quantum.
3. Await the plugin's completion within the advance budget.
4. Finish the quantum from shared memory.
5. Yield to the control plane before returning.

`QemuAsyncDriverPolicy` holds four budgets, selected by `QemuAsyncWait`:

| Wait | Field |
| --- | --- |
| `Handshake` | `handshake_timeout` |
| `QmpCommand` | `qmp_command_timeout` |
| `ProcessEvent` | `process_event_timeout` |
| `AdvanceCompletion` | `advance_completion_timeout` |

`QemuAsyncDriverPolicy::validate` rejects any zero budget
(`QemuAsyncDriverError::UnboundedAwait`).
`with_unbounded_advance_completion` renews advance polling slices instead of
treating one slice as a deadline, for long runs that have no host watchdog.

On expiry, advance and lifecycle timeouts become a typed crashed-node status
(`QemuCrashCause::BoundedAwaitTimeout`) followed by shutdown escalation, never
a retry or a hang; QMP timeout errors observed through the node take the same
path. Host timing may decide only whether lifecycle I/O failed. It never
feeds an ordering-significant decision: per-quantum timing is decided in
shared memory by virtual time, and the driver path uses no wall-clock reads,
randomness, sleeps, or nondeterministic selection.

## Crash detection

`QemuNodeRunStatus` is `Running`, `Idle`, `Done`, `Crashed`, or
`IntendedCrashFault`. An intended crash is a scenario fault and is reported
separately from infrastructure failure. `QemuCrashDetector` classifies
infrastructure failures into `QemuCrashedNodeStatus` with one of these
causes:

| `QemuCrashCause` | Detail |
| --- | --- |
| `UnexpectedChildExit` | `QemuProcessExit` with exit code, signal, and display string |
| `PluginIpcClosed` | `QemuChannelFailure` naming the operation |
| `QmpDisconnected` | `QemuChannelFailure` naming the operation |
| `BoundedAwaitTimeout` | `QemuBoundedAwaitTimeout` with the operation and budget |

Every crashed status carries `QemuCrashHandling::ReportAndLocalize`, whose
`retry_on_determinism_gate` returns `false`. A crash on a determinism-gated
path is reported for localization, never retried until it passes.

## Shutdown escalation

`shutdown_qemu_child` walks `QEMU_SHUTDOWN_ESCALATION_ORDER`:

```text
ControlQuit -> QmpQuit -> Sigterm -> Sigkill -> Reap
```

Each rung has its own bounded wait in `QemuShutdownPolicy`
(`control_quit_wait`, `qmp_quit_wait`, `sigterm_wait`, `sigkill_wait`,
`reap_wait`). The runner stops at the first rung after which the child has
exited. A rung that fails, such as a broken control socket or a dead QMP
connection, is recorded in `QemuShutdownReport::failures` and escalation
continues; it does not abort the ladder. The final reap runs on every path.
If the child is still alive after `SIGKILL` and the reap deadline, the
runner returns `QemuShutdownError::LeakedChild` with the report.
`UnixQemuChildShutdownTarget` is the production adapter; tests implement
`QemuShutdownTarget` to model unresponsive guests without spawning QEMU.

## Control-plane inertness

`assert_qemu_control_plane_inert` checks a `QemuControlPlaneObservation`
against the simulation mode:

- **Sim off.** No argv element may contain a control-plane fragment (for
  example `-plugin` or `control-socket=`), no control socket may be created,
  and no control frame may be sent. `QemuControlPlaneObservation::sim_off`
  uses `canonical_sim_off_qemu_args`, which is the canonical profile with
  `tcg,thread=single`. That vector exists only for inertness comparison and
  is never a valid Crucible launch.
- **Sim on.** The runtime data plane must be shared memory, the control
  channel must carry no frame payloads or delivery icounts, it must be silent
  between `SetupAck` and `Quit`, and every frame in
  `SIM_ON_CONTROL_FRAME_CLASSES` (`Hello`, `HelloAck`, `Setup`, `SetupAck`,
  `Quit`) is timing-insignificant and disallowed during the run.

The plugin half of the inertness argument and the real-QEMU corpus are
described in [qemu-plugin.md](qemu-plugin.md#inertness) and
[qemu-patch.md](qemu-patch.md#inertness).

## Tests

The relevant checks are listed in
[testing-and-gates.md](testing-and-gates.md). The focused host checks include
`checks.crucible.phase2.qemuLaunchBuilder`,
`checks.crucible.phase2.qemuLaunchValidation`,
`checks.crucible.phase2.qemuSpawnFdPassing`,
`checks.crucible.phase2.qemuQmpClient`,
`checks.crucible.phase2.qemuNodeWrapper`,
`checks.crucible.phase2.qemuAsyncDriver`,
`checks.crucible.phase2.qemuCrashDetection`,
`checks.crucible.phase2.qemuShutdownEscalation`, and
`checks.crucible.phase2.qemuRrQuantumIcount`. Operator-facing setup is in
[../../users/crucible/running.md](../../users/crucible/running.md).
