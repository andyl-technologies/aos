# Determinism contract

Crucible guarantees hermetic instruction-level determinism: for a fixed
scenario, seed, and schedule, every VM retires the same instruction stream
and passes through the same architectural states, and the whole multi-node
run is reproducible to the instruction. This page states the contract the
implementation enforces, lists every entropy source and the mechanism that
eliminates it, and describes the fingerprints and checks that defend it.

Time is the backbone of the contract; its units and handoff protocol are in
[virtual-time.md](virtual-time.md). Operator workflows for reproducing and
verifying runs are in
[../../users/crucible/reproduction.md](../../users/crucible/reproduction.md).

## The contract

For one VM, fix:

- `image`: kernel, read-only root image, and firmware;
- `cmdline`: the kernel command line;
- `seed`: the root entropy for all intended randomness;
- `I`: an ordered list of injected inputs, each stamped with the exact
  logical tick at which it becomes architecturally visible.

The VM's execution is a function

```text
run(image, cmdline, seed, I) = (S, T)
```

where `S` is the instruction stream (retired guest instructions in order) and
`T` is the architectural-state trajectory (registers, guest physical memory,
and emulated device state as a function of instruction count). Crucible
requires `S` and `T` to be bit-identical across runs and conforming hosts,
regardless of host CPU model, load, scheduling, core count, or wall-clock
time.

Bit-identical `T` is the strong clause. Equal network outputs are not
enough; the same bytes must be in guest memory at the same instruction count.
That property is what makes the rest of the system simple:

- a fork agrees with its parent because both share a bit-identical prefix;
- a materialized snapshot can be checked against a replay from an ancestor
  (the replay oracle);
- a divergence localizes to a single instruction because `T` is a function of
  instruction count;
- a failure reproduces byte for byte under a debugger.

The pinning work needed for even message-sequence determinism (fixed CPU
model, no host `RDRAND`/`RDTSC`, seeded guest entropy, instruction-driven
time) already makes the interior deterministic, so the stronger contract
costs little extra.

### Source elimination, not record/replay

Every entropy source is removed, fixed, or routed through the seeded decision
source. No source is left live with a log compensating for it. A record/replay
log would itself be the output of a nondeterministic first run, valid only for
that build and host path; source elimination makes the first run already
deterministic, so any run reproduces any other and a divergence is a real
defect. QEMU's own record/replay is not part of the runtime. Crucible also
does not use KVM: only TCG emulation makes TSC, interrupt boundaries, entropy
instructions, and floating point pure functions of the inputs.

### Whole-system statement

Across nodes the contract is the purity of reduction:

```text
State(t) = reduce(ScenarioDef, Schedule[0..t])
```

`reduce` in `crates/crucible/crucible-engine/src/model/runtime.rs` maps a
`ScenarioDef` and a `Schedule` to a content-addressed `State`. A
`Configuration` is exactly `(def, schedule)`; `Configuration::genesis` starts
with an empty schedule, and `try_step` appends one `Decision`. No wall-clock
value, host scheduling order, host entropy, or uncontrolled external input is
a free variable of `reduce`. Start, resume, fork, replay, and search are all
evaluations of the same function; see
[execution-model.md](execution-model.md) and
[execution-graph.md](execution-graph.md).

## Contract A: intra-VM hermeticity

For one VM with `N >= 1` vCPUs, fixed `(image, cmdline, seed, N,
rr_switch_quantum)`, and a fixed recorded input list `I`, the VM produces a
bit-identical aggregate-icount stream and trajectory `T`. For `N > 1`, `T`
includes every vCPU's register file and the round-robin cursor, and the
interleaving (which vCPU retires each instruction and where each is
preempted) is a pure function of those inputs and of the schedule's
preemption decisions, never of host thread scheduling.

Contract A takes input arrival points as given. It is the union of every
elimination in the table below and is testable on a single VM with no
scheduler, transport, or peers.

`crates/crucible/crucible-determinism/src/contract_a.rs` owns the isolated
model of this contract:

- `ContractAConfig::new(image, cmdline, seed, vcpu_count, rr_switch_quantum)`
  rejects zero vCPUs and a zero quantum, and hashes all inputs together with
  `CONTRACT_A_TICKS_PER_NS = 1_000` and
  `CONTRACT_A_TICKS_PER_INSTRUCTION = 50`.
- `RecordedInput` carries a `delivery_icount` and payload. Inputs must be
  nondecreasing and inside the run.
- `ContractADriver::run` injects inputs stamped `k` before the instruction that
  advances the node from `k` to `k + 1`, in recorded-list order for equal
  stamps, and records the instruction stream, the state trajectory, the
  `(icount, ticks, ns)` time trajectory, and per-vCPU register and RR-cursor
  samples. It never observes host time, transport arrival, or a scheduler.
- `ContractARun` carries a `ContractATimeFingerprint` (fixed scale, final
  coordinates, and trajectory digests) and an overall `fingerprint`.

The real backend is held to the same shape by the single-VM fingerprint and
layer-0 checks below.

## Contract B: injection determinism

The tick at which an external input becomes visible to a VM is a pure
function of virtual time and the scheduler's total order, never of when a
producer computed it in host time. A frame produced early by a fast host peer
and the same frame produced late by a slow one become visible at the same
consumer tick.

Contract B rests on four mechanisms:

1. **Stamped delivery.** Every input carries an explicit delivery tick
   in-band. `FrameEntry::delivery_icount` in the shared-memory ring is that
   tick (the `_icount` name is historical; see
   [virtual-time.md](virtual-time.md#the-ceiling-handoff)). The plugin is
   time-driven: a frame's presence in the ring never determines when the guest
   sees it.
2. **Lookahead gating.** A node never runs to or past a tick at which an input
   could still arrive. `authorize_advance_ceiling`
   (`crates/crucible/crucible-qemu-shmem/src/shmem/delivery_errors/frame.rs`)
   fails with `LookaheadGateError::AdvanceReachesPossibleDelivery` when a
   ceiling would reach the earliest possible delivery, so a delivery tick is
   always in the consumer's future when it is computed. A consumer that has
   already passed a delivery tick is a contract violation that fails loudly;
   it is never papered over by late delivery.
3. **Deterministic tie-break.** Simultaneous inputs to one consumer are
   ordered by `(virtual_time, consumer node, producer node, sequence)`
   (`ScheduledEventKey` in the scheduler, `FrameDeliveryKey` in shared
   memory).
4. **One authoritative scheduler.** All virtual-time advancement and all
   cross-node ordering decisions flow through the single scheduler actor; see
   [scheduling.md](scheduling.md).

Delivery is to the node's aggregate timeline. Routing a delivered input to a
particular vCPU, and the RR boundary at which that vCPU observes it, belongs to
Contract A.

## Entropy sources and their elimination

Each row names a source, how it would leak into `S` or `T`, and where the
current code eliminates it. "Launch" means the validated QEMU command line,
"patch" the atomic QEMU patch in `pkgs/emulation/qemu-patches/`, and "plugin"
`crates/crucible/crucible-qemu-plugin`.

| Source | Leak | Elimination | Where |
| --- | --- | --- | --- |
| Hardware RNG (`RDRAND`, `RDSEED`) | Guest reads host entropy | CPU model must not enable them; `-rdrand,-rdseed` are appended when absent | Launch |
| CPU model variation | Host feature bits change semantics | Fixed `-cpu` (default `qemu64,-rdrand,-rdseed`), never `host`; AArch64 requires `pmu=off` | Launch |
| Floating point | Host FPU behavior | TCG soft-float under a fixed CPU model | Launch |
| Idle warp | QEMU advances virtual time by host time when idle | Warp disabled under `sim`; idle time moves only by authorized jumps | Patch, plugin |
| Realtime deadlines in the TB budget | Instructions per TB depend on host speed | `sim` budget uses `QEMU_CLOCK_VIRTUAL` deadlines only | Patch |
| TSC (`RDTSC`, `RDTSCP`) | Host-correlated cycle counter | TSC is `floor(logical_tick / 250)`, uniform per vCPU | Patch |
| RTC and wall-clock reads | Guest reads host time | `-rtc base=2026-01-01T00:00:00,clock=vm`; host `base`/`clock` rejected | Launch |
| Timer devices (LAPIC, PIT, HPET, RTC) | Fire timing relative to instructions | Driven by `QEMU_CLOCK_VIRTUAL` at picosecond resolution | Patch |
| Interrupt delivery timing | One instruction earlier or later forks the path | TCG delivers at deterministic TB boundaries under icount | Launch |
| Async virtio completions | Host main-loop bottom half picks the completion instruction | In `sim` mode, rng/block/net/console kicks dispatch on the requesting vCPU; `rng-builtin` completes synchronously at the request; shared-memory block devices launch with `ioeventfd=off` | Patch, launch |
| Guest entropy pool | Guest CSPRNG seeded from host entropy | 32-byte seed at `fw_cfg` name `opt/crucible/seed` derived from the scenario seed; `virtio-rng-pci` backed by `rng-builtin` | Launch |
| QEMU-internal RNG | Device IDs, MACs, UUIDs from host entropy | `-seed <run_seed>` seeds `qemu_guest_getrandom` and GLib's global PRNG; under `sim`, a guest-random request without `-seed` fails instead of using host crypto | Patch, launch |
| KASLR and userspace ASLR | Randomized layout changes `T` | Left enabled; randomization derives from the seeded boot entropy above | Launch |
| Multi-vCPU interleaving | MTTCG interleaves on host threads | `-accel sim,thread=single`; MTTCG and stock TCG rejected | Launch, patch |
| RR switch quantum | Switch granularity fixes the interleaving | Fixed `rr_switch_quantum` in retired instructions, ascending vCPU rotation | Launch, patch |
| Inter-vCPU IPI timing | IPI taken one instruction earlier or later on the target | All vCPUs share one RR thread, so IPIs land at deterministic boundaries; a commanded IPI is planned by `plan_deterministic_ipi_delivery` at sender icount plus a fixed modeled IPI latency, rounded up to the next RR boundary | Patch, plugin |
| vCPU bring-up and hotplug | SIPI timing or topology change | Fixed-at-genesis topology; runtime hotplug forbidden | Launch |
| Host thread scheduling | Order of QEMU threads | Single RR thread plus icount; synchronous time-control handshake at idle and advance | Patch, plugin |
| Uninitialized memory and reset values | Power-on state differs | Deterministic reset: zeroed fresh RAM, fixed device reset | Launch |
| Interactive input | Asynchronous host input | No keyboard, mouse, monitor, or serial input; all input is stamped | Launch |
| Network arrival timing | Producer/consumer race | Contract B | Plugin, scheduler |
| Block and 9p completion timing | Host I/O latency | I/O sub-nodes compute completion ticks; see [io-subnodes.md](io-subnodes.md) | Plugin, scheduler |
| Snapshot restore | Lost icount, bias, or device state | Exact checkpoints restore raw icount and logical tick together; replay oracle checks them | Patch, host |

### The validated launch profile

The host turns these eliminations into a validated profile in
`crates/crucible/crucible-qemu-host/src/launch.rs`.
`LaunchProfileCandidate::try_into_deterministic` rejects:

- a `host` CPU model or one enabling `rdrand`/`rdseed`;
- any accelerator other than `sim,thread=single`;
- zero vCPUs, a zero RR quantum, or a quantum above `i32::MAX`;
- an RTC clock other than `vm`;
- a run seed different from the scenario seed;
- a reset mode other than `MachineResetMode::Deterministic`;
- `DiskImageMode::WritableBacking` or a host-mutable genesis backing state;
- `GuestCoreContentMode::GuestInjectedContent`;
- `InputPolicy::HostInteractive`.

Independently, `validate_pre_spawn_qemu_launch_args` re-checks the final argv
before spawn. It rejects KVM, HVF, and WHPX; any non-`sim` accelerator;
`thread=multi`; an unpinned single-thread mode; a `-machine accel=` other than
`sim`; a missing or nonzero icount shift, `shift=auto`, or `sleep`/`align`
other than `off`; an unpinned RR quantum; `-cpu host`; enabled entropy
features; `/dev/random` and `/dev/urandom`; `rng-random` and `rng-egd`
objects; `-realtime`; host RTC bases; and host-facing network, character, and
USB input options. The validator rejects MTTCG rather than accepting it with a
warning.

`scenario_hash_material` renders the profile as `crucible.launch.v3`
canonical text that enters the scenario hash. Representative lines:

```text
crucible.launch.v3
cpu_model=qemu64,-rdrand,-rdseed
vcpu_topology=fixed-at-genesis
runtime_cpu_hotplug=forbidden
accelerator=sim,thread=single
stock_tcg_crucible_runtime=forbidden
qemu_icount_shift=0
sim_ticks_per_ns=1000
sim_ticks_per_instruction=50
rr_switch_quantum=4096
rr_vcpu_rotation=ascending-vcpu-id
per_vcpu_tsc_source=logical-picoseconds-div-250
rtc_epoch_utc=2026-01-01T00:00:00
idle_warp_under_time_control=suppressed
icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL
machine_reset=deterministic-zeroed-ram-fixed-devices
qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin
guest_entropy_fw_cfg_name=opt/crucible/seed
guest_entropy_host_sources=disabled
```

`scenario_hash_material_for_launch_command` appends the complete QEMU command
line, so any argument change changes scenario identity.

The default kernel command line is `console=ttyS0 reboot=k panic=1 quiet`.
Crucible neither adds nor requires `nokaslr`, `norandmaps`, or other guest
entropy-suppression flags; a guest may still set them itself. Determinism is
delivered entirely at the QEMU/host boundary, so no part of the guest's own
configuration is load-bearing.

## Intended randomness: the seeded decision source

Eliminating accidental nondeterminism is separate from making intended
randomness reproducible. Probabilistic faults, link loss and jitter draws,
and randomized workloads all draw from one seeded source rooted at the scenario
seed. There is no other randomness in the engine.

`crates/crucible/crucible-determinism/src/lib.rs` defines it:

| Item | Value or behavior |
| --- | --- |
| `DECISION_RNG_ALGORITHM` | `"splitmix64-v1"` |
| `DECISION_RNG_NAME_HASH_DOMAIN` | `"crucible.decision-rng.name-hash.v1"` |
| `DECISION_RNG_NODE_STREAM_DOMAIN` | `"crucible.decision-rng.node-stream.v1"` |
| `DECISION_RNG_LINK_STREAM_DOMAIN` | `"crucible.decision-rng.link-stream.v1"` |
| `DECISION_RNG_DEVICE_STREAM_DOMAIN` | `"crucible.decision-rng.device-stream.v1"` (`crucible-engine`) |
| `DecisionRng::stream_seed` | `self.seed ^ stable_name_hash(entity_name)` |
| `DecisionRng::stream_seed_in_domain` | `self.seed ^ stable_domain_name_hash(stream_domain, entity_name)` |
| `fork_for_node`, `fork_for_link` | `fork_in_domain` with the node or link domain |
| `DecisionStream::advance_by` | Constant-time skip, equal to `n` calls of `next_u64` |

Forking by name hash, rather than drawing sequentially from a root, means
adding, removing, or reordering an entity never perturbs another entity's
stream, and the same name yields the same stream regardless of construction
order. Domains keep a node and a link or device with the same name
independent. `stable_name_hash` uses `StableHasher`, a fixed, cross-platform
hasher, never the language's randomized default. A known vector pins the
algorithm: `DecisionRng::new(0).fork("known-vector")` yields
`0xfe32_417a_273f_d586` then `0x44bf_2b53_3f3e_07fd`.

The scenario `Seed` is 256 bits. `Seed::decision_rng_root_seed` derives the
64-bit root from a content hash in the
`crucible.model.seed-decision-rng-root.v1` domain, and `Seed::fork_stream`
forks a world-declared `RngStreamId` (domain plus name).

Every probabilistic choice is recorded as a `Decision` in the `Schedule`
(`Decision::RngDraw` carries the stream and drawn value). A recorded decision
is reproducible, because the same seed gives the same draw, and forkable,
because a different draw is a different branch.

### Ambient guest entropy versus app-requested randomness

Two things touch guest randomness and are deliberately separate:

- **Ambient guest entropy** is the seed the guest CSPRNG starts from: ambient
  `fw_cfg` entropy derived from the scenario seed plus the seeded
  `virtio-rng`. It needs no guest changes, is opaque to Crucible, and is an
  elimination mechanism, not an explorable choice.
- **App-requested randomness** is optional. A cooperating guest asks for named
  draws through the white-box doorbell
  ([guest-host-channel.md](guest-host-channel.md)). Each draw comes from the
  single seeded source through a per-node stream named
  `app-random/node:<len>:<node>/stream:<len>:<tag>`
  (`app_random_stream_name`), is recorded as a decision with backend RNG
  evidence, and is bounded by `ScenarioDef::app_random_draw_cap`; `reduce`
  fails with `EngineError::AppRandomDrawCapExceeded` past the cap. App-random
  requests introduce no new entropy source.

## Harness determinism

Crucible's own host code must also be deterministic.
`crates/clippy.toml` disallows on state paths:

```toml
disallowed-methods = [
  { path = "std::time::Instant::now", ... },
  { path = "std::time::SystemTime::now", ... },
  { path = "rand::thread_rng", ... },
  { path = "rand::random", ... },
  { path = "getrandom::getrandom", ... },
]
disallowed-types = [
  { path = "std::collections::HashMap", ... },
  { path = "std::collections::HashSet", ... },
  { path = "std::collections::hash_map::DefaultHasher", ... },
  { path = "std::collections::hash_map::RandomState", ... },
]
```

The harness lint (`crates/crucible/crucible-test-support/tests/harness_lint.rs`,
check `checks.crucible.phase0.gates.harnessLint`) scans reduction paths for
these and related hazards. Ordered collections (`BTreeMap`, `BTreeSet`) are
used wherever iteration order can reach state or output.

## Fingerprints

Full comparison of `T` at every instruction is too expensive, so the
execution fingerprint is the cheap witness that is compared on every check.

### Execution fingerprint sample

The plugin computes a sample on an authenticated on-demand request for an
exact aggregate icount and publishes it in a per-node slot under a generation
seqlock (`crates/crucible/crucible-qemu-shmem/src/shmem/fingerprint_sample.rs`).
The host requests a capture by setting an odd `capture_request`, and the
plugin acknowledges with the matching even value after publishing:

```text
offset  size  field
0       4     sample_gen (even = stable, odd = writing)
4       4     capture_request (even = acknowledged, odd = requested)
8       W*8   payload words (little-endian u64)
```

The payload holds `sample_icount`, `vcpu_count`, `rr_current_vcpu`,
`rr_position_in_quantum`, `rr_switch_quantum`, `component_failures`,
`ram_bytes`, `device_state_bytes`, `device_state_sections`, the 32-byte
`ram_digest`, `device_state_digest`, and `device_state_schema_digest`, then
one block per tracked vCPU with its register digest, register-file size, and
retired-instruction stamp (`FINGERPRINT_SAMPLE_MAX_VCPUS = 8`). Under aggregate
accounting the per-vCPU retired stamp is always zero, because single-threaded
RR keeps one global counter. Per-vCPU state crosses the boundary only here,
never through the node slot.

The fingerprint is computed black-box from the host side with no guest
cooperation. Device state is projected through a fixed manifest
(`crates/crucible/crucible-qemu-host/src/launch/fingerprint_projection.rs`)
whose rows tag each VMState section with a `VOLATILE`, `DEVICE`, or `CONTROL`
domain and a versioned projection schema. The request contract and projected
state are fixed and versioned, so two builds compare the same digest over the
same state at the same coordinate.

### Time fingerprint

`ContractATimeFingerprint` covers only time-derived fields: the fixed scale,
the final `(icount, ticks, ns)`, and digests of the full trajectory. It
detects a time-model change independently of payload bytes.

### Divergence localization

A fingerprint mismatch is always a defect, never an accepted tolerance. The
helpers in `crates/crucible/crucible-test-support/src/divergence.rs` localize
it: `locate_first_decision_mismatch` finds the first differing decision at the
schedule level, `locate_first_divergence` finds the first differing
fingerprint sample, and `bisect_first_different_icount` narrows that window to
the first differing instruction count. A divergence must never be smoothed
over, tolerated, or retried until it passes. See
[failure-triage.md](failure-triage.md) and
[time-travel-debugging.md](time-travel-debugging.md).

## Verification

Determinism that holds only on a quiet host is not determinism. Checks run the
same inputs repeatedly while deliberately perturbing the host and require
identical fingerprints. The shared fixture in
`crates/crucible/crucible-test-support/src/adversarial.rs` runs the
`quiet_single_core`, `loaded_single_core`, `reordered_two_core`, and
`loaded_many_core` profiles, covering seeded scheduling, logical affinity,
injected load, and producer/consumer skew. `crucible verify --adversarial`
additionally varies executor workers, cores, wall-clock skew and coarsening,
backsteps, and host I/O stalls.

| Check | Property |
| --- | --- |
| `checks.crucible.phase1.gates.layer0Determinism` | Single-VM determinism across the elimination set |
| `checks.crucible.phase1.singleVmFingerprint` | Run-twice fingerprint equality |
| `checks.crucible.phase1.timeContractADeterminism` | Contract A time trajectory under hostile host profiles |
| `checks.crucible.phase1.layer1Injection` | Contract B consumer ticks under skewed producer timing |
| `checks.crucible.phase1.decisionRng` | Decision RNG algorithm, domains, and vectors |
| `checks.crucible.phase1.adversarialHostFixture` | The hostile host fixture |
| `checks.crucible.phase1.gates.replayOracle` | Materialized state equals replay from an ancestor |
| `checks.crucible.phase1.gates.divergenceBisect` | First differing decision and instruction |
| `checks.crucible.phase2.gates.anyGuest` | Black-box determinism on an unmodified guest |
| `checks.crucible.phase2.gates.qemuInert` | Sim-off patched QEMU matches upstream |
| `checks.crucible.phase2.gates.patchMicrotests` | Per-capability patch effects |
| `checks.crucible.phase2.qemuMultiVcpuLaunch` | Multi-vCPU launch validation |
| `checks.crucible.phase2.qemuPluginPreemption` | Commanded preemption and IPI planning |
| `checks.crucible.phase2.qemuPluginAppRandomDoorbell` | App-requested randomness, distinct from ambient entropy |
| `checks.crucible.phase2.qemuPatchRegeneration` | QEMU build identity in reproduction material |
| `checks.crucible.phase4.gates.e2eDeterminism` | Multi-VM fault-injected run across hostile hosts, reproduced from its artifact |

[testing-and-gates.md](testing-and-gates.md) describes the gate structure.

The replay oracle is the structural form of the contract: if `reduce` is
pure, a fat checkpoint's materialized state hashes equal to its thin
derivation by construction, so an oracle failure is a determinism defect.
`instantiate` checks exact cached snapshots against the oracle before loading
them whenever a baked genesis root exists.

## Build identity

Determinism holds for a fixed QEMU build: TCG code generation, device models,
and the patch all affect `T`. `pkgs/emulation/qemu.nix` emits
`share/aos/crucible/qemu-build-identity.env` with a `qemu_build_id` that
hashes the QEMU version and source hash, the `qemu.nix` hash, configure flags
and targets, the atomic-patch and patch-branch hashes, plugin and patch
switches, `qemu_sim_capability`, and the shared-memory ABI version and header
hash. `QemuLaunchArtifactIdentity::authenticate`
(`crates/crucible/crucible-qemu-host/src/artifact_identity.rs`) requires the
QEMU and plugin markers to agree on that build and on the shared-memory ABI
before launch. A reproduction artifact replays only against the build that
produced it; see [packaging.md](packaging.md).

## Sim-off inertness

The same patched QEMU serves ordinary TCG. Simulation control is inert unless
sim mode is active (the `sim` accelerator, the Crucible plugin, and its
control descriptors):

- Simulation-control paths in the patch are gated on the `sim` accelerator
  (`current_accel_is_sim()`, `icount_crucible_sim_mode()`). Plain TCG keeps
  upstream idle warp, realtime budget deadlines, asynchronous virtio dispatch,
  and has no `rr_switch_quantum`.
- With simulation off, the host forbids `-plugin` and control arguments
  (`crates/crucible/crucible-qemu-host/src/inertness.rs`), and the plugin
  records that it performed no setup, registrations, or patched-capability
  calls (`crates/crucible/crucible-qemu-plugin/src/inertness.rs`).
- The patch does change ordinary TCG in one deliberate way: the internal
  virtual clock and timer deadlines use picoseconds, with nanosecond
  projections at public APIs. The sim-off migration comparison
  (`tests/crucible/qemu-inert-migration.py`) admits only the framed
  wide-timer VMState subsections (for `apic`, `mc146818rtc`, `ich9_pm`,
  `hpet`, `i8254`, `serial`, and `pckbd`), the section-ID shift they cause,
  and PIT's nanosecond shadows. Everything else is byte-identical to the
  reference QEMU.

The licensing boundary that keeps this code in a separate GPL process is in
[../../legal/licensing.md](../../legal/licensing.md); patch structure is in
[qemu-patch.md](qemu-patch.md).

## Guest non-modification

Booting and running a guest never mutates its on-disk image. The validated
profile requires `DiskImageMode::CopyOnWriteOverlay` with
`GuestBackingStateMode::ByteIdenticalGenesis` (or no block device at all), so
all guest writes land in copy-on-write overlays and every run starts from
byte-identical backing state. Core operation requires no content placed
inside the guest by Crucible (`GuestCoreContentMode::HostSideOnly`); launch
identity records
`guest_on_disk_mutation_policy=forbidden-by-launch-profile`. The optional
white-box channel may add markers and app-requested randomness, but it is
never required for the contract, and black-box operation must keep working
when the channel is enabled but unused.

## Scope

### Goals the implementation holds

- Hermetic instruction-level determinism for a fixed scenario, seed, and
  schedule, by source elimination.
- Any unmodified guest, with only launch-time configuration and seeded
  firmware entropy; black-box by default, white-box by opt-in.
- One execution model: start, resume, and fork are the same `instantiate`
  over one content-addressed graph.
- Deterministic multi-vCPU guests through single-threaded RR TCG and icount,
  with vCPU switch and interrupt timing as an explorable `Decision::Preemption`.
- Hermetic, from-source build of QEMU, plugin, and guests inside AOS.
- Versioned, conformance-tested boundaries: the shared-memory ABI, the
  guest-host channel, and the control protocol.

### Non-goals

- **MTTCG.** Multi-threaded TCG has no deterministic memory-ordering model;
  global-lock MTTCG would be single-threaded RR by another name, without the
  icount-commandable switch.
- **In-process testing of host Rust code.** A node is always a QEMU guest or
  an I/O sub-node.
- **A formal-methods engine.** Temporal properties are checked against the
  event log ([assertions.md](assertions.md)).
- **Real-time fidelity.** Timings are modeled virtual timings, not measured
  host performance. Crucible is not a benchmarking tool.
- **Record/replay as the mechanism.** Decision logs exist for forking and
  search, not to compensate for live entropy.

### Invariants

| Invariant | Statement |
| --- | --- |
| Purity of reduction | `State(t) = reduce(ScenarioDef, Schedule[0..t])` with no host inputs |
| Replay-oracle equality | Materialized and replayed checkpoints hash equal |
| Total order | Cross-node events order by `(virtual_time, consumer node, producer node, sequence)` |
| Instruction-derived time | Logical ticks come from retirement plus authorized idle jumps only |
| Instruction-derived interleaving | vCPU switches and interrupt points depend only on node icount, `rr_switch_quantum`, and preemption decisions |
| Guest non-modification | Copy-on-write overlays only; no required in-guest content |
| Content addressing | Immutable artifacts are identified by content hash |
| Patch inertness | Simulation control has no effect unless sim mode is active |
| Single scheduler | One scheduler owns all time advancement and ordering |
| Harness determinism | No host clocks, host RNG, or unordered iteration on state paths |
| No silent nondeterminism | Every leak is eliminated, seeded, or fails loudly; divergences localize |

### Not guaranteed

- Reproduction across QEMU builds, plugin builds, or shared-memory ABI
  versions. Replay against a different build or tick scale fails closed.
- Byte identity with upstream for ordinary-TCG timer behavior and migration
  layouts outside the pinned sim-off corpus.
- Determinism for launches that bypass the validated profile, such as stock
  `-accel tcg`, KVM, or host-backed devices.
- Determinism of observational event-log entries, which are excluded from
  determinism comparison by schema ([event-log.md](event-log.md)).
