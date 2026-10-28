# Performance

Performance is a real goal for Crucible, but it is secondary to correctness.
No optimization may change which guest instruction observes which input. This
page describes the cost model that explains where Crucible's wall-clock time
goes, the `gate:perf-bench` regression gate that encodes that model, the
register that admits host-parallel mechanisms, and the checks that measure
real QEMU-backed runs.

Two kinds of evidence are kept apart throughout:

- **Modeled evidence.** `crates/crucible/crucible-test-support/src/perf.rs`
  and its `perf/` submodules evaluate a closed-form cost model with no QEMU.
  They prove *relations* between the model's terms, such as idle time adding
  zero wall-clock or parallelism never falling as lookahead grows.
- **Measured evidence.** Separate checks run real QEMU/TCG processes and
  record timings, ratios, and identity witnesses. Only a few of them enforce
  thresholds; the rest retain timings without a portable pass/fail limit.

The perf gate result itself states the split:
`evidence_scope=deterministic-cost-model` and
`live_qemu_acceptance=not-established-by-this-check`.

## The cost model

Guests run under QEMU TCG with instruction-count virtual time (see
[virtual-time.md](virtual-time.md)). KVM is never used: hardware
virtualization puts the host CPU's TSC, `RDRAND`, feature set, and interrupt
timing inside the guest's view, and none of those can be made deterministic
from outside. Under TCG with icount, the TSC is derived from the instruction
counter, interrupts land at deterministic block boundaries, and soft-float
makes floating point a pure function of its inputs. That determinism has a
price: busy guest code runs well below native speed.

The model decomposes a run's wall-clock into four terms:

```text
  wall_clock  ~=  (sum over nodes of busy_i) / (tcg_ips * P)   busy term
               +  0                                           idle term
               +  boot_cost / scenarios_sharing_world         amortized boot
               +  sync_overhead                                synchronization
```

The perf gate records the same shape in its result as
`cost_model=wall_clock=busy/(tcg_ips*P)+amortized_boot+sync_overhead`.

| Term | Mechanism | Why it is small or bounded |
| --- | --- | --- |
| Busy | TCG retires guest instructions. | Charged at the TCG rate and divided by realized parallelism `P`. |
| Idle | A halted node jumps straight to its next exact wake coordinate. | A 60-second idle gap costs the same as a 60-millisecond one: one clock jump. No spinning, no host sleep. |
| Boot | Only `bake` cold-boots a guest; start, resume, and fork restore or replay from the content-addressed genesis checkpoint (see [execution-model.md](execution-model.md)). | Every scenario and fork sharing a `World` shares one boot. |
| Sync | Clock publication, ceiling stores, futex wakes, eventfd writes, and scheduler bookkeeping. | Carried by shared-memory atomics, never a socket or QMP round trip per quantum (see [shmem-abi.md](shmem-abi.md)). |

### Parallelism is the lookahead budget

The conservative scheduler lets a node advance up to its lookahead, the
minimum inbound link latency, without hearing from peers (see
[scheduling.md](scheduling.md)). The same number is both the determinism
bound ("no peer can affect me sooner") and the parallelism budget ("I may run
this far alone on my own core"). Widening one widens the other, so the design
never trades exactness for speed. Two consequences follow:

- Realized parallelism is bounded by the scenario's critical path. A single
  long causal chain realizes `P` near 1 regardless of core count; mostly
  independent nodes approach `min(nodes, cores)`.
- Lowering the minimum link latency shrinks every window, multiplies
  synchronization events, and drives `P` toward 1. This is the one real
  performance trade a scenario author controls. It never changes determinism,
  and the link-latency floor keeps it from collapsing to zero-width windows
  (see [scenario-model.md](scenario-model.md)).

Host worker count is a host resource, not scenario content. It must never
enter a content hash or change state, time, or the canonical log.

### The evaluator

`crates/crucible/crucible-test-support/src/perf/model.rs` implements the model
over abstract integer units:

- `BenchScenario` carries `BenchNode`s (`busy_instructions`, `idle_ticks`),
  directed `BenchLink`s (`latency_ticks`), `tcg_ips`, `cores`,
  `per_tb_atomics`, and a `CoverageMode` (`Off` or `On`).
- `RealizationConfig` carries `boot_cost`, `scenarios_sharing_world`, and
  `rendezvous_frequency`. `RealizationConfig::single_scenario` uses one
  scenario and rendezvous frequency 1.
- `evaluate_cost_model` returns a `CostModelBreakdown` with `busy_term`,
  `idle_term` (always 0), `amortized_boot_term`, `sync_overhead_term`, and
  `realized_parallelism`. `CostModelBreakdown::wall_clock` sums the terms with
  saturating arithmetic, and `sync_overhead_pct` divides the sync term by the
  busy term. The function panics if `tcg_ips` is zero.

`realized_parallelism` computes `P` as follows:

```text
  if nodes <= 1:            P = 1
  core_bound      = min(nodes, max(cores, 1))
  critical_bound  = clamp(total_busy / critical_path_busy, 1, core_bound)
  lookahead_bound = clamp(min_link_latency, 1, core_bound)   (core_bound if no links)
  P               = max(min(critical_bound, lookahead_bound), 1)
```

`BenchScenario::critical_path_busy` follows links upstream: a node's critical
cost is its own busy work plus the largest critical cost of any node feeding
it. A cycle counts the revisited node's own busy work only, so causal loops are
never double-counted. The sync term grows with node count and rendezvous
frequency and shrinks with link latency, and is capped at
`SYNC_OVERHEAD_FAIL_PCT` percent of the busy term.

Constants exported by the model:

| Constant | Value | Meaning |
| --- | --- | --- |
| `TCG_FLOOR_MIN` / `TCG_FLOOR_MAX` | 10 / 20 | Modeled TCG slowdown versus native. A planning figure, not a measured guarantee. |
| `SYNC_OVERHEAD_WARN_PCT` | 5 | Sync-overhead warning threshold, percent of busy wall-clock. |
| `SYNC_OVERHEAD_FAIL_PCT` | 10 | Sync-overhead hard-fail threshold. |
| `COVERAGE_ON_MIN_PCT` | 70 | Minimum coverage-on guest IPS as a percentage of coverage-off IPS. |
| `THROUGHPUT_REGRESSION_MAX_PCT` | 10 | Largest tolerated fuzz-throughput regression against the baseline. |

## The perf-bench gate

`gate:perf-bench` is a regression gate, unlike the determinism gates, which
check byte identity (see [testing-and-gates.md](testing-and-gates.md)). It
compares metrics against a stored baseline and fails on a regression past a
threshold. It runs on shared, noisy builders, so it asserts host-independent
properties: ratios, monotonicity, kernel-entry counts, and flatness. It
records wall-clock numbers but never hard-asserts an absolute wall-clock
threshold. A performance measurement never stands in for a determinism gate,
or the reverse.

### Corpus and baseline

`crates/crucible/crucible-test-support/src/perf/corpus.rs` owns the canonical
input:

- `canonical_bench_corpus` returns one scenario, `perf-reference-fanout`: a
  `coordinator` (2,000,000 busy instructions) feeding four independent
  `worker-N` nodes (4,000,000 each) over links of 8 latency units, with
  `tcg_ips = 200_000_000`, 4 cores, 3 atomics per translation block, and
  coverage on. The workers are independent, so the critical path is the
  coordinator plus one worker. That keeps the parallelism sweeps non-trivial.
- `canonical_perf_baseline` returns `PerfBaseline { fuzz_throughput: 50_000,
  coverage_on_off_pct: 82, cumulative_coverage: 12_800 }`.
- `canonical_perf_bench_input` pairs them with the canonical
  host-parallelism admission register in a `PerfBenchInput`.

`perf_corpus_digest` hashes the corpus fingerprints, TCG rates, per-TB costs,
and baseline values together, so a baseline cannot drift away from the
scenario it measures. `canonical_host_profile` pins the profile the numbers
belong to (4 cores, `crucible-reference-x86_64-tcg`). Changing the baseline
is an explicit, reviewed source change.

### Assertions

`run_perf_bench_gate` (in `perf/gate.rs`) validates the admission register
first, then runs the assertions below over the first corpus scenario. It
returns the first violated property as a `PerfBenchError`, or a
`PerfBenchReport` of recorded metrics. An empty corpus fails with
`EmptyCorpus`.

| Property | Assertion | Error |
| --- | --- | --- |
| Idle is free | Adding 0 to 86,400,000 idle ticks per node leaves wall-clock unchanged. | `IdleNotCompressed` |
| Latency is the budget | `latency_parallelism_sweep` over latencies 1 to 32: `P` never falls as latency rises. | `ParallelismNotLookaheadBounded` |
| Speedup | `core_count_speedup_sweep` over 1, 2, 4, 8 cores: wall-clock never rises. | `SpeedupNotMonotone` |
| Serial equals parallel | 1-core and 64-core variants share a `scenario_result_fingerprint`. | `SerialParallelDivergence` |
| Low-latency trade | At latency 1 the fingerprint is stable and `P` does not exceed the baseline's. | `LowLatencyDeterminismLoss` |
| Sync budget | Sync overhead is at most `SYNC_OVERHEAD_FAIL_PCT`. | `SyncOverheadExceeded` |
| No per-quantum IPC | Advance-path accounting (below) has zero socket/control round trips and the expected counts. | `PerQuantumIpcRoundTrip`, `AdvanceKernelEntryAccounting` |
| Per-TB cost | Adding nodes does not change per-TB atomics. | `PerTbScalesWithNodes` |
| Rendezvous neutrality | `rendezvous_frequency_sweep` over 1 to 16 keeps one result fingerprint. | `RendezvousChangedResult` |
| Boot amortization | Cold boots stay at one across campaign sizes 1 to 1,000,000. | `BootNotAmortized` |
| Coverage budget | The baseline coverage-on/off ratio is at least `COVERAGE_ON_MIN_PCT`. | `CoverageOnBelowBudget` |
| Coverage is observation-only | Coverage on and off share a result fingerprint. | `CoveragePerturbedResult` |
| Fork cost | `fork_cost_bytes` (256-byte header plus 4,096 bytes per delta page) grows with the delta and ignores absolute state size. | `ForkCostNotDeltaBounded` |
| Snapshot latency | `snapshot_latency_series`: capture cost never falls as changed pages grow. | `CaptureNotChangedStateBounded` |
| Replay cost | `replay_cost_units` never falls as the schedule suffix grows. | `ReplayCostNotSuffixBounded` |
| Throughput ratchet | Observed throughput is at least 90 percent of the baseline. | `ThroughputRegressed` |
| Fleet scaling | `fleet_host_sweep` aggregate throughput never falls from 1 to 32 hosts. | `FleetThroughputNotLinear` |
| Coverage ratchet | Cumulative coverage never decreases. | `CoverageRegressed` |
| Memory | `peak_rss_units` (guest RAM + active rings + summed deltas) stays below a full-copy-per-fork model. | `RssScalesWithForkCount` |

Several of these are structural over the model rather than measurements:
`scenario_result_fingerprint` is a pure function of the scenario's semantic
inputs, and boot amortization is asserted by construction. Live identity
evidence for the same properties comes from the dependency checks described in
[The Nix gate](#the-nix-gate) and from the determinism gates.

### Advance-path kernel entries

The hot advance path avoids request/response IPC, but it is not free of system
calls. `advance_syscall_count` keeps an explicit arithmetic account of the
current integration in an `AdvanceSyscallCount`:

| Field | Count |
| --- | --- |
| `futex_ceiling_wakes` | One unconditional non-private futex wake per quantum. |
| `futex_wait_calls` | Actual futex waits, including repeats after spurious or non-actionable returns. |
| `futex_service_release_wakes` | Extra wakes for service or ring-backpressure producer releases. |
| `futex_delivery_wakes` | Extra wakes for inbound or completed-frame delivery. |
| `futex_wake_wait` | Sum of the four futex categories. |
| `eventfd_quantum_wake_writes` | One plugin-eventfd write per quantum. |
| `eventfd_unchanged_icount_wake_writes` | Resignal writes for unchanged-icount polls. |
| `eventfd_service_wake_writes` | Writes after servicing host I/O. |
| `eventfd_wake_writes` | Sum of the eventfd categories. |
| `host_poll_sleep_calls` | Host poll sleeps between pending advance observations. |
| `per_quantum_socket_control_round_trips` | Always 0. |

This is bookkeeping, not observed syscalls, and it does not count QEMU-side
eventfd reads or event-loop polls. A future optimization may wake only armed
waiters without changing the shared-memory ABI.

Arithmetic cannot see source-level I/O, so the gate test target adds a source
scan. `crates/crucible/crucible-test-support/tests/gate_perf_bench/hot_path_io.rs`
holds an explicit inventory of hot-path owners, among them
`crucible-qemu-host/src/async_driver/driver.rs`,
`async_driver/hot_path.rs`, `supervision/host_io_runtime.rs`, and
`supervision/block_io_servicer.rs`, plus targeted QEMU patch sources. Each
owner carries identity markers, and the scan fails if socket, QMP, or
plugin-control APIs appear in that scope. Moving or replacing an owner
requires updating the inventory.

### Report

`PerfBenchReport` records `tcg_ips`, the `idle_compression` series,
`parallelism_p` (the largest `P` seen across the latency sweep),
`sync_overhead_pct`, `per_tb_atomics`, `cold_boots_per_campaign`,
`restore_latency_units`, `fuzz_throughput`, `coverage_on_off_pct`,
`fork_cost_bytes`, `replay_cost_by_suffix`, `peak_rss_units`,
`advance_syscalls`, `snapshot_latency`, `host_profile`, and `corpus_digest`.

## Host-parallelism admission

The most dangerous change to a deterministic system is "make it faster". Any
host-parallel mechanism must therefore fit one of exactly two classes, and the
class is an argument about the mechanism, not a measurement on one host:

- **Class A, outside the observable boundary**
  (`HostParallelismClass::OutsideObservableBoundary`). The work produces
  nothing the guest, the execution fingerprint, or the canonical log can
  observe, or it computes a pure function of input already fixed before the
  worker starts. A digest over captured bytes is Class A: the bytes cannot
  change while the worker runs.
- **Class B, commit pinned to virtual time**
  (`HostParallelismClass::CommitPinnedToVirtualTime`). The work is observable,
  but its commit coordinate is computed before dispatch, and the requester
  stalls at that coordinate if it arrives first. Host delay can change only how
  long the guest waits, never what it sees.

There is no third class. "It will probably come out the same", or one
bit-identical run, does not admit a mechanism. Multi-threaded TCG (MTTCG) is
the canonical rejection: guest memory ordering is observable, so it is not
Class A, and the interleaving *is* the output, so there is no precomputed
commit coordinate for Class B. The launch validator rejects `thread=multi`
outright (see [determinism.md](determinism.md)).

### The register

`crates/crucible/crucible-test-support/src/perf/admission.rs` defines the
canonical register, `canonical_host_parallelism_admissions`:

| Mechanism id | Class | Argument | Proving gates |
| --- | --- | --- | --- |
| `scheduler-host-worker-pool` (`HOST_WORKER_POOL`) | B | Each node ceiling and completion-order key are fixed before worker dispatch. | `gate:perf-bench`, `gate:adversarial-determinism` |
| `fingerprint-digest-offload` (`FINGERPRINT_DIGEST_OFFLOAD`) | A | Workers digest an immutable sample captured at the exact icount coordinate. | `gate:single-vm-fingerprint`, `gate:perf-bench` |
| `device-host-work-overlap` (`DEVICE_WORK_OVERLAP`) | B | Device completion icount is fixed before host work is dispatched. | `gate:e2e-determinism`, `gate:perf-bench` |
| `segment-parallel-replay` (`SEGMENT_PARALLEL_REPLAY`) | A | Checkpoint-bounded segment results are joined in canonical coordinate order. | `gate:replay-oracle`, `gate:divergence-bisect` |

`validate_host_parallelism_admissions` fails closed. It rejects an empty or
duplicate mechanism id, an empty argument, a record with no proving gate, a
repeated gate, or a gate outside `PROVING_GATES` (`const PROVING_GATES:
[&str; 6]`: `gate:adversarial-determinism`, `gate:divergence-bisect`,
`gate:e2e-determinism`, `gate:perf-bench`, `gate:replay-oracle`, and
`gate:single-vm-fingerprint`). Each of these yields
`InvalidHostParallelismAdmission`. A missing required mechanism yields
`MissingHostParallelismAdmission`. A mechanism whose class argument turns out
to be false must be disabled, not tolerance-banded.

### The admitted mechanisms

- **Cross-node host workers.** The scheduler selects a run set of nodes whose
  horizons do not constrain each other, orders it by a completion-order key
  computed from the plans, and commits outcomes in that order, never in worker
  completion order. Speculative preparation and the authoritative commit live
  in `crates/crucible/crucible-engine/src/scheduler/concurrent_prepare.rs`
  (`SchedulerConcurrentRunSet`), parameterized by `max_host_workers`; the QEMU
  node set dispatches in
  `crates/crucible/crucible-qemu-host/src/node_set/concurrent.rs`. Until this
  path runs, `P` is 1 regardless of cores or lookahead.
- **Fingerprint digest offload.** The plugin copies writable RAM and the
  admitted read-only projection into sealed descriptors while the exact
  boundary is held, then a bounded worker thread
  (`crucible-fingerprint-digest`, in
  `crates/crucible/crucible-qemu-plugin/src/runtime/live_callbacks/fingerprint_worker.rs`)
  hashes and publishes them after the guest resumes. The digest must equal
  hashing the bytes at the boundary, and every authenticated on-demand request
  still publishes at its exact coordinate. Dropping requests to save time is
  not admissible: each request is determinism evidence.
- **Device host-work overlap.** `QemuLiveBlockHostWorkPool` in
  `crates/crucible/crucible-qemu-host/src/supervision/device_host_work.rs`
  derives and publishes a block completion coordinate before handing the
  host-side work to a worker. Delivery waits until guest icount reaches the
  pinned coordinate, so whether the host or the guest wins the race is
  unobservable.
- **Segment-parallel replay.** `crates/crucible/crucible-test-support/src/segment_replay.rs`
  replays each checkpoint-to-checkpoint segment on its own scoped thread,
  validates state at every boundary, and joins canonical-log entries in segment
  order. Divergence bisection uses the same split, and the located divergence
  coordinate must not depend on the segment count. This speeds up debugging
  (`goto`, reverse step, bisect) rather than forward runs.

Two things are deliberately not admitted. Parallel vCPU execution inside one
node would need conflict detection on every guest memory access plus
per-quantum rollback, which usually costs more than it returns, and it would
hide the round-robin switch point that exploration treats as a first-class
decision. Widening lookahead past the modeled link latency is not a speedup at
all: it describes a different scenario.

## The Nix gate

`checks.crucible.phase7.gates.perfBench` (`tests/crucible/phase7-perf-bench.nix`)
runs `cargo test -p crucible-test-support --test gate_perf_bench` and then
requires `PASS` plus specific evidence lines from five live dependency checks:

| Dependency check | Evidence required |
| --- | --- |
| `checks.crucible.phase7.deviceHostWorkOverlap` | `gate=gate:device-host-work-overlap`; synchronous and asynchronous completion icounts and canonical logs identical; both race outcomes proven. |
| `checks.crucible.phase7.qemuHostParallel` | `gate=gate:qemu-host-parallel`; `scheduler_commit=after-all-fixed-runs-complete`; `realized_parallelism=2`; `state_identity=bit-identical`. |
| `checks.crucible.phase7.fingerprintDigestOffload` | `authenticated_on_demand_requests_acknowledged=14`; `on_demand_boundary_stream_bit_identical=true`. |
| `checks.crucible.phase2.qemuCheckpointDeltaFlight` | `restore_latency_measurement=descriptor-restore-through-cont-ack`; positive `direct_restore_to_runnable_us` and `delta_restore_to_runnable_us`. |
| `checks.crucible.phase7.segmentParallelReplay` | `gate=gate:segment-parallel-replay`. |

The result lists the metric classes (`metric_idle_compression=flat`,
`metric_sync_overhead_pct=warn-5-fail-10`,
`metric_parallelism_P=lookahead-bounded`, and so on), records
`host_parallelism_admission_register=fail-closed` and
`unclassified_host_parallelism_policy=reject`, and copies the live metrics
from the dependency results with `metric_` prefixes. It also names where real
measurements live, for example `real_coverage_ips=checks.crucible.phase0.coverageOverhead`
and `real_throughput_baseline=checks.fleet.crucible-perf`. The gate runs after
the determinism gates it depends on, so it never trades determinism for speed.

## Measured checks

| Check | What it measures | Enforced |
| --- | --- | --- |
| `checks.fleet.crucible-perf` (root `default.nix`) | Real `crucible --backend qemu verify happy-path.scn --runs 2` processes: an 8-run sequential batch, the same batch concurrently, and a logical fleet sweep over 1, 2, 4, and 8 hosts sharing one store. | Requires the perf gate and restore-latency results to pass; concurrent wall-clock at most 3x sequential; before core saturation, fleet throughput at least half of ideal linear scaling from the one-host run. Throughput, speedup, and per-host store growth are recorded. |
| `checks.crucible.phase0.coverageOverhead` (`tests/crucible/phase0-coverage.nix`) | Guest IPS with no plugin, hook disabled, hook counting, and coverage on, over three repetitions. | Coverage-on IPS at least 0.70 of both the no-plugin baseline and the hook-off run; retired-instruction and TB-execution deltas at most 0.001. The probe is a C-ABI plugin, not the production Rust plugin. |
| `checks.crucible.phase2.qemuCheckpointDeltaFlight` | Descriptor restore through `cont` acknowledgement, direct and delta. | Positive restore latencies; values recorded. |
| `checks.crucible.phase2.tcgPerformanceDeterminism` (`tests/crucible/tcg-performance.nix`) | Cold and VMState-restored continuation of a fixture BIOS to an exact stop icount. | Exact stop and logical tick, identical registers and RAM digest across repeats and restore. Timings retained without a portable threshold. |
| `checks.crucible.phase2.tcgLinuxBootPerformanceDeterminism` | Packaged QEMU and plugin booting the stock fixture kernel to an authenticated `flight.ready` stop. | Identical stopped registers, full physical memory, and marker coordinates. Launch and boot timings retained without a threshold. |

The `phase2` performance drivers `tcgProductionPerformanceDriver`,
`tcgLinuxSerialPerformanceDriver`, and `tcgFiniteRomPerformanceDriver`, with
`tcgPerformanceFixtures`, build host fixtures for manual comparisons of QEMU
and plugin variants. They use only the public socket and shared-memory
protocols and never link QEMU. The scripts beside them
(`tests/crucible/tcg-*-performance.py`) retain every attempt, timing sample,
and identity hash, stop on the first failed trial, and do not substitute
successful runs for failed ones. Their docstrings note that rows using
different clock contracts, such as ordinary TCG versus `sim` at 50 ticks per
instruction, do not measure equal-instruction overhead.

Campaign throughput has its own baseline procedure; see
[the campaign performance baseline guide](../../maintainers/crucible-campaign-performance-baseline.md).

## Limits of the evidence

- The 10x to 20x TCG slowdown is a planning figure in the model. No check
  enforces a native-to-TCG ratio.
- The modeled gate proves the model's relations; serial/parallel and
  coverage identity in the model are true by construction. Real identities
  come from `qemuHostParallel`, `fingerprintDigestOffload`,
  `deviceHostWorkOverlap`, `segmentParallelReplay`, and the determinism gates.
- No check enforces an absolute wall-clock target for boot, restore, or
  throughput. Those numbers are recorded for trend tracking.
