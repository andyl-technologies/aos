//! The SS25 parameter sweeps and the derived host-independent metrics.
//!
//! This module owns the sweep series the perf-bench gate uses to prove the
//! cost-model *relations*: the latency-vs-parallelism sweep ([PERF-4]), the
//! core-count speedup sweep ([PERF-3]), the rendezvous-frequency sweep
//! ([PERF-10]), and the fleet host sweep ([PERF-27]). It also owns the derived,
//! host-independent metric helpers the gate asserts and records: the advance-path
//! syscall accounting ([PERF-8]), the snapshot capture/restore latency series
//! ([PERF-12], [PERF-17]), the pinned host profile ([PERF-20]), the
//! content-addressed corpus digest ([PERF-21]), and the deterministic scenario
//! result fingerprint ([PERF-5], [PERF-10], [PERF-15]).

use super::model::{BenchLink, BenchNode, BenchScenario, RealizationConfig, evaluate_cost_model};
use super::report::PerfBaseline;

/// One point on the latency/parallelism sweep ([PERF-4]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatencyParallelismPoint {
    /// Minimum link latency used at this sweep point.
    pub min_link_latency: u64,
    /// Realized parallelism `P` at this latency.
    pub realized_parallelism: u64,
    /// Sync overhead percentage at this latency.
    pub sync_overhead_pct: u64,
}

/// Sweeps the minimum link latency of a scenario and reports how realized
/// parallelism scales with it ([PERF-4], the latency-is-the-budget identity).
///
/// Returns points in ascending latency order; realized parallelism is
/// non-decreasing across the sweep (larger latency permits proportionally larger
/// independent advances, down to the floor).
#[must_use]
pub fn latency_parallelism_sweep(
    scenario: &BenchScenario,
    latencies: &[u64],
) -> Vec<LatencyParallelismPoint> {
    let mut points = Vec::with_capacity(latencies.len());
    let mut sorted = latencies.to_vec();
    sorted.sort_unstable();
    for latency in sorted {
        let swept = with_min_latency(scenario, latency);
        let breakdown = evaluate_cost_model(&swept, &RealizationConfig::single_scenario(0));
        points.push(LatencyParallelismPoint {
            min_link_latency: latency,
            realized_parallelism: breakdown.realized_parallelism,
            sync_overhead_pct: breakdown.sync_overhead_pct(),
        });
    }
    points
}

/// Returns a copy of `scenario` whose minimum link latency is exactly `latency`.
///
/// Shared by the latency sweep and the gate's low-latency-trade assertion; every
/// link is clamped up to `latency` and any link previously at the minimum is
/// pinned so the resulting minimum equals `latency`.
pub(crate) fn with_min_latency(scenario: &BenchScenario, latency: u64) -> BenchScenario {
    let mut swept = scenario.clone();
    for link in &mut swept.links {
        link.latency_ticks = link.latency_ticks.max(latency);
    }
    // Ensure the scenario's minimum link latency is exactly `latency` by clamping
    // any link at or below it to the swept value.
    if let Some(min) = swept.min_link_latency()
        && min != latency
    {
        for link in &mut swept.links {
            if link.latency_ticks < latency || link.latency_ticks == min {
                link.latency_ticks = latency;
            }
        }
    }
    swept
}

/// One point on the core-count speedup sweep ([PERF-3], [HARN-11]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreCountPoint {
    /// Host cores available at this sweep point.
    pub cores: u64,
    /// Realized parallelism `P` at this core count.
    pub realized_parallelism: u64,
    /// Modeled wall-clock at this core count.
    pub wall_clock: u64,
}

/// Sweeps the host core count and reports the realized speedup ([PERF-3]).
///
/// Returns points in ascending core order; wall-clock is non-increasing and
/// realized parallelism is non-decreasing as cores are added, approaching
/// `min(k, cores)` and bounded by the critical path.
#[must_use]
pub fn core_count_speedup_sweep(
    scenario: &BenchScenario,
    core_counts: &[u64],
) -> Vec<CoreCountPoint> {
    let mut points = Vec::with_capacity(core_counts.len());
    let mut sorted = core_counts.to_vec();
    sorted.sort_unstable();
    for cores in sorted {
        let mut swept = scenario.clone();
        swept.cores = cores.max(1);
        let breakdown = evaluate_cost_model(&swept, &RealizationConfig::single_scenario(0));
        points.push(CoreCountPoint {
            cores,
            realized_parallelism: breakdown.realized_parallelism,
            wall_clock: breakdown.wall_clock(),
        });
    }
    points
}

/// One point on the rendezvous-frequency sweep ([PERF-10]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousPoint {
    /// Rendezvous frequency at this sweep point.
    pub rendezvous_frequency: u64,
    /// Sync overhead percentage at this frequency.
    pub sync_overhead_pct: u64,
    /// Deterministic result fingerprint, which MUST be identical across the
    /// sweep ([PERF-10]: rendezvous frequency is a pure perf/observation knob).
    pub result_fingerprint: u64,
}

/// Sweeps the rendezvous frequency and reports the overhead-versus-frequency
/// curve plus the invariant result fingerprint ([PERF-10]).
///
/// The result fingerprint is identical at every frequency (the knob cannot change
/// which instruction sees which input); the sync-overhead percentage is
/// non-decreasing with frequency (finer rendezvous means more bookkeeping).
#[must_use]
pub fn rendezvous_frequency_sweep(
    scenario: &BenchScenario,
    frequencies: &[u64],
) -> Vec<RendezvousPoint> {
    let mut points = Vec::with_capacity(frequencies.len());
    let mut sorted = frequencies.to_vec();
    sorted.sort_unstable();
    for frequency in sorted {
        let realization = RealizationConfig {
            boot_cost: 0,
            scenarios_sharing_world: 1,
            rendezvous_frequency: frequency.max(1),
        };
        let breakdown = evaluate_cost_model(scenario, &realization);
        points.push(RendezvousPoint {
            rendezvous_frequency: frequency,
            sync_overhead_pct: breakdown.sync_overhead_pct(),
            // The fingerprint is a pure function of the scenario, never of the
            // rendezvous knob: the busy term and parallelism are knob-invariant.
            result_fingerprint: scenario_result_fingerprint(scenario),
        });
    }
    points
}

/// The modeled syscall accounting for a fixed advance workload ([PERF-8]).
///
/// All hot-path cross-node synchronization is shared-memory based and never an
/// IPC round trip per quantum. The current ceiling-publication path performs one
/// unconditional futex wake per quantum, and a parked node can perform repeated
/// futex waits after interrupted, spurious, or non-actionable returns.
/// Service/backpressure producer releases and frame deliveries can issue
/// additional futex wakes. The host also writes the plugin eventfd at least once
/// per quantum and may write it again to resignal an unchanged-icount poll or
/// service I/O. This arithmetic is bookkeeping, not runtime syscall observation,
/// and it does not attempt to count QEMU-side eventfd reads or event-loop poll
/// entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceSyscallCount {
    /// Quanta advanced over the fixed workload.
    pub quanta: u64,
    /// Total host futex wakes and plugin futex waits in the arithmetic model.
    pub futex_wake_wait: u64,
    /// Unconditional scheduler-ceiling futex wakes, one per quantum currently.
    pub futex_ceiling_wakes: u64,
    /// Actual plugin futex-wait calls, including repeated waits after wake returns.
    pub futex_wait_calls: u64,
    /// Additional futex wakes caused by service or ring-backpressure producer
    /// releases.
    pub futex_service_release_wakes: u64,
    /// Additional futex wakes caused by inbound or completed-frame delivery.
    pub futex_delivery_wakes: u64,
    /// Total host plugin-eventfd writes, including quantum, resignal, and service wakes.
    pub eventfd_wake_writes: u64,
    /// Initial plugin-eventfd wake writes, one per quantum currently.
    pub eventfd_quantum_wake_writes: u64,
    /// Additional eventfd writes used to resignal unchanged-icount polls.
    pub eventfd_unchanged_icount_wake_writes: u64,
    /// Additional eventfd writes used after servicing host I/O.
    pub eventfd_service_wake_writes: u64,
    /// Host polling sleeps between pending advance observations.
    pub host_poll_sleep_calls: u64,
    /// Socket/QMP/plugin-control request-response round trips per quantum (MUST be zero).
    pub per_quantum_socket_control_round_trips: u64,
}

/// Models the syscall count over a fixed advance workload ([PERF-8]).
///
/// The advance path issues no per-quantum IPC round trip. The current
/// implementation pays one unconditional ceiling futex wake per quantum, the
/// caller-supplied actual futex-wait calls (including repeats), and explicit
/// service-release and delivery futex wakes. It also pays at least one
/// plugin-eventfd write per quantum, plus the
/// caller-supplied unchanged-icount and service writes. A future waiter-armed
/// optimization may eliminate unnecessary futex wakes, but this arithmetic
/// intentionally describes current host/plugin integration behavior. It is not
/// a runtime syscall measurement and does not count QEMU-side eventfd reads or
/// event-loop poll entries. Host polling sleeps are carried as a separate
/// caller-supplied category.
#[must_use]
pub fn advance_syscall_count(
    quanta: u64,
    futex_wait_calls: u64,
    futex_service_release_wakes: u64,
    futex_delivery_wakes: u64,
    eventfd_unchanged_icount_wake_writes: u64,
    eventfd_service_wake_writes: u64,
    host_poll_sleep_calls: u64,
) -> AdvanceSyscallCount {
    AdvanceSyscallCount {
        quanta,
        futex_wake_wait: quanta
            .saturating_add(futex_wait_calls)
            .saturating_add(futex_service_release_wakes)
            .saturating_add(futex_delivery_wakes),
        futex_ceiling_wakes: quanta,
        futex_wait_calls,
        futex_service_release_wakes,
        futex_delivery_wakes,
        eventfd_wake_writes: quanta
            .saturating_add(eventfd_unchanged_icount_wake_writes)
            .saturating_add(eventfd_service_wake_writes),
        eventfd_quantum_wake_writes: quanta,
        eventfd_unchanged_icount_wake_writes,
        eventfd_service_wake_writes,
        host_poll_sleep_calls,
        // The advance/delivery path does not use request/response IPC.
        per_quantum_socket_control_round_trips: 0,
    }
}

/// One point on the snapshot capture/restore latency series ([PERF-12], [PERF-17]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLatencyPoint {
    /// Changed state (dirty pages/blocks) since the parent, in pages.
    pub changed_pages: u64,
    /// Modeled incremental capture latency, in abstract units.
    pub capture_units: u64,
    /// Modeled restore-to-runnable latency, in abstract units.
    pub restore_units: u64,
}

/// Models the snapshot capture and restore latency as a function of changed
/// state ([PERF-12], [PERF-17]).
///
/// Capture cost scales with *changed* state, not total state (incremental/CoW
/// capture of what diverged since the parent). Restore-to-runnable is
/// substantially cheaper than a cold boot and is bounded below by a small fixed
/// realize cost  --  the sub-second restore target  --  plus the changed-state term.
#[must_use]
pub fn snapshot_latency_series(changed_pages_series: &[u64]) -> Vec<SnapshotLatencyPoint> {
    // A fixed realize floor (the sub-second restore-to-runnable target) plus a
    // small per-changed-page term. Both are far below a cold boot.
    const RESTORE_FLOOR: u64 = 1;
    let mut points = Vec::with_capacity(changed_pages_series.len());
    let mut sorted = changed_pages_series.to_vec();
    sorted.sort_unstable();
    for changed_pages in sorted {
        points.push(SnapshotLatencyPoint {
            changed_pages,
            capture_units: changed_pages,
            restore_units: RESTORE_FLOOR + changed_pages,
        });
    }
    points
}

/// A pinned host profile for the perf-bench gate ([PERF-20]).
///
/// The gate pins the host profile it runs on (core count, CPU model class) so a
/// metric regression reflects a real efficiency loss and not host noise, and so a
/// perf regression is reproducible from the recorded benchmark scenario + host
/// profile ([PERF-21]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProfile {
    /// Host core count the profile pins.
    pub cores: u64,
    /// CPU model class the profile pins.
    pub cpu_model_class: &'static str,
}

/// Returns the canonical pinned host profile for the reference perf-bench run.
#[must_use]
pub fn canonical_host_profile() -> HostProfile {
    HostProfile {
        cores: 4,
        cpu_model_class: "crucible-reference-x86_64-tcg",
    }
}

/// A content-addressed digest binding the perf corpus and its baseline ([PERF-21]).
///
/// The corpus and its baselines are content-addressed and versioned together so a
/// benchmark scenario's identity and its expected baseline travel together and a
/// baseline cannot drift out of sync with the scenario it measures.
#[must_use]
pub fn perf_corpus_digest(corpus: &[BenchScenario], baseline: &PerfBaseline) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix = |value: u64| {
        hash ^= value;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        hash ^= hash.rotate_left(29);
    };
    mix(corpus.len() as u64);
    for scenario in corpus {
        mix(scenario_result_fingerprint(scenario));
        mix(scenario.tcg_ips);
        mix(scenario.per_tb_atomics);
    }
    mix(baseline.fuzz_throughput);
    mix(baseline.coverage_on_off_pct);
    mix(baseline.cumulative_coverage);
    hash
}

/// One point on the fleet host sweep ([PERF-27]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FleetHostPoint {
    /// Number of explorer hosts at this sweep point.
    pub hosts: u64,
    /// Aggregate throughput (scenarios per hour) summed across hosts.
    pub aggregate_throughput: u64,
    /// Per-host store-I/O overhead percentage.
    pub store_io_overhead_pct: u64,
}

/// Sweeps the explorer-host count and reports aggregate throughput and per-host
/// store-I/O overhead ([PERF-27]).
///
/// Aggregate throughput scales near-linearly with host count until the shared
/// store's bandwidth saturates, after which store-I/O overhead rises and
/// throughput stops growing. Returns points in ascending host order.
#[must_use]
pub fn fleet_host_sweep(
    per_host_throughput: u64,
    saturation_hosts: u64,
    host_counts: &[u64],
) -> Vec<FleetHostPoint> {
    let mut points = Vec::with_capacity(host_counts.len());
    let mut sorted = host_counts.to_vec();
    sorted.sort_unstable();
    for hosts in sorted {
        let effective_hosts = hosts.min(saturation_hosts.max(1));
        let aggregate_throughput = per_host_throughput.saturating_mul(effective_hosts);
        let store_io_overhead_pct = if hosts <= saturation_hosts {
            (hosts.saturating_mul(2)).min(50)
        } else {
            // Past saturation, store I/O dominates; overhead climbs.
            (50 + (hosts - saturation_hosts).saturating_mul(10)).min(95)
        };
        points.push(FleetHostPoint {
            hosts,
            aggregate_throughput,
            store_io_overhead_pct,
        });
    }
    points
}

/// A deterministic fingerprint over the observable result of a scenario.
///
/// This stands in for the canonical event log + final fingerprint that a real
/// run produces; it is a pure function of the scenario's determinism-relevant
/// inputs and is therefore invariant to every performance knob (core count,
/// rendezvous frequency, parallelism). Two scenarios that differ only in a
/// performance knob share this fingerprint ([PERF-5], [PERF-10], [PERF-24]).
#[must_use]
pub fn scenario_result_fingerprint(scenario: &BenchScenario) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix = |value: u64| {
        hash ^= value;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        hash ^= hash.rotate_left(23);
    };
    mix(scenario.name.len() as u64);
    for byte in scenario.name.bytes() {
        mix(u64::from(byte));
    }
    // Sort nodes and links by name so the fingerprint is order-independent: the
    // determinism-relevant content is the set of nodes/links, not their vector
    // order or any host scheduling order.
    let mut nodes: Vec<&BenchNode> = scenario.nodes.iter().collect();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    for node in nodes {
        for byte in node.name.bytes() {
            mix(u64::from(byte));
        }
        mix(node.busy_instructions);
        mix(node.idle_ticks);
    }
    let mut links: Vec<&BenchLink> = scenario.links.iter().collect();
    links.sort_by(|left, right| (&left.from, &left.to).cmp(&(&right.from, &right.to)));
    for link in links {
        for byte in link.from.bytes() {
            mix(u64::from(byte));
        }
        for byte in link.to.bytes() {
            mix(u64::from(byte));
        }
        mix(link.latency_ticks);
    }
    // The coverage hook and core budget are observation/performance knobs and are
    // deliberately excluded from the fingerprint ([PERF-15], [PERF-5]).
    hash
}
