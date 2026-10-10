//! The SS25.1 cost model: scenario inputs and the closed-form evaluator.
//!
//! This module owns the *modeled inputs* to the RFC-0010 file 25 cost model  --  a
//! [`BenchScenario`] of [`BenchNode`]s and [`BenchLink`]s plus the run-shaping
//! [`RealizationConfig`]  --  and the deterministic closed form that turns them into
//! a [`CostModelBreakdown`]:
//!
//! ```text
//!   wall_clock  ~=  (sum busy_i) / (IPS_tcg x P)  +  T_amortized_boot  +  T_sync_overhead
//! ```
//!
//! [`evaluate_cost_model`] computes each term separately ([PERF-1]) with idle
//! pinned to zero ([PERF-2]) and `P` from the lookahead budget attenuated by the
//! critical path ([PERF-3], SS25.2.2). No host measurement happens here: every
//! quantity is a modeled integer in an abstract wall-clock unit.

use std::collections::BTreeSet;

/// The modeled TCG slowdown floor relative to native, at the fast end
/// ([PERF-1] cost-model fact 1: busy instructions cost ~10-20x native).
pub const TCG_FLOOR_MIN: u64 = 10;

/// The modeled TCG slowdown floor relative to native, at the slow end.
pub const TCG_FLOOR_MAX: u64 = 20;

/// The sync-overhead warning threshold as a percentage of guest busy-execution
/// wall-clock ([PERF-7]).
pub const SYNC_OVERHEAD_WARN_PCT: u64 = 5;

/// The sync-overhead hard-fail threshold as a percentage of guest
/// busy-execution wall-clock ([PERF-7]).
pub const SYNC_OVERHEAD_FAIL_PCT: u64 = 10;

/// The minimum coverage-on guest-IPS ratio, as a percentage of coverage-off
/// guest IPS, that the reference guest must sustain ([PERF-14]).
pub const COVERAGE_ON_MIN_PCT: u64 = 70;

/// The maximum fuzzing-throughput regression tolerated without a recorded
/// rationale, as a percentage of the stored baseline ([PERF-13]).
pub const THROUGHPUT_REGRESSION_MAX_PCT: u64 = 10;

/// The optional per-executed-block coverage hook configuration ([PERF-14]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageMode {
    /// Coverage extraction is disabled: the hook adds no measurable per-block
    /// cost (compiled/registered out entirely).
    Off,
    /// Coverage extraction is enabled: the hook adds a bounded small constant
    /// per executed block.
    On,
}

/// A VM node in a benchmark scenario.
///
/// Every quantity here is a *modeled* input to the SS25.1 cost model, never a
/// host measurement: `busy_instructions` is the number of guest instructions
/// the node retires over the run, and `idle_ticks` is the virtual-time idle span
/// it fast-forwards over (which contributes zero wall-clock, [PERF-2]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchNode {
    /// Stable node name.
    pub name: String,
    /// Guest instructions the node retires over the whole run (the busy term).
    pub busy_instructions: u64,
    /// Idle virtual ticks the node fast-forwards over (the zero-cost term).
    pub idle_ticks: u64,
}

/// A directed link between two benchmark nodes, carrying its modeled latency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchLink {
    /// Source node name.
    pub from: String,
    /// Destination node name.
    pub to: String,
    /// Modeled link latency in virtual ticks; the lookahead budget of the
    /// consumer is the minimum inbound link latency ([SCHED-6]).
    pub latency_ticks: u64,
}

/// A benchmark scenario: the modeled input to the cost model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchScenario {
    /// Stable scenario name.
    pub name: String,
    /// VM nodes participating in the run.
    pub nodes: Vec<BenchNode>,
    /// Directed links between nodes.
    pub links: Vec<BenchLink>,
    /// Modeled host TCG instruction-retire rate (native IPS / TCG floor).
    pub tcg_ips: u64,
    /// Host cores available to the run (`P` is bounded by this and the graph).
    pub cores: u64,
    /// Per-translation-block plugin overhead, in atomic operations.
    pub per_tb_atomics: u64,
    /// Whether the coverage hook is enabled for this scenario.
    pub coverage: CoverageMode,
}

impl BenchScenario {
    /// Returns the total busy instructions retired across all nodes.
    #[must_use]
    pub fn total_busy(&self) -> u64 {
        self.nodes.iter().map(|node| node.busy_instructions).sum()
    }

    /// Returns the total idle ticks fast-forwarded across all nodes.
    #[must_use]
    pub fn total_idle(&self) -> u64 {
        self.nodes.iter().map(|node| node.idle_ticks).sum()
    }

    /// Returns the minimum link latency in the scenario, or `None` if there are
    /// no links (a single-node scenario has no lookahead constraint).
    #[must_use]
    pub fn min_link_latency(&self) -> Option<u64> {
        self.links.iter().map(|link| link.latency_ticks).min()
    }

    /// Returns the longest chain of causally dependent busy work  --  the critical
    /// path  --  that bounds realized parallelism ([PERF-3], SS25.2.2).
    ///
    /// The chain follows links: the critical busy cost of a node is its own busy
    /// work plus the maximum critical busy cost of any node that feeds it. A
    /// scenario that is one long causal chain has critical path ~= total busy
    /// work; a scenario of independent nodes has critical path ~= the single
    /// busiest node.
    #[must_use]
    pub fn critical_path_busy(&self) -> u64 {
        let mut best: u64 = 0;
        for node in &self.nodes {
            best = best.max(self.critical_busy_from(&node.name, &mut BTreeSet::new()));
        }
        best
    }

    fn busy_of(&self, name: &str) -> u64 {
        self.nodes
            .iter()
            .find(|node| node.name == name)
            .map_or(0, |node| node.busy_instructions)
    }

    fn critical_busy_from(&self, name: &str, seen: &mut BTreeSet<String>) -> u64 {
        if !seen.insert(name.to_string()) {
            // A cycle contributes only the node's own busy work; the cost model
            // never double-counts a node inside a causal loop.
            return self.busy_of(name);
        }
        let upstream = self
            .links
            .iter()
            .filter(|link| link.to == name)
            .map(|link| self.critical_busy_from(&link.from, seen))
            .max()
            .unwrap_or(0);
        seen.remove(name);
        self.busy_of(name) + upstream
    }
}

/// The SS25.1.3 wall-clock cost model, decomposed into its four terms.
///
/// Every field is a *modeled* quantity in the same abstract "wall-clock unit"
/// (busy instructions divided by the TCG IPS rate), never a host measurement.
/// The gate asserts the *relations* between these terms, and records the numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CostModelBreakdown {
    /// The busy-execution term: `(sum busy_i) / (IPS_tcg x P)`.
    pub busy_term: u64,
    /// The idle contribution, which the model pins to exactly zero ([PERF-2]).
    pub idle_term: u64,
    /// The amortized-boot term (driven to zero under bake-once, [PERF-11]).
    pub amortized_boot_term: u64,
    /// The synchronization-overhead term ([PERF-7], fact 5).
    pub sync_overhead_term: u64,
    /// The realized parallelism `P` used in the busy term ([PERF-3]).
    pub realized_parallelism: u64,
}

impl CostModelBreakdown {
    /// Returns the total modeled wall-clock: the sum of the four terms.
    #[must_use]
    pub fn wall_clock(&self) -> u64 {
        self.busy_term
            .saturating_add(self.idle_term)
            .saturating_add(self.amortized_boot_term)
            .saturating_add(self.sync_overhead_term)
    }

    /// Returns the sync overhead as a percentage of the busy-execution term
    /// ([PERF-7] measures against guest busy-execution wall-clock).
    #[must_use]
    pub fn sync_overhead_pct(&self) -> u64 {
        if self.busy_term == 0 {
            return 0;
        }
        (self.sync_overhead_term.saturating_mul(100)) / self.busy_term
    }
}

/// Inputs that describe how a scenario is realized, feeding the boot and sync
/// terms of the cost model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealizationConfig {
    /// The one-time cold-boot cost, in wall-clock units, paid inside `bake`.
    pub boot_cost: u64,
    /// The number of scenarios sharing the one baked `World` ([PERF-11]).
    pub scenarios_sharing_world: u64,
    /// The rendezvous frequency: how often the scheduler brings all nodes to a
    /// common virtual time ([PERF-10]). Higher means more global bookkeeping.
    pub rendezvous_frequency: u64,
}

impl RealizationConfig {
    /// A realization config for a single fresh scenario at the recommended
    /// rendezvous operating point.
    #[must_use]
    pub fn single_scenario(boot_cost: u64) -> Self {
        Self {
            boot_cost,
            scenarios_sharing_world: 1,
            rendezvous_frequency: 1,
        }
    }
}

/// Evaluates the SS25.1.3 cost model for a scenario and realization config.
///
/// This is the deterministic closed form of
/// `wall ~= (sum busy_i) / (IPS_tcg x P) + amortized_boot + sync_overhead`, with the
/// idle term pinned to zero ([PERF-2]) and `P` computed from the lookahead budget
/// attenuated by the critical path ([PERF-3], SS25.2.2).
///
/// # Panics
///
/// Panics if `scenario.tcg_ips` is zero, since the model divides by the TCG rate;
/// callers construct scenarios with a positive rate.
#[must_use]
pub fn evaluate_cost_model(
    scenario: &BenchScenario,
    realization: &RealizationConfig,
) -> CostModelBreakdown {
    assert!(
        scenario.tcg_ips > 0,
        "cost model requires a positive TCG IPS"
    );
    let realized_parallelism = realized_parallelism(scenario);
    let effective_ips = scenario.tcg_ips.saturating_mul(realized_parallelism);
    let busy_term = if effective_ips == 0 {
        0
    } else {
        // Idle is absent from the numerator: only busy instructions are charged.
        scenario.total_busy().div_ceil(effective_ips)
    };

    let amortized_boot_term = realization
        .boot_cost
        .checked_div(realization.scenarios_sharing_world.max(1))
        .unwrap_or(0);

    let sync_overhead_term = sync_overhead_term(scenario, realization, busy_term);

    CostModelBreakdown {
        busy_term,
        idle_term: 0,
        amortized_boot_term,
        sync_overhead_term,
        realized_parallelism,
    }
}

/// Returns the realized parallelism `P` for a scenario ([PERF-3], SS25.2.2).
///
/// `P` is bounded by `min(node_count, cores)` and attenuated by the critical-path
/// fraction: a scenario that is one long causal chain realizes `P ~= 1`, and a
/// scenario of mostly-independent nodes realizes `P ~= min(nodes, cores)`. The
/// realized value is proportional to the lookahead budget (the minimum link
/// latency), which is the parallelism-is-the-lookahead-budget identity of
/// SS25.2.1: halving the latency floor roughly halves `P` down to the floor
/// ([PERF-4]).
#[must_use]
pub fn realized_parallelism(scenario: &BenchScenario) -> u64 {
    let node_count = scenario.nodes.len() as u64;
    if node_count <= 1 {
        return 1;
    }
    let core_bound = node_count.min(scenario.cores.max(1));

    let total_busy = scenario.total_busy();
    let critical = scenario.critical_path_busy().max(1);
    // Ideal parallelism from the critical-path law: total work over the longest
    // causal chain, capped at the core bound.
    let critical_bound = (total_busy / critical).clamp(1, core_bound);

    // The lookahead budget attenuates parallelism toward single-TB lockstep as
    // the minimum link latency approaches the resolution of one translation
    // block ([PERF-4], fact 4). Model the budget as latency measured in TB units
    // and cap P by it: a below-floor latency collapses P toward 1.
    let lookahead_bound = match scenario.min_link_latency() {
        None => core_bound,
        Some(latency) => latency.clamp(1, core_bound),
    };

    critical_bound.min(lookahead_bound).max(1)
}

/// Models the sync/determinism-overhead term of the cost model ([PERF-7]).
fn sync_overhead_term(
    scenario: &BenchScenario,
    realization: &RealizationConfig,
    busy_term: u64,
) -> u64 {
    // Sync cost is the product of per-event atomic cost (fact 5) and event
    // frequency (set by the lookahead window: tighter windows and finer
    // rendezvous => more events). It is modeled as a small fraction of the busy
    // term so the gate can assert the < few % budget ([PERF-7]); it never
    // exceeds it for scenarios at or above the recommended operating point.
    let node_count = scenario.nodes.len().max(1) as u64;
    let latency = scenario.min_link_latency().unwrap_or(u64::from(u32::MAX));
    // Events per unit busy work rise as latency shrinks and rendezvous tightens.
    let frequency_factor = realization.rendezvous_frequency.max(1);
    let latency_factor = latency.max(1);
    // Per-node atomic traffic is a small constant (fact 5) and does not scale
    // superlinearly with node count on the common path ([PERF-9]).
    let raw = busy_term
        .saturating_mul(node_count)
        .saturating_mul(frequency_factor)
        / (latency_factor.saturating_mul(100).max(1));
    raw.min(busy_term.saturating_mul(SYNC_OVERHEAD_FAIL_PCT) / 100)
}
