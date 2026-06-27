//! Memoization admission policy for incremental evaluation cache nodes.
//!
//! This module names the coarse §3.3 cache-granularity classes and the §3.4
//! durable materialization threshold. It also provides deterministic cost
//! observation vocabulary for callers. It does not wire policy decisions into
//! the evaluator, collect evaluator demand observations, or write persistent
//! cache records.

/// A coarse evaluator computation category for memoization admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoizationSubject {
    /// A `derivationStrict` result.
    DerivationStrict,
    /// A file-backed import result.
    Import,
    /// A large top-level attribute binding such as `pkgs.<name>`.
    LargeAttrBinding,
    /// A thunk whose profitability depends on demand and value-hash cost.
    Thunk,
    /// A trivially cheap computation where probing costs more than recomputing.
    Trivial,
}

impl MemoizationSubject {
    /// Returns the default memoization class for this subject.
    pub const fn default_class(self) -> MemoizationClass {
        match self {
            Self::DerivationStrict | Self::Import | Self::LargeAttrBinding => {
                MemoizationClass::Always
            }
            Self::Thunk => MemoizationClass::Conditional,
            Self::Trivial => MemoizationClass::Never,
        }
    }
}

/// The coarse memoization policy class for one computation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoizationClass {
    /// Always probe and populate the in-process memo table.
    Always,
    /// Probe and populate only when admission signals show a likely win.
    Conditional,
    /// Bypass the incremental memo table.
    Never,
}

impl MemoizationClass {
    /// Returns the in-process memoization decision for this class and signals.
    pub const fn decide(self, signals: MemoizationSignals) -> MemoizationDecision {
        match self {
            Self::Always => MemoizationDecision::Admit,
            Self::Conditional if signals.used_many() && signals.cheap_value_hash() => {
                MemoizationDecision::Admit
            }
            Self::Conditional | Self::Never => MemoizationDecision::Bypass,
        }
    }
}

/// Admission signals for conditionally memoized computations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoizationSignals {
    used_many: bool,
    cheap_value_hash: bool,
}

impl MemoizationSignals {
    /// Creates admission signals from demand and value-hash cost observations.
    pub const fn new(used_many: bool, cheap_value_hash: bool) -> Self {
        Self {
            used_many,
            cheap_value_hash,
        }
    }

    /// Returns whether demand analysis or profiling marks this computation used-many.
    pub const fn used_many(self) -> bool {
        self.used_many
    }

    /// Returns whether the value hash is already available or cheap to compute.
    pub const fn cheap_value_hash(self) -> bool {
        self.cheap_value_hash
    }
}

/// Same-run demand observations for RAM-tier memoization admission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoizationDemand {
    current_run_demands: u64,
}

impl MemoizationDemand {
    /// Creates same-run demand observations from an explicit count.
    pub const fn new(current_run_demands: u64) -> Self {
        Self {
            current_run_demands,
        }
    }

    /// Returns the number of demands observed in the current run.
    pub const fn current_run_demands(self) -> u64 {
        self.current_run_demands
    }

    /// Returns observations with one more current-run demand, saturating on overflow.
    pub const fn record_current_demand(self) -> Self {
        Self {
            current_run_demands: self.current_run_demands.saturating_add(1),
        }
    }

    /// Returns whether this computation has crossed the used-many threshold.
    pub const fn used_many(self) -> bool {
        self.current_run_demands > 1
    }

    /// Combines same-run demand with caller-supplied value-hash cost information.
    pub const fn signals(self, cheap_value_hash: bool) -> MemoizationSignals {
        MemoizationSignals::new(self.used_many(), cheap_value_hash)
    }
}

/// Whether one computation should use the in-process memo table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoizationDecision {
    /// Use the incremental memo table for this computation.
    Admit,
    /// Recompute directly without probing or populating the incremental memo table.
    Bypass,
}

/// Cross-run reuse counters for durable materialization policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationReuse {
    previous_run_demands: u64,
    current_run_demands: u64,
}

impl MaterializationReuse {
    /// Creates reuse counters from prior and current run demand observations.
    pub const fn new(previous_run_demands: u64, current_run_demands: u64) -> Self {
        Self {
            previous_run_demands,
            current_run_demands,
        }
    }

    /// Creates reuse counters with prior-run demand and no current observations.
    pub const fn from_previous_run(previous_run_demands: u64) -> Self {
        Self::new(previous_run_demands, 0)
    }

    /// Returns the demand count carried forward from previous runs.
    pub const fn previous_run_demands(self) -> u64 {
        self.previous_run_demands
    }

    /// Returns the demand count observed in this run.
    pub const fn current_run_demands(self) -> u64 {
        self.current_run_demands
    }

    /// Returns counters with one more current-run demand, saturating on overflow.
    pub const fn record_current_demand(self) -> Self {
        Self {
            previous_run_demands: self.previous_run_demands,
            current_run_demands: self.current_run_demands.saturating_add(1),
        }
    }

    /// Returns counters for the next run, carrying current demand into history.
    pub const fn advance_run(self) -> Self {
        Self {
            previous_run_demands: self
                .previous_run_demands
                .saturating_add(self.current_run_demands),
            current_run_demands: 0,
        }
    }

    /// Returns whether prior metadata predicts cross-run reuse.
    pub const fn likely_redemanded_across_runs(self) -> bool {
        self.previous_run_demands > 0
    }

    /// Combines these reuse counters with measured costs for materialization.
    pub const fn signals(self, costs: MaterializationCosts) -> MaterializationSignals {
        MaterializationSignals::new(costs, self.likely_redemanded_across_runs())
    }
}

/// Caller-measured costs for the durable materialization threshold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationCosts {
    eval_cost: u64,
    hash_cost: u64,
    serialize_cost: u64,
    io_cost: u64,
}

impl MaterializationCosts {
    /// Creates materialization cost inputs in caller-defined comparable units.
    pub const fn new(eval_cost: u64, hash_cost: u64, serialize_cost: u64, io_cost: u64) -> Self {
        Self {
            eval_cost,
            hash_cost,
            serialize_cost,
            io_cost,
        }
    }

    /// Returns the measured cold evaluation cost.
    pub const fn eval_cost(self) -> u64 {
        self.eval_cost
    }

    /// Returns the measured value-hash cost.
    pub const fn hash_cost(self) -> u64 {
        self.hash_cost
    }

    /// Returns the measured durable serialization cost.
    pub const fn serialize_cost(self) -> u64 {
        self.serialize_cost
    }

    /// Returns the measured durable I/O cost.
    pub const fn io_cost(self) -> u64 {
        self.io_cost
    }

    /// Returns the saturating cost of hashing, serializing, and writing the value.
    pub const fn write_cost(self) -> u64 {
        self.hash_cost
            .saturating_add(self.serialize_cost)
            .saturating_add(self.io_cost)
    }
}

/// Evaluator observations used to derive durable materialization costs.
///
/// The work-unit and payload-size counters are intentionally deterministic:
/// callers can compare cache-enabled and cache-disabled behavior without
/// depending on wall-clock timing noise. Runtime tuning still belongs in the
/// caller-supplied unit costs carried by [`MaterializationCosts`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationCostObservation {
    eval_work_units: u64,
    persistent_payload_bytes: u64,
}

impl MaterializationCostObservation {
    const PERSISTENT_PAYLOAD_COST_UNIT_BYTES: u64 = 1024;

    /// Creates a materialization cost observation.
    pub const fn new(eval_work_units: u64, persistent_payload_bytes: u64) -> Self {
        Self {
            eval_work_units,
            persistent_payload_bytes,
        }
    }

    /// Returns the observed evaluator work units.
    pub const fn eval_work_units(self) -> u64 {
        self.eval_work_units
    }

    /// Returns the observed canonical persistent payload byte length.
    pub const fn persistent_payload_bytes(self) -> u64 {
        self.persistent_payload_bytes
    }

    /// Returns KiB-rounded payload cost units, with zero-byte payloads costing one unit.
    pub const fn persistent_payload_cost_units(self) -> u64 {
        let whole_units = self.persistent_payload_bytes / Self::PERSISTENT_PAYLOAD_COST_UNIT_BYTES;
        let has_partial_unit = !self
            .persistent_payload_bytes
            .is_multiple_of(Self::PERSISTENT_PAYLOAD_COST_UNIT_BYTES);
        let units = whole_units.saturating_add(has_partial_unit as u64);
        if units == 0 { 1 } else { units }
    }

    /// Converts observations into comparable materialization costs.
    pub const fn costs(self, unit_costs: MaterializationCosts) -> MaterializationCosts {
        let eval_work_units = if self.eval_work_units == 0 {
            1
        } else {
            self.eval_work_units
        };
        let payload_units = self.persistent_payload_cost_units();
        MaterializationCosts::new(
            unit_costs.eval_cost().saturating_mul(eval_work_units),
            unit_costs.hash_cost().saturating_mul(payload_units),
            unit_costs.serialize_cost().saturating_mul(payload_units),
            unit_costs.io_cost().saturating_mul(payload_units),
        )
    }
}

/// Admission signals for durable materialization of a memoized result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializationSignals {
    costs: MaterializationCosts,
    likely_redemanded_across_runs: bool,
}

impl MaterializationSignals {
    /// Creates materialization signals from measured costs and reuse likelihood.
    pub const fn new(costs: MaterializationCosts, likely_redemanded_across_runs: bool) -> Self {
        Self {
            costs,
            likely_redemanded_across_runs,
        }
    }

    /// Returns the materialization cost model inputs.
    pub const fn costs(self) -> MaterializationCosts {
        self.costs
    }

    /// Returns whether persistent metadata predicts cross-run reuse.
    pub const fn likely_redemanded_across_runs(self) -> bool {
        self.likely_redemanded_across_runs
    }

    /// Returns the durable materialization decision for these signals.
    pub const fn decide(self) -> MaterializationDecision {
        if self.likely_redemanded_across_runs && self.costs.eval_cost() > self.costs.write_cost() {
            MaterializationDecision::Materialize
        } else {
            MaterializationDecision::KeepInMemory
        }
    }
}

/// Whether one memoized result should be written to the durable value store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationDecision {
    /// Persist the memoized result to the durable content-addressed store.
    Materialize,
    /// Keep the result in the in-process memo tier only.
    KeepInMemory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_defaults_match_granularity_policy() {
        assert_eq!(
            MemoizationSubject::DerivationStrict.default_class(),
            MemoizationClass::Always
        );
        assert_eq!(
            MemoizationSubject::Import.default_class(),
            MemoizationClass::Always
        );
        assert_eq!(
            MemoizationSubject::LargeAttrBinding.default_class(),
            MemoizationClass::Always
        );
        assert_eq!(
            MemoizationSubject::Thunk.default_class(),
            MemoizationClass::Conditional
        );
        assert_eq!(
            MemoizationSubject::Trivial.default_class(),
            MemoizationClass::Never
        );
    }

    #[test]
    fn always_and_never_ignore_admission_signals() {
        let weak = MemoizationSignals::new(false, false);
        let strong = MemoizationSignals::new(true, true);

        assert_eq!(
            MemoizationClass::Always.decide(weak),
            MemoizationDecision::Admit
        );
        assert_eq!(
            MemoizationClass::Never.decide(strong),
            MemoizationDecision::Bypass
        );
    }

    #[test]
    fn conditional_requires_used_many_and_cheap_value_hash() {
        let class = MemoizationClass::Conditional;

        assert_eq!(
            class.decide(MemoizationSignals::new(false, false)),
            MemoizationDecision::Bypass
        );
        assert_eq!(
            class.decide(MemoizationSignals::new(true, false)),
            MemoizationDecision::Bypass
        );
        assert_eq!(
            class.decide(MemoizationSignals::new(false, true)),
            MemoizationDecision::Bypass
        );
        assert_eq!(
            class.decide(MemoizationSignals::new(true, true)),
            MemoizationDecision::Admit
        );
    }

    #[test]
    fn memoization_demand_marks_second_demand_as_used_many() {
        let first = MemoizationDemand::default().record_current_demand();
        let second = first.record_current_demand();

        assert_eq!(first.current_run_demands(), 1);
        assert!(!first.used_many());
        assert_eq!(
            MemoizationClass::Conditional.decide(first.signals(true)),
            MemoizationDecision::Bypass
        );
        assert_eq!(second.current_run_demands(), 2);
        assert!(second.used_many());
        assert_eq!(
            MemoizationClass::Conditional.decide(second.signals(true)),
            MemoizationDecision::Admit
        );
    }

    #[test]
    fn memoization_demand_still_requires_cheap_value_hash() {
        let used_many = MemoizationDemand::new(2);

        assert!(used_many.used_many());
        assert_eq!(
            MemoizationClass::Conditional.decide(used_many.signals(false)),
            MemoizationDecision::Bypass
        );
    }

    #[test]
    fn memoization_demand_saturates() {
        let demand = MemoizationDemand::new(u64::MAX).record_current_demand();

        assert_eq!(demand.current_run_demands(), u64::MAX);
        assert!(demand.used_many());
    }

    #[test]
    fn materialization_reuse_tracks_prior_and_current_demand() {
        let reuse = MaterializationReuse::new(2, 3);

        assert_eq!(reuse.previous_run_demands(), 2);
        assert_eq!(reuse.current_run_demands(), 3);
        assert!(reuse.likely_redemanded_across_runs());
        assert!(!MaterializationReuse::from_previous_run(0).likely_redemanded_across_runs());
    }

    #[test]
    fn materialization_reuse_current_demand_saturates() {
        let reuse = MaterializationReuse::new(1, u64::MAX).record_current_demand();

        assert_eq!(reuse.previous_run_demands(), 1);
        assert_eq!(reuse.current_run_demands(), u64::MAX);
    }

    #[test]
    fn materialization_reuse_advances_current_demand_to_history() {
        let reuse = MaterializationReuse::new(2, 3).advance_run();

        assert_eq!(reuse.previous_run_demands(), 5);
        assert_eq!(reuse.current_run_demands(), 0);
        assert!(reuse.likely_redemanded_across_runs());
    }

    #[test]
    fn materialization_reuse_advance_saturates_history() {
        let reuse = MaterializationReuse::new(u64::MAX - 1, 2).advance_run();

        assert_eq!(reuse.previous_run_demands(), u64::MAX);
        assert_eq!(reuse.current_run_demands(), 0);
    }

    #[test]
    fn materialization_reuse_builds_policy_signals_from_prior_runs() {
        let profitable = MaterializationCosts::new(100, 10, 20, 30);

        assert_eq!(
            MaterializationReuse::from_previous_run(1)
                .signals(profitable)
                .decide(),
            MaterializationDecision::Materialize
        );
        assert_eq!(
            MaterializationReuse::from_previous_run(0)
                .record_current_demand()
                .signals(profitable)
                .decide(),
            MaterializationDecision::KeepInMemory
        );
        assert_eq!(
            MaterializationReuse::from_previous_run(0)
                .record_current_demand()
                .advance_run()
                .signals(profitable)
                .decide(),
            MaterializationDecision::Materialize
        );
    }

    #[test]
    fn materialization_requires_eval_cost_above_write_cost_and_cross_run_demand() {
        let profitable = MaterializationCosts::new(100, 10, 20, 30);

        assert_eq!(
            MaterializationSignals::new(profitable, true).decide(),
            MaterializationDecision::Materialize
        );
        assert_eq!(
            MaterializationSignals::new(profitable, false).decide(),
            MaterializationDecision::KeepInMemory
        );
    }

    #[test]
    fn materialization_rejects_costs_at_or_below_write_floor() {
        let equal = MaterializationCosts::new(60, 10, 20, 30);
        let below = MaterializationCosts::new(59, 10, 20, 30);

        assert_eq!(
            MaterializationSignals::new(equal, true).decide(),
            MaterializationDecision::KeepInMemory
        );
        assert_eq!(
            MaterializationSignals::new(below, true).decide(),
            MaterializationDecision::KeepInMemory
        );
    }

    #[test]
    fn materialization_write_cost_saturates_on_overflow() {
        let costs = MaterializationCosts::new(u64::MAX, u64::MAX, 1, 1);

        assert_eq!(costs.write_cost(), u64::MAX);
        assert_eq!(
            MaterializationSignals::new(costs, true).decide(),
            MaterializationDecision::KeepInMemory
        );
    }

    #[test]
    fn materialization_observation_scales_unit_costs() {
        let units = MaterializationCosts::new(4, 1, 2, 3);
        let observation = MaterializationCostObservation::new(3, 2049);

        assert_eq!(observation.eval_work_units(), 3);
        assert_eq!(observation.persistent_payload_bytes(), 2049);
        assert_eq!(observation.persistent_payload_cost_units(), 3);
        assert_eq!(
            observation.costs(units),
            MaterializationCosts::new(12, 3, 6, 9)
        );
    }

    #[test]
    fn materialization_observation_has_minimum_units() {
        let units = MaterializationCosts::new(4, 1, 1, 1);
        let observation = MaterializationCostObservation::new(0, 0);

        assert_eq!(observation.persistent_payload_cost_units(), 1);
        assert_eq!(
            observation.costs(units),
            MaterializationCosts::new(4, 1, 1, 1)
        );
    }
}
