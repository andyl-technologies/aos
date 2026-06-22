//! Memoization admission policy for incremental evaluation cache nodes.
//!
//! This module names the coarse §3.3 cache-granularity classes and the §3.4
//! durable materialization threshold. It does not wire policy decisions into
//! the evaluator, collect demand counters, or write persistent cache records.

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

/// Whether one computation should use the in-process memo table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoizationDecision {
    /// Use the incremental memo table for this computation.
    Admit,
    /// Recompute directly without probing or populating the incremental memo table.
    Bypass,
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
}
