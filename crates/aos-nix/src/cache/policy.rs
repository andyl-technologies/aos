//! Memoization admission policy for incremental evaluation cache nodes.
//!
//! This module names the coarse §3.3 cache-granularity classes. It does not
//! wire policy decisions into the evaluator, collect demand counters, or decide
//! durable materialization.

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
}
