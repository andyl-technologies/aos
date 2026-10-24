//! Admits concrete disposable cold Native17 constructors before allocation.
//!
//! Rows describe actual requested layouts. They neither authenticate native or
//! Source history nor issue restoration, model-state or execution authority.

use super::*;
use std::cell::Cell;
use std::mem::size_of;

/// Names the closed constructor sequence of one actual cold native graph pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCold17Work {
    /// Validates the exact nonowning role framing before any cold constructor.
    Framing,
    /// Retains five exact role references/bodies and the original before bytes.
    RawInputs,
    /// Allocates the before decoder header, raw copy and three alias banks.
    BeforeGraphBanks,
    /// Reconstructs the before graph's genuinely preflighted selected targets.
    BeforeGraphTargets,
    /// Allocates the after decoder header, raw copy and three alias banks.
    AfterGraphBanks,
    /// Reconstructs the after graph's genuinely preflighted selected targets.
    AfterGraphTargets,
    /// Counts actual typed output-pair serialization with funded formatter work.
    OutputPairQuote,
    /// Authenticates the actual pair using separately quoted pure temporary work.
    OutputPair,
    /// Counts actual Hold serialization with funded formatter work.
    RestorationHoldQuote,
    /// Serializes and hashes the actual retained restoration Hold.
    RestorationHold,
}

impl NativeCold17Work {
    /// Reports the actual final constructor before another Source bucket may begin.
    pub const fn is_final_data(self) -> bool {
        matches!(self, Self::RestorationHold)
    }

    /// Checks the exact defining constructor sequence without issuing permission.
    pub fn follows_data(self, previous: Option<Self>) -> bool {
        matches!(
            (previous, self),
            (None, Self::Framing)
                | (Some(Self::Framing), Self::RawInputs)
                | (Some(Self::RawInputs), Self::BeforeGraphBanks)
                | (Some(Self::BeforeGraphBanks), Self::BeforeGraphTargets)
                | (Some(Self::BeforeGraphTargets), Self::AfterGraphBanks)
                | (Some(Self::AfterGraphBanks), Self::AfterGraphTargets)
                | (Some(Self::AfterGraphTargets), Self::OutputPairQuote)
                | (Some(Self::OutputPairQuote), Self::OutputPair)
                | (Some(Self::OutputPair), Self::RestorationHoldQuote)
                | (Some(Self::RestorationHoldQuote), Self::RestorationHold)
        )
    }
}

/// Bounds a concrete quote walk beside all previously initialized native caches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCold17PrewalkData {
    work: NativeCold17Work,
    prior: usize,
    transient: usize,
    scratch: usize,
}

impl NativeCold17PrewalkData {
    /// Returns the exact constructor family being quoted.
    pub const fn work_data(self) -> NativeCold17Work {
        self.work
    }

    /// Returns actual previously retained native backing, excluding its inline root.
    pub const fn prior_native_cache_retained_bytes_data(self) -> usize {
        self.prior
    }

    /// Returns the independently funded temporary storage used by the quote.
    pub const fn quote_transient_bytes_data(self) -> usize {
        self.transient
    }

    /// Returns the defining fixed borrowed counter and observer controls.
    pub const fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }
}

/// Bounds one actual constructor while all previous native caches remain live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCold17ConstructionData {
    work: NativeCold17Work,
    prior: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl NativeCold17ConstructionData {
    /// Returns the exact independently admitted constructor family.
    pub const fn work_data(self) -> NativeCold17Work {
        self.work
    }

    /// Returns actual previously retained native backing, excluding its inline root.
    pub const fn prior_native_cache_retained_bytes_data(self) -> usize {
        self.prior
    }

    /// Returns requested backing newly retained by this constructor, including partials.
    pub const fn maximum_new_retained_bytes_data(self) -> usize {
        self.retained
    }

    /// Returns separately named simultaneous constructor temporary storage.
    pub const fn constructor_transient_bytes_data(self) -> usize {
        self.transient
    }

    /// Returns the defining fixed constructor/counter controls.
    pub const fn counter_scratch_bytes_data(self) -> usize {
        self.scratch
    }
}

/// Borrows an independent enclosing admission for actual cold Native17 work.
///
/// Implementations retain each row and perform genuine whole-owner observation
/// before returning. The reader retains no callback and no row grants authority.
pub trait NativeCold17Admission {
    /// Admits one quote before its first formatter, parser or allocation.
    ///
    /// # Errors
    /// Refuses stale custody, duplicate work, unfinished observation or short credit.
    fn begin_data(&self, prewalk: NativeCold17PrewalkData) -> Result<(), ProviderError>;

    /// Admits the complete actual constructor before its first owning operation.
    ///
    /// # Errors
    /// Refuses unobserved or changed work, short credit or stale real custody.
    fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError>;

    /// Retains the completed stage and actual native-cache census before continuing.
    ///
    /// # Errors
    /// Refuses changed work, actual backing above its row or stale real custody.
    fn finish_data(
        &self,
        work: NativeCold17Work,
        actual_native_cache_bytes: usize,
    ) -> Result<(), ProviderError>;
}

pub(crate) struct NativeCold17Boundary<'a> {
    admission: &'a dyn NativeCold17Admission,
    retained: Cell<usize>,
}

impl<'a> NativeCold17Boundary<'a> {
    pub(super) fn new(admission: &'a dyn NativeCold17Admission) -> Self {
        Self {
            admission,
            retained: Cell::new(0),
        }
    }

    pub(crate) fn retained_data(&self) -> usize {
        self.retained.get()
    }

    pub(crate) fn begin_data(
        &self,
        work: NativeCold17Work,
        transient: usize,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        self.admission.begin_data(NativeCold17PrewalkData {
            work,
            prior: self.retained.get(),
            transient,
            scratch,
        })
    }

    pub(crate) fn construct_data(
        &self,
        work: NativeCold17Work,
        retained: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        self.admission.construct_data(NativeCold17ConstructionData {
            work,
            prior: self.retained.get(),
            retained,
            transient,
            scratch,
        })
    }

    pub(crate) fn finish_data(
        &self,
        work: NativeCold17Work,
        retained: usize,
    ) -> Result<(), ProviderError> {
        self.admission.finish_data(work, retained)?;
        self.retained.set(retained);
        Ok(())
    }
}

/// Borrows one actual graph constructor's already retained external cache total.
pub(crate) struct NativeCold17GraphAdmission<'a, 'boundary> {
    pub(crate) boundary: &'a NativeCold17Boundary<'boundary>,
    pub(crate) base: usize,
    pub(crate) banks: NativeCold17Work,
    pub(crate) targets: NativeCold17Work,
}

impl NativeCold17GraphAdmission<'_, '_> {
    pub(crate) fn finish_data(
        &self,
        work: NativeCold17Work,
        child: usize,
    ) -> Result<(), ProviderError> {
        self.boundary
            .finish_data(work, self.base.checked_add(child).ok_or_else(invalid)?)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeCold17Work>()
        + size_of::<NativeCold17PrewalkData>()
        + size_of::<NativeCold17ConstructionData>()
        + size_of::<NativeCold17Boundary<'static>>()
        + size_of::<NativeCold17GraphAdmission<'static, 'static>>()
        + size_of::<Option<NativeCold17Boundary<'static>>>()
        + size_of::<Option<NativeCold17GraphAdmission<'static, 'static>>>()
        + size_of::<Option<&'static NativeCold17GraphAdmission<'static, 'static>>>()
        + size_of::<&'static dyn NativeCold17Admission>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + 6 * size_of::<usize>()
}

#[cfg(test)]
mod controls {
    use super::*;

    #[test]
    fn actual_native_constructor_dag_cannot_skip_repeat_or_finish_early() {
        use NativeCold17Work::*;
        let stages = [
            Framing,
            RawInputs,
            BeforeGraphBanks,
            BeforeGraphTargets,
            AfterGraphBanks,
            AfterGraphTargets,
            OutputPairQuote,
            OutputPair,
            RestorationHoldQuote,
            RestorationHold,
        ];
        let mut previous = None;
        for stage in stages {
            assert!(stage.follows_data(previous));
            assert!(!stage.follows_data(Some(stage)));
            assert_eq!(stage.is_final_data(), stage == RestorationHold);
            previous = Some(stage);
        }
        assert!(!RawInputs.follows_data(None));
        assert!(!BeforeGraphTargets.follows_data(Some(RawInputs)));
        assert!(!OutputPair.follows_data(Some(AfterGraphTargets)));
        assert!(!RestorationHold.follows_data(Some(OutputPair)));
    }

    struct RefuseConstruction {
        calls: Cell<usize>,
    }

    impl NativeCold17Admission for RefuseConstruction {
        fn begin_data(&self, row: NativeCold17PrewalkData) -> Result<(), ProviderError> {
            assert_eq!(row.work_data(), NativeCold17Work::RawInputs);
            assert_eq!(row.prior_native_cache_retained_bytes_data(), 0);
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }

        fn construct_data(&self, row: NativeCold17ConstructionData) -> Result<(), ProviderError> {
            assert_eq!(row.work_data(), NativeCold17Work::RawInputs);
            assert_eq!(row.prior_native_cache_retained_bytes_data(), 0);
            assert_eq!(row.maximum_new_retained_bytes_data(), 19);
            self.calls.set(self.calls.get() + 1);
            Err(invalid())
        }

        fn finish_data(&self, _: NativeCold17Work, _: usize) -> Result<(), ProviderError> {
            panic!("a refused constructor must never be completed");
        }
    }

    #[test]
    fn constructor_refusal_keeps_saved_native_cache_census_unchanged() {
        let admission = RefuseConstruction {
            calls: Cell::new(0),
        };
        let boundary = NativeCold17Boundary::new(&admission);
        boundary
            .begin_data(NativeCold17Work::RawInputs, 20, 23)
            .unwrap();

        assert!(
            boundary
                .construct_data(NativeCold17Work::RawInputs, 19, 29, 31)
                .is_err()
        );

        assert_eq!(admission.calls.get(), 2);
        assert_eq!(boundary.retained_data(), 0);
    }
}
