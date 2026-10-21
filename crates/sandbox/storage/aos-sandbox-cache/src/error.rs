//! Retains Cache-native journal failures without unrelated role authority.
//!
//! Mechanical classification stays in the sole Broker implementation. Cache
//! adds only its existing streaming-prefix first cause and independently owed
//! final bookend. Conversions move the original error objects; no string,
//! boolean or decoded receipt replaces their ownership.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;

/// Reports Cache journal mechanics or its original native-prefix failure.
#[derive(Debug, thiserror::Error)]
pub enum CacheJournalErrorV1 {
    /// Selects the retained upper Current fixed quote at its original frontier.
    #[error("retained upper Current fixed receiving quote refused")]
    DeferredUpperFixedQuote,
    /// Selects the retained upper forecast failure after the full prefix recipe.
    ///
    /// The upper owner keeps the actual cause. This negative marker never
    /// substitutes a zero supplement or authorizes receiving growth.
    #[error("retained upper semantic forecast refused")]
    DeferredUpperSemanticQuote,
    /// Retains the original checked receiving representation arithmetic refusal.
    #[error(transparent)]
    ReceivingAccounting(#[from] aos_sandbox_model::AccountingError),
    /// Selects a refused native name observation while its archive retains the cause.
    #[error("selected readonly name observation {0} refused")]
    ReadOnlyNameReceivingFailure(u8),
    /// Preserves the canonical mechanical class and its actual owning cause.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Retains the actual authenticated Controller Root flight's native refusal.
    #[error(transparent)]
    RootOriginal(Box<aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1>),
    /// Retains the exact role-local Q04 original and its independent native debt.
    #[error(transparent)]
    Q04Original(Box<CacheQ04ErrorV1>),
    /// Retains an exact shared Q04 history failure beyond mechanical framing.
    #[error(transparent)]
    Q04HistoryData(Box<aos_sandbox_ledger_replay::q04_native_history::Q04NativeHistoryDataErrorV1>),
    /// Keeps the first streaming-prefix cause and separate final native debt.
    #[error(transparent)]
    NativePrefix(Box<CacheNativePrefixErrorV1>),
}

/// Retains a native Cache prefix's first failure and later bookend debt.
#[derive(Debug, thiserror::Error)]
#[error("Git coverage native prefix failed: {first}")]
pub struct CacheNativePrefixErrorV1 {
    #[source]
    first: CacheJournalErrorV1,
    final_bookend: Option<CacheJournalErrorV1>,
}

impl CacheNativePrefixErrorV1 {
    pub(crate) fn new(
        first: CacheJournalErrorV1,
        final_bookend: Option<CacheJournalErrorV1>,
    ) -> Self {
        Self {
            first,
            final_bookend,
        }
    }

    /// Borrows the unchanged first owning native or semantic cause.
    #[must_use]
    pub const fn first_cause(&self) -> &CacheJournalErrorV1 {
        &self.first
    }

    /// Borrows later physical/name debt without replacing the first cause.
    #[must_use]
    pub const fn final_bookend_cause(&self) -> Option<&CacheJournalErrorV1> {
        self.final_bookend.as_ref()
    }
}

impl CacheJournalErrorV1 {
    /// Creates the established coarse stopping marker without moving its cause.
    ///
    /// This refusal grants no native custody, stage progression or permission.
    #[doc(hidden)]
    #[must_use]
    pub const fn boundary_data_v1() -> Self {
        Self::boundary()
    }

    pub(crate) const fn boundary() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)
    }

    pub(crate) const fn poisoned() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::Poisoned)
    }

    pub(crate) const fn foreign_namespace() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::ForeignAuthorityNamespace)
    }

    pub(crate) const fn stale_snapshot() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot)
    }

    pub(crate) const fn preflight_mismatch() -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::AuthorityPreflightMismatch)
    }

    pub(crate) const fn limit_exceeded(bound: &'static str) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::LimitExceeded(bound))
    }

    // These writers keep the existing ordinary temporary-disposal policy.
    pub(crate) fn from_ordinary_native_v1(
        cause: aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1,
    ) -> Self {
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(
            cause,
        ))
    }
}

impl aos_sandbox_journal::protected_storage::ProtectedFailure for CacheJournalErrorV1 {
    const BOUNDARY: Self = Self::boundary();
    const UNSUPPORTED_OPEN: Self =
        Self::Mechanical(CanonicalJournalMechanicalErrorV1::UnsupportedProtectedOpen);
    const STALE_NAME: Self = Self::stale_snapshot();
}

// These finite conversions reuse the existing classifier. They neither copy
// native interpretation nor provide a blanket constructor from arbitrary DATA.
macro_rules! mechanical_conversion {
    ($($source:ty),+ $(,)?) => {
        $(impl From<$source> for CacheJournalErrorV1 {
            fn from(cause: $source) -> Self {
                Self::Mechanical(CanonicalJournalMechanicalErrorV1::from(cause))
            }
        })+
    };
}

mechanical_conversion!(
    std::io::Error,
    aos_sandbox_journal::framing::FrameError,
    aos_sandbox_journal::record::RecordError,
    aos_sandbox_journal::recovery::RecoveryTailError,
    aos_sandbox_journal::replay::NativeReplayError,
    aos_sandbox_model::journal_namespace::UnknownRecordNamespace,
    aos_sandbox_protocol::domain_ledger::JournalTransactionDataError,
    aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1,
    aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1,
    aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError,
    aos_sandbox_broker::canonical_journal::append_stages::CanonicalAppendErrorV1,
);


/// Preserves the finite native and comparison causes of a Cache Q04 observation.
///
/// Root and Controller retain their own actual native flights and higher
/// semantic errors. This role-local enum cannot adopt a phase or grant a loan.
#[derive(Debug, thiserror::Error)]
pub enum CacheQ04ErrorV1 {
    /// Retains the actual fixed Cache bootstrap writer's original refusal.
    #[error(transparent)]
    Bootstrap(#[from] crate::CacheReplayControllerBootstrapErrorV1),
    /// Retains physical Cache custody and held-identity failures.
    #[error(transparent)]
    Physical(#[from] crate::CacheOwnerErrorV1),
    /// Retains the sole native readback packet preparation cause.
    #[error(transparent)]
    Packet(crate::CacheOwnerReadbackErrorV1),
    /// Fences an abandoned actual native Cache/Clock pair before release.
    #[error("the original Cache Q04 continuation unwound")]
    Unwind,

    /// Retains the actual canonical native Cache journal refusal.
    #[error(transparent)]
    Journal(#[from] CacheJournalErrorV1),
    /// Retains the protected Cache replay or capability refusal.
    #[error(transparent)]
    CacheJournal(#[from] crate::CacheResidencyProtectedJournalErrorV1),
    /// Retains the first native replay cause and its independently owed post.
    #[error("the original Q04 native history or its final bookend changed")]
    NativeHistory {
        /// Keeps the first failure at its original replay frontier.
        first: CacheJournalErrorV1,
        /// Keeps a later native name or identity failure separately.
        final_bookend: Option<CacheJournalErrorV1>,
    },
    /// Refuses a changed original identity, expected phase or exact recipe.
    #[error("the original Q04 continuation cut changed")]
    ChangedCut,
    /// Refuses an unchanged bounded comparison or canonical suffix overflow.
    #[error("the original Q04 input or suffix exceeds its bound")]
    Bounds,
}

impl From<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1>
    for CacheQ04ErrorV1
{
    fn from(cause: aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1) -> Self {
        use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1;
        match cause {
            Q04HistoryDataErrorV1::Malformed => Self::Journal(CacheJournalErrorV1::boundary()),
            Q04HistoryDataErrorV1::ChangedCut => Self::ChangedCut,
            Q04HistoryDataErrorV1::Bounds => Self::Bounds,
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04RecipeDataErrorV1>
    for CacheQ04ErrorV1
{
    fn from(
        cause: aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04RecipeDataErrorV1,
    ) -> Self {
        use aos_sandbox_protocol::domain_ledger::create_q04_history::recipes::Q04RecipeDataErrorV1;

        match cause {
            Q04RecipeDataErrorV1::ChangedCut => Self::ChangedCut,
            Q04RecipeDataErrorV1::Bounds => Self::Bounds,
            Q04RecipeDataErrorV1::SequenceExhausted => Self::Journal(
                CacheJournalErrorV1::Mechanical(CanonicalJournalMechanicalErrorV1::SequenceExhausted),
            ),
            Q04RecipeDataErrorV1::History(first) => Self::Journal(first.into()),
            Q04RecipeDataErrorV1::Transaction(first) => Self::Journal(first.into()),
        }
    }
}

impl From<aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1>
    for CacheQ04ErrorV1
{
    fn from(cause: aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1) -> Self {
        Self::Journal(CacheJournalErrorV1::RootOriginal(Box::new(cause)))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1> for CacheQ04ErrorV1 {
    fn from(cause: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        Self::Journal(CacheJournalErrorV1::from(cause))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1>
    for CacheJournalErrorV1
{
    fn from(cause: aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1) -> Self {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryPairPreparationErrorV1;
        match cause {
            HistoryPairPreparationErrorV1::Envelope => Self::boundary(),
            HistoryPairPreparationErrorV1::Transaction(cause) => Self::from(cause),
        }
    }
}
