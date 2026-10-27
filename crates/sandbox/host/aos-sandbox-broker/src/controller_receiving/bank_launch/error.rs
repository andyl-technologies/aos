//! Preserves fixed Controller Bank/native/launch causes below role consumers.

/// Reports failure of the genuine fixed Controller writer or launch interval.
///
/// Boundary classifications never replace a parked native or arithmetic cause.
/// The actual operation owner retains those whole original Results separately.
#[derive(Debug, thiserror::Error)]
pub enum ControllerBankLaunchErrorV1 {
    /// The once-only interval, actual original, native state or role differs.
    #[error("fixed Controller Bank/launch original conflicts")]
    Conflict,
    /// Same-original C admission or financial arithmetic refused entry.
    #[error(transparent)]
    Receiving(#[from] crate::controller_receiving::ControllerReceivingErrorV1),
    /// An actual same-profile observation failed.
    #[error(transparent)]
    Profile(#[from] crate::controller_receiving::profile::ControllerProfileErrorV1),
    /// The existing canonical Bank format or subdivision engine refused DATA.
    #[error(transparent)]
    Bank(#[from] aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError),
    /// The same retained native acquisition, parser or physical owner failed.
    #[error(transparent)]
    Native(#[from] crate::canonical_journal::NativeJournalDataErrorV1),
    /// The actual physical replacement or its canonical snapshot failed.
    #[error(transparent)]
    Replacement(#[from] crate::canonical_journal::coordinator::replacement::CanonicalReplacementErrorV1),
    /// Existing all-dimension checked arithmetic failed before growth.
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
}
