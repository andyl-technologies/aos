//! Retains reached strict ordinary mutation destinations through their outcome.
//!
//! The actual ordinary session creates a slot before entering native capacity
//! or append work. Its failure handle shares that same original allocation;
//! it does not create a selected account or copy an entered native graph.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::{CanonicalJournalMechanicalErrorV1, CommitResult};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::super::RootAuthorityErrorV1;
use super::super::names::RootAuthorityNamesOriginalV1;
use super::capacity::{PreparedRootGenesisCapacityOriginalV1, RootGenesisCapacityOriginalV1};
use super::native_cut::RootGenesisNativeCrossingOriginalV1;

pub(super) struct RootStrictGenesisCustodyV1 {
    pub(super) initialization: Option<Arc<RootStrictGenesisOperationOriginalV1>>,
    pub(super) preparation: Option<Arc<RootStrictGenesisOperationOriginalV1>>,
    pub(super) anchoring: Option<Arc<RootStrictGenesisOperationOriginalV1>>,
}

impl RootStrictGenesisCustodyV1 {
    pub(super) const fn new() -> Self {
        Self {
            initialization: None,
            preparation: None,
            anchoring: None,
        }
    }
}

pub(super) struct RootStrictGenesisOperationOriginalV1 {
    pub(super) transaction: Option<JournalTransaction>,
    pub(super) prepared: PreparedRootGenesisCapacityOriginalV1,
    pub(super) reservation: Option<RootGenesisCapacityOriginalV1>,
    pub(super) recovery_owner: RootAuthorityNamesOriginalV1,
    pub(super) advisory: RootGenesisNativeCrossingOriginalV1,
    pub(super) crossing: RootGenesisNativeCrossingOriginalV1,
    pub(super) native: Option<Result<CommitResult, crate::native::PolicyNativeJournalErrorV1>>,
    pub(super) admission:
        Option<Result<RootGenesisCapacityOriginalV1, CanonicalJournalMechanicalErrorV1>>,
    pub(super) returned: Option<RootAuthorityErrorV1>,
}

impl RootStrictGenesisOperationOriginalV1 {
    fn new() -> Self {
        Self {
            transaction: None,
            prepared: PreparedRootGenesisCapacityOriginalV1::new(),
            reservation: None,
            recovery_owner: RootAuthorityNamesOriginalV1::new(),
            advisory: RootGenesisNativeCrossingOriginalV1::new(),
            crossing: RootGenesisNativeCrossingOriginalV1::new(),
            native: None,
            admission: None,
            returned: None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prepared
            .failure()
            .or_else(|| self.recovery_owner.failure())
            .or_else(|| self.advisory.failure())
            .or_else(|| self.crossing.failure())
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.returned.as_ref().map(|cause| cause as _))
    }
}

// Each slot is genuinely absent until this ordinary operation enters. A failed
// or completed entered original is never replaced to make another attempt fit.
pub(super) fn begin_once_v1(
    destination: &mut Option<Arc<RootStrictGenesisOperationOriginalV1>>,
) -> Result<(), RootAuthorityErrorV1> {
    if destination.is_some() {
        return Err(RootAuthorityErrorV1::Conflict);
    }
    *destination = Some(Arc::new(RootStrictGenesisOperationOriginalV1::new()));
    Ok(())
}

pub(super) fn entered_mut_v1(
    destination: &mut Option<Arc<RootStrictGenesisOperationOriginalV1>>,
) -> Result<&mut RootStrictGenesisOperationOriginalV1, RootAuthorityErrorV1> {
    destination
        .as_mut()
        .and_then(Arc::get_mut)
        .ok_or(RootAuthorityErrorV1::Conflict)
}

/// Borrows the same completed negative ordinary original through owned custody.
///
/// The private handle constructor is used only after actual native/body failure.
/// Cloning its existing Arc allocates nothing and grants neither retry nor role.
pub struct RootStrictGenesisFailureV1 {
    original: Arc<RootStrictGenesisOperationOriginalV1>,
}

pub(super) fn failure_v1(
    destination: &Option<Arc<RootStrictGenesisOperationOriginalV1>>,
) -> RootAuthorityErrorV1 {
    match destination {
        Some(original) => RootAuthorityErrorV1::GenesisMutation(RootStrictGenesisFailureV1 {
            original: Arc::clone(original),
        }),
        None => RootAuthorityErrorV1::Conflict,
    }
}

impl std::fmt::Debug for RootStrictGenesisFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootStrictGenesisFailureV1")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RootStrictGenesisFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => write!(formatter, "{cause}"),
            None => formatter.write_str("the original strict Root mutation was refused"),
        }
    }
}

impl Error for RootStrictGenesisFailureV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

pub(super) fn finish_body_v1(
    destination: &mut Option<Arc<RootStrictGenesisOperationOriginalV1>>,
    returned: Result<(), RootAuthorityErrorV1>,
) -> Result<(), RootAuthorityErrorV1> {
    match returned {
        Ok(()) => Ok(()),
        Err(cause) => {
            let original = match destination.as_mut().and_then(Arc::get_mut) {
                Some(original) if original.returned.is_none() => original,
                _ => {
                    // Neither an entered second cause nor the first native
                    // original may be dropped after a violated single entry.
                    let _still_owned = cause;
                    std::process::abort();
                }
            };
            original.returned = Some(cause);
            Err(failure_v1(destination))
        }
    }
}
