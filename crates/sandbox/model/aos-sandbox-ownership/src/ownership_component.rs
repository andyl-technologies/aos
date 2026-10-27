//! Owns the genuine Ownership PID1 receiving original and startup result.
//!
//! The closed role2 recipe authenticates the distinct F subdivision before
//! private bootstrap, signing-key, clock or journal IO. A borrowed loan never
//! exports the ledger or reconstructs authority from a row or ResourceVector.
//! The private operation child retains the actual listener, fixed MAC key,
//! authenticated records and same-ledger handler calls through all native posts.

use std::error::Error;

pub(super) mod funding;
mod operation;

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use crate::journal::{CapturedJournalOpenModeV1, OwnershipCapturedJournalOpenV1};
use crate::{Journal, JournalError, RecoveryReport};
use crate::local_ownership::{ProtectedFixedLocalLeaseOwnerV1, ProtectedLeaseAuthorityErrorV1};
use crate::ownership_authority::DurableOwnershipAuthorityError;

use aos_sandbox_broker::receiving::FixedServiceCurrentnessSampleV1;
use aos_sandbox_broker::receiving::{FixedServiceReceivingCaptureV1, RepresentationDemandDebitV1};

const CLOSED: OwnershipReceivingClosedV1 = OwnershipReceivingClosedV1;

/// Reports a closed Ownership interval while its original cause stays owned.
#[derive(Clone, Copy, Debug, Default, thiserror::Error)]
#[error("the original Ownership service receiving interval is unavailable")]
pub struct OwnershipReceivingClosedV1;

#[derive(Debug, thiserror::Error)]
enum OwnershipReplayDemandErrorV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

#[derive(Clone, Copy)]
enum Failure {
    Common,
    Entry,
    Demand,
    Accounting,
    Before,
    Opening,
    ReplayDemand,
    HistoryDemand,
    Startup,
    After,
    Operation,
}

/// Retains one actual role2 delivery and its complete private startup outcome.
///
/// Construction performs no IO. The only entry uses this process's fixed
/// inherited activation table, actual PID1 original and immutable profile.
/// Neither success nor failure exports the private local signing handler.
#[must_use]
pub struct OwnershipServiceReceivingOriginalV1 {
    common: FixedServiceReceivingCaptureV1<OwnershipReceivingClosedV1>,
    first: Option<Failure>,
    startup_entered: bool,
    fixed_entered: bool,
    fixed_admitted: bool,
    opening_entered: bool,
    history_entered: bool,
    startup_demand: Option<Result<ResourceVector, AccountingError>>,
    descriptor_bound: u64,
    descriptor_refusal: Option<AccountingError>,
    before: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    before_result: Option<Result<(), OwnershipReceivingClosedV1>>,
    opening: OwnershipCapturedJournalOpenV1,
    preparation_demand: Option<ResourceVector>,
    replay_demand: Option<Result<ResourceVector, OwnershipReplayDemandErrorV1>>,
    history_demand: Option<Result<ResourceVector, DurableOwnershipAuthorityError>>,
    startup: Option<Result<ProtectedFixedLocalLeaseOwnerV1, ProtectedLeaseAuthorityErrorV1>>,
    after: FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
    after_result: Option<Result<(), OwnershipReceivingClosedV1>>,
    operations: operation::OwnershipServiceOperationsV1,
}

impl OwnershipServiceReceivingOriginalV1 {
    /// Creates fixed empty destinations without observing a file or process.
    pub fn new() -> Self {
        let upper_inline = std::mem::size_of::<Self>()
            .saturating_sub(std::mem::size_of::<FixedServiceReceivingCaptureV1<OwnershipReceivingClosedV1>>());
        Self {
            common: FixedServiceReceivingCaptureV1::new_ownership(upper_inline),
            first: None,
            startup_entered: false,
            fixed_entered: false,
            fixed_admitted: false,
            opening_entered: false,
            history_entered: false,
            startup_demand: None,
            descriptor_bound: 0,
            descriptor_refusal: None,
            before: Default::default(),
            before_result: None,
            opening: OwnershipCapturedJournalOpenV1::new(),
            preparation_demand: None,
            replay_demand: None,
            history_demand: None,
            startup: None,
            after: Default::default(),
            after_result: None,
            operations: Default::default(),
        }
    }

    /// Authenticates the same original and privately initializes its authority.
    ///
    /// The whole constructor Result is parked before the independent final
    /// process/control posts. Reentry cannot replace either result or respend F.
    ///
    /// # Errors
    /// Retains the actual first native, permit, key, history or post failure.
    pub fn start_local_authority_once_v1(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        if self.startup_entered {
            return Err(self.fail(Failure::Entry));
        }
        self.startup_entered = true;
        if self.common.capture_once().is_err() {
            return Err(self.fail(Failure::Common));
        }
        self.descriptor_bound = self.common.demand.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?.get(D::OpenFiles);

        let startup = {
            let mut loan = OwnershipServiceReceivingLoanV1 { original: self };
            ProtectedFixedLocalLeaseOwnerV1::open_fixed_protected(&mut loan)
        };
        self.startup = Some(startup);
        if !matches!(self.startup, Some(Ok(_))) {
            self.fail(Failure::Startup);
        }

        // Once admission reached, its independent after sample is owed even
        // when bootstrap, signing, opening or semantic construction failed.
        if self.fixed_admitted {
            self.after_result = Some(observe_same_original(&mut self.common, &mut self.after));
            if !matches!(self.after_result, Some(Ok(()))) {
                self.fail(Failure::After);
            }
        }
        if self.first.is_none() { Ok(()) } else { Err(CLOSED) }
    }

    fn fail(&mut self, failure: Failure) -> OwnershipReceivingClosedV1 {
        self.first.get_or_insert(failure);
        CLOSED
    }

    fn reserve(&mut self, demand: ResourceVector) -> Result<(), OwnershipReceivingClosedV1> {
        let permanent = self.common.permanent_open_files()?;
        let next = match self.descriptor_bound.checked_add(demand.get(D::OpenFiles)) {
            Some(next) if next <= permanent => next,
            next => {
                let cause = match next {
                    Some(attempted) => AccountingError::LimitExceeded {
                        dimension: D::OpenFiles, limit: permanent, attempted,
                    },
                    None => AccountingError::ArithmeticOverflow { dimension: D::OpenFiles },
                };
                self.descriptor_refusal.get_or_insert(cause);
                return Err(self.fail(Failure::Accounting));
            }
        };
        if self.common.representation.as_mut().ok_or(CLOSED)?.reserve(demand.with(D::OpenFiles, 0)).is_err() {
            return Err(self.fail(Failure::Accounting));
        }
        // Every reservation here retains its corresponding native owners.
        // There is no prospective disposal or reset credit for a later stage.
        self.descriptor_bound = next;
        Ok(())
    }

    /// Borrows the earliest actual failure without resampling its originals.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            Failure::Common => self.common.failure(),
            Failure::Demand => error(&self.startup_demand),
            Failure::Accounting => self.descriptor_refusal.as_ref().map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|cause| cause as _)),
            Failure::Before => self.before.failure().or_else(|| error(&self.before_result)),
            Failure::Opening => self.opening.failure(),
            Failure::ReplayDemand => error(&self.replay_demand),
            Failure::HistoryDemand => error(&self.history_demand),
            Failure::Startup => error(&self.startup),
            Failure::After => self.after.failure().or_else(|| error(&self.after_result)),
            Failure::Operation => self.descriptor_refusal.as_ref().map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| self.common.representation.as_ref().and_then(|ledger| ledger.failure()).map(|cause| cause as _))
                .or_else(|| self.startup.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(|owner| owner.retained_failure()))
                .or_else(|| self.operations.failure()),
            Failure::Entry => Some(&CLOSED as &(dyn Error + 'static)),
        }.or(Some(&CLOSED as &(dyn Error + 'static)))
    }
}

impl Default for OwnershipServiceReceivingOriginalV1 {
    fn default() -> Self { Self::new() }
}

/// Borrows the actual private startup owner; no public constructor exists.
///
/// Its methods choose only compiled bootstrap, key, clock and journal recipes.
/// The outer original retains every entered result and the sole monotone F.
pub struct OwnershipServiceReceivingLoanV1<'original> {
    original: &'original mut OwnershipServiceReceivingOriginalV1,
}

impl OwnershipServiceReceivingLoanV1<'_> {
    /// Reserves the actual fixed private startup before its first native IO.
    ///
    /// # Errors
    /// Refuses replay, absent original, arithmetic, finite FD or resource debt.
    pub(crate) fn admit_local_authority_startup_once_v1(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        let original = &mut *self.original;
        if original.fixed_entered || original.first.is_some() {
            return Err(original.fail(Failure::Entry));
        }
        original.fixed_entered = true;
        if original.common.require_permanent_fd_coverage_v1().is_err() {
            return Err(original.fail(Failure::Entry));
        }
        original.startup_demand = Some((|| {
            let fixed = crate::local_ownership::fixed_startup_demand_v1()
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            let sample = FixedServiceCurrentnessSampleV1::<OwnershipReceivingClosedV1>::dynamic_demand()?;
            fixed.checked_add(sample)?.checked_add(sample)
        })());
        let demand = match original.startup_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(original.fail(Failure::Demand)),
        };
        original.reserve(demand)?;
        original.fixed_admitted = true;
        original.before_result = Some(observe_same_original(&mut original.common, &mut original.before));
        if !matches!(original.before_result, Some(Ok(()))) {
            return Err(original.fail(Failure::Before));
        }
        Ok(())
    }

    /// Opens only the fixed existing Ownership journal through held-prefix replay.
    ///
    /// # Errors
    /// Retains original acquisition/parser/posts, demand or one-shot refusal.
    pub(crate) fn open_local_authority_journal_once_v1(&mut self) -> Result<(Journal, RecoveryReport), OwnershipReceivingClosedV1> {
        let original = &mut *self.original;
        if !original.fixed_entered || !matches!(original.before_result, Some(Ok(())))
            || original.first.is_some() || original.opening_entered {
            return Err(original.fail(Failure::Entry));
        }
        original.opening_entered = true;
        let preparation = OwnershipCapturedJournalOpenV1::fixed_preparation_demand();
        original.preparation_demand = Some(preparation);
        original.reserve(preparation)?;
        original.opening.prepare_once(crate::local_ownership::fixed_journal_limits_v1(), CapturedJournalOpenModeV1::CreateAndRepair);
        let extent = match original.opening.captured_extent().copied() {
            Some(extent) => extent,
            None => return Err(original.fail(Failure::Opening)),
        };
        original.replay_demand = Some((|| {
            let native = extent.dominant_native_receiving_demand_v1()?;
            let semantic = extent.dominant_semantic_receiving_demand_v1()?;
            Ok::<_, OwnershipReplayDemandErrorV1>(native.checked_add(semantic)?)
        })());
        let demand = match original.replay_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(original.fail(Failure::ReplayDemand)),
        };
        original.reserve(demand)?;
        original.opening.replay_once();
        if !original.opening.replay_ready() {
            return Err(original.fail(Failure::Opening));
        }
        original.opening.take_opened().ok_or_else(|| original.fail(Failure::Opening))
    }

    /// Prices domain history on this exact taken native Journal before decoding.
    ///
    /// # Errors
    /// Rejects another Journal, reentry, malformed history or exhausted original F.
    pub(crate) fn reserve_local_history_capture_once_v1(&mut self, journal: &Journal) -> Result<(), OwnershipReceivingClosedV1> {
        let original = &mut *self.original;
        if original.history_entered || original.first.is_some()
            || !original.opening.was_taken_positive_v1()
            || original.opening.opening_owner_link_v1().is_none_or(|link| !link.matches_journal_v1(journal)) {
            return Err(original.fail(Failure::Entry));
        }
        original.history_entered = true;
        original.history_demand = Some(crate::local_ownership::history_capture_demand_v1(journal));
        let demand = match original.history_demand.as_ref() {
            Some(Ok(demand)) => *demand,
            _ => return Err(original.fail(Failure::HistoryDemand)),
        };
        original.reserve(demand)
    }
}

fn observe_same_original(
    original: &mut FixedServiceReceivingCaptureV1<OwnershipReceivingClosedV1>,
    sample: &mut FixedServiceCurrentnessSampleV1<OwnershipReceivingClosedV1>,
) -> Result<(), OwnershipReceivingClosedV1> {
    let expected_context = original.startup_currentness.captured_context().ok_or(CLOSED)?;
    let initial_info = original.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
    let initial_identity = original.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?;
    let anchor = original.cgroup.as_ref().ok_or(CLOSED)?;
    sample.observe_once(
        &mut original.process,
        anchor,
        &original.limits,
        initial_info,
        initial_identity,
        Some(expected_context),
        false,
    )
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
