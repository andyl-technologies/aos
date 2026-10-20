//! Keeps predurable public compilation on the same entered C18 original.
//!
//! The Journal temporarily owns this complete scope while the canonical public
//! compiler runs. Scope presence permits no generic append. The private exact
//! authorization-floor and canonical Core admission recipes are the only
//! mutation ports. Admission additionally needs genuine cross-owner owners.

use std::sync::{Arc, Mutex};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::*;
use crate::cli_model::authorization_adapter::PublicAuthorizationFloorRecipeV1;
use crate::{JournalError, JournalTransaction};

type Slot<T, E> = Option<Result<T, E>>;

mod core;
mod compiler;
mod geometry;
mod handoff;
mod preaccept_source;
mod accepted_source;
pub(super) mod availability;
pub use availability::ControllerExecutionAvailabilityClientLoanV2;
pub use availability::ControllerExecutionAvailabilityPositiveRetirementV2;
pub use availability::ControllerExecutionAvailabilitySessionCurrentnessErrorV2;
pub use accepted_source::ExecutionAcceptedCreateSourceDataV2;
pub use preaccept_source::ExecutionPublicPreacceptSourceDataV2;
pub use handoff::ControllerExecutionAdmissionRetirementV2;

#[derive(Clone, Copy)]
enum First {
    Entry,
    Current,
    Identity,
    FloorGeometry,
    FloorFunding,
    FloorAppend,
    Plan,
    Compiler,
    CompilerGeometry,
    CompilerFunding,
    Preparation,
    Assignment,
    Availability,
    AcceptedBind,
    Acceptance,
    Handoff,
    HandoffGeometry,
    AdmissionGeometry,
    AdmissionFunding,
    AdmissionAppend,
    Reentry,
}

/// Owns the same C18 and complete predurable public Execution prefix.
///
/// Construction requires the actual configured native original and its same
/// Controller bank/profile association. This owner supplies neither Host nor
/// Storage availability, admission, execution or terminal authority.
#[must_use = "retain this owner through all entered native posts and handoffs"]
pub struct ExecutionPublicAdmissionScopeV2 {
    pub(super) financial: ControllerExecutionOperationOriginalV1,
    pub(super) retired: bool,
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    prefix: ExecutionPublicAdmissionPrefixV2,
}

struct ExecutionPublicAdmissionPrefixV2 {
    journal_identity: Option<crate::journal::ExecutionObservationJournalIdentityV4>,
    compiler: Option<compiler::ExecutionPublicCompilerOriginalV2>,
    assignment: Option<preaccept_source::ExecutionPublicAssignmentOriginalV2>,
    accepted_bind: Option<accepted_source::ExecutionAcceptedBindOriginalV2>,
    availability: Option<availability::ExecutionAvailabilityClientOriginalV2>,
    compiler_geometry: Slot<ResourceVector, ResourceReservationErrorV1>,
    compiler_funding: Slot<(), ResourceReservationErrorV1>,
    compiler_funding_native_selected: bool,
    entry: Slot<(), ResourceReservationErrorV1>,
    current: Slot<(), ResourceReservationErrorV1>,
    identity: Slot<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1, JournalError>,
    floor_geometry: Slot<ResourceVector, JournalError>,
    floor_funding: Slot<(), ResourceReservationErrorV1>,
    floor_transaction: Option<JournalTransaction>,
    floor_append: Slot<crate::journal::CommitResult, JournalError>,
    plan: Option<Arc<crate::OperationPlan>>,
    accepted_outcome: Slot<crate::AcceptOutcome, crate::ControllerServiceError>,
    prepared_outcome: Slot<(), crate::ControllerServiceError>,
    handoff_geometry: Slot<ResourceVector, ResourceReservationErrorV1>,
    handoff_entry: Slot<(), ResourceReservationErrorV1>,
    handoff_funding: Slot<(), ResourceReservationErrorV1>,
    handoff_park: Slot<(), ResourceReservationErrorV1>,
    admission_geometry: Slot<ResourceVector, JournalError>,
    admission_funding: Slot<(), ResourceReservationErrorV1>,
    admission_transaction: Option<JournalTransaction>,
    admission_append: Slot<crate::journal::CommitResult, JournalError>,
    admission_entered: bool,
    admission_funding_native_selected: bool,
    floor_entered: bool,
    entry_native_selected: bool,
    current_native_selected: bool,
    floor_funding_native_selected: bool,
    refused_post: Slot<(), ResourceReservationErrorV1>,
    first: Option<First>,
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(super) fn can_retire_native_v2(
        &self,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &Arc<ProductionControllerNormalRootProfileV1>,
    ) -> bool {
        self.has_completed_retirement_v2()
            && Arc::ptr_eq(&self.bank, bank) && Arc::ptr_eq(&self.profile, profile)
    }

    pub(super) fn into_retired_native_v2(self: Box<Self>) -> ControllerExecutionOperationOriginalV1 {
        let Self { financial, .. } = *self;
        financial
    }

    fn has_completed_retirement_v2(&self) -> bool {
        self.retired && self.prefix.first.is_none()
            && !self.financial.active && self.financial.accepted.is_none()
            && self.financial.post.is_none() && !self.financial.predurable_entered
            && self.financial.predurable_prefix.is_none() && self.financial.failure().is_none()
    }

    // Public retirement drops its prefix before Source disposal. The retired
    // bit alone is therefore insufficient: the SAME native original must also
    // have crossed genuine D-positive and retain no pending/failed interval.
    pub(super) fn borrow_retired_cleanup_native_v2(
        &mut self,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&mut ControllerExecutionOperationOriginalV1, ResourceReservationErrorV1> {
        if !self.has_completed_retirement_v2()
            || !std::ptr::eq(profile, self.profile.as_ref())
            || !self.financial.journal_identity.is_same_original_v4(
                &controller.execution_observation_identity_v4())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // The following genuine native entry independently checks its same
        // Bank/enrollment and preserves spent traffic; no old Source or D is
        // projected from the retired public scope.
        Ok(&mut self.financial)
    }

    pub(crate) fn take_compiler_v2(&mut self) -> Option<compiler::ExecutionPublicCompilerOriginalV2> {
        self.prefix.compiler.take()
    }

    pub(crate) fn restore_compiler_v2(
        &mut self,
        original: compiler::ExecutionPublicCompilerOriginalV2,
        failed: bool,
    ) {
        if self.prefix.compiler.is_some() {
            std::process::abort();
        }
        if failed {
            self.prefix.first.get_or_insert(First::Compiler);
        }
        self.prefix.compiler = Some(original);
    }

    // The actual executor supplies the previously funded original and its SAME
    // bank/profile Arcs. No declared amount or decoded packet can create them.
    pub(crate) fn new(
        financial: ControllerExecutionOperationOriginalV1,
        bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: Arc<ProductionControllerNormalRootProfileV1>,
    ) -> Self {
        Self { financial, retired: false, bank, profile, prefix: ExecutionPublicAdmissionPrefixV2::new() }
    }

    pub(crate) fn retain_preparation_once_v2(
        &mut self,
        returned: Result<(), crate::ControllerServiceError>,
    ) -> bool {
        if self.prefix.prepared_outcome.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return false;
        }
        if returned.is_err() {
            self.prefix.first.get_or_insert(First::Preparation);
        }
        self.prefix.prepared_outcome = Some(returned);
        self.prefix.first.is_none()
    }

    pub(crate) fn begin_once_v2(
        &mut self,
        controller: &mut Journal,
        complete: Demand,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.prefix.entry.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prefix.entry = Some((|| {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let loan = self.financial.begin_public_admission_once_v2(
                &bank, controller, self.profile.as_ref(), complete,
            )?;
            // A refused native before remains parked too: independent posts
            // must stay reachable through this same whole owning scope.
            loan.park_public_admission_v2()
        })());
        if !matches!(self.prefix.entry, Some(Ok(()))) {
            self.prefix.entry_native_selected = self.financial.failure().is_some();
            self.prefix.first = Some(First::Entry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prefix.journal_identity = Some(controller.execution_observation_identity_v4());
        self.prefix.current = Some(self.require_native_current_v2(controller));
        if !matches!(self.prefix.current, Some(Ok(()))) {
            self.prefix.current_native_selected = self.financial.failure().is_some();
            self.prefix.first = Some(First::Current);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // This is historical comparison DATA from the paid SAME C. It is not
        // an adopted Q04 owner or Source/currentness permission.
        self.prefix.identity = Some(controller.controller_q04_history_v1().and_then(|history| {
            history.map(|history| history.identity).ok_or(JournalError::ProtectedBoundary)
        }));
        if !matches!(self.prefix.identity, Some(Ok(_))) {
            self.prefix.first = Some(First::Identity);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    fn require_native_current_v2(&self, controller: &Journal) -> Result<(), ResourceReservationErrorV1> {
        let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        self.financial.require_public_admission_current_v2(&bank, controller, self.profile.as_ref())
    }

    pub(crate) fn require_current_v2(&self, controller: &Journal) -> Result<(), JournalError> {
        if self.prefix.first.is_some() || !matches!(self.prefix.entry, Some(Ok(())))
            || !matches!(self.prefix.identity, Some(Ok(_)))
            || self.prefix.availability.as_ref().is_some_and(|original| original.failure_v2().is_some())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_native_current_v2(controller).map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn matches_q04_v2(
        &self,
        identity: &aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1,
    ) -> bool {
        self.prefix.identity.as_ref().is_some_and(|result| matches!(result, Ok(actual) if actual == identity))
    }

    pub(crate) fn prepare_floor_v2(
        &mut self,
        controller: &mut Journal,
        transaction: &JournalTransaction,
        recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if self.prefix.floor_entered || self.prefix.floor_transaction.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_exact_v1(transaction)?;
        self.prefix.floor_entered = true;
        self.prefix.floor_geometry = Some((|| {
            let native = controller.append_receiving_demand_v1(transaction.records().iter().map(|record| {
                aos_sandbox_journal::geometry::RecordShape {
                    key_bytes: record.key().len(),
                    value_bytes: record.value().map(<[u8]>::len),
                }
            })).map_err(|cause| match cause {
                crate::journal::JournalAppendReceivingDemandErrorV1::Journal(cause) => cause,
                crate::journal::JournalAppendReceivingDemandErrorV1::Accounting(cause) => JournalError::ReceivingAccounting(cause),
            })?;
            // Retain one exact canonical transaction before native append.
            // These are Vec/byte carriers, not additional namespace entries.
            let bytes = transaction.records().iter().try_fold(
                std::mem::size_of::<JournalTransaction>(),
                |bytes, record| bytes.checked_add(std::mem::size_of::<crate::JournalRecord>())?
                    .checked_add(record.key().len())?
                    .checked_add(record.value().map_or(0, <[u8]>::len)),
            ).and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            native.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(JournalError::ReceivingAccounting)
        })());
        let Some(demand) = self.prefix.floor_geometry.as_ref().and_then(|result| result.as_ref().ok()).copied() else {
            self.prefix.first = Some(First::FloorGeometry);
            return Err(JournalError::ProtectedBoundary);
        };
        self.prefix.floor_funding = Some((|| {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(&bank, controller, self.profile.as_ref())?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(&bank, controller, self.profile.as_ref(), Demand::from_demand_v1(complete));
            // Even a debit refusal retains this native owner for its owed post.
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(self.prefix.floor_funding, Some(Ok(()))) {
            self.prefix.floor_funding_native_selected = self.financial.failure().is_some();
            self.prefix.first = Some(First::FloorFunding);
            return Err(JournalError::ProtectedBoundary);
        }
        self.prefix.floor_transaction = Some(transaction.clone());
        Ok(())
    }

    pub(crate) fn require_floor_v2(
        &self,
        controller: &Journal,
        transaction: &JournalTransaction,
        recipe: &PublicAuthorizationFloorRecipeV1<'_>,
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if !self.prefix.floor_entered || !matches!(self.prefix.floor_funding, Some(Ok(())))
            || self.prefix.floor_transaction.as_ref() != Some(transaction)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        recipe.require_exact_v1(transaction)
    }

    pub(crate) fn retain_floor_append_v2(
        &mut self,
        returned: Result<crate::journal::CommitResult, JournalError>,
    ) -> Result<crate::journal::CommitResult, JournalError> {
        if self.prefix.floor_append.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }
        self.prefix.floor_append = Some(returned);
        match self.prefix.floor_append.as_ref() {
            Some(Ok(commit)) => Ok(*commit),
            _ => {
                self.prefix.first.get_or_insert(First::FloorAppend);
                Err(JournalError::ProtectedBoundary)
            }
        }
    }

    pub(crate) fn finish_refused_once_v2(&mut self, controller: &mut Journal) {
        if self.prefix.refused_post.is_some() || !self.financial.active {
            return;
        }
        self.prefix.refused_post = Some((|| {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(&bank, controller, self.profile.as_ref())?;
            loan.finish_without_source_v2(&bank, controller, self.profile.as_ref());
            // The original post result remains in financial.post. Dropping
            // this refused loan closes its slot; no negative owner is reset.
            Ok(())
        })());
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.prefix.first {
            Some(First::Entry) => self.prefix.entry_native_selected.then(|| self.financial.failure()).flatten()
                .or_else(|| error(&self.prefix.entry)),
            Some(First::Current) => self.prefix.current_native_selected.then(|| self.financial.failure()).flatten()
                .or_else(|| error(&self.prefix.current)),
            Some(First::Identity) => error(&self.prefix.identity),
            Some(First::FloorGeometry) => error(&self.prefix.floor_geometry),
            Some(First::FloorFunding) => self.prefix.floor_funding_native_selected.then(|| self.financial.failure()).flatten()
                .or_else(|| error(&self.prefix.floor_funding)),
            Some(First::FloorAppend) => error(&self.prefix.floor_append),
            Some(First::Plan) => Some(&ResourceReservationErrorV1::Conflict),
            Some(First::Compiler) => self.prefix.compiler.as_ref().and_then(|compiler| compiler.failure_v2()),
            Some(First::CompilerGeometry) => error(&self.prefix.compiler_geometry),
            Some(First::CompilerFunding) => self.prefix.compiler_funding_native_selected
                .then(|| self.financial.failure()).flatten()
                .or_else(|| error(&self.prefix.compiler_funding)),
            Some(First::Preparation) => error(&self.prefix.prepared_outcome),
            Some(First::AcceptedBind) => self.prefix.accepted_bind.as_ref().and_then(|original| {
                if original.funding_native_selected_v2() { self.financial.failure() } else { None }
            }).or_else(|| self.prefix.accepted_bind.as_ref().and_then(|original| original.failure_v2()))
                .or(Some(&ResourceReservationErrorV1::Conflict)),
            Some(First::Assignment) => self.prefix.assignment.as_ref().and_then(|original| {
                if original.funding_native_selected_v2() { self.financial.failure() } else { None }
            }).or_else(|| self.prefix.assignment.as_ref().and_then(|original| original.failure_v2()))
                .or(Some(&ResourceReservationErrorV1::Conflict)),
            Some(First::Availability) => self.prefix.availability.as_ref()
                .filter(|original| original.funding_native_selected_v2())
                .and_then(|_| self.financial.failure())
                .or_else(|| self.prefix.availability.as_ref().and_then(|original| original.failure_v2()))
                .or_else(|| self.financial.failure())
                .or(Some(&ResourceReservationErrorV1::Conflict)),
            Some(First::Acceptance) => error(&self.prefix.accepted_outcome),
            Some(First::Handoff) => self.financial.failure()
                .or_else(|| error(&self.prefix.handoff_entry))
                .or_else(|| error(&self.prefix.handoff_funding))
                .or_else(|| error(&self.prefix.handoff_park))
                .or(Some(&ResourceReservationErrorV1::Conflict)),
            Some(First::HandoffGeometry) => error(&self.prefix.handoff_geometry),
            Some(First::AdmissionGeometry) => error(&self.prefix.admission_geometry),
            Some(First::AdmissionFunding) => self.prefix.admission_funding_native_selected
                .then(|| self.financial.failure()).flatten()
                .or_else(|| error(&self.prefix.admission_funding)),
            Some(First::AdmissionAppend) => error(&self.prefix.admission_append),
            Some(First::Reentry) => Some(&ResourceReservationErrorV1::Conflict),
            None => self.financial.failure()
                .or_else(|| self.prefix.availability.as_ref().and_then(|original| original.failure_v2()))
                .or_else(|| error(&self.prefix.refused_post)),
        }
    }
}

impl ExecutionPublicAdmissionPrefixV2 {
    fn new() -> Self {
        Self {
            journal_identity: None,
            compiler: Some(compiler::ExecutionPublicCompilerOriginalV2::new()),
            assignment: Some(preaccept_source::ExecutionPublicAssignmentOriginalV2::new()),
            accepted_bind: Some(accepted_source::ExecutionAcceptedBindOriginalV2::new()),
            availability: None,
            compiler_geometry: None,
            compiler_funding: None,
            compiler_funding_native_selected: false,
            prepared_outcome: None,
            entry: None,
            current: None,
            identity: None,
            floor_geometry: None,
            floor_funding: None,
            floor_transaction: None,
            floor_append: None,
            plan: None,
            accepted_outcome: None,
            handoff_geometry: None,
            handoff_entry: None,
            handoff_funding: None,
            handoff_park: None,
            admission_geometry: None,
            admission_funding: None,
            admission_transaction: None,
            admission_append: None,
            admission_entered: false,
            admission_funding_native_selected: false,
            floor_entered: false,
            entry_native_selected: false,
            current_native_selected: false,
            floor_funding_native_selected: false,
            refused_post: None,
            first: None,
        }
    }
}
