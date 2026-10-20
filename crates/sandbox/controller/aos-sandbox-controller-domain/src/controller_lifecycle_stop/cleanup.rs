//! Lends only fresh Stop22 finance, currentness and clocks for closed cleanup.
//!
//! The genuine completed Recover association funds the same recovered Stop
//! seed/publication engine. The actual HostDispatch Source turn observes the
//! existing Completing cursor directly; ordinary Source admission phases are
//! never replayed or asserted complete. Root456 and authenticated Host evidence
//! remain separate requirements for effects and terminal completion.

mod source_append;
pub use source_append::{StopCleanupCompletionErrorV1, StopCleanupCompletionOriginalV1};
pub use source_append::StopCleanupSourceAppendOriginalV1;
pub(crate) use source_append::StopCleanupSourceAppendAuthorizationV1;
mod controller;
mod completion;
pub(crate) use controller::StopCleanupControllerAppendContextV1;
pub use completion::{ControllerHostStopCleanupCompletionV1, ControllerHostStopCleanupPendingDisposalV1,
    ControllerHostStopCleanupPositiveDisposalV1};
use controller::StopCleanupControllerOriginalV1;

use super::*;
use crate::controller_execution_operation::ControllerExecutionClockOriginalV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::{
    provisioning_root::finality_recover::{
        CreateFinalityObservationAdmissionDataV1 as Admission,
        finality_admission_commitment_v1,
    },
    resource_bank::RecoveredHostStopCleanupAssociationDataV1 as Association,
};
use aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1 as Subject;

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;
type Reference = crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2;
type Inventory = crate::controller_resource_reservation::ControllerRecoveryInventoryOriginalsV3;
type QueryReference = ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

// Construction is confined to the genuine held Root child borrower. This
// narrows Host requests only; original finance/cold/Root affinity never changes.
struct RootHostHorizonV1 {
    cutoff: u64,
}

struct CurrentStoppedGenerationV1 {
    generation: u64,
    key: Vec<u8>,
    commitment: [u8; 32],
}

pub(super) struct StopCleanupOriginalV1 {
    subject: Subject,
    association: Association,
    dispatch_record: aos_sandbox_model::ObjectDigest,
    completion_entered: bool,
    admission: Reference,
    first: Option<Result<RawPairedClockSample>>,
    cutoff: Option<Result<u64>>,
    frontier: ControllerExecutionClockOriginalV1,
    frontier_result: Option<Result<RawPairedClockSample>>,
    owed_clock: Option<Result<RawPairedClockSample>>,
    models: Option<Result<ResourceVector>>,
    complete: Option<ResourceVector>,
    funding: Option<Result<()>>,
    posts: Option<Result<()>>,
    cold: Option<Result<Option<crate::ControllerInitialBrokerSessionReceivingV1>>>,
    cold_refusal: Option<ResourceReservationErrorV1>,
    root_total: ResourceVector,
    inventory: [Inventory; 2],
    inventory_receipts: [Option<Result<QueryReference>>; 2],
    reentry: Option<ResourceReservationErrorV1>,
    controller: crate::journal::ExecutionObservationJournalIdentityV4,
    host_horizon: Option<std::result::Result<RootHostHorizonV1, crate::normal_root::RootStopCleanupClientClosedV1>>,
    stopped_generation: Option<std::result::Result<CurrentStoppedGenerationV1,
        aos_sandbox_protocol::public_api::projection::PublicProjectionError>>,
    terminal: Option<Box<StopCleanupControllerOriginalV1>>,
}

impl StopCleanupOriginalV1 {
    pub(super) fn fixed_demand(_controller: &Journal) -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|n| n.checked_add(std::mem::size_of::<ControllerHostStopCleanupSourceLoanV1<'_, '_>>().checked_mul(3)?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(CLOSED)?;
        let affinity = aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1::receiving_demand_v1()?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .checked_add(ControllerExecutionClockOriginalV1::fixed_demand_v1().ok_or(CLOSED)?)?
            .checked_add(affinity)?)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.selected_terminal_failure()
            .or_else(|| error(&self.first)).or_else(|| error(&self.cutoff))
            .or_else(|| self.frontier.failure()).or_else(|| error(&self.frontier_result))
            .or_else(|| error(&self.owed_clock))
            .or_else(|| error(&self.models))
            .or_else(|| self.cold.as_ref().and_then(|value| match value {
                Ok(Some(receiver)) => receiver.failure(),
                Err(cause) => Some(cause as &(dyn Error + 'static)), _ => None,
            }))
            .or_else(|| error(&self.funding)).or_else(|| error(&self.posts))
            .or_else(|| self.cold_refusal.as_ref().map(|cause| cause as _))
            .or_else(|| self.inventory.iter().find_map(Inventory::failure_v1))
            .or_else(|| self.inventory_receipts.iter().find_map(error))
            .or_else(|| error(&self.host_horizon))
            .or_else(|| error(&self.stopped_generation))
            .or_else(|| self.terminal.as_deref().and_then(StopCleanupControllerOriginalV1::failure))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn selected_terminal_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.terminal.as_deref()?.selected_failure()
    }
}

/// Retains the actual fresh Stop22 and Source while lending financial reception.
///
/// No ordinary Stop authority, mutable Source getter, inner owner or Host grant
/// escapes this loan. Root and SDK consumers must independently obtain their
/// actual finite authority before invoking any effect.
///
/// ```compile_fail
/// use aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1;
/// fn extract(loan: ControllerHostStopCleanupSourceLoanV1<'_, '_>) {
///     let _ordinary_authority = loan.owner;
/// }
/// ```
#[doc(hidden)]
#[must_use = "finish all independent Source/C posts and actual upper disposal"]
pub struct ControllerHostStopCleanupSourceLoanV1<'owner, 'source> {
    owner: &'owner mut Option<ControllerLifecycleStopOriginalV4>,
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
}

// Only the lender below constructs a loan, after checking the actual slot.
// Its exclusive borrow prevents replacement until the consuming pending
// disposer destroys the payload. Missing custody is an internal invariant
// failure; it cannot select a default owner or release native authority.
fn held_owner(
    slot: &Option<ControllerLifecycleStopOriginalV4>,
) -> &ControllerLifecycleStopOriginalV4 {
    match slot {
        Some(owner) => owner,
        None => std::process::abort(),
    }
}

fn held_owner_mut(
    slot: &mut Option<ControllerLifecycleStopOriginalV4>,
) -> &mut ControllerLifecycleStopOriginalV4 {
    match slot {
        Some(owner) => owner,
        None => std::process::abort(),
    }
}

impl ControllerLifecycleStopOriginalV4 {
    /// Lends the same occupied Core slot to the recovered Stop Source turn.
    ///
    /// The supplied subject and association are comparison DATA. The genuine
    /// completed same-B kind2 Recover and current protected Source independently
    /// validate them before the one-shot financial seed debit. A returned loan
    /// can retain an entered failure; its independent finish remains owed.
    /// The exclusive slot borrow also controls final in-place Core retirement.
    ///
    /// # Errors
    /// Refuses an empty slot, another target, subject, handoff, profile, bank,
    /// Source or prior entry. Seed failures retain the same occupied native and
    /// owed-post originals.
    #[doc(hidden)]
    pub fn begin_host_stop_cleanup_source_once_v1<'owner, 'source, T>(
        slot: &'owner mut Option<Self>,
        controller: &mut Journal,
        source: &'source mut ProtectedSourceDomainJournalOwnerV1,
        completed: &crate::OperatorStopCleanupRecoveryCompletedHandoffV1<'_>,
        subject: Subject,
        association: Association,
    ) -> Result<ControllerHostStopCleanupSourceLoanV1<'owner, 'source>> {
        let owner = slot.as_mut().ok_or(CLOSED)?;
        owner.enter_host_stop_cleanup_source_once_v1::<T>(
            controller, source, completed, subject, association)?;

        Ok(ControllerHostStopCleanupSourceLoanV1 { owner: slot, source })
    }

    fn enter_host_stop_cleanup_source_once_v1<T>(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        completed: &crate::OperatorStopCleanupRecoveryCompletedHandoffV1<'_>,
        subject: Subject,
        association: Association,
    ) -> Result<()> {
        if self.entered || self.cleanup.is_some() || self.host_entry.is_some()
            || self.source_preparation.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        if completed.target_operation_data_v1(controller)? != self.operation {
            return Err(CLOSED);
        }
        if completed.cleanup_subject_data_v1(controller, source)? != subject {
            return Err(CLOSED);
        }
        let (key, raw) = completed.admission_record_data_v1(controller)?;
        let data = Admission::decode_v1(raw).map_err(|_| CLOSED)?;
        let reference = Reference { key, commitment: finality_admission_commitment_v1(raw),
            original: data.original, cutoff: data.cutoff, wall_expiry: data.wall_expiry };
        if subject.recovery_operation_v1() != &data.operation
            || subject.cleanup_request_v1() != &association.cleanup_operation
            || subject.recovery_request_digest_v1() != &data.request_digest_v1()
            || subject.authorization_revision_v1() != &data.authorization_revision
            || subject.current_boot_v1() != &data.original.host_boot_id()
            || subject.original_cutoff_v1() != reference.cutoff
            || subject.digest_data_v1() != association.cleanup_subject_digest
        { return Err(CLOSED); }
        let (dispatch, _) = completed.stop_dispatch_data_v1(controller, source)?;
        if subject.historical_scope_v1().stop_v4() != dispatch.sdk_request_data_v1() {
            return Err(CLOSED);
        }
        {
            let bank = self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            completed.require_fresh_stop_cleanup_v1(&bank, controller, self.profile.as_ref(), source, &association)?;
        }
        let dispatch_record = completed.stop_dispatch_auxiliary_digest_data_v1(controller, source)?;
        self.prepare_cleanup_seed_once_v1::<T>(controller, source, completed, association, reference.original)?;
        self.cleanup = Some(Box::new(StopCleanupOriginalV1 {
            subject, association, dispatch_record, completion_entered: false, admission: reference, first: None, cutoff: None,
            frontier: ControllerExecutionClockOriginalV1::new(), frontier_result: None,
            owed_clock: None, models: None,
            complete: None, funding: None, posts: None, cold: None, cold_refusal: None,
            root_total: ResourceVector::ZERO,
            inventory: std::array::from_fn(|_| Default::default()),
            inventory_receipts: std::array::from_fn(|_| None), reentry: None,
            controller: controller.execution_observation_identity_v4(),
            host_horizon: None,
            stopped_generation: None,
            terminal: None,
        }));
        self.host_entry = Some((|| {
            let native = self.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
            let resident = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(CLOSED)?;
            self.host_turn.enter_cleanup_once_v1(self.operation, &self.bank, self.profile.as_ref(),
                native, resident, controller, source)
        })());
        if matches!(self.host_entry, Some(Ok(()))) {
            let cleanup = self.cleanup.as_mut().ok_or(CLOSED)?;
            cleanup.first = Some(self.host_turn.sample_data_v4());
            cleanup.cutoff = Some((|| {
                let first = *positive(&cleanup.first)?;
                reference.original.validate_same_boot_elapsed_data_v1(first).map_err(|_| CLOSED)?;
                let expiry = first.conservative_expiry_deadline_data_v1(reference.wall_expiry).ok_or(CLOSED)?;
                let cutoff = reference.cutoff.min(expiry);
                if first.boottime_nanoseconds() >= cutoff { return Err(CLOSED); }
                Ok(cutoff)
            })());
            cleanup.models = Some(self.host_turn.paid_models_v4());
            cleanup.complete = cleanup.models.as_ref().and_then(|value| value.as_ref().ok()).copied();
        }
        Ok(())
    }
}

impl<'owner, 'source> ControllerHostStopCleanupSourceLoanV1<'owner, 'source> {
    fn original(&self) -> Result<&StopCleanupOriginalV1> { held_owner(self.owner).cleanup.as_deref().ok_or(CLOSED) }

    pub(crate) fn require_inventory_ordinal_v1(&self, controller: &Journal, index: usize) -> Result<()> {
        self.require_current_v1(controller)?;
        let original = self.original()?;
        if index >= original.inventory.len()
            || !original.inventory[..index].iter().all(Inventory::is_completed_query_v2)
            || (index == 1 && !matches!(original.host_horizon, Some(Ok(_))))
        { return Err(CLOSED); }
        Ok(())
    }

    // The private common adapter validates the ordinal before construction.
    // Its actual Source22 loan cannot lose the paid Box or change that ordinal.
    pub(crate) fn state_v1(&self, index: usize) -> &Inventory {
        match held_owner(self.owner).cleanup.as_ref().and_then(|original| original.inventory.get(index)) {
            Some(state) => state,
            None => std::process::abort(),
        }
    }

    pub(crate) fn state_mut_v1(&mut self, index: usize) -> &mut Inventory {
        match held_owner_mut(self.owner).cleanup.as_mut().and_then(|original| original.inventory.get_mut(index)) {
            Some(state) => state,
            None => std::process::abort(),
        }
    }

    /// Borrows one finite Host3 query from this same live Source22 original.
    ///
    /// # Errors
    /// Refuses another ordinal, missing prior query, foreign cold native
    /// receiver, expired original horizon or unpayable complete representation.
    #[doc(hidden)]
    pub fn borrow_inventory_once_v1<'query>(&'query mut self,
        controller: &'query mut Journal, index: usize,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1, journal: &Journal,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<crate::ControllerRecoveryInventoryLoanV2<'query, 'owner, 'source, 'static, 'static>> {
        crate::controller_resource_reservation::borrow_stop_cleanup_source_inventory_once_v1(
            self, controller, index, receiving, journal, shape)
    }

    /// Rejoins the actual current Source22 native original and Controller owner.
    ///
    /// # Errors
    /// Refuses unfinished entry, failure, posts already begun or foreign custody.
    pub fn require_current_v1(&self, controller: &Journal) -> Result<()> {
        let owner = held_owner(self.owner);
        let original = owner.cleanup.as_deref().ok_or(CLOSED)?;
        if !matches!(owner.host_entry, Some(Ok(()))) || original.posts.is_some()
            || original.failure().is_some() || owner.failure_v4().is_some()
            || !original.controller.is_same_original_v4(&controller.execution_observation_identity_v4()) {
            return Err(CLOSED);
        }
        positive(&original.first)?;
        positive(&original.cutoff)?;
        let native = owner.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_lifecycle_stop_native_current_v4(native, controller, owner.profile.as_ref())?;
        self.source.journal_ref_v1().ensure_protected_authority()?;
        owner.host_turn.require_cleanup_source_current_v1(owner.operation,
            &owner.bank, owner.profile.as_ref(), native, controller,
            self.source.journal_ref_v1())?;
        Ok(())
    }

    /// Pays the cumulative co-resident receiver before further growth.
    ///
    /// # Errors
    /// Retains arithmetic, capacity and genuine native currentness refusals.
    pub fn reserve_additional_v1(&mut self, controller: &Journal, additional: ResourceVector) -> Result<()> {
        self.require_current_v1(controller)?;
        let owner = held_owner_mut(self.owner);
        let native = owner.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
        let original = owner.cleanup.as_mut().ok_or(CLOSED)?;
        let complete = original.complete.ok_or(CLOSED)?.checked_add(additional)?;
        original.funding = Some(owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_lifecycle_stop_complete_v4(native, controller, owner.profile.as_ref(), complete));
        positive(&original.funding)?;
        original.complete = Some(complete);
        Ok(())
    }

    /// Binds later Host turns to this actual held Root exchange's narrower D.
    ///
    /// # Errors
    /// Refuses another Source22/Root child, repeat binding or any query1 entry
    /// before binding. The original financial and cold Session D stay unchanged.
    #[doc(hidden)]
    pub fn bind_root_child_once_v1(&mut self, controller: &Journal,
        child: &crate::normal_root::RootStopCleanupChildLoanV1<'_>) -> Result<()> {
        self.require_current_v1(controller)?;
        if self.original()?.host_horizon.is_some()
            || self.state_v1(1).has_entered_query_v3()
            || self.original()?.inventory_receipts[1].is_some() {
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.reentry.get_or_insert(CLOSED);
            return Err(CLOSED);
        }
        let original_cutoff = *positive(&self.original()?.cutoff)?;
        let result = child.effective_cutoff_data_v1(self, controller)
            .map(|cutoff| RootHostHorizonV1 { cutoff: original_cutoff.min(cutoff) });
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.host_horizon = Some(result);
        self.original()?.host_horizon.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CLOSED)?;
        Ok(())
    }

    /// Returns the request-only Host D bound by the actual Root child.
    ///
    /// # Errors
    /// Refuses failed Source22 custody or a failed held Root binding.
    #[doc(hidden)]
    pub fn host_cutoff_data_v1(&self, controller: &Journal) -> Result<u64> {
        self.require_current_v1(controller)?;
        match self.original()?.host_horizon.as_ref() {
            None => positive(&self.original()?.cutoff).copied(),
            Some(Ok(bound)) => Ok(bound.cutoff),
            Some(Err(_)) => Err(CLOSED),
        }
    }

    /// Samples the same paid clock and checks the actual Host request horizon.
    ///
    /// # Errors
    /// Retains Source/native clock, expiry or narrower Root D refusal.
    #[doc(hidden)]
    pub fn host_check_frontier_v1(&mut self, controller: &Journal) -> Result<RawPairedClockSample> {
        let cutoff = self.host_cutoff_data_v1(controller)?;
        let sample = self.check_frontier_v1(controller)?;
        if sample.boottime_nanoseconds() >= cutoff {
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.reentry.get_or_insert(CLOSED);
            return Err(CLOSED);
        }
        Ok(sample)
    }

    pub(crate) fn require_completed_cleanup_host_horizon_v1(&self, controller: &Journal) -> Result<()> {
        self.require_current_v1(controller)?;
        let bound = self.original()?.host_horizon.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        self.state_v1(1).require_completed_cutoff_data_v3(bound.cutoff)
    }

    // Only the actual completed-query join returns this bound as comparison
    // DATA. Source A8's own sealed borrower still authorizes its native append.
    pub(crate) fn completed_cleanup_host_cutoff_data_v1(&self, controller: &Journal) -> Result<u64> {
        self.require_completed_cleanup_host_horizon_v1(controller)?;
        self.original()?.host_horizon.as_ref().and_then(|value| value.as_ref().ok())
            .map(|bound| bound.cutoff).ok_or(CLOSED)
    }

    /// Reads the current desired-Stopped generation from its protected target.
    ///
    /// The historical launch fence remains separate. The shared Sandbox
    /// decoder is paid before its first model, and subsequent callers compare
    /// the literal same protected row before reusing its generation DATA.
    ///
    /// # Errors
    /// Retains failed funding/decoding or a different project, Stop operation,
    /// Sandbox, lifecycle, zero generation or changed protected projection.
    #[doc(hidden)]
    pub fn current_desired_generation_data_v1(&mut self, controller: &Journal) -> Result<u64> {
        use aos_sandbox_protocol::public_api::projection::{
            PublicProjectionError, PublicProjectionKindV1, PublicProjectionResourceV1, projection_key,
        };
        use sha2::{Digest as _, Sha256};
        self.require_current_v1(controller)?;
        if self.original()?.stopped_generation.is_none() {
            let bytes = crate::controller_service::public_projection::sandbox_source_receiving_bytes_v1(controller)
                .ok_or(CLOSED)?;
            self.reserve_additional_v1(controller, ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
            let sandbox = *self.original()?.subject.historical_scope_v1().fence_v4().sandbox_id();
            let context = held_owner(self.owner).accepted.as_ref().and_then(|value| value.as_ref().ok())
                .and_then(Option::as_ref).ok_or(CLOSED)?;
            let project = context.project();
            let result = (|| {
                let projection = crate::controller_service::public_projection::PublicProjectionStoreV1::new(controller)
                    .get(PublicProjectionKindV1::Sandbox, sandbox)?
                    .ok_or(PublicProjectionError::CorruptRecord)?;
                let PublicProjectionResourceV1::Sandbox(public) = projection.resource() else {
                    return Err(PublicProjectionError::InvalidIdentity);
                };
                let desired = public.desired.as_option().ok_or(PublicProjectionError::CorruptRecord)?;
                if projection.operation() != held_owner(self.owner).operation || projection.project() != project
                    || public.project_id.as_slice() != project.as_bytes()
                    || public.sandbox_id.as_slice() != sandbox
                    || desired.lifecycle.as_known() != Some(
                        aos_sandbox_api::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_STOPPED)
                    || desired.generation == 0 {
                    return Err(PublicProjectionError::InvalidIdentity);
                }
                let key = projection_key(PublicProjectionKindV1::Sandbox, sandbox);
                let raw = controller.get(crate::RecordNamespace::DesiredState, &key)
                    .ok_or(PublicProjectionError::CorruptRecord)?;
                Ok(CurrentStoppedGenerationV1 { generation: desired.generation,
                    key, commitment: Sha256::digest(raw).into() })
            })();
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.stopped_generation = Some(result);
        }
        let captured = self.original()?.stopped_generation.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        let current = controller.get(crate::RecordNamespace::DesiredState, &captured.key);
        if current.map(|raw| <[u8; 32]>::from(Sha256::digest(raw))) != Some(captured.commitment) {
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.reentry.get_or_insert(CLOSED);
            return Err(CLOSED);
        }
        Ok(captured.generation)
    }

    /// Samples the genuine kernel clock under the immutable cleanup horizon.
    ///
    /// # Errors
    /// Retains boot, provenance, monotonicity, wall expiry and original D refusal.
    pub fn check_frontier_v1(&mut self, controller: &Journal) -> Result<RawPairedClockSample> {
        self.require_current_v1(controller)?;
        let original = held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?;
        original.frontier_result = Some((|| {
            let sample = original.frontier.sample_v1().map_err(|_| CLOSED)?;
            require_cleanup_clock(sample, *positive(&original.first)?,
                *positive(&original.cutoff)?, original.admission.wall_expiry)?;
            Ok(sample)
        })());
        positive(&original.frontier_result).copied()
    }

    /// Borrows the actual fresh first paired clock as comparison DATA.
    ///
    /// # Errors
    /// Refuses incomplete or failed current cleanup custody.
    pub fn original_clock_data_v1(&self, controller: &Journal) -> Result<RawPairedClockSample> {
        self.require_current_v1(controller)?;
        positive(&self.original()?.first).copied()
    }

    /// Returns the immutable fresh cleanup deadline ceiling.
    ///
    /// # Errors
    /// Refuses incomplete or failed current cleanup custody.
    pub fn original_cutoff_v1(&self, controller: &Journal) -> Result<u64> {
        self.require_current_v1(controller)?;
        positive(&self.original()?.cutoff).copied()
    }

    /// Borrows the exact strict456 subject without granting Host authority.
    ///
    /// # Errors
    /// Refuses incomplete or failed current cleanup custody.
    pub fn subject_data_v1(&self, controller: &Journal) -> Result<Subject> {
        self.require_current_v1(controller)?;
        Ok(self.original()?.subject)
    }

    /// Reads the selected Source parent from the retained protected Source model.
    ///
    /// The exact record must still match the genuine completed Recover/A7
    /// association used by this native Source22 entry. No supplied digest or
    /// historical receipt can substitute for that retained Source capture.
    ///
    /// # Errors
    /// Refuses changed original custody, Source parent or Stop selection.
    #[doc(hidden)]
    pub fn source_parent_data_v1(&self, controller: &Journal) -> Result<[u8; 32]> {
        self.require_current_v1(controller)?;
        let owner = held_owner(self.owner);
        let actual = owner.host_turn.cleanup_source_parent_data_v1(owner.operation)?;
        if actual != self.original()?.association.source_parent_digest { return Err(CLOSED); }
        Ok(actual)
    }

    /// Returns the immutable A7 record captured by this actual Source22 entry.
    ///
    /// # Errors
    /// Refuses another, disposed or failed current Source22/native original.
    pub(crate) fn stop_dispatch_commitment_data_v1(&self, controller: &Journal)
        -> Result<aos_sandbox_model::ObjectDigest> {
        self.require_current_v1(controller)?;
        Ok(self.original()?.dispatch_record)
    }

    /// Joins only a real completed Host3 query and its sole decoded body.
    ///
    /// The immutable receipt coordinates retain comparison DATA for Root.
    /// The actual SDK, native inventory originals and Source22 loan remain
    /// resident and independently required for final Source settlement.
    ///
    /// # Errors
    /// Refuses a foreign or repeated query, another decoded body, unsupported
    /// ordinal, advanced Session or failed original Source22 interval.
    #[doc(hidden)]
    pub fn require_completed_inventory_model_v1(&mut self, controller: &Journal,
        journal: &Journal,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        decoded: &aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::ControllerInventoryDecodedOriginalV2,
        index: usize, retained_prefix: bool,
    ) -> Result<()> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        use sha2::{Digest as _, Sha256};

        self.require_inventory_ordinal_v1(controller, index)?;
        if retained_prefix || self.original()?.inventory_receipts[index].is_some() {
            held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.reentry.get_or_insert(CLOSED);
            return Err(CLOSED);
        }
        let result = (|| {
            let method = aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME;
            let (request, session) = self.state_v1(index)
                .require_completed_inventory_model_v3(journal, outcome, decoded, method, false)?;
            if index == 1 { self.require_completed_cleanup_host_horizon_v1(controller)?; }
            if request == *self.original()?.subject.cleanup_request_v1() { return Err(CLOSED); }
            let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
                return Err(CLOSED);
            };
            Ok((request, session, Sha256::digest(outcome.request().canonical_packet()).into(),
                Sha256::digest(outcome.canonical_packet()).into(), Sha256::digest(exact_body).into()))
        })();
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.inventory_receipts[index] = Some(result);
        positive(&self.original()?.inventory_receipts[index]).map(|_| ())
    }

    /// Returns the saved coordinates of the same completed native Host3 query.
    ///
    /// # Errors
    /// Refuses another ordinal, missing actual model join or failed interval.
    #[doc(hidden)]
    pub fn completed_host_inventory_reference_data_v1(&self, controller: &Journal,
        index: usize) -> Result<QueryReference> {
        self.require_current_v1(controller)?;
        let original = self.original()?;
        let receipt = original.inventory_receipts.get(index).ok_or(CLOSED)?;
        positive(receipt).copied()
    }

    /// Runs all reached prepaid Source/C posts independently of the body.
    ///
    /// Positive native disposition remains a separate, purpose-closed step
    /// after actual SDK, connection, model and cold Session retirement.
    ///
    /// # Errors
    /// Retains an independent Source/C/clock refusal or repeated finish.
    pub fn finish_native_posts_once_v1(&mut self, controller: &mut Journal) -> Result<()> {
        if self.original()?.posts.is_some() { return Err(CLOSED); }
        let result = (|| {
            let owner = held_owner_mut(self.owner);
            let native = owner.native.as_mut()
                .and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
            owner.host_turn.finish_posts_once_v4(&owner.bank,
                owner.profile.as_ref(), native, controller, self.source)
        })();
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.posts = Some(result);
        positive(&self.original()?.posts).map(|_| ())
    }

    pub(crate) fn root_profile_v1(&self) -> &ProductionControllerNormalRootProfileV1 {
        held_owner(self.owner).profile.as_ref()
    }

    pub(crate) fn root_profile_arc_v1(&self) -> Arc<ProductionControllerNormalRootProfileV1> {
        Arc::clone(&held_owner(self.owner).profile)
    }

    pub(crate) fn capture_inventory_financial_original_v1(&self, controller: &Journal)
        -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1> {
        self.require_current_v1(controller)?;
        let owner = held_owner(self.owner);
        let native = owner.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .capture_stop_cleanup_source_affinity_v1(native, controller, owner.profile.as_ref())
    }

    pub(crate) fn require_same_inventory_financial_original_v1(&self,
        affinity: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerStopCleanupSourceAffinityV1,
        controller: &Journal) -> Result<()> {
        self.require_current_v1(controller)?;
        let owner = held_owner(self.owner);
        let native = owner.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_stop_cleanup_source_affinity_v1(native, affinity, controller, owner.profile.as_ref())
    }

    pub(crate) fn admit_root_transport_complete_v1(&mut self, controller: &Journal,
        cumulative_root: ResourceVector) -> Result<()> {
        let additional = cumulative_root.checked_sub(self.original()?.root_total)?;
        self.reserve_additional_v1(controller, additional)?;
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.root_total = cumulative_root;
        Ok(())
    }

    /// Prepares the genuine fresh Host receiver on this same Stop22 ledger.
    ///
    /// # Errors
    /// Retains repeated entry, expiry, financial or native receiver refusal.
    pub fn prepare_cold_session_once_v1(&mut self, controller: &Journal,
        shape: crate::ControllerInitialBrokerSessionShapeV1) -> Result<()> {
        self.check_frontier_v1(controller)?;
        if self.original()?.cold.is_some() { return Err(CLOSED); }
        let cutoff = *positive(&self.original()?.cutoff)?;
        let owner = held_owner_mut(self.owner);
        let native = owner.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
        let result = owner.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .prepare_stop_cleanup_source_session_v1(native, controller,
                Arc::clone(&owner.profile), shape, cutoff).map(Some);
        owner.cleanup.as_mut().ok_or(CLOSED)?.cold = Some(result);
        let receiver = positive(&self.original()?.cold)?.as_ref().ok_or(CLOSED)?;
        if receiver.failure().is_some() { return Err(CLOSED); }
        Ok(())
    }

    /// Moves only the actual prepared cold receiver without releasing its payer.
    ///
    /// # Errors
    /// Refuses a missing, failed, already taken or noncurrent actual receiver.
    pub fn take_cold_receiver_once_v1(&mut self, controller: &Journal)
        -> Result<crate::ControllerInitialBrokerSessionReceivingV1> {
        self.require_current_v1(controller)?;
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.cold.as_mut()
            .and_then(|value| value.as_mut().ok()).and_then(Option::take).ok_or(CLOSED)
    }

    /// Rejoins the same completed cold native receiver and protected Session.
    ///
    /// # Errors
    /// Refuses a foreign Source22 payer, native Session, original D or owner.
    pub fn require_completed_cold_session_v1(&self, controller: &Journal,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1, journal: &Journal) -> Result<()> {
        self.require_current_v1(controller)?;
        let native = held_owner(self.owner).native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        receiving.require_completed_stop_cleanup_source_journal_v1(native, journal,
            *positive(&self.original()?.cutoff)?)
    }

    /// Retains a failed upper cold flight without releasing or replacing custody.
    pub fn retain_cold_sdk_refusal_v1(&mut self) {
        if let Some(original) = held_owner_mut(self.owner).cleanup.as_mut() {
            original.cold_refusal.get_or_insert(CLOSED);
        }
    }

    /// Rejoins the real cold receiver before its finite private native work.
    ///
    /// # Errors
    /// Refuses a foreign receiver, changed Source22 original or closed payer.
    pub fn require_cold_session_original_v1(&self, controller: &Journal,
        receiving: &crate::ControllerInitialBrokerSessionReceivingV1) -> Result<()> {
        self.require_current_v1(controller)?;
        let native = held_owner(self.owner).native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        receiving.require_stop_cleanup_source_original_v1(native)
    }

    /// Runs the already paid cold clock post even after an upper body failure.
    ///
    /// # Errors
    /// Retains actual kernel, boot, continuity, wall expiry and original D
    /// refusal without a fresh healthy-body check or financial reentry.
    pub fn owed_clock_after_v1(&mut self, controller: &Journal) -> Result<RawPairedClockSample> {
        let original = held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?;
        if original.owed_clock.as_ref().is_some_and(std::result::Result::is_err) {
            return Err(CLOSED);
        }
        original.owed_clock = Some((|| {
            if !original.controller.is_same_original_v4(&controller.execution_observation_identity_v4()) {
                return Err(CLOSED);
            }
            let sample = original.frontier.sample_v1().map_err(|_| CLOSED)?;
            require_cleanup_clock(sample, *positive(&original.first)?,
                *positive(&original.cutoff)?, original.admission.wall_expiry)?;
            Ok(sample)
        })());
        positive(&original.owed_clock).copied()
    }

    pub(crate) fn recovery_admission_data_v1(&self, controller: &Journal) -> Result<Reference> {
        self.require_current_v1(controller)?;
        Ok(self.original()?.admission)
    }

    /// Borrows the retained financial, Source and native cause without new IO.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let owner = held_owner(self.owner);
        owner.cleanup.as_deref().and_then(StopCleanupOriginalV1::selected_terminal_failure)
            .or_else(|| owner.failure_v4())
            .or_else(|| owner.cleanup.as_deref()?.failure())
    }
}

fn positive<T>(value: &Option<Result<T>>) -> Result<&T> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)
}

fn error<T, E: Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn require_cleanup_clock(sample: RawPairedClockSample, first: RawPairedClockSample,
    cutoff: u64, wall_expiry: i64) -> Result<()> {
    first.validate_later_sample(sample).map_err(|_| CLOSED)?;
    if sample.boottime_nanoseconds() >= cutoff || sample.wall_seconds() >= wall_expiry {
        return Err(CLOSED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::RawClockProvenance;

    fn pair(boot: u8, wall: i64, elapsed: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [boot; 16], wall, elapsed).unwrap()
    }

    #[test]
    fn fresh_stop_clock_refuses_expiry_while_original_boottime_is_live() {
        let first = pair(1, 100, 1_000_000_000);
        let later = pair(1, 101, 1_500_000_000);
        assert!(require_cleanup_clock(later, first, 3_000_000_000, 110).is_ok());
        assert!(require_cleanup_clock(later, first, 3_000_000_000, 101).is_err());
        assert!(require_cleanup_clock(later, first, 1_500_000_000, 110).is_err());
        assert!(require_cleanup_clock(pair(2, 101, 1_500_000_000), first, 3_000_000_000, 110).is_err());
        assert!(require_cleanup_clock(pair(1, 99, 2_000_000_000), first, 3_000_000_000, 110).is_err());
    }
}
