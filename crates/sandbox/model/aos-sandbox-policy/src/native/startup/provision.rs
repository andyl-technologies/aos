//! Retains the real startup journal, credentials and listener receiving stages.
//!
//! Completed loans borrow this same sequence and actual Initial. The private
//! stage engine shares accounting and service observation without accepting a
//! completed result, account high-water, or caller-selected cumulative prefix.

use std::error::Error;
use std::sync::Arc;

mod peer;
pub use peer::{RootControllerPeerProvisionOriginalV1, RootCurrentWritersPredecessorV1, RootStartupControllerPeerOriginalV1};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::{
    RootInitialReceivingOriginalV1, RootJournalFinancialOriginalV1, RootObservationErrorV1,
    RootPrearmedHistoryServicePostV1, RootSelectedProvisionBorrowV1, RootSelectedStartupBorrowV1,
    RootStartupServicePostErrorV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::ResourceVector;

use super::{RootStartupJournalErrorV1, RootStartupJournalOriginalV1, StartupJournalStorageV1};
use crate::native::PolicyNativeJournalErrorV1;

/// Retains actual native receiving and representation failures.
#[derive(Debug, thiserror::Error)]
pub enum RootStartupProvisionErrorV1 {
    /// Preserves the original selected-service or association error.
    #[error(transparent)]
    Root(#[from] RootObservationErrorV1),
    /// Preserves the actual canonical twelve-read geometry refusal.
    #[error(transparent)]
    Schema(#[from] crate::signed_inputs::startup_credentials::RootStartupCredentialGeometryErrorV1),
    /// Preserves the native journal or representation cause.
    #[error(transparent)]
    Native(#[from] PolicyNativeJournalErrorV1),
}

impl RootStartupProvisionErrorV1 {
    fn closed() -> Self {
        Self::Root(RootObservationErrorV1::Service)
    }
}

/// Owns the original selected journal-to-listener receiving sequence.
///
/// The fixed startup journal remains a separate actual owner and is released
/// at its original successful disposal boundary. This sequence moves intact
/// into the receiving role; it neither borrows nor reopens that old journal.
pub struct RootStartupProvisionOriginalV1 {
    financial: RootJournalFinancialOriginalV1,
    selected: Result<ResourceVector, RootObservationErrorV1>,
    journal: Option<JournalStageV1>,
    credentials: Option<ServiceStageV1>,
    credential_names: Option<Result<(), RootStartupJournalErrorV1>>,
    listener: Option<ServiceStageV1>,
}

#[derive(Default)]
pub(in crate::native) struct ServiceStageV1 {
    permit: Option<Result<ResourceVector, RootStartupProvisionErrorV1>>,
    post: Option<Result<RootPrearmedHistoryServicePostV1, RootStartupServicePostErrorV1>>,
    before: Option<Result<(), RootObservationErrorV1>>,
    currentness_failure:
        Option<aos_sandbox_broker::receiving::RootSelectedCurrentnessFailureOriginalV1>,
    after: Option<Result<(), RootObservationErrorV1>>,
}

#[derive(Default)]
struct JournalStageV1 {
    service: ServiceStageV1,
    native: Option<Result<(), RootStartupJournalErrorV1>>,
    variable: Option<Result<ResourceVector, RootStartupProvisionErrorV1>>,
    before_replay: Option<Result<(), RootObservationErrorV1>>,
    replay: Option<Result<(), RootStartupJournalErrorV1>>,
}

impl ServiceStageV1 {
    pub(in crate::native) fn stage_once(
        &mut self,
        demand: Result<ResourceVector, RootStartupProvisionErrorV1>,
        financial: &RootJournalFinancialOriginalV1,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        self.permit = Some(demand.and_then(|demand| {
            financial
                .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
                .map_err(|_| PolicyNativeJournalErrorV1::Financial(financial.clone()))?;
            Ok(demand)
        }));
    }

    pub(in crate::native) fn before_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
        owed: bool,
    ) {
        if !matches!(self.permit, Some(Ok(_))) {
            return;
        }
        if owed {
            self.arm_owed_once(initial, startup, exclusion);
            if !self.post_armed_v1() {
                return;
            }
        }
        self.before = Some(startup.recheck_under_upper_exclusion_v1(exclusion));
        if !matches!(self.before, Some(Ok(()))) {
            self.currentness_failure = startup.failure_original_v1();
        }
    }

    pub(in crate::native) fn arm_owed_once(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        if self.post.is_some() {
            return;
        }
        self.post = Some(startup.arm_paid_startup_service_post_once_v1(initial, exclusion));
    }

    pub(in crate::native) fn post_armed_v1(&self) -> bool {
        matches!(self.post, Some(Ok(_)))
    }

    pub(in crate::native) fn before_positive_v1(&self) -> bool {
        matches!(self.before, Some(Ok(())))
    }

    pub(in crate::native) fn post_positive_v1(&self) -> bool {
        matches!(self.after, Some(Ok(()))) && self.failure().is_none()
    }

    pub(in crate::native) fn permit_data_v1(&self) -> Option<ResourceVector> {
        self.permit.as_ref()?.as_ref().ok().copied()
    }

    pub(in crate::native) fn finish_owed_once(
        &mut self,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) {
        if self.after.is_some() {
            return;
        }
        if let Some(Ok(post)) = self.post.as_mut() {
            self.after =
                Some(startup.observe_owed_service_post_under_upper_exclusion_v1(exclusion, post));
        }
    }

    pub(in crate::native) fn retire_positive(&mut self) {
        if let Some(Ok(post)) = self.post.as_mut() {
            post.retire_positive_once_v1();
        }
    }

    pub(in crate::native) fn prefix(&self) -> Option<ResourceVector> {
        if !matches!(self.before, Some(Ok(()))) {
            return None;
        }
        self.permit.as_ref()?.as_ref().ok().copied()
    }

    pub(in crate::native) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.permit
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.currentness_failure
                    .as_ref()
                    .map(|cause| cause as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.before
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.post
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(RootPrearmedHistoryServicePostV1::failure)
            })
            .or_else(|| {
                self.after
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

impl RootStartupProvisionOriginalV1 {
    /// Creates inert stage custody from the same real selected provision.
    #[must_use]
    pub fn new_selected_v1(original: &RootSelectedProvisionBorrowV1<'_>) -> Self {
        Self {
            financial: original.financial_original_v1().clone(),
            selected: original.selected_prefix_data_v1(),
            journal: None,
            credentials: None,
            credential_names: None,
            listener: None,
        }
    }

    fn require_initial(&self, initial: &RootInitialReceivingOriginalV1) -> Result<(), ()> {
        if initial.failure().is_some()
            || !initial
                .financial_diagnostic_original_v1()
                .as_ref()
                .is_some_and(|actual| actual.same_original_data_v1(&self.financial))
        {
            return Err(());
        }
        Ok(())
    }

    fn completed_credentials(&self) -> Option<ResourceVector> {
        let stage = self.credentials.as_ref()?;
        if !matches!(self.credential_names, Some(Ok(())))
            || !matches!(stage.after, Some(Ok(())))
            || stage.failure().is_some()
        {
            return None;
        }
        stage.prefix()
    }

    fn completed_listener(&self) -> Option<ResourceVector> {
        let stage = self.listener.as_ref()?;
        if stage.failure().is_some() {
            return None;
        }
        stage.prefix()
    }

    /// Borrows only this same receiving sequence's retained first cause.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static))
            };
        }
        if let Err(cause) = &self.selected {
            return Some(cause);
        }
        if let Some(stage) = &self.journal {
            let failure = stage
                .service
                .permit
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| {
                    stage
                        .service
                        .currentness_failure
                        .as_ref()
                        .map(|cause| cause as &(dyn Error + 'static))
                })
                .or_else(|| cause!(stage.service.before))
                .or_else(|| cause!(stage.native))
                .or_else(|| cause!(stage.variable))
                .or_else(|| cause!(stage.before_replay))
                .or_else(|| cause!(stage.replay))
                .or_else(|| stage.service.failure());
            if failure.is_some() {
                return failure;
            }
        }
        if let Some(stage) = &self.credentials {
            let failure = cause!(stage.permit)
                .or_else(|| cause!(stage.post))
                .or_else(|| {
                    stage
                        .currentness_failure
                        .as_ref()
                        .map(|cause| cause as &(dyn Error + 'static))
                })
                .or_else(|| cause!(stage.before))
                .or_else(|| cause!(self.credential_names))
                .or_else(|| {
                    stage
                        .post
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .and_then(RootPrearmedHistoryServicePostV1::failure)
                })
                .or_else(|| cause!(stage.after));
            if failure.is_some() {
                return failure;
            }
        }
        self.listener.as_ref().and_then(ServiceStageV1::failure)
    }
}

/// Borrows the same completed listener and its actual mutable Initial.
///
/// Only the real sequence constructs this lender. Neither layout DATA nor an
/// externally supplied successful result can manufacture its private fields.
pub struct RootCompletedPolicyListenerBorrowV1<'owner, 'initial> {
    original: &'owner RootStartupProvisionOriginalV1,
    initial: &'initial mut RootInitialReceivingOriginalV1,
    completed: &'owner RootCompletedPolicyListenerOriginalV1,
}

impl RootCompletedPolicyListenerBorrowV1<'_, '_> {
    /// Reborrows the same Initial for the next real physical receiving stage.
    pub fn initial_mut_v1(&mut self) -> &mut RootInitialReceivingOriginalV1 {
        self.initial
    }

    /// Borrows the existing same financial allocation without constructing one.
    #[must_use]
    pub fn financial_original_v1(&self) -> &RootJournalFinancialOriginalV1 {
        &self.original.financial
    }

    /// Copies only this real completed listener's original cumulative permit.
    ///
    /// # Errors
    /// Refuses a later actual failure or unavailable same-original completion.
    pub fn completed_prefix_data_v1(&self) -> Result<ResourceVector, RootObservationErrorV1> {
        self.original
            .require_initial(self.initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        self.original
            .completed_listener()
            .ok_or(RootObservationErrorV1::Service)
    }
}

impl RootStartupProvisionOriginalV1 {
    /// Receives the actual selected startup journal under the original exclusion.
    ///
    /// # Errors
    /// Retains actual fixed, native, semantic, replay and service errors. Its
    /// independently prearmed post executes after every returned body refusal.
    pub fn receive_selected_journal_once_v1(
        &mut self,
        actual: &mut RootStartupJournalOriginalV1,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        let fixed = RootStartupJournalOriginalV1::selected_fixed_preparation_demand_v1();
        let StartupJournalStorageV1::Selected(journal) = &mut actual.storage else {
            initial.latch_root_refusal_v1();
            return Err(());
        };
        let owner = self;
        if !journal.financial.same_original_data_v1(&owner.financial) {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        if owner.journal.is_some()
            || owner.require_initial(initial).is_err()
            || !startup.same_financial_original_data_v1(&owner.financial)
        {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        owner.journal = Some(JournalStageV1::default());
        let stage = owner.journal.as_mut().ok_or(())?;
        let demand = owner
            .selected
            .as_ref()
            .map_err(|cause| RootStartupProvisionErrorV1::Root(*cause))
            .and_then(|base| {
                base.checked_add(fixed?)
                    .map_err(|_| RootStartupProvisionErrorV1::closed())
            });
        stage
            .service
            .stage_once(demand, &owner.financial, exclusion);
        stage.service.before_once(initial, startup, exclusion, true);
        if matches!(stage.service.before, Some(Ok(()))) {
            stage.native = Some(journal.prepare_once_v1(initial));
            if matches!(stage.native, Some(Ok(()))) {
                stage.variable = Some((|| {
                    journal.extent_v1().ok_or_else(RootStartupProvisionErrorV1::closed)?;
                    let [native, semantic, index] = journal.variable_components_v1()?;
                    let fixed = stage
                        .service
                        .permit
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or_else(RootStartupProvisionErrorV1::closed)?;
                    let demand = fixed
                        .checked_add(native)
                        .and_then(|demand| demand.checked_add(semantic))
                        .and_then(|demand| demand.checked_add(index))
                        .map_err(|_| RootStartupProvisionErrorV1::closed())?;
                    owner
                        .financial
                        .require_receiving_demand_under_upper_exclusion_v1(exclusion, demand)
                        .map_err(|_| {
                            PolicyNativeJournalErrorV1::Financial(owner.financial.clone())
                        })?;
                    Ok(demand)
                })());
                if matches!(stage.variable, Some(Ok(_))) {
                    stage.before_replay = Some(startup.recheck_under_upper_exclusion_v1(exclusion));
                    if !matches!(stage.before_replay, Some(Ok(()))) {
                        stage.service.currentness_failure = startup.failure_original_v1();
                    }
                    if matches!(stage.before_replay, Some(Ok(()))) {
                        journal.replay_once_v1();
                        stage.replay = Some(if journal.replay_ready_data_v1() {
                            Ok(())
                        } else {
                            Err(RootStartupJournalErrorV1::Closed)
                        });
                    }
                }
            }
        }
        if matches!(stage.service.post, Some(Ok(_))) {
            journal.finish_receiving_names_once_v1();
            stage.service.finish_owed_once(startup, exclusion);
        }
        if matches!(stage.replay, Some(Ok(())))
            && matches!(stage.service.after, Some(Ok(())))
            && journal.replay_ready_data_v1()
        {
            stage.service.retire_positive();
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(())
        }
    }

    /// Prepays the same actual credential interval before its fixed twelve reads.
    ///
    /// # Errors
    /// Retains missing original replay, prior failure, reentry, actual geometry,
    /// Stage denial or selected service refusal on this same owner.
    pub fn begin_selected_credentials_once_v1(
        &mut self,
        actual: &RootStartupJournalOriginalV1,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        let append = actual.selected_credential_append_peak_v1();
        let schema = crate::signed_inputs::startup_credentials::fixed_root_credential_demand_v1();
        let owner = self;
        if owner.credentials.is_some()
            || owner.require_initial(initial).is_err()
            || !startup.same_financial_original_data_v1(&owner.financial)
            || !matches!(&actual.storage, StartupJournalStorageV1::Selected(journal) if journal.replay_ready_data_v1() && journal.financial.same_original_data_v1(&owner.financial))
        {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        let base = owner
            .journal
            .as_ref()
            .and_then(|stage| stage.variable.as_ref())
            .and_then(|result| result.as_ref().ok())
            .copied();
        owner.credentials = Some(ServiceStageV1::default());
        let stage = owner.credentials.as_mut().ok_or(())?;
        let demand = (|| {
            let append = append?;
            let schema = schema?;
            base.ok_or_else(RootStartupProvisionErrorV1::closed)?
                .checked_add(append)
                .and_then(|demand| demand.checked_add(schema))
                .map_err(|_| RootStartupProvisionErrorV1::closed())
        })();
        stage.stage_once(demand, &owner.financial, exclusion);
        stage.before_once(initial, startup, exclusion, true);
        if matches!(stage.before, Some(Ok(()))) {
            return Ok(());
        }
        stage.finish_owed_once(startup, exclusion);
        initial.latch_root_refusal_v1();
        Err(())
    }

    /// Completes the old names-then-independent-service credential bookend.
    ///
    /// # Errors
    /// Retains both actual results after prior body refusal. Only a wholly
    /// positive interval retires its prearmed sampler and lends the next stage.
    pub fn finish_selected_credentials_once_v1(
        &mut self,
        actual: &mut RootStartupJournalOriginalV1,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        let StartupJournalStorageV1::Selected(journal) = &mut actual.storage else {
            initial.latch_root_refusal_v1();
            return Err(());
        };
        let owner = self;
        if !journal.financial.same_original_data_v1(&owner.financial) {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        let Some(stage) = owner.credentials.as_mut() else {
            initial.latch_root_refusal_v1();
            return Err(());
        };
        if owner.credential_names.is_some() || stage.after.is_some() {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        owner.credential_names = Some(journal.finish_names_once_v1());
        stage.finish_owed_once(startup, exclusion);
        if matches!(owner.credential_names, Some(Ok(())))
            && matches!(stage.after, Some(Ok(())))
            && stage.prefix().is_some()
            && stage.failure().is_none()
        {
            stage.retire_positive();
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(())
        }
    }

    /// Stages this genuine completed credential sequence's fixed listener once.
    ///
    /// # Errors
    /// Refuses absent completion, layout or same-original association, reentry,
    /// actual Stage denial or its original one selected-service observation.
    pub fn begin_selected_listener_once_v1(
        &mut self,
        initial: &mut RootInitialReceivingOriginalV1,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        let owner = self;
        if owner.listener.is_some()
            || owner.require_initial(initial).is_err()
            || !startup.same_financial_original_data_v1(&owner.financial)
        {
            initial.latch_root_refusal_v1();
            return Err(());
        }
        let base = owner.completed_credentials();
        owner.listener = Some(ServiceStageV1::default());
        let stage = owner.listener.as_mut().ok_or(())?;
        let demand = (|| {
            let base = base.ok_or_else(RootStartupProvisionErrorV1::closed)?;
            let fixed = initial
                .policy_listener_layout_data_v1()
                .ok_or_else(RootStartupProvisionErrorV1::closed)?;
            let receiving = Self::completed_listener_construction_demand_v1()?;
            base.checked_add(fixed)
                .and_then(|demand| demand.checked_add(receiving))
                .map_err(|_| RootStartupProvisionErrorV1::closed())
        })();
        stage.stage_once(demand, &owner.financial, exclusion);
        stage.before_once(initial, startup, exclusion, false);
        if stage.prefix().is_some() {
            Ok(())
        } else {
            initial.latch_root_refusal_v1();
            Err(())
        }
    }

    /// Transfers only this whole positive listener sequence into resident custody.
    ///
    /// The earlier listener Stage pays this actual allocation and its control
    /// planes before construction. The separately held startup journal can end
    /// at its original successful scope; no borrow of its lock is retained.
    ///
    /// # Errors
    /// Returns this entire unchanged owner if real completion or association is
    /// missing; no failed prefix is disposed merely to expose a unit marker.
    pub fn complete_listener_into_original_v1(
        self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<RootCompletedPolicyListenerOriginalV1, Self> {
        if self.require_initial(initial).is_err()
            || self.completed_listener().is_none()
            || self.failure_v1().is_some()
        {
            return Err(self);
        }
        Ok(RootCompletedPolicyListenerOriginalV1 {
            original: Arc::new(self),
        })
    }
}

/// Owns the same completed listener sequence outside receiving mutex guards.
///
/// The private allocation is issued once by the actual completed producer.
/// Clones retain that original; they cannot create a new receiving or financial
/// account and all later loans rejoin the same real Initial.
pub struct RootCompletedPolicyListenerOriginalV1 {
    original: Arc<RootStartupProvisionOriginalV1>,
}

impl Clone for RootCompletedPolicyListenerOriginalV1 {
    fn clone(&self) -> Self {
        Self {
            original: Arc::clone(&self.original),
        }
    }
}

impl RootCompletedPolicyListenerOriginalV1 {
    /// Borrows actual completion and the same mutable Initial for one stage.
    ///
    /// # Errors
    /// Refuses later failure, unavailable completion or a different original.
    pub fn borrow_initial_v1<'owner, 'initial>(
        &'owner self,
        initial: &'initial mut RootInitialReceivingOriginalV1,
    ) -> Result<RootCompletedPolicyListenerBorrowV1<'owner, 'initial>, RootObservationErrorV1> {
        self.original
            .require_initial(initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        if self.original.completed_listener().is_none() || self.original.failure_v1().is_some() {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(RootCompletedPolicyListenerBorrowV1 {
            original: &self.original,
            initial,
            completed: self,
        })
    }

    /// Borrows the same existing financial allocation without a new account.
    #[must_use]
    pub fn financial_original_v1(&self) -> &RootJournalFinancialOriginalV1 {
        &self.original.financial
    }
}

impl RootStartupProvisionOriginalV1 {
    /// Quotes the actual whole-sequence resident allocation and owning handoffs.
    ///
    /// # Errors
    /// Refuses checked allocation/control representation overflow before Stage.
    pub fn completed_listener_construction_demand_v1()
    -> Result<ResourceVector, PolicyNativeJournalErrorV1> {
        use std::mem::{align_of, size_of};
        let bytes = size_of::<Self>()
            .checked_add(size_of::<usize>() * 2)
            .and_then(|bytes| bytes.checked_add(align_of::<Self>().checked_sub(1)?))
            .and_then(|bytes| {
                bytes
                    .checked_add(size_of::<RootCompletedPolicyListenerOriginalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    size_of::<Result<RootCompletedPolicyListenerOriginalV1, Self>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(size_of::<Arc<Self>>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(PolicyNativeJournalErrorV1::geometry)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes))
    }
}

impl RootStartupProvisionOriginalV1 {
    /// Quotes finite native stage and loan controls before original profile entry.
    ///
    /// This scalar creates no permit. Actual frame/model/path backing and the
    /// shared service-post Native debt retain their separate reached suppliers.
    #[must_use]
    pub fn additional_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        size_of::<Self>().checked_mul(2)?
            .checked_add(crate::native::journal::RootPolicyJournalConstructionOriginalV1::diagnostic_control_bytes_v1()?)?
            .checked_add(size_of::<&super::RootSelectedStartupJournalOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&(dyn std::error::Error + 'static)>>().checked_mul(18)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?

            .checked_add(aos_sandbox_broker::receiving::RootStartupNativeOriginalV1::selected_original_borrow_control_bytes_v1()?)?
            .checked_add(size_of::<aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>().checked_mul(3)?)?
            .checked_add(size_of::<aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1>().checked_mul(3)?)?
            .checked_add(size_of::<PolicyNativeJournalErrorV1>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(&Self, &RootInitialReceivingOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<(&RootCompletedPolicyListenerOriginalV1, &RootInitialReceivingOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<RootStartupJournalOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<super::RootSelectedStartupJournalOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<crate::native::journal::RootPolicyJournalConstructionOriginalV1>().checked_mul(2)?)?
            .checked_add(size_of::<RootJournalFinancialOriginalV1>().checked_mul(3)?)?
            .checked_add(size_of::<RootSelectedProvisionBorrowV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootSelectedProvisionBorrowV1<'_>, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<JournalStageV1>().checked_mul(2)?)?
            .checked_add(size_of::<ServiceStageV1>().checked_mul(8)?)?
            .checked_add(size_of::<RootCompletedPolicyListenerBorrowV1<'static, 'static>>().checked_mul(3)?)?
            .checked_add(size_of::<RootCurrentWritersPredecessorV1<'static, 'static, 'static>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootCompletedPolicyListenerBorrowV1<'static, 'static>, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootCurrentWritersPredecessorV1<'static, 'static, 'static>, RootObservationErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut Self, &mut RootStartupJournalOriginalV1, &mut RootInitialReceivingOriginalV1,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(9)?)?
            .checked_add(size_of::<(&mut Self, &mut RootInitialReceivingOriginalV1,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&mut ServiceStageV1, &RootJournalFinancialOriginalV1,
                &RootUpperMutationGuardV1<'_>, Result<ResourceVector, RootStartupProvisionErrorV1>)>().checked_mul(12)?)?
            .checked_add(size_of::<(&mut ServiceStageV1, &mut RootInitialReceivingOriginalV1,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>, bool)>().checked_mul(12)?)?
            .checked_add(size_of::<(&mut ServiceStageV1, &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(12)?)?
            .checked_add(size_of::<Result<ResourceVector, RootStartupProvisionErrorV1>>().checked_mul(18)?)?
            .checked_add(size_of::<Result<ResourceVector, PolicyNativeJournalErrorV1>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<ResourceVector, RootObservationErrorV1>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<ResourceVector, crate::signed_inputs::startup_credentials::RootStartupCredentialGeometryErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<RootPrearmedHistoryServicePostV1, RootStartupServicePostErrorV1>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(24)?)?
            .checked_add(size_of::<Result<(), RootStartupJournalErrorV1>>().checked_mul(12)?)?
            .checked_add(size_of::<Result<(), ()>>().checked_mul(18)?)?
            .checked_add(size_of::<Result<(), aos_sandbox_broker::receiving::RootFinancialClosedV1>>().checked_mul(18)?)?
            .checked_add(size_of::<Option<ResourceVector>>().checked_mul(15)?)?
            .checked_add(size_of::<Option<RootJournalFinancialOriginalV1>>().checked_mul(9)?)?
            .checked_add(size_of::<Option<aos_sandbox_broker::receiving::RootSelectedCurrentnessFailureOriginalV1>>().checked_mul(6)?)?
            .checked_add(size_of::<Option<aos_sandbox_broker::receiving::ObservationLifetimeV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<usize, std::num::TryFromIntError>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<ResourceVector, aos_sandbox_model::AccountingError>>().checked_mul(24)?)?
            .checked_add(size_of::<ResourceVector>().checked_mul(30)?)?
            .checked_add(size_of::<bool>().checked_mul(24)?)?
            .checked_add(size_of::<(&mut ServiceStageV1, &mut RootInitialReceivingOriginalV1,
                &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?)?
            .checked_add(size_of::<(&ServiceStageV1, bool, Option<ResourceVector>)>().checked_mul(12)?)?
            .checked_add(RootSelectedStartupBorrowV1::held_exclusion_control_bytes_v1()?)?
            .checked_add(RootSelectedStartupBorrowV1::startup_provision_forwarding_control_bytes_v1()?)
    }
}

impl RootStartupProvisionOriginalV1 {
    /// Requires this actual same-Initial credential interval to remain entered.
    ///
    /// # Errors
    /// Refuses earlier failure, missing paid before, or an already-ended interval.
    pub fn require_selected_credentials_receiving_v1(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<(), RootObservationErrorV1> {
        self.require_initial(initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        let stage = self
            .credentials
            .as_ref()
            .ok_or(RootObservationErrorV1::Service)?;
        if self.failure_v1().is_some()
            || !matches!(stage.permit, Some(Ok(_)))
            || !matches!(stage.before, Some(Ok(())))
            || self.credential_names.is_some()
            || stage.after.is_some()
        {
            return Err(RootObservationErrorV1::Service);
        }
        Ok(())
    }
}

impl RootCompletedPolicyListenerOriginalV1 {
    /// Copies the same whole completed listener's original prefix for old callers.
    ///
    /// # Errors
    /// Refuses a foreign Initial or any actual same-original receiving failure.
    pub fn completed_prefix_data_v1(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<ResourceVector, RootObservationErrorV1> {
        self.original
            .require_initial(initial)
            .map_err(|()| RootObservationErrorV1::Service)?;
        self.original
            .completed_listener()
            .ok_or(RootObservationErrorV1::Service)
    }
}
