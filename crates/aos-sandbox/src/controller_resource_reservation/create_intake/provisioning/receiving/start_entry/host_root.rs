//! Borrows a genuine new Start native interval for its separate Host Root flight.
//!
//! The completed Create intake lends historical original inputs only. Its old
//! clock, J/U, Root6 financial scope and C23 receiver never fund this purpose.
//! Currentness and all receiving extend the actual NEW Start native original.

use super::*;
use crate::CreateContinuationIntakeAttemptV1;
use super::super::super::CreateStorageCompletedIntakeOriginalV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1;

/// Borrows only the actual new Start native owner and its historical originals.
///
/// The private constructor belongs to the retained Start entry. No byte model,
/// amount, external profile, or caller-selected horizon can create this loan.
#[doc(hidden)]
pub struct OriginalStartHostRootLoanV1<'turn, 'intake> {
    pub(super) native: &'turn mut StartNativeStateV1,
    pub(super) identity: &'turn Arc<()>,
    pub(super) plan: &'turn Arc<crate::OperationPlan>,
    pub(super) authorization: &'turn crate::public_mutation_compiler::AuthorizedPublicMutationRequestV1,
    pub(super) source: &'turn Journal,
    pub(super) source_origin: &'turn source_origin::StartSourceOriginOriginalV1,
    origin: StartNativeOriginDataV1,
    completed: CreateStorageCompletedIntakeOriginalV1<'intake>,
    ownership: Option<&'turn super::StartOwnershipOriginalV1>,
    assignment: &'turn super::assignment::StartAssignmentOriginalV2,
    pub(super) resident_base:ResourceVector,
    host_stage: &'turn resource_state::StartResourceEntryOriginalV2,
}

impl<'turn, 'intake> OriginalStartHostRootLoanV1<'turn, 'intake> {
    pub(crate) fn resource_completion_native_demand_v2(&self, controller: &Journal)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        crate::journal::StartResourceNativePositionsOriginalV2::receiving_demand_v2(
            controller, self.source).map_err(ResourceReservationErrorV1::Journal)
    }

    pub(crate) fn observe_resource_completion_positions_v2(&self, controller: &Journal,
        positions: &mut crate::journal::StartResourceNativePositionsOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        positions.observe_once_v2(controller, self.source)
            .map_err(ResourceReservationErrorV1::Journal)
    }

    pub(crate) fn retained_resource_identity_v2(&self) -> Arc<()> {
        Arc::clone(self.identity)
    }

    pub(crate) fn require_current_v1(&self,controller:&Journal)
        ->Result<(),ResourceReservationErrorV1> {
        self.native.require_current_v1(controller)?;
        self.plan.require_accepted_start_data_v1(controller).map_err(|_|CLOSED)?;
        controller.require_public_mutation_targets_live_v2(
            self.authorization.project(), self.authorization.request().request(),
        ).map_err(ResourceReservationErrorV1::Journal)?;
        self.source_origin.require_completed_source_affinity_v1(self.source)?;
        self.completed.require_current_v1()?;
        if self.completed.operation_v1()!=self.native.create_parent {
            return Err(CLOSED);
        }
        let (manifest,_,_)=self.completed.publication_material_v1()?;
        let q04=self.native.q04_v1()?;
        if manifest.manifest().project()!=q04.project()
            || manifest.manifest().sandbox()!=q04.sandbox()
            || self.plan.accepted_start_origin_data_v1()!=Some(self.origin.accepted_v1()) {
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn require_complete_v1(&mut self,controller:&Journal,reached:ResourceVector)
        ->Result<(),ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        let complete=self.resident_base.checked_add(reached)?
            .checked_add(self.native.resources.retained_demand_v2(self.native.native_turn)?)?;
        let native=self.native.native.as_mut().and_then(|value|value.as_mut().ok()).ok_or(CLOSED)?;
        self.native.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_create_provisioning_complete_v1(native.original_mut_v1(),controller,
                self.native.profile.as_ref(),complete)
    }

    pub(crate) fn native_turn_v1(&self) -> u64 { self.native.native_turn }

    pub(crate) fn parent_operation_v1(&self)->aos_sandbox_core::OperationId {
        self.plan.operation_id()
    }

    pub(crate) fn original_horizon_v1(&self)->(RawPairedClockSample,u64) {
        (self.origin.first_native_clock_v1(),self.origin.cutoff_v1())
    }

    pub(crate) fn original_wall_expiry_v1(&self)->Result<i64,ResourceReservationErrorV1> {
        self.origin.accepted_v1().original_wall_expiry_v1().ok_or(CLOSED)
    }

    pub(crate) fn profile_v1(&self)->&ProductionControllerNormalRootProfileV1 {
        self.native.profile.as_ref()
    }

    pub(crate) fn retained_profile_v1(&self)->Arc<ProductionControllerNormalRootProfileV1> {
        Arc::clone(&self.native.profile)
    }

    pub(crate) fn failure_v1(&self)->Option<&(dyn Error+'static)> {
        self.native.failure().or_else(||self.native.native_failure_v1())
    }

    pub(crate) fn require_original_input_data_v1(&self,controller:&Journal,ready:&[u8],
        preparation:&AuthenticatedBrokerMethodOutcomeV1,
    )->Result<(),ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        self.completed.require_storage_apply_inputs_v1(ready,preparation)
    }

    pub(crate) fn historical_ownership_lease_v1(&self)
        ->Result<&'intake aos_sandbox_ownership_protocol::SignedOwnershipLease,ResourceReservationErrorV1> {
        self.completed.ownership_lease_v1()
    }

    pub(crate) fn start_origin_data_v1(&self)->StartNativeOriginDataV1 {self.origin}

    pub(crate) fn fresh_ownership_lease_v1(&self)
        ->Result<&'turn aos_sandbox_ownership_protocol::SignedOwnershipLease,ResourceReservationErrorV1> {
        self.ownership.ok_or(CLOSED)?.lease_v1()
    }

    pub(crate) fn fresh_ownership_claim_v1(&self)
        ->Result<&'turn aos_sandbox_ownership_protocol::OwnershipClaimV1,ResourceReservationErrorV1> {
        self.ownership.ok_or(CLOSED)?.claim_v1()
    }

    pub(crate) fn controller_account_head_v1<'journal>(&self,controller:&'journal Journal)
        ->Result<&'journal[u8],ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        let native=self.native.native.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?;
        self.native.bank.lock().map_err(|_|ResourceReservationErrorV1::EnrollmentUnavailable)?
            .provisioning_controller_head_v1(native.original_v1(),controller,self.native.profile.as_ref())
    }

    /// Borrows the genuinely compiled successor assignment and unchanged exact Spec.
    ///
    /// # Errors
    /// Refuses an incomplete native proposal or changed accepted Start/Source/C.
    #[doc(hidden)]
    pub fn start_assignment_v2(&self, controller: &Journal) -> Result<(
        &aos_sandbox_core::CanonicalAssignmentManifestV1,
        &crate::sandbox_spec_state::DurableSandboxSpecV1,
    ), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        Ok((self.assignment.manifest_v2()?, self.completed.original_specification_v2()?))
    }

    pub(crate) fn original_create_v1(&self)->&CreateStorageCompletedIntakeOriginalV1<'intake> {
        &self.completed
    }

    pub(crate) fn original_start_plan_v1(&self)->&crate::OperationPlan {
        self.plan
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Selects the actual final-proof financial cause before independent posts.
    ///
    /// This diagnostic join grants no completion, new turn or native owner.
    #[doc(hidden)]
    #[must_use]
    pub fn snapshot_network_final_proof_failure_v2(&mut self,
        client: &crate::normal_root::RootHostLaunchClientOriginalV1,
    ) -> bool {
        let selected = client.selected_original_failure_v1()
            && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        if selected { self.resource_entries.network.turn_native_selected[3] = true; }
        selected
    }

    /// Freezes the same Host final proof's actual original refusal before posts.
    ///
    /// This diagnostic join retains the Host turn's cause and grants no new turn
    /// or resource completion.
    #[doc(hidden)]
    #[must_use]
    pub fn snapshot_host_final_proof_failure_v2(&mut self,
        client: &crate::normal_root::RootHostLaunchClientOriginalV1,
    ) -> bool {
        let selected = client.selected_original_failure_v1()
            && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        if selected { self.resource_entries.host.turn_native_selected[3] = true; }
        selected
    }

    /// Borrows fresh Start's own native turn for a separately admitted Host Root.
    ///
    /// Historical Create inputs remain borrowed from their completed originals.
    /// Only the current new Start native receiver supplies receiving/currentness.
    /// This loan supplies neither a Host grant nor a relative time window.
    ///
    /// # Errors
    /// Refuses incomplete Source origin, another actual intake, changed original
    /// owners or a missing/currentness-failed new native Start interval.
    #[doc(hidden)]
    pub fn borrow_host_root_v1<'turn,'intake>(&'turn mut self,
        intake:&'intake CreateContinuationIntakeAttemptV1,controller:&Journal,
        source:&'turn ProtectedSourceDomainJournalOwnerV1,
    )->Result<OriginalStartHostRootLoanV1<'turn,'intake>,ResourceReservationErrorV1> {
        if self.failure().is_some() || !self.start_ownership.completed_v1() {return Err(CLOSED);}
        self.borrow_start_turn_v1(intake,controller,source,true)
    }

    pub(super) fn borrow_start_turn_v1<'turn,'intake>(&'turn mut self,
        intake:&'intake CreateContinuationIntakeAttemptV1,controller:&Journal,
        source:&'turn ProtectedSourceDomainJournalOwnerV1,require_fresh:bool,
    )->Result<OriginalStartHostRootLoanV1<'turn,'intake>,ResourceReservationErrorV1> {
        let plan=self.body.plan_v1()?;
        let origin=self.body.origin_v1()?;
        let authorization = self.body.retained_authorized_request_v2()?;
        let resident_base=if require_fresh {
            self.native_state.as_ref().and_then(|state|state.history_resident).ok_or(CLOSED)?
        } else {
            *self.ownership_base.as_ref().and_then(|value|value.as_ref().ok()).ok_or(CLOSED)?
        };
        let native=self.native_state.as_mut().ok_or(CLOSED)?;
        let completed=intake.borrow_completed_provisioning_v1(native.create_parent)?;
        completed.require_original_owners_v1(controller,source,native.profile.as_ref())?;
        let loan=OriginalStartHostRootLoanV1 {native,identity:self.identity.as_ref().map_err(|_|CLOSED)?,plan,source:source.journal_ref_v1(),
            source_origin:&self.source_origin,origin,completed,authorization,
            ownership:if require_fresh {Some(&self.start_ownership)} else {None},
            assignment: &self.start_assignment, resident_base, host_stage: &self.resource_entries.host};
        loan.require_current_v1(controller)?;
        Ok(loan)
    }
}

const CLOSED:ResourceReservationErrorV1=ResourceReservationErrorV1::Conflict;

#[derive(Debug, thiserror::Error)]
pub(super) enum StartRootEntryErrorV1 {
    #[error(transparent)]
    Loan(ResourceReservationErrorV1),
    #[error(transparent)]
    Client(crate::normal_root::RootHostLaunchClientClosedV1),
}

impl AcceptedStartEntryOriginalV1 {
    /// Opens the sole Network Root child under a fresh native Start interval.
    ///
    /// The external child is retained inline by the actual Runtime owner. Its
    /// full compiled native shape and both Root observations are admitted before
    /// the lower next-turn entry. Every reached C post runs even when entry,
    /// Root funding, body, transport, temporal or Root post fails.
    ///
    /// # Errors
    /// Refuses reentry or incomplete predecessor, and retains the exact whole
    /// next-entry/body/C-post result. No Root failure can select ordinary IO.
    #[doc(hidden)]
    pub fn begin_network_root_once_v1(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_once_v2(resource_state::StartResourceKindV2::Network,
            client, intake, controller, source, ready, preparation, prepared)
    }

    pub(super) fn begin_resource_root_once_v2(&mut self,
        kind: resource_state::StartResourceKindV2,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if prepared.purpose_data_v2() != kind.purpose_v2()
            || (kind != resource_state::StartResourceKindV2::Network
                && !matches!(self.resource_entries.member_v2(kind).predecessor, Some(Ok(())))) {
            return Err(CLOSED);
        }
        if self.failure().is_some() || !self.start_ownership.completed_v1()
            || self.resource_entries.member_mut_v2(kind).root_next.is_some() {
            return Err(CLOSED);
        }
        let request_body = prepared.deadline_free_request_body_v2().map_err(|_| CLOSED)?;
        if prepared.content_parent_v2()? != self.body.plan_v1()?.operation_id() { return Err(CLOSED); }
        let mut entered = false;
        self.resource_entries.member_mut_v2(kind).root_next = Some((|| {
            let state = self.native_state.as_mut().ok_or(CLOSED)?;
            let resident = state.history_resident.ok_or(CLOSED)?;
            let fixed = crate::normal_root::RootHostLaunchClientOriginalV1::fixed_receiving_demand_v1(
                state.profile.as_ref())?;
            let traffic = crate::normal_root::RootHostLaunchClientOriginalV1::opening_peer_traffic_v1()?;
            let returned = state.begin_next_start_native_v1(controller,
                resident.checked_add(fixed)?.checked_add(traffic)?);
            entered = state.after.is_none();
            returned
        })());
        if !matches!(self.resource_entries.member_mut_v2(kind).root_next, Some(Ok(()))) {
            self.resource_entries.member_mut_v2(kind).root_native_selected = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1).is_some();
        } else {
            self.resource_entries.member_mut_v2(kind).root_body = Some(match self.borrow_host_root_v1(intake, controller, source) {
                Ok(mut loan) => client.begin_resource_prepare_once_v2(kind.purpose_v2(), &mut loan, controller,
                    ready, preparation, request_body).map_err(StartRootEntryErrorV1::Client),
                Err(cause) => Err(StartRootEntryErrorV1::Loan(cause)),
            });
            self.resource_entries.member_mut_v2(kind).root_selected = self.resource_entries.member_mut_v2(kind).root_body.as_ref().is_some_and(Result::is_err);
            self.resource_entries.member_mut_v2(kind).root_native_selected = client.selected_original_failure_v1()
                && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        }
        if entered {
            let returned = match self.native_state.as_mut() {
                Some(state) => state.finish_native_once_v1(controller),
                None => Err(CLOSED),
            };
            let after_failed = returned.is_err();
            let earlier_failed = self.resource_entries.member_mut_v2(kind).root_next.as_ref().is_some_and(Result::is_err)
                || self.resource_entries.member_mut_v2(kind).root_body.as_ref().is_some_and(Result::is_err);
            self.resource_entries.member_mut_v2(kind).root_after = Some(returned);
            client.retain_controller_after_from_entry_v1(self.resource_entries.member_mut_v2(kind).root_after.as_ref());
            if after_failed && !earlier_failed { self.resource_entries.member_mut_v2(kind).root_native_selected = true; }
        }
        if self.failure().is_some() { Err(CLOSED) } else { Ok(()) }
    }

    /// Reports only which retained owner supplies the first Root child cause.
    #[doc(hidden)]
    #[must_use]
    pub fn network_root_failure_is_selected_v1(&self) -> bool {
        self.resource_entries.network.root_selected && !self.resource_entries.network.root_native_selected
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(crate) fn require_completed_host_turn_v1(&self, parent: aos_sandbox_core::OperationId,
        turn: u64, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        if self.body.plan_v1()?.operation_id() != parent || state.native_turn != turn
            || !matches!(state.after, Some(Ok(()))) || state.failure().is_some() {
            return Err(CLOSED);
        }
        let native = state.native.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        state.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_completed_provisioning_original_v1(native.original_v1(), controller, state.profile.as_ref())
    }

    pub(crate) fn require_completed_resource_context_v2(&self,
        parent: aos_sandbox_core::OperationId, turn: u64, identity: &Arc<()>,
        profile: &ProductionControllerNormalRootProfileV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        let actual = self.identity.as_ref().map_err(|_| CLOSED)?;
        if !Arc::ptr_eq(actual, identity) || !std::ptr::eq(state.profile.as_ref(), profile) {
            return Err(CLOSED);
        }
        self.require_completed_host_turn_v1(parent, turn, controller)
    }

    /// Starts the once-only construction interval for this same Root child.
    ///
    /// # Errors
    /// Retains actual next-C and Root-before failure; every reached native post
    /// remains owed through finish_network_root_turn_once_v2 even on refusal.
    #[doc(hidden)]
    pub fn begin_network_construction_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_network_root_turn_v2(client, intake, controller, source, 0)
    }

    /// Starts only the genuine Network Session-opening native interval.
    ///
    /// # Errors
    /// Refuses incomplete construction or any changed original/native owner.
    #[doc(hidden)]
    pub fn begin_network_session_opening_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_network_root_turn_v2(client, intake, controller, source, 1)
    }

    /// Starts only this same Network child's resource-IO native interval.
    ///
    /// # Errors
    /// Refuses an incomplete genuine opening or any native/currentness failure.
    #[doc(hidden)]
    pub fn begin_network_io_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_network_root_turn_v2(client, intake, controller, source, 2)
    }

    /// Starts the same resource's final proof under a fresh native Start turn.
    ///
    /// # Errors
    /// Retains incomplete IO, changed original, funding or native failure.
    /// Every reached C and Root post remains owed through the common finisher.
    #[doc(hidden)]
    pub fn begin_network_final_proof_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_network_root_turn_v2(client, intake, controller, source, 3)
    }

    fn begin_network_root_turn_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Network,
            client, intake, controller, source, index)
    }

    pub(super) fn begin_resource_root_turn_v2(&mut self,
        kind: resource_state::StartResourceKindV2,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, index: usize,
    ) -> Result<(), ResourceReservationErrorV1> {
        let turn_limit = if kind == resource_state::StartResourceKindV2::Host { 7 } else { 4 };
        if index >= turn_limit || self.failure().is_some() || self.resource_entries.member_mut_v2(kind).turn_next[index].is_some() {
            return Err(CLOSED);
        }
        if kind == resource_state::StartResourceKindV2::Host && index == 5 {
            self.require_host_activation_predecessor_v2(client, controller)?;
        }
        self.resource_entries.member_mut_v2(kind).active_turn = Some(index);
        self.resource_entries.member_mut_v2(kind).turn_next[index] = Some((|| {
            let reached = client.next_turn_receiving_demand_v2()?;
            let state = self.native_state.as_mut().ok_or(CLOSED)?;
            if index == 2 && !matches!(state.resources.member_v2(kind).session_resident, Some(Ok(_))) {
                return Err(CLOSED);
            }
            let returned = state.begin_next_start_native_v1(controller,
                state.history_resident.ok_or(CLOSED)?.checked_add(reached)?);
            self.resource_entries.member_mut_v2(kind).turn_ordinal[index] = Some(state.native_turn);
            returned
        })());
        if !matches!(self.resource_entries.member_mut_v2(kind).turn_next[index], Some(Ok(()))) {
            self.resource_entries.member_mut_v2(kind).turn_native_selected[index] = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1).is_some();
            return Err(CLOSED);
        }
        self.resource_entries.member_mut_v2(kind).turn_before[index] = Some(match self.borrow_host_root_v1(intake, controller, source) {
            Ok(mut loan) => match index {
                0 => client.begin_resource_construction_once_v2(kind.purpose_v2(), &mut loan, controller),
                1 => client.begin_resource_session_opening_once_v2(kind.purpose_v2(), &mut loan, controller),
                2 => client.begin_resource_io_once_v2(kind.purpose_v2(), &mut loan, controller),
                3 => client.begin_resource_final_proof_once_v2(kind.purpose_v2(), &mut loan, controller),
                4 if kind == resource_state::StartResourceKindV2::Host =>
                    client.begin_host_admission_once_v2(&mut loan, controller),
                5 if kind == resource_state::StartResourceKindV2::Host =>
                    client.begin_host_activation_once_v2(&mut loan, controller),
                6 if kind == resource_state::StartResourceKindV2::Host =>
                    client.begin_host_catalog_once_v2(&mut loan, controller),
                _ => Err(crate::normal_root::RootHostLaunchClientClosedV1),
            }.map_err(StartRootEntryErrorV1::Client),
            Err(cause) => Err(StartRootEntryErrorV1::Loan(cause)),
        });
        if self.resource_entries.member_mut_v2(kind).turn_before[index].as_ref().is_some_and(Result::is_err) {
            self.resource_entries.member_mut_v2(kind).turn_native_selected[index] = client.selected_original_failure_v1();
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Runs C-after and then independently owed Root-after for the entered turn.
    ///
    /// This must run after the actual body Result is retained in Runtime, even
    /// when the corresponding begin/body call refused. It never opens a new
    /// native turn, debits after failure or changes any accepted expiry.
    ///
    /// # Errors
    /// Retains every reached C/Root post and the earlier whole entry/body cause.
    #[doc(hidden)]
    pub fn finish_network_root_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &mut Journal, body: Result<(), crate::normal_root::RootHostLaunchClientClosedV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_resource_root_turn_once_v2(resource_state::StartResourceKindV2::Network,
            client, controller, body)
    }

    pub(super) fn finish_resource_root_turn_once_v2(&mut self,
        kind: resource_state::StartResourceKindV2,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &mut Journal, body: Result<(), crate::normal_root::RootHostLaunchClientClosedV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let index = self.resource_entries.member_v2(kind).active_turn.ok_or(CLOSED)?;
        if self.resource_entries.member_mut_v2(kind).turn_after[index].is_some() || self.resource_entries.member_mut_v2(kind).turn_root_after[index].is_some() {
            return Err(CLOSED);
        }
        let state = self.native_state.as_mut().ok_or(CLOSED)?;
        let entered = state.after.is_none();
        if entered {
            let earlier_failed = self.resource_entries.member_mut_v2(kind).turn_next[index].as_ref().is_some_and(Result::is_err)
                || self.resource_entries.member_mut_v2(kind).turn_before[index].as_ref().is_some_and(Result::is_err) || body.is_err();
            self.resource_entries.member_mut_v2(kind).turn_after[index] = Some(state.finish_native_once_v1(controller));
            if self.resource_entries.member_mut_v2(kind).turn_after[index].as_ref().is_some_and(Result::is_err) && !earlier_failed {
                self.resource_entries.member_mut_v2(kind).turn_native_selected[index] = true;
            }
        }
        // If the new C entry failed before Root-before, the old prepaid spare
        // supplies the independent negative Root observation without a new loan.
        self.resource_entries.member_mut_v2(kind).turn_root_after[index] = Some(
            client.finish_resource_turn_after_original_v2(kind.purpose_v2(), self, controller, index, body));
        if self.failure().is_some() { Err(CLOSED) } else { Ok(()) }
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Starts the paired Host construction after the complete resource prefix.
    ///
    /// # Errors
    /// Refuses a changed predecessor, repeated turn or native/Root entry failure.
    #[doc(hidden)]
    pub fn begin_host_construction_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, 0)
    }

    /// Starts one finite Host publication interval on the same Root child.
    ///
    /// # Errors
    /// Refuses changed Source/C affinity, reentry, or an incomplete predecessor.
    #[doc(hidden)]
    pub fn begin_host_publication_turn_once_v2(&mut self,
        phase: crate::normal_root::RootHostPublicationTurnKindV2,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use crate::normal_root::RootHostPublicationTurnKindV2 as Phase;
        let index = match phase {
            Phase::Admission => 4,
            Phase::Catalog => 6,
            Phase::Activation => 5,
        };
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, index)
    }

    /// Finishes every reached Host C and Root post in actual semantic order.
    ///
    /// # Errors
    /// Retains the complete earlier refusal and each independent native post.
    #[doc(hidden)]
    pub fn finish_host_root_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &mut Journal,
        body: Result<(), crate::normal_root::RootHostLaunchClientClosedV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_resource_root_turn_once_v2(resource_state::StartResourceKindV2::Host,
            client, controller, body)
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(crate) fn network_negative_entry_association_v2(&self,
        parent: aos_sandbox_core::OperationId,
        profile: &ProductionControllerNormalRootProfileV1, prior_turn: u64, index: usize,
    ) -> Result<u64, ResourceReservationErrorV1> {
        self.resource_negative_entry_association_v2(resource_state::StartResourceKindV2::Network.purpose_v2(),
            parent, profile, prior_turn, index)
    }

    pub(crate) fn resource_negative_entry_association_v2(&self,
        purpose: aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1,
        parent: aos_sandbox_core::OperationId,
        profile: &ProductionControllerNormalRootProfileV1, prior_turn: u64, index: usize,
    ) -> Result<u64, ResourceReservationErrorV1> {
        let kind = resource_state::StartResourceKindV2::from_purpose_v2(purpose)?;
        let member = self.resource_entries.member_v2(kind);
        let state = self.native_state.as_ref().ok_or(CLOSED)?;
        if self.body.plan_v1()?.operation_id() != parent
            || !std::ptr::eq(state.profile.as_ref(), profile)
        {
            return Err(CLOSED);
        }
        let next = member.turn_next.get(index).and_then(Option::as_ref).ok_or(CLOSED)?;
        let before = member.turn_before.get(index).ok_or(CLOSED)?.as_ref();
        failed_network_entry_ordinal_v2(next, before, prior_turn, state.native_turn)
    }
}

// This compares only the actual stored entry Results after the same Start,
// parent and profile have joined. It cannot enter C or mint a Root interval.
fn failed_network_entry_ordinal_v2(
    next: &Result<(), ResourceReservationErrorV1>,
    before: Option<&Result<(), StartRootEntryErrorV1>>,
    previous: u64,
    actual: u64,
) -> Result<u64, ResourceReservationErrorV1> {
    let advanced = previous.checked_add(1) == Some(actual);
    let refused = match (next, before) {
        // A bank-lock/completed-association refusal precedes the C ordinal
        // increment. A later next-entry refusal retains its one increment.
        (Err(_), None) => actual == previous || advanced,
        // The short loan or Root-before may refuse before Root records entry.
        // A successful next-C still proves exactly one native advancement.
        (Ok(()), Some(Err(_))) => advanced,
        _ => false,
    };
    if refused { Ok(actual) } else { Err(CLOSED) }
}

#[cfg(test)]
mod negative_entry_tests {
    use super::*;

    #[test]
    fn original_refusal_posts_accept_only_the_recorded_failed_prefix() {
        let refused = Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        let succeeded = Ok(());
        let loan = Err(StartRootEntryErrorV1::Loan(CLOSED));
        let root = Err(StartRootEntryErrorV1::Client(
            crate::normal_root::RootHostLaunchClientClosedV1));

        assert_eq!(failed_network_entry_ordinal_v2(&refused, None, 7, 7).unwrap(), 7);
        assert_eq!(failed_network_entry_ordinal_v2(&refused, None, 7, 8).unwrap(), 8);
        assert_eq!(failed_network_entry_ordinal_v2(&succeeded, Some(&loan), 7, 8).unwrap(), 8);
        assert_eq!(failed_network_entry_ordinal_v2(&succeeded, Some(&root), 7, 8).unwrap(), 8);

        assert!(failed_network_entry_ordinal_v2(&succeeded, None, 7, 8).is_err());
        assert!(failed_network_entry_ordinal_v2(&succeeded, Some(&loan), 7, 7).is_err());
        assert!(failed_network_entry_ordinal_v2(&refused, Some(&loan), 7, 8).is_err());
        assert!(failed_network_entry_ordinal_v2(&refused, None, 7, 6).is_err());
        assert!(failed_network_entry_ordinal_v2(&refused, None, 7, 9).is_err());
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Identifies the Root owner only for the latest entered Network turn's cause.
    ///
    /// This diagnostic selector preserves actual next-C, loan and C-after
    /// precedence over an independently owed later Root failure. The caller
    /// still selects its retained body/model error before consulting this port.
    /// It supplies no currentness, completion or authorization proof.
    #[doc(hidden)]
    #[must_use]
    pub fn network_current_turn_root_failure_is_selected_v2(&self) -> bool {
        let Some(index) = self.resource_entries.network.turn_next.iter().rposition(Option::is_some) else {
            return false;
        };
        if self.resource_entries.network.turn_next[index].as_ref().is_some_and(Result::is_err)
            || self.resource_entries.network.turn_native_selected[index]
        {
            return false;
        }
        if let Some(Err(cause)) = &self.resource_entries.network.turn_before[index] {
            return matches!(cause, StartRootEntryErrorV1::Client(_));
        }
        if self.resource_entries.network.turn_after[index].as_ref().is_some_and(Result::is_err) {
            return false;
        }
        self.resource_entries.network.turn_root_after[index].as_ref().is_some_and(Result::is_err)
    }
}

/// Borrows only the new Start's read-only current signed-input interval.
///
/// The private wrapper shares the same actual native/financial turn checks as
/// the resource loan. It exposes no lease, manifest, resource plan or signing
/// preparation port, and cannot be constructed from a request or reply.
#[doc(hidden)]
pub struct OriginalStartAssignmentInputsLoanV2<'turn, 'intake> {
    original: OriginalStartHostRootLoanV1<'turn, 'intake>,
}

impl OriginalStartAssignmentInputsLoanV2<'_, '_> {
    pub(crate) fn require_current_v2(&self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.original.require_current_v1(controller)
    }

    pub(crate) fn require_complete_v2(&mut self, controller: &Journal, incoming: ResourceVector)
        -> Result<(), ResourceReservationErrorV1>
    {
        self.original.require_complete_v1(controller, incoming)
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure_v1()
    }

    pub(crate) fn native_turn_v2(&self) -> u64 {
        self.original.native_turn_v1()
    }

    pub(crate) fn parent_operation_v2(&self) -> aos_sandbox_core::OperationId {
        self.original.parent_operation_v1()
    }

    pub(crate) fn original_horizon_v2(&self) -> (RawPairedClockSample, u64) {
        self.original.original_horizon_v1()
    }

    pub(crate) fn original_wall_expiry_v2(&self) -> Result<i64, ResourceReservationErrorV1> {
        self.original.original_wall_expiry_v1()
    }

    pub(crate) fn profile_v2(&self) -> &ProductionControllerNormalRootProfileV1 {
        self.original.profile_v1()
    }

    pub(crate) fn retained_profile_v2(&self) -> Arc<ProductionControllerNormalRootProfileV1> {
        self.original.retained_profile_v1()
    }

    pub(crate) fn retained_identity_v2(&self) -> Arc<()> {
        Arc::clone(self.original.identity)
    }

    pub(crate) fn controller_account_head_v2<'journal>(&self, controller: &'journal Journal)
        -> Result<&'journal [u8], ResourceReservationErrorV1>
    {
        self.original.controller_account_head_v1(controller)
    }

    pub(crate) fn original_create_v2(&self) -> &CreateStorageCompletedIntakeOriginalV1<'_> {
        self.original.original_create_v1()
    }

    pub(crate) fn original_start_plan_v2(&self) -> &crate::OperationPlan {
        self.original.original_start_plan_v1()
    }

    pub(crate) fn canonical_request_v2(&self) -> Result<&[u8], ResourceReservationErrorV1> {
        self.original.authorization.retained_start_request_data_v2().map_err(|_| CLOSED)
    }
}

/// Borrows the actual completed native turn of the same Start input flight.
///
/// Its private issuer requires the genuine stored C-after and Bank disposition.
/// This mechanical join supplies no current policy or resource authority.
#[doc(hidden)]
pub struct StartAssignmentInputsCompletedTurnV2<'held> {
    state: &'held StartNativeStateV1,
    identity: &'held Arc<()>,
    parent: aos_sandbox_core::OperationId,
}

impl StartAssignmentInputsCompletedTurnV2<'_> {
    pub(crate) fn require_same_context_v2(
        &self,
        parent: aos_sandbox_core::OperationId,
        native_turn: u64,
        identity: &Arc<()>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.parent != parent || self.state.native_turn != native_turn
            || !Arc::ptr_eq(self.identity, identity)
            || !std::ptr::eq(self.state.profile.as_ref(), profile)
            || !matches!(self.state.after, Some(Ok(())))
            || self.state.failure().is_some()
        {
            return Err(CLOSED);
        }
        let native = self.state.native.as_ref()
            .and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.state.bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_completed_provisioning_original_v1(
                native.original_v1(), controller, self.state.profile.as_ref(),
            )
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(super) fn prepare_start_assignment_inputs_once_v2(
        &mut self,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        use super::assignment_inputs::{InputsFirstV2, StartAssignmentInputsOriginalV2};

        if self.assignment_inputs.next.is_some() || self.assignment_inputs.first.is_some() {
            self.assignment_inputs.first.get_or_insert(InputsFirstV2::Reentry);
            return Err(CLOSED);
        }
        self.assignment_inputs.base = Some((|| {
            self.native_state.as_ref().and_then(|state| state.history_resident)
                .ok_or(CLOSED)?.checked_add(StartAssignmentInputsOriginalV2::fixed_demand_v2()?)
                .map_err(Into::into)
        })());
        let mut entered = false;
        self.assignment_inputs.next = Some((|| {
            let complete = *self.assignment_inputs.base.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
            let state = self.native_state.as_mut().ok_or(CLOSED)?;
            let result = state.begin_next_start_native_v1(controller, complete);
            entered = state.after.is_none();
            result
        })());
        if !matches!(self.assignment_inputs.next, Some(Ok(()))) {
            self.assignment_inputs.first = Some(InputsFirstV2::Next);
            self.assignment_inputs.native_selected = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1).is_some();
        } else {
            self.assignment_inputs.body = Some((|| {
                let plan = self.body.plan_v1()?;
                let origin = self.body.origin_v1()?;
                let authorization = self.body.retained_authorized_request_v2()?;
                let native = self.native_state.as_mut().ok_or(CLOSED)?;
                let completed = intake.borrow_completed_provisioning_v1(native.create_parent)?;
                completed.require_original_owners_v1(controller, source, native.profile.as_ref())?;
                let resident_base = *self.assignment_inputs.base.as_ref()
                    .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
                let original = OriginalStartHostRootLoanV1 {
                    native,
                    identity: self.identity.as_ref().map_err(|_| CLOSED)?,
                    plan,
                    authorization,
                    source: source.journal_ref_v1(),
                    source_origin: &self.source_origin,
                    origin,
                    completed,
                    ownership: None,
                    assignment: &self.start_assignment,
                    resident_base,
                    host_stage: &self.resource_entries.host,
                };
                let mut loan = OriginalStartAssignmentInputsLoanV2 { original };
                loan.original.require_original_input_data_v1(controller, ready, preparation)?;
                self.assignment_inputs.client.begin_inputs_once_v2(
                    &mut loan, controller, ready, preparation,
                ).map_err(|_| CLOSED)
            })());
            if !matches!(self.assignment_inputs.body, Some(Ok(()))) {
                self.assignment_inputs.first = Some(InputsFirstV2::Body);
                self.assignment_inputs.root_selected = self.assignment_inputs.client.failure().is_some();
                self.assignment_inputs.native_selected = !self.assignment_inputs.root_selected
                    && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
            }
        }

        // C is independently owed after any reached lower entry, including a
        // refused Root body. The whole client stays in place across this post.
        if entered {
            self.assignment_inputs.controller_after = Some(self.native_state.as_mut().ok_or(CLOSED)?
                .finish_native_once_v1(controller));
            if !matches!(self.assignment_inputs.controller_after, Some(Ok(())))
                && self.assignment_inputs.first.is_none()
            {
                self.assignment_inputs.first = Some(InputsFirstV2::ControllerAfter);
                self.assignment_inputs.native_selected = self.native_state.as_ref()
                    .and_then(StartNativeStateV1::native_failure_v1).is_some();
            }
        }

        let completed = if self.assignment_inputs.first.is_none() {
            Some(StartAssignmentInputsCompletedTurnV2 {
                state: self.native_state.as_ref().ok_or(CLOSED)?,
                identity: self.identity.as_ref().map_err(|_| CLOSED)?,
                parent: self.body.plan_v1()?.operation_id(),
            })
        } else { None };
        self.assignment_inputs.root_after = Some(self.assignment_inputs.client
            .finish_inputs_after_original_once_v2(completed.as_ref(), controller));
        if !matches!(self.assignment_inputs.root_after, Some(Ok(())))
            && self.assignment_inputs.first.is_none()
        {
            self.assignment_inputs.first = Some(InputsFirstV2::RootAfter);
            self.assignment_inputs.root_selected = true;
        }
        if self.assignment_inputs.first.is_some() {
            return Err(CLOSED);
        }

        // The response backing already exists under the completed paid peak.
        // This passive handoff records survivors; it performs no late growth,
        // credit or new debit after closing the real native C turn.
        self.assignment_inputs.resident = Some((|| {
            let base = *self.assignment_inputs.base.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
            base.checked_add(self.assignment_inputs.client.completed_resident_receiving_demand_v2()
                .map_err(|_| CLOSED)?).map_err(Into::into)
        })());
        let resident = self.assignment_inputs.resident.as_ref()
            .and_then(|value| value.as_ref().ok()).copied();
        match resident {
            Some(resident) => {
                self.native_state.as_mut().ok_or(CLOSED)?.history_resident = Some(resident);
                Ok(())
            }
            None => {
                self.assignment_inputs.first = Some(InputsFirstV2::Resident);
                Err(CLOSED)
            }
        }
    }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Joins one real Host stage to its actual fresh native ordinal.
    ///
    /// Stage numbers are comparison DATA. Only the private Entry issuer can
    /// record the active stage and its actual native next-entry Result. Root
    /// therefore cannot relabel an Admission borrow as Catalog or Activation.
    pub(crate) fn require_host_stage_v2(&self, index: usize, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        let stage = self.host_stage;
        if index >= stage.turn_next.len() || stage.active_turn != Some(index)
            || stage.turn_ordinal[index] != Some(self.native.native_turn)
            || !matches!(stage.turn_next[index], Some(Ok(())))
            || stage.turn_before[index].as_ref().is_some_and(Result::is_err)
            || stage.turn_after[index].is_some() || stage.turn_root_after[index].is_some()
        {
            return Err(CLOSED);
        }
        Ok(())
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Opens only Host's actual Root resource child after genuine content posts.
    ///
    /// # Errors
    /// Retains changed purpose, predecessor, content, native or Root refusal.
    #[doc(hidden)]
    pub fn begin_host_root_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_once_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, ready, preparation, prepared)
    }

    /// Rejoins the same catalog Host Session after actual activation.
    ///
    /// # Errors
    /// Retains incomplete genuine predecessors or native/current Root refusal.
    #[doc(hidden)]
    pub fn begin_host_session_opening_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, 1)
    }

    /// Enters only Host launch and fresh inventory on the active successor.
    ///
    /// # Errors
    /// Retains incomplete genuine predecessors or native/current Root refusal.
    #[doc(hidden)]
    pub fn begin_host_io_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, 2)
    }

    /// Enters Host final proof after the actual launch/inventory interval.
    ///
    /// # Errors
    /// Retains incomplete genuine predecessors or native/current Root refusal.
    #[doc(hidden)]
    pub fn begin_host_final_proof_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Host,
            client, intake, controller, source, 3)
    }

    /// Reports only the actual Host opening's selected Root failure.
    #[doc(hidden)]
    #[must_use]
    pub fn host_root_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.host.root_selected && !self.resource_entries.host.root_native_selected
    }

    /// Reports only the active semantic Host stage's selected Root refusal.
    ///
    /// Earlier body/native causes remain selected by their own retained owners.
    /// Numeric maximum cannot identify Host's catalog6→activation5 chronology.
    #[doc(hidden)]
    #[must_use]
    pub fn host_current_turn_root_failure_is_selected_v2(&self) -> bool {
        let stages = &self.resource_entries.host;
        let Some(index) = stages.active_turn else { return false; };
        if stages.turn_next[index].as_ref().is_some_and(Result::is_err)
            || stages.turn_native_selected[index]
        {
            return false;
        }
        if let Some(Err(cause)) = &stages.turn_before[index] {
            return matches!(cause, StartRootEntryErrorV1::Client(_));
        }
        if stages.turn_after[index].as_ref().is_some_and(Result::is_err) {
            return false;
        }
        stages.turn_root_after[index].as_ref().is_some_and(Result::is_err)
    }
}
