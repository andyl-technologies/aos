//! Keeps the genuine Stop Source/B interval across its real Host exchange.
//!
//! Cost inputs remain DATA. Actual accepted Stop, Source cursor and native
//! receiving are rejoined independently; dispatch authority comes only from
//! the existing current signed Host template and its original signed ceilings.

use super::*;
use aos_sandbox_api::aos::sandbox::local::v1::RuntimeAction;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};
use crate::lifecycle::{
    LifecycleEffectObservationV1, LifecycleIntentV1, LifecyclePhase6ErrorV1,
    LifecycleSuspensionPlanV1, LiveRuntimeFenceV1,
};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

#[derive(Clone, Copy)]
pub(super) enum HostFirstV4 { Entry, Fee, Authority, InventoryFee, Dispatch, After }

impl ControllerLifecycleStopOriginalV4 {
    /// Enters the paid Source/B before for this original Stop's Host turn.
    ///
    /// The Source borrow remains occupied until `finish_host_stop_once_v4`,
    /// including SDK preparation, transport, decoding or currentness refusal.
    ///
    /// # Errors
    /// Retains repeated entry, incomplete metadata, financial, native or Source
    /// selection refusal. A reached before still owes the independent finish.
    pub fn begin_host_stop_once_v4(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.host_entry.is_some() || !matches!(self.source_preparation, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.host_entry = Some((|| {
            let resident = self.source_resident.ok_or(ResourceReservationErrorV1::Conflict)?;
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.host_turn.enter_once_v4(self.operation, &self.bank, self.profile.as_ref(),
                native, resident, controller, source)
        })());
        if matches!(self.host_entry, Some(Ok(()))) { Ok(()) }
        else {
            self.host_first.get_or_insert(HostFirstV4::Entry);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    /// Rejoins this original's current Source/native Host entry before borrowing Session.
    ///
    /// # Errors
    /// Refuses another phase, a failed or finished owner, or changed native B.
    pub fn require_host_stop_session_current_v4(&self, controller: &Journal) -> Result<()> {
        if !matches!(self.host_entry, Some(Ok(()))) || self.host_finish.is_some()
            || self.failure_v4().is_some()
        { return Err(ResourceReservationErrorV1::Conflict); }
        let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_lifecycle_stop_native_current_v4(native, controller, self.profile.as_ref())
    }

    /// Pays the compiled same-Session forecast and independent post destinations.
    ///
    /// # Errors
    /// Retains reentry, stale native Source association, arithmetic or capacity refusal.
    pub fn admit_host_stop_fixed_receiving_once_v4(
        &mut self,
        controller: &Journal,
        fixed: ControllerOperationIntakeDemandDataV1,
    ) -> Result<()> {
        if self.host_fixed.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.host_fixed = Some((|| {
            self.require_host_stop_session_current_v4(controller)?;
            let complete = self.host_turn.paid_models_v4()?.checked_add(fixed.demand_v1())?;
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_lifecycle_stop_complete_v4(native, controller, self.profile.as_ref(), complete)
        })());
        if matches!(self.host_fixed, Some(Ok(()))) { Ok(()) }
        else {
            self.host_fee_original = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|native| native.failure().is_some());
            self.host_first.get_or_insert(HostFirstV4::Fee);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    /// Debits the actual same-Session Stop quote before its first model growth.
    ///
    /// The quote has no permission semantics. The occupied Stop original
    /// checks its own current native purpose and Source entry, then adds this
    /// complete named stage to the same B ledger without resetting prior debt.
    ///
    /// # Errors
    /// Retains repeated funding, overflow, changed original or capacity refusal.
    pub fn admit_host_stop_receiving_once_v4(
        &mut self,
        controller: &Journal,
        demand: ControllerOperationIntakeDemandDataV1,
    ) -> Result<()> {
        if self.host_fee.is_some() || !matches!(self.host_fixed, Some(Ok(())))
            || !matches!(self.host_entry, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.host_fee = Some((|| {
            self.host_models = Some(crate::runtime_authority::current_publication_receiving_demand_v2(controller)
                .ok_or(ResourceReservationErrorV1::Conflict));
            let models = self.host_models.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = self.host_turn.paid_models_v4()?.checked_add(models)?
                .checked_add(demand.demand_v1())?;
            self.host_complete = Some(complete);
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_lifecycle_stop_complete_v4(native, controller, self.profile.as_ref(), complete)
        })());
        if !matches!(self.host_fee, Some(Ok(()))) {
            self.host_first.get_or_insert(HostFirstV4::Fee);
            self.host_fee_original = self.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_some_and(|native| native.failure().is_some());
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    /// Selects the exact existing signed Stop under its original finite caps.
    ///
    /// # Errors
    /// Retains missing, ambiguous, expired or mismatched publication, lease,
    /// runtime and actual Stop Source association. This never signs a plan.
    pub fn prepare_host_stop_authority_once_v4(
        &mut self,
        controller: &Journal,
        node: aos_sandbox_model::NodeId,
        transport_bound_data: u64,
    ) -> Result<()> {
        if self.host_authority_entry.is_some() {
            self.host_first.get_or_insert(HostFirstV4::Authority);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.host_authority_entry = Some((|| {
            self.require_host_stop_current_v4(controller)?;
            let fence = self.host_stop_fence_data_v4(controller)?;
            let clock = self.host_stop_clock_data_v4()?;
            self.host_authority.prepare_once_v4(controller, node, fence, clock, transport_bound_data)
                .map_err(|_| ResourceReservationErrorV1::Conflict)
        })());
        if matches!(self.host_authority_entry, Some(Ok(()))) { Ok(()) }
        else {
            self.host_first.get_or_insert(HostFirstV4::Authority);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    /// Pays only the actual adjacent Inventory's canonical same-Session quote.
    ///
    /// # Errors
    /// Retains reentry, prior refusal, checked overflow or actual same-B capacity failure.
    pub fn admit_host_stop_inventory_receiving_once_v5(&mut self, controller: &Journal,
        demand: ControllerOperationIntakeDemandDataV1,
    ) -> Result<()> {
        if self.inventory_fee.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.inventory_fee = Some((|| {
            self.require_host_stop_current_v4(controller)?;
            let complete = self.host_complete.ok_or(ResourceReservationErrorV1::Conflict)?
                .checked_add(demand.demand_v1())?;
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .require_lifecycle_stop_complete_v4(native, controller, self.profile.as_ref(), complete)?;
            self.host_complete = Some(complete);
            Ok(())
        })());
        if matches!(self.inventory_fee, Some(Ok(()))) { Ok(()) }
        else {
            self.host_fee_original = self.native.as_ref().and_then(|value| value.as_ref().ok())
                .is_some_and(|native| native.failure().is_some());
            self.host_first.get_or_insert(HostFirstV4::InventoryFee);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    /// Borrows the genuine selected request without replacing its signed scope.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or already finished actual Host turn.
    pub fn prepared_host_stop_effect_v4(&self, controller: &Journal)
        -> Result<&crate::PreparedAuthorityEffectV1> {
        self.require_host_stop_current_v4(controller)?;
        self.host_authority.completed_v4().ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the retained clock DATA used to attenuate the signed template.
    ///
    /// # Errors
    /// Refuses missing, failed, unfunded or already finished Host turns.
    pub fn host_stop_clock_data_v4(&self) -> Result<RawPairedClockSample> {
        if !matches!(self.host_fee, Some(Ok(()))) || self.host_finish.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.host_turn.sample_data_v4()
    }

    /// Borrows the exact current Source Stop fence as comparison DATA.
    ///
    /// # Errors
    /// Refuses another intent, incomplete Source cursor or changed B/native owner.
    pub fn host_stop_fence_data_v4(&self, controller: &Journal) -> Result<LiveRuntimeFenceV1> {
        self.require_host_stop_current_v4(controller)?;
        let current = self.host_turn.current_host_operation_v4()?;
        match current.operation().intent() {
            LifecycleIntentV1::Stop { fence, .. } => Ok(*fence),
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    /// Validates the actual SDK-prepared signed request against the held cursor.
    ///
    /// # Errors
    /// Rejects another effect, request, action or live assignment fence.
    pub fn require_host_stop_request_v4(
        &self,
        controller: &Journal,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> std::result::Result<(), LifecyclePhase6ErrorV1> {
        self.require_host_stop_current_v4(controller)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let current = self.host_turn.current_host_operation_v4()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let fence = match current.operation().intent() {
            LifecycleIntentV1::Stop { fence, .. } => *fence,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        LifecycleSuspensionPlanV1::stop(&current)?.next_effect(&current)?
            .validate_authenticated_runtime_request(request, fence, RuntimeAction::RUNTIME_ACTION_STOP)
    }

    /// Commits this public Stop's literal prepared SDK request before sending it.
    ///
    /// The same Source/native interval remains held across binding, SDK effects
    /// and all independently owed posts. This append leaves the Operation and
    /// reserved attempt unchanged; only its own canonical successor is accepted.
    ///
    /// # Errors
    /// Retains stale Source/C, another request, insufficient same-B capacity,
    /// canonical append uncertainty or unequal actual readback as refusal.
    pub fn bind_host_stop_dispatch_once_v1(
        &mut self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        sdk_replay: ControllerOperationIntakeDemandDataV1,
    ) -> Result<()> {
        self.require_host_stop_request_v4(controller, request).map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let complete = self.host_complete.ok_or(ResourceReservationErrorV1::Conflict)?;
        let native = self.native.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let result = self.host_turn.bind_host_dispatch_once_v1(self.operation, &self.bank,
            self.profile.as_ref(), native, controller, source, request, complete, sdk_replay.demand_v1());
        match result {
            Ok(complete) => {
                // Dispatch DATA and append/readback originals remain held while
                // the later inventory graph grows on the same absolute ledger.
                self.host_complete = Some(complete);
                Ok(())
            }
            Err(cause) => {
                self.host_first.get_or_insert(HostFirstV4::Dispatch);
                Err(cause)
            }
        }
    }

    /// Binds the same actual authenticated outcome to its reserved Stop effect.
    ///
    /// The private Runtime caller must retain the SDK outcome/currentness and
    /// every independently completed native post through Source/C emission.
    /// This observation is not itself a terminal append authorization.
    ///
    /// # Errors
    /// Rejects stale Source/B custody, a foreign effect or malformed residual.
    pub fn observe_host_stop_outcome_v4(
        &self,
        controller: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> std::result::Result<Option<LifecycleEffectObservationV1>, LifecyclePhase6ErrorV1> {
        self.require_host_stop_current_v4(controller)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let current = self.host_turn.current_host_operation_v4()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let fence = match current.operation().intent() {
            LifecycleIntentV1::Stop { fence, .. } => *fence,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        LifecycleSuspensionPlanV1::stop(&current)?.next_effect(&current)?
            .observe_authenticated_stop_residual_v4(outcome, fence)
    }

    pub(super) fn require_host_stop_current_v4(&self, controller: &Journal) -> Result<()> {
        if !matches!(self.host_entry, Some(Ok(()))) || !matches!(self.host_fee, Some(Ok(())))
            || self.host_finish.is_some() || self.failure_v4().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = self.native.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_lifecycle_stop_native_current_v4(native, controller, self.profile.as_ref())
    }

    /// Commits residual dependency debt after this original's real Host posts.
    ///
    /// The private Runtime consumer continuously borrows the same actual SDK
    /// outcome, currentness and positive post originals. These authenticated
    /// bytes are compared with this Stop's actual reserved Source request;
    /// they do not alone authorize a public terminal record or deletion.
    ///
    /// # Errors
    /// Retains foreign outcomes, missing native posts, Source/currentness,
    /// exact residual CAS, independent after or positive-disposal refusal.
    pub fn commit_host_stop_residual_source_once_v4(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<()> {
        if self.residual_result.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.residual_result = Some((|| {
            if self.host_first.is_some() || !matches!(self.host_finish, Some(Ok(())))
                || !matches!(self.host_fee, Some(Ok(())))
            { return Err(ResourceReservationErrorV1::Conflict); }
            self.residual_observation = Some((|| {
                let current = self.host_turn.completed_host_operation_v4()
                    .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
                let fence = match current.operation().intent() {
                    LifecycleIntentV1::Stop { fence, .. } => *fence,
                    _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
                };
                LifecycleSuspensionPlanV1::stop(&current)?.next_effect(&current)?
                    .observe_authenticated_stop_residual_v4(outcome, fence)?
                    .ok_or(LifecyclePhase6ErrorV1::InvalidInput)
            })());
            let observation = self.residual_observation.as_ref()
                .and_then(|result| result.as_ref().ok()).copied()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.commit_stop_observation_source_v5(controller, source, observation)
        })());
        if matches!(self.residual_result, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Commits healthy Stop only from its exact adjacent Inventory observation.
    ///
    /// # Errors
    /// Retains wrong family, earlier SDK/Source posts, native/CAS or independent after refusal.
    pub fn commit_host_stop_success_source_once_v5(&mut self,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        observation: LifecycleEffectObservationV1,
    ) -> Result<()> {
        if self.residual_result.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.residual_result = Some((|| {
            if self.host_first.is_some() || !matches!(self.host_finish, Some(Ok(())))
                || !matches!(self.host_fee, Some(Ok(()))) || observation.capture_stop_residual_v4().is_some()
            { return Err(ResourceReservationErrorV1::Conflict); }
            self.residual_observation = Some(Ok(observation));
            self.commit_stop_observation_source_v5(controller, source, observation)
        })());
        if matches!(self.residual_result, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn commit_stop_observation_source_v5(&mut self,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        observation: LifecycleEffectObservationV1,
    ) -> Result<()> {
        self.residual_turn.retain_residual_observation_v4(observation)?;
        // The lower permanent ledger already carries every prior traffic
        // charge into its next interval. Keep all capacity resident, while
        // the shared projector avoids billing that spent traffic twice.
        let resident = aos_sandbox_model::component_receiving::without_operation_traffic_v1(
            self.host_complete.ok_or(ResourceReservationErrorV1::Conflict)?);
        let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.residual_turn.run_once_v4(self.operation, &self.bank, self.profile.as_ref(),
            native, resident, controller, source)?;
        self.residual_record = Some(self.residual_turn.completed_record_v4()?);
        let backing = u64::try_from(self.residual_turn.resident_bytes_v4()?)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.residual_complete = Some(resident.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, backing))?);
        Ok(())
    }

    /// Runs independently owed Source, Controller and final-clock posts once.
    ///
    /// # Errors
    /// Retains native/name/clock refusal. Earlier SDK or funding errors remain
    /// owned by their original destinations and cannot be healed here.
    pub fn finish_host_stop_once_v4(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.host_finish.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.host_finish = Some((|| {
            let native = self.native.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            self.host_turn.finish_once_v4(&self.bank, self.profile.as_ref(), native, controller, source)
        })());
        if matches!(self.host_finish, Some(Ok(()))) { Ok(()) }
        else {
            self.host_first.get_or_insert(HostFirstV4::After);
            Err(ResourceReservationErrorV1::Conflict)
        }
    }
}
