//! Activates the private Host child after actual Catalog17 physical disposition.
//!
//! Runtime independently qualifies its opaque SDK Session before native5. This
//! lower owner rejoins the same disposed native receipt and original payer,
//! prepays canonical models, then calls the sole atomic Core activation kernel.
//! Its readback is retained before the independently owed C and Root posts.

use super::*;
use crate::normal_root::{RootHostPublicationTurnKindV2, RootStartResourceCurrentTurnV2};
use crate::reconciler::start_admission::{StartAdmissionScopeV1, StartHostCoreScopePhaseV2};

#[derive(Default)]
pub(super) struct StartHostActivationOriginalV2 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    geometry: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    scope: Option<Result<(), ResourceReservationErrorV1>>,
    turn: Option<u64>,
    original_taken: bool,
    native_selected: bool,
    readback: Option<Result<[u8; aos_sandbox_protocol::domain_ledger::runtime_authority_history::runtime_head_encoded_bytes_v1()], Cause>>,
}

impl StartHostActivationOriginalV2 {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn failure_v2(&self) -> Option<(&(dyn Error + 'static), bool)> {
        if let Some(cause) = self.entry.as_ref().and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        if let Some(cause) = self.geometry.as_ref().and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        for returned in [&self.funding, &self.scope] {
            if let Some(cause) = returned.as_ref().and_then(|returned| returned.as_ref().err()) {
                return Some((cause, self.native_selected));
            }
        }
        None
    }
}

impl StartHostPublicationActionOriginalV2 {
    pub(crate) fn activation_body_failure_v2(&self)
        -> Option<(&(dyn Error + 'static), bool)> {
        self.activation_original.failure_v2()
            .or_else(|| self.activation_preparation.as_ref()
                .and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause as &(dyn Error + 'static), false)))
            .or_else(|| self.activation.as_ref().and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause as &(dyn Error + 'static), self.activation_original.native_selected)))
            .or_else(|| self.activation_original.readback.as_ref()
                .and_then(|returned| returned.as_ref().err())
                .map(|cause| (cause.as_ref() as &(dyn Error + 'static), false)))
    }
}

impl StartNativeStateV1 {
    pub(crate) fn require_host_catalog_disposed_v2(&self,
        expected: &Arc<StartHostPublicationContractV2>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let action = self.host_publication_action.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(&action.contract, expected)
            || !matches!(self.resources.host.session_resident, Some(Ok(_)))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resources.host_catalog_completion.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_disposed_owner_v2(&expected.identity, expected.parent,
                expected.catalog_generation, &expected.catalog_digest)
    }

    pub(crate) fn require_host_activation_scope_v2(&self, controller: &Journal,
        expected: &Arc<StartHostPublicationContractV2>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_host_catalog_disposed_v2(expected)?;
        let action = self.host_publication_action.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = &action.activation_original;
        let prepared = match action.activation_preparation.as_ref() {
            Some(Ok(Some(_))) => !original.original_taken,
            Some(Ok(None)) => original.original_taken,
            _ => false,
        };
        if original.turn != Some(self.native_turn)
            || !matches!(original.entry, Some(Ok(())))
            || !matches!(original.geometry, Some(Ok(_)))
            || !matches!(original.funding, Some(Ok(())))
            || action.activation.is_some() || !prepared
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        action.require_pending_rows_v2(controller)
    }

    pub(crate) fn require_active_host_publication_v2(&self, controller: &Journal,
        expected: &Arc<StartHostPublicationContractV2>,
    ) -> Result<(), ResourceReservationErrorV1> {
        controller.ensure_protected_authority().map_err(ResourceReservationErrorV1::Journal)?;
        let action = self.host_publication_action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let head = action.activation_original.readback.as_ref()
            .and_then(|returned| returned.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(&action.contract, expected)
            || !matches!(action.activation, Some(Ok(_)))
            || !matches!(action.activation_after, Some(Ok(())))
            || controller.get(crate::RecordNamespace::RuntimeAuthority, &expected.predecessor_head_key)
                != Some(head.as_slice())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn take_host_activation_original_v2(&mut self,
        expected: &Arc<StartHostPublicationContractV2>,
    ) -> Result<crate::publication::AuthorityPublicationActivationV1, ResourceReservationErrorV1> {
        let action = self.host_publication_action.as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if !Arc::ptr_eq(&action.contract, expected) || action.activation_original.original_taken {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let activation = action.activation_preparation.as_mut()
            .and_then(|returned| returned.as_mut().ok()).and_then(Option::take)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.original_taken = true;
        Ok(activation)
    }
}

impl AcceptedStartEntryOriginalV1 {
    pub(crate) fn require_host_activation_predecessor_v2(&self,
        root: &RootHostLaunchClientOriginalV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.require_completed_host_catalog_turn_v2(root, controller)?;
        let native = self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        native.require_host_catalog_disposed_v2(&action.contract)
    }

    /// Runs only the genuine private child's atomic generation2 activation.
    ///
    /// The actual Runtime must first qualify its opaque completed catalog
    /// Session against this Entry's native completion before it enters stage5.
    /// This method independently rejoins the same disposed lower receipt and
    /// pending child, then retains canonical preparation, Core and readback.
    ///
    /// # Errors
    /// Retains changed context, disposition, model funding, atomic mutation or
    /// canonical readback failure. Both independent posts remain owed.
    #[doc(hidden)]
    pub fn activate_host_publication_once_v2(&mut self,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let contract = {
            let loan = self.borrow_host_root_v1(intake, controller, source)?;
            loan.require_host_stage_v2(5, controller)?;
            root.require_host_publication_owner_v2(RootHostPublicationTurnKindV2::Activation,
                loan.parent_operation_v1(), loan.native_turn_v1(), loan.native.profile.as_ref())?;
            let action = loan.native.host_publication_action.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            if action.activation_original.entry.is_some() || action.activation_preparation.is_some()
                || action.activation.is_some()
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Arc::clone(&action.contract)
        };
        let entry = (|| {
            let native = self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            native.require_host_catalog_disposed_v2(&contract)?;
            native.host_publication_action.as_ref()
                .ok_or(ResourceReservationErrorV1::Conflict)?.require_pending_rows_v2(controller)
        })();
        let action = self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.entry = Some(entry);
        if !matches!(action.activation_original.entry, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        let geometry = contract.plan.start_host_publication_phase_receiving_demand_v2(
            controller, &contract.draft, &contract.prepared,
            crate::cold_launch_publication::action::PublicationActionPhaseV1::Activation,
        ).and_then(|models| models.checked_add(StartAdmissionScopeV1::host_scope_receiving_demand_v2()
            .map_err(ResourceReservationErrorV1::Journal)?).map_err(Into::into));
        let action = self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.geometry = Some(geometry);
        let demand = *action.activation_original.geometry.as_ref()
            .and_then(|returned| returned.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        let funding = (|| {
            let mut loan = self.borrow_host_root_v1(intake, controller, source)?;
            let resident = loan.native.resources.host_publication_resident.checked_add(demand)?;
            let returned = loan.require_complete_v1(controller, demand);
            let selected = returned.is_err() && loan.native.native_failure_v1().is_some();
            let turn = loan.native.native_turn;
            let action = loan.native.host_publication_action.as_mut()
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            action.activation_original.turn = Some(turn);
            action.activation_original.native_selected = selected;
            if returned.is_ok() {
                loan.native.resources.host_publication_resident = resident;
            }
            returned
        })();
        let action = self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.funding = Some(funding);
        if !matches!(action.activation_original.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        action.activation_preparation = Some(crate::publication::AuthorityPublicationStore::new(controller)
            .prepare_gate_activation(&contract.draft, &contract.prepared).map(Some));
        if !matches!(action.activation_preparation, Some(Ok(Some(_)))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.run_host_activation_core_once_v2(controller, source, root)?;
        let readback = readback_activation_v2(controller, &contract);
        let action = self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.readback = Some(readback);
        if matches!(action.activation_original.readback, Some(Ok(_))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    fn run_host_activation_core_once_v2(&mut self, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
        root: &RootStartResourceCurrentTurnV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let scoped = StartAdmissionScopeV1::from_host_entry_v2(self, controller,
            StartHostCoreScopePhaseV2::Activation, root, source);
        let scope = match scoped {
            Ok(scope) => scope,
            Err(cause) => {
                self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
                    .ok_or(ResourceReservationErrorV1::Conflict)?.activation_original.scope = Some(Err(cause));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        match controller.install_start_admission_scope_v1(Box::new(scope)) {
            Ok(()) => {}
            Err(scope) => {
                self.restore_native_state_v1(scope.into_native_v1());
                self.native_state.as_mut().and_then(|native| native.host_publication_action.as_mut())
                    .ok_or(ResourceReservationErrorV1::Conflict)?.activation_original.scope = Some(Err(ResourceReservationErrorV1::Conflict));
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let returned = controller.activate_start_host_publication_v2();
        let Some(scope) = controller.take_start_admission_scope_v1() else { std::process::abort(); };
        self.restore_native_state_v1(scope.into_native_v1());
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let selected = returned.is_err() && native.native_failure_v1().is_some();
        let action = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        action.activation_original.scope = Some(Ok(()));
        action.activation_original.native_selected = selected;
        action.activation = Some(returned);
        if matches!(action.activation, Some(Ok(_))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    /// Rejoins actual activation only after the real phase5 C and Root posts.
    ///
    /// # Errors
    /// Retains incomplete activation/readback or changed original ordinal/posts.
    #[doc(hidden)]
    pub fn finish_host_activation_after_posts_once_v2(&mut self, controller: &Journal)
        -> Result<(), ResourceReservationErrorV1> {
        let stage = &self.resource_entries.host;
        let native = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action = native.host_publication_action.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if action.activation_after.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        action.activation_after = Some((|| {
            controller.ensure_protected_authority().map_err(ResourceReservationErrorV1::Journal)?;
            if stage.active_turn != Some(5) || stage.turn_ordinal[5] != Some(native.native_turn)
                || action.activation_original.turn != Some(native.native_turn)
                || !matches!(action.activation, Some(Ok(_)))
                || !matches!(action.activation_original.readback, Some(Ok(_)))
                || !matches!(stage.turn_after[5], Some(Ok(())))
                || !matches!(stage.turn_root_after[5], Some(Ok(())))
            { return Err(ResourceReservationErrorV1::Conflict); }
            Ok(())
        })());
        if matches!(action.activation_after, Some(Ok(()))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }
}

fn readback_activation_v2(controller: &mut Journal, contract: &StartHostPublicationContractV2)
    -> Result<[u8; aos_sandbox_protocol::domain_ledger::runtime_authority_history::runtime_head_encoded_bytes_v1()], Cause> {
    let sandbox = contract.prepared.manifest().manifest().sandbox();
    let current = RuntimeAuthorityStore::load(controller, RuntimeAuthorityLimits::default())?
        .current(sandbox)?.ok_or(CLOSED)?;
    let publication = crate::publication::AuthorityPublicationStore::new(controller)
        .current(sandbox)?.ok_or(CLOSED)?;
    if current.operation() != contract.plan.operation_id()
        || current.manifest() != contract.prepared.manifest()
        || current.revision() != contract.predecessor.revision().checked_add(1).ok_or(CLOSED)?
        || current.request_digest() != &contract.plan.request_digest()
        || current.publication_digest() != contract.prepared.digest()
        || current.lease_digest() != contract.prepared.lease_digest()
        || current.lease_generation() != contract.prepared.lease_generation()
        || publication.canonical_bytes() != contract.prepared.canonical_bytes()
    { return Err(Box::new(CLOSED)); }
    Ok(controller.get(crate::RecordNamespace::RuntimeAuthority, &contract.predecessor_head_key)
        .ok_or(CLOSED)?.try_into()?)
}
