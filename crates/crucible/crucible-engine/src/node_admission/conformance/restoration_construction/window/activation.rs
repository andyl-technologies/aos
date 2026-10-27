//! Rechecks the same four-owner proof at each distinct activation boundary.
//!
//! Source authenticates its actual Commit and current native state inside its
//! armed read fence. The Window comparison binds that evidence to the actual
//! retained three-node inspections and the fourth Host2 scope owner. An effect
//! phase remains spent until opaque Source evidence passes the terminal fence.

use super::super::activation::{
    OriginalInstalledRestorationActivationPhase,
    OriginalInstalledRestorationActivationSigningInputs,
};
use super::*;
use crate::node_contract::OriginalLineageNativeScope;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;

impl CompleteOriginalRestorationWindow {
    pub(crate) fn original_complete_scope_proof_identity_data(
        &self,
    ) -> Result<[u8; 32], RuntimeError> {
        self.origin()?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        Ok(super::continuation::reference_identity(&scope.proof))
    }

    pub(in super::super) fn authenticate_original_activation_hold_data(
        &self,
        selected: usize,
        scope: &OriginalLineageNativeScope,
        held: &PacketNativeRestoredCommitHold,
        reference: &ContentRef,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let original = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        if !std::ptr::eq(scope, original) || scope.source_record != *self.archive.runtime_object() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let native = self
            .native_continuations
            .get(selected)
            .and_then(Cell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if native.held_reference != super::continuation::reference_identity(reference)
            || native.inventory != super::continuation::hash_identity(&held.inventory_hash)
            || native.cursor != held.local_cursor
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        self.authenticate_original_runtime_member_current_data(&scope.target.world_binding_hash)
    }

    pub(super) fn authenticate_original_activation_identity_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        phase: OriginalInstalledRestorationActivationPhase,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        let original_source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !std::ptr::eq(source, original_source.as_ref())
            || self.original_complete_scope_proof_identity_data()? != proof_identity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let target = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.activation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_started(phase)?;
        // The original activation pointer was authenticated before complete
        // scope issuance. This later owned association compares that exact
        // retained pointer without dereferencing it or accepting a new record.
        target.authenticate_original_installed_member_data(
            &self.runtime,
            &plan,
            original_source,
            self.original_activation_slot,
            &scope.target.world_binding_hash,
        )?;
        self.activation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_started(phase)?;
        target.authenticate_original_installed_member_data(
            &self.runtime,
            &plan,
            original_source,
            self.original_activation_slot,
            &scope.target.world_binding_hash,
        )
    }
}

impl CompleteOriginalRestorationWindow {
    pub(super) fn retain_original_activation_request_ids_data(
        &self,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.activation_request_ids.get().is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        let make = |prefix: &str| -> Result<Id, RuntimeError> {
            let capacity = prefix
                .len()
                .checked_add(activation.activation_id.as_str().len())
                .ok_or(RuntimeError::ResourceLimit)?;
            let mut bytes = String::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            bytes.push_str(prefix);
            bytes.push_str(activation.activation_id.as_str());
            Id::new(bytes).map_err(|_| RuntimeError::InvalidReceipt)
        };
        let arm = make("cnp-activate-")?;
        let world = make("cnp-world-activate-")?;
        self.activation_request_ids
            .set([arm, world])
            .map_err(|_| RuntimeError::DuplicateOperation)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(in super::super) fn authenticate_original_activation_member_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        phase: OriginalInstalledRestorationActivationPhase,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_activation_identity_data(
            selected,
            source,
            phase,
            proof_identity,
        )?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let member = OriginalRestorationMemberScope {
            plan: &plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        self.authenticate_original_activation_identity_data(selected, source, phase, proof_identity)
    }

    pub(in super::super) fn with_original_activation_signing_inputs_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        phase: OriginalInstalledRestorationActivationPhase,
        proof_identity: [u8; 32],
        inspect: impl FnOnce(
            &OriginalInstalledRestorationActivationSigningInputs<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_activation_identity_data(
            selected,
            source,
            phase,
            proof_identity,
        )?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let target = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let scope_owner = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let scope = scope_owner.scope_data()?;
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let custody = node
            .installed_custody
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let uploaded = target.completed_upload_data()?;
        let uploaded = uploaded.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let ids = self
            .activation_request_ids
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let request_id = &ids[match phase {
            OriginalInstalledRestorationActivationPhase::Arm => 0,
            OriginalInstalledRestorationActivationPhase::WorldActivate => 1,
        }];
        let inputs = OriginalInstalledRestorationActivationSigningInputs {
            transfer: self.original_signing_inputs_data(target, source, &plan, &scope.target)?,
            inspection: OriginalRestorationTransactionInspection {
                window: self,
                target,
                source,
                plan: &plan,
                activation: &scope.target,
                installed_scope: Some(scope),
            },
            signer: node.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
            uploaded,
            scope,
            scope_proof: &scope.proof,
            scope_proof_body: scope_owner
                .proof_body_data(&scope.proof)
                .ok_or(RuntimeError::OwnerUnavailable)?,
            activation_data: custody.activation_construction_data(),
            source_construction: node
                .source_activation
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            phase,
            request_id,
            world: match phase {
                OriginalInstalledRestorationActivationPhase::Arm => None,
                OriginalInstalledRestorationActivationPhase::WorldActivate => Some(
                    self.activation_world
                        .get()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                ),
            },
            window: self,
            selected,
        };
        inspect(&inputs)?;
        // Source's evidence authenticator already invoked the final erased
        // member under SourceRead. No erased callback follows its final fence.
        self.authenticate_original_retained_activation_identity_data(
            selected,
            source.as_ref(),
            phase,
            proof_identity,
        )
    }

    pub(crate) fn original_installed_node_custody_data(
        &self,
        selected: usize,
    ) -> Result<
        &crate::node_adapters::cnp::OriginalInstalledRestorationCustodyConstructionData,
        RuntimeError,
    > {
        self.origin()?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.installed_custody.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn begin_original_installed_activation_claim_data(
        self: &Rc<Self>,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        phase: OriginalInstalledRestorationActivationPhase,
        world: Option<&crate::node_contract::WorldActivation>,
    ) -> Result<super::super::activation::OriginalInstalledRestorationActivationClaim, RuntimeError>
    {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        if self.phase_in_flight.get() || !self.context_issued.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.with_original_installed_node_custody_data(
            selected,
            source,
            controller,
            read_owner,
            |_, _, _| Ok(()),
        )?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        match (phase, world) {
            (OriginalInstalledRestorationActivationPhase::Arm, None) => {}
            (OriginalInstalledRestorationActivationPhase::WorldActivate, Some(world)) => {
                self.runtime
                    .authenticate_world_activation_data(world, &scope.target)?;
                if let Some(original) = self.activation_world.get() {
                    if !original.same_authority(world) {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                } else {
                    self.activation_world
                        .set(world.clone())
                        .map_err(|_| RuntimeError::DuplicateOperation)?;
                }
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        let proof = self.original_complete_scope_proof_identity_data()?;
        let ledger = self
            .activation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        ledger.begin(phase)?;
        self.authenticate_original_activation_member_data(
            selected,
            self.sources[selected].as_ref(),
            phase,
            proof,
        )?;
        Ok(super::super::activation::OriginalInstalledRestorationActivationClaim::from_original_window(
            self, selected, phase, proof))
    }
}

impl CompleteOriginalRestorationWindow {
    fn authenticate_original_retained_activation_identity_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        phase: OriginalInstalledRestorationActivationPhase,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if !std::ptr::eq(
            source,
            self.sources
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?
                .as_ref(),
        ) || self.original_complete_scope_proof_identity_data()? != proof_identity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.activation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_retained_phase_data(phase)?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_identity_data(&plan, scope)
    }

    pub(crate) fn authenticate_original_activation_evidence_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        phase: OriginalInstalledRestorationActivationPhase,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestorationActivationVerifiedPhase<'_>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_original_activation_identity_data(
            selected,
            source.as_ref(),
            phase,
            proof,
        )?;
        self.with_original_activation_signing_inputs_data(
            selected,
            source.as_ref(),
            phase,
            proof,
            |inputs| {
                let actual =
                    evidence.authenticate_current(inputs, inputs.source_construction, || {
                        self.authenticate_original_activation_member_data(
                            selected,
                            source.as_ref(),
                            phase,
                            proof,
                        )
                    })?;
                if actual != phase {
                    return Err(RuntimeError::InvalidReceipt);
                }
                Ok(())
            },
        )?;
        // No erased callback follows SourceRead's kernel/registrar completion.
        self.activation_phases[selected].complete_verified(phase)?;
        if self
            .activation_phases
            .iter()
            .all(|ledger| ledger.is_verified(phase))
        {
            self.whole_observation.require_observation();
        }
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    pub(crate) fn original_installed_source_activation_data(
        &self,
        selected: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData,
        RuntimeError,
    > {
        self.origin()?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.source_activation)
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}
